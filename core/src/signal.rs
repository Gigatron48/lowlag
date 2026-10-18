//! Rendezvous transport. Only used for a few small encrypted messages while connecting; all real
//! traffic goes peer-to-peer.
//!
//! The production transport speaks the ntfy HTTP pub/sub protocol (https://ntfy.sh, open source,
//! self-hostable), so the public instance can later be swapped for our own servers by changing a
//! URL.

use crate::{Error, Result};
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DEFAULT_SERVER: &str = "https://ntfy.sh";

/// Rendezvous servers used together (any one reachable on both sides is enough).
pub const DEFAULT_SERVERS: &[&str] = &[
    "https://ntfy.sh",
    "mqtt://broker.emqx.io:1883",
    "mqtt://broker.hivemq.com:1883",
    "mqtt://test.mosquitto.org:1883",
];

/// Build a transport from a URL: `https://…` (ntfy) or `mqtt://host:port`.
pub fn transport_for(url: &str) -> Result<Arc<dyn SignalTransport>> {
    if url.starts_with("mqtt://") {
        Ok(Arc::new(crate::mqtt::Mqtt::new(url)?))
    } else if url.starts_with("https://") || url.starts_with("http://") {
        Ok(Arc::new(Ntfy::new(url)?))
    } else {
        Err(Error::Signal(format!("unsupported rendezvous url: {url}")))
    }
}

/// Short human name for a server URL ("ntfy.sh", "broker.emqx.io").
pub fn server_label(url: &str) -> String {
    let rest = url.split("://").nth(1).unwrap_or(url);
    rest.split(['/', ':']).next().unwrap_or(rest).to_string()
}

#[derive(Debug, Clone, PartialEq)]
pub enum SignalEvent {
    /// Subscription is live; messages published from now on will be delivered.
    Open,
    Message(String),
}

pub trait SignalTransport: Send + Sync {
    fn publish(&self, topic: &str, body: &str) -> Result<()>;
    /// Blocks, delivering events until `stop` is set, the callback returns `false`, or the
    /// connection fails (then returns Err and the caller may retry). `since` replays cached
    /// messages newer than that ("30s", a message id, ...).
    fn subscribe(
        &self,
        topic: &str,
        since: Option<&str>,
        stop: &AtomicBool,
        on_event: &mut dyn FnMut(SignalEvent) -> bool,
    ) -> Result<()>;
}

// ------------------------------------------------------------------ ntfy

pub struct Ntfy {
    base: String,
    agent: ureq::Agent,
}

impl Ntfy {
    pub fn new(base: &str) -> Result<Self> {
        let tls = native_tls::TlsConnector::new().map_err(|e| Error::Signal(format!("tls: {e}")))?;
        let agent = ureq::AgentBuilder::new()
            .tls_connector(Arc::new(tls))
            .timeout_connect(Duration::from_secs(10))
            // ntfy sends a keepalive every ~45 s; if nothing arrives for 70 s, reconnect.
            .timeout_read(Duration::from_secs(70))
            .timeout_write(Duration::from_secs(10))
            .user_agent(concat!("LowLag/", env!("CARGO_PKG_VERSION")))
            .try_proxy_from_env(true)
            .build();
        Ok(Self { base: base.trim_end_matches('/').to_string(), agent })
    }
}

impl SignalTransport for Ntfy {
    fn publish(&self, topic: &str, body: &str) -> Result<()> {
        let url = format!("{}/{}", self.base, topic);
        self.agent
            .post(&url)
            .set("Content-Type", "text/plain")
            .send_string(body)
            .map_err(|e| Error::Signal(format!("publish: {e}")))?;
        Ok(())
    }

    fn subscribe(
        &self,
        topic: &str,
        since: Option<&str>,
        stop: &AtomicBool,
        on_event: &mut dyn FnMut(SignalEvent) -> bool,
    ) -> Result<()> {
        let mut url = format!("{}/{}/json", self.base, topic);
        if let Some(s) = since {
            url.push_str("?since=");
            url.push_str(s);
        }
        let resp = self.agent.get(&url).call().map_err(|e| Error::Signal(format!("subscribe: {e}")))?;
        let reader = BufReader::new(resp.into_reader());
        for line in reader.lines() {
            if stop.load(Ordering::Relaxed) {
                return Ok(());
            }
            let line = line.map_err(|e| Error::Signal(format!("stream: {e}")))?;
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
            let ev = match v.get("event").and_then(|e| e.as_str()) {
                Some("open") => SignalEvent::Open,
                Some("message") => match v.get("message").and_then(|m| m.as_str()) {
                    Some(m) => SignalEvent::Message(m.to_string()),
                    None => continue,
                },
                _ => continue, // keepalive etc.
            };
            if !on_event(ev) {
                return Ok(());
            }
        }
        Err(Error::Signal("stream closed".into()))
    }
}

// ------------------------------------------------------------------ in-memory (tests, LAN demos)

#[derive(Default)]
pub struct MemSignal {
    subs: Mutex<HashMap<String, Vec<Sender<String>>>>,
}

impl MemSignal {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

impl SignalTransport for MemSignal {
    fn publish(&self, topic: &str, body: &str) -> Result<()> {
        let mut subs = self.subs.lock().unwrap();
        if let Some(list) = subs.get_mut(topic) {
            list.retain(|tx| tx.send(body.to_string()).is_ok());
        }
        Ok(())
    }

    fn subscribe(
        &self,
        topic: &str,
        _since: Option<&str>,
        stop: &AtomicBool,
        on_event: &mut dyn FnMut(SignalEvent) -> bool,
    ) -> Result<()> {
        let (tx, rx) = channel();
        self.subs.lock().unwrap().entry(topic.to_string()).or_default().push(tx);
        if !on_event(SignalEvent::Open) {
            return Ok(());
        }
        loop {
            if stop.load(Ordering::Relaxed) {
                return Ok(());
            }
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(m) => {
                    if !on_event(SignalEvent::Message(m)) {
                        return Ok(());
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Err(Error::Signal("closed".into())),
            }
        }
    }
}

// ------------------------------------------------------------------ several servers at once

/// Uses several rendezvous servers in parallel: publishes to all of them and listens on all of
/// them, de-duplicating messages. Works as long as each side reaches at least one common server.
pub struct MultiSignal {
    parts: Vec<(String, Arc<dyn SignalTransport>)>,
}

enum PartEvent {
    Ev(usize, SignalEvent),
    Fail(usize, String),
}

impl MultiSignal {
    pub fn new(urls: &[String]) -> Result<Self> {
        let mut parts = Vec::new();
        for u in urls {
            match transport_for(u) {
                Ok(t) => parts.push((server_label(u), t)),
                Err(e) => log::warn!("skipping rendezvous server {u}: {e}"),
            }
        }
        if parts.is_empty() {
            return Err(Error::Signal("no usable rendezvous servers".into()));
        }
        Ok(Self { parts })
    }

    pub fn from_parts(parts: Vec<(String, Arc<dyn SignalTransport>)>) -> Self {
        Self { parts }
    }

    pub fn parts(&self) -> &[(String, Arc<dyn SignalTransport>)] {
        &self.parts
    }
}

fn msg_hash(m: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    m.hash(&mut h);
    h.finish()
}

impl SignalTransport for MultiSignal {
    fn publish(&self, topic: &str, body: &str) -> Result<()> {
        let (tx, rx) = channel();
        for (name, t) in &self.parts {
            let (tx, t, name, topic, body) = (tx.clone(), t.clone(), name.clone(), topic.to_string(), body.to_string());
            std::thread::spawn(move || {
                let r = t.publish(&topic, &body);
                let _ = tx.send((name, r));
            });
        }
        drop(tx);
        let mut errors = Vec::new();
        loop {
            match rx.recv_timeout(Duration::from_secs(12)) {
                Ok((_, Ok(()))) => return Ok(()), // the others keep going in the background
                Ok((name, Err(e))) => errors.push(format!("{name}: {e}")),
                Err(_) => break,
            }
        }
        Err(Error::Signal(format!("publish failed everywhere: {}", errors.join("; "))))
    }

    fn subscribe(
        &self,
        topic: &str,
        since: Option<&str>,
        stop: &AtomicBool,
        on_event: &mut dyn FnMut(SignalEvent) -> bool,
    ) -> Result<()> {
        let n = self.parts.len();
        let inner_stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = channel::<PartEvent>();
        for (i, (name, t)) in self.parts.iter().enumerate() {
            let (tx, t, name, topic, since, st) =
                (tx.clone(), t.clone(), name.clone(), topic.to_string(), since.map(|s| s.to_string()), inner_stop.clone());
            std::thread::Builder::new()
                .name(format!("ll-sig-{name}"))
                .spawn(move || {
                    let mut backoff = Duration::from_secs(2);
                    let mut first = true;
                    while !st.load(Ordering::Relaxed) {
                        let since_now = if first { since.clone() } else { Some("60s".to_string()) };
                        first = false;
                        let res = t.subscribe(&topic, since_now.as_deref(), &st, &mut |ev| {
                            tx.send(PartEvent::Ev(i, ev)).is_ok() && !st.load(Ordering::Relaxed)
                        });
                        if st.load(Ordering::Relaxed) {
                            break;
                        }
                        let why = match res {
                            Err(e) => e.to_string(),
                            Ok(()) => "ended".to_string(),
                        };
                        log::debug!("rendezvous {name}: {why}");
                        if tx.send(PartEvent::Fail(i, why)).is_err() {
                            break;
                        }
                        let until = Instant::now() + backoff;
                        while Instant::now() < until && !st.load(Ordering::Relaxed) {
                            std::thread::sleep(Duration::from_millis(100));
                        }
                        backoff = (backoff * 2).min(Duration::from_secs(30));
                    }
                })
                .expect("spawn rendezvous thread");
        }
        drop(tx);

        let finish = |r: Result<()>| {
            inner_stop.store(true, Ordering::SeqCst);
            r
        };
        let start = Instant::now();
        let mut opened = vec![false; n];
        let mut failures: Vec<Option<String>> = vec![None; n];
        let mut first_open: Option<Instant> = None;
        let mut announced = false;
        let mut pending: Vec<String> = Vec::new();
        let mut seen: VecDeque<u64> = VecDeque::new();
        loop {
            if stop.load(Ordering::Relaxed) {
                return finish(Ok(()));
            }
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(PartEvent::Ev(i, SignalEvent::Open)) => {
                    if !opened[i] {
                        log::info!("rendezvous: listening via {}", self.parts[i].0);
                    }
                    opened[i] = true;
                    first_open.get_or_insert_with(Instant::now);
                }
                Ok(PartEvent::Ev(_, SignalEvent::Message(m))) => {
                    let h = msg_hash(&m);
                    if !seen.contains(&h) {
                        seen.push_back(h);
                        if seen.len() > 256 {
                            seen.pop_front();
                        }
                        if announced {
                            if !on_event(SignalEvent::Message(m)) {
                                return finish(Ok(()));
                            }
                        } else {
                            pending.push(m);
                        }
                    }
                }
                Ok(PartEvent::Fail(i, why)) => {
                    opened[i] = false;
                    failures[i] = Some(why);
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return finish(Err(Error::Signal("all rendezvous threads ended".into()))),
            }
            if !announced {
                // Wait briefly for the slower servers so a peer that only reaches one of them
                // is still heard; but never longer than 3 s after the first one is live.
                let all = opened.iter().all(|o| *o);
                if all || first_open.map_or(false, |t| t.elapsed() > Duration::from_secs(3)) {
                    announced = true;
                    if !on_event(SignalEvent::Open) {
                        return finish(Ok(()));
                    }
                    for m in pending.drain(..) {
                        if !on_event(SignalEvent::Message(m)) {
                            return finish(Ok(()));
                        }
                    }
                } else if first_open.is_none() && start.elapsed() > Duration::from_secs(20) {
                    let detail: Vec<String> = self
                        .parts
                        .iter()
                        .zip(&failures)
                        .map(|((name, _), f)| format!("{name}: {}", f.as_deref().unwrap_or("no answer")))
                        .collect();
                    return finish(Err(Error::Signal(format!("no rendezvous server reachable ({})", detail.join("; ")))));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A transport that never connects.
    struct Dead;
    impl SignalTransport for Dead {
        fn publish(&self, _t: &str, _b: &str) -> Result<()> {
            Err(Error::Signal("dead".into()))
        }
        fn subscribe(&self, _t: &str, _s: Option<&str>, stop: &AtomicBool, _f: &mut dyn FnMut(SignalEvent) -> bool) -> Result<()> {
            for _ in 0..10 {
                if stop.load(Ordering::Relaxed) {
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(Error::Signal("dead".into()))
        }
    }

    #[test]
    fn multi_works_if_one_server_is_shared() {
        // host reaches A and B, client reaches only B (A is "blocked" for the client)
        let a = MemSignal::new();
        let b = MemSignal::new();
        let host = Arc::new(MultiSignal::from_parts(vec![("a".into(), a.clone()), ("b".into(), b.clone())]));
        let client = MultiSignal::from_parts(vec![("dead".into(), Arc::new(Dead)), ("b".into(), b.clone())]);
        let (tx, rx) = channel();
        let h2 = host.clone();
        std::thread::spawn(move || {
            let stop = AtomicBool::new(false);
            let _ = h2.subscribe("topic", None, &stop, &mut |ev| tx.send(ev).is_ok());
        });
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), SignalEvent::Open);
        client.publish("topic", "hi").unwrap();
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), SignalEvent::Message("hi".into()));
        // the host publishes to both; the duplicate must not show up twice
        host.publish("topic", "dup").unwrap();
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), SignalEvent::Message("dup".into()));
        assert!(rx.recv_timeout(Duration::from_millis(300)).is_err());
    }

    #[test]
    fn multi_reports_when_nothing_is_reachable() {
        let m = MultiSignal::from_parts(vec![("x".into(), Arc::new(Dead))]);
        assert!(m.publish("t", "b").is_err());
    }

    #[test]
    fn labels() {
        assert_eq!(server_label("https://ntfy.sh"), "ntfy.sh");
        assert_eq!(server_label("mqtt://broker.emqx.io:1883"), "broker.emqx.io");
    }
}
