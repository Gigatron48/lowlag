//! Rendezvous transport. Only used for a few small encrypted messages while connecting; all real
//! traffic goes peer-to-peer.
//!
//! The production transport speaks the ntfy HTTP pub/sub protocol (https://ntfy.sh, open source,
//! self-hostable), so the public instance can later be swapped for our own servers by changing a
//! URL.

use crate::{Error, Result};
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const DEFAULT_SERVER: &str = "https://ntfy.sh";

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
