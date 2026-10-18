//! "Check network": which rendezvous servers, STUN servers and router features work from here.
//! Shown in the UI and included in support reports.

use crate::platform::Platform;
use llcore::signal::{server_label, transport_for, SignalEvent};
use serde::Serialize;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CheckItem {
    /// server | stun | router | zapret
    pub group: String,
    pub name: String,
    pub ok: bool,
    pub detail: String,
    pub ms: u32,
}

fn item(group: &str, name: &str, ok: bool, detail: impl Into<String>, ms: u128) -> CheckItem {
    CheckItem { group: group.into(), name: name.into(), ok, detail: detail.into(), ms: ms.min(u32::MAX as u128) as u32 }
}

fn check_server(url: &str) -> CheckItem {
    let name = server_label(url);
    let t0 = Instant::now();
    let t = match transport_for(url) {
        Ok(t) => t,
        Err(e) => return item("server", &name, false, e.to_string(), 0),
    };
    let (tx, rx) = channel();
    let stop = Arc::new(AtomicBool::new(false));
    let st = stop.clone();
    let topic = format!("ll1check{}", llcore::random_hex(8));
    thread::spawn(move || {
        let r = t.subscribe(&topic, None, &st, &mut |ev| {
            let _ = tx.send(Ok(ev));
            false
        });
        if let Err(e) = r {
            let _ = tx.send(Err(e.to_string()));
        }
    });
    let res = rx.recv_timeout(Duration::from_secs(8));
    stop.store(true, Ordering::SeqCst);
    match res {
        Ok(Ok(SignalEvent::Open)) => item("server", &name, true, "", t0.elapsed().as_millis()),
        Ok(Ok(_)) => item("server", &name, true, "", t0.elapsed().as_millis()),
        Ok(Err(e)) => item("server", &name, false, e, t0.elapsed().as_millis()),
        Err(_) => item("server", &name, false, "timeout", t0.elapsed().as_millis()),
    }
}

fn check_stun(servers: &[String]) -> Vec<CheckItem> {
    let resolved = llcore::stun::resolve_within(servers, Duration::from_secs(3));
    let mut out = Vec::new();
    let mut mapped_ports = Vec::new();
    for name in servers {
        let short = name.split(':').next().unwrap_or(name).to_string();
        let Some((_, addr)) = resolved.iter().find(|(n, _)| n == name) else {
            out.push(item("stun", &short, false, "DNS lookup failed", 0));
            continue;
        };
        let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else { continue };
        let t0 = Instant::now();
        let r = llcore::stun::query(&sock, &[*addr], Duration::from_millis(2500));
        match r.first() {
            Some((_, m)) => {
                mapped_ports.push(m.port() != sock.local_addr().map(|a| a.port()).unwrap_or(0));
                out.push(item("stun", &short, true, m.ip().to_string(), t0.elapsed().as_millis()))
            }
            None => out.push(item("stun", &short, false, "no reply", t0.elapsed().as_millis())),
        }
    }
    out
}

/// Runs all checks in parallel; takes up to ~9 s.
pub fn run(platform: &Arc<dyn Platform>, signal_servers: &[String], stun_servers: &[String]) -> Vec<CheckItem> {
    let (tx, rx) = channel::<(usize, Vec<CheckItem>)>();
    let mut jobs = 0;
    for (i, url) in signal_servers.iter().enumerate() {
        let (tx, url) = (tx.clone(), url.clone());
        thread::spawn(move || {
            let _ = tx.send((i, vec![check_server(&url)]));
        });
        jobs += 1;
    }
    {
        let (tx, st) = (tx.clone(), stun_servers.to_vec());
        thread::spawn(move || {
            let _ = tx.send((100, check_stun(&st)));
        });
        jobs += 1;
    }
    {
        let tx = tx.clone();
        thread::spawn(move || {
            let t0 = Instant::now();
            let it = match llcore::netinfo::upnp_probe() {
                Some(d) => item("router", "UPnP", true, d, t0.elapsed().as_millis()),
                None => item("router", "UPnP", false, "not available", t0.elapsed().as_millis()),
            };
            let _ = tx.send((200, vec![it]));
        });
        jobs += 1;
    }
    {
        let (tx, p) = (tx.clone(), platform.clone());
        thread::spawn(move || {
            let v = p.zapret_status().map(|z| vec![item("zapret", "Zapret", !z.risky, z.describe(), 0)]).unwrap_or_default();
            let _ = tx.send((300, v));
        });
        jobs += 1;
    }
    drop(tx);
    let mut parts = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(12);
    while parts.len() < jobs {
        let Some(left) = deadline.checked_duration_since(Instant::now()) else { break };
        match rx.recv_timeout(left) {
            Ok(p) => parts.push(p),
            Err(_) => break,
        }
    }
    parts.sort_by_key(|p| p.0);
    let out: Vec<CheckItem> = parts.into_iter().flat_map(|p| p.1).collect();
    for i in &out {
        log::info!("netcheck {} {}: {} {} ({} ms)", i.group, i.name, if i.ok { "ok" } else { "FAIL" }, i.detail, i.ms);
    }
    out
}

pub fn to_text(items: &[CheckItem]) -> String {
    items
        .iter()
        .map(|i| format!("[{}] {:<8} {:<22} {} {} ms\n", if i.ok { "ok" } else { "--" }, i.group, i.name, i.detail, i.ms))
        .collect()
}
