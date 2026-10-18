//! An established tunnel: moves IP packets between the virtual adapter and the peer, keeps the
//! path alive, measures RTT, carries control messages and runs the bandwidth probe.
//!
//! Latency notes: no queues between the adapter and the socket – each thread reads a packet,
//! encrypts/decrypts it and immediately hands it on. Lost packets are never retransmitted here
//! (the video stream has its own FEC); late data is worse than lost data for game streaming.

use crate::crypto::{RxCipher, TxCipher};
use crate::proto::*;
use crate::tun::{ipv4_src_dst, TunDevice};
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const KEEPALIVE: Duration = Duration::from_millis(1000);
const DEAD_AFTER_MS: u64 = 15_000;
const FILL_SIZE: usize = 1200;

pub struct ConnParams {
    pub sock: UdpSocket,
    pub peer: SocketAddr,
    pub tx: TxCipher,
    pub rx: RxCipher,
    pub local_ip: Ipv4Addr,
    pub peer_ip: Ipv4Addr,
}

#[derive(Debug, Clone)]
pub enum ConnEvent {
    Ctrl(Ctrl),
    Closed(String),
}

#[derive(Debug, Clone, Default)]
pub struct ConnStats {
    pub rtt_ms: f64,
    pub path: String,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub idle_ms: u64,
}

#[derive(Debug, Clone)]
pub struct SpeedResult {
    /// (rate Mbit/s, loss 0..1)
    pub steps: Vec<(u32, f64)>,
    /// Highest rate with <= 3 % loss (0 if none).
    pub best_mbps: u32,
}

struct Inner {
    sock: UdpSocket,
    peer: Mutex<SocketAddr>,
    tx: TxCipher,
    tun: Arc<dyn TunDevice>,
    local_ip: Ipv4Addr,
    peer_ip: Ipv4Addr,
    start: Instant,
    closed: AtomicBool,
    last_rx_ms: AtomicU64,
    srtt_us: AtomicU64,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    events: Sender<ConnEvent>,
    speed_rx: Mutex<Vec<u32>>,
    speed_done: (Mutex<Option<Vec<u32>>>, Condvar),
    filler_running: AtomicBool,
}

impl Inner {
    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    fn send_to(&self, ptype: u8, payload: &[u8], buf: &mut Vec<u8>, to: SocketAddr) {
        self.tx.seal(ptype, payload, buf);
        match self.sock.send_to(buf, to) {
            Ok(n) => {
                self.tx_bytes.fetch_add(n as u64, Ordering::Relaxed);
            }
            Err(e) => log::debug!("send_to {to}: {e}"),
        }
    }

    fn send(&self, ptype: u8, payload: &[u8], buf: &mut Vec<u8>) {
        let to = *self.peer.lock().unwrap();
        self.send_to(ptype, payload, buf, to);
    }

    fn send_ctrl(&self, c: &Ctrl) {
        let body = serde_json::to_vec(c).expect("ctrl serializes");
        let mut buf = Vec::with_capacity(body.len() + 32);
        self.send(P_CTRL, &body, &mut buf);
    }

    fn close_internal(&self, reason: String) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            log::info!("tunnel closed: {reason}");
            self.tun.shutdown();
            let _ = self.events.send(ConnEvent::Closed(reason));
        }
    }

    /// Authentic traffic from a new address means the peer's NAT mapping changed (or it switched
    /// networks): follow it, like WireGuard does.
    fn roam(&self, from: SocketAddr) {
        let mut p = self.peer.lock().unwrap();
        if *p != from {
            log::info!("peer moved {} -> {}", *p, from);
            *p = from;
        }
    }
}

#[derive(Clone)]
pub struct Conn {
    inner: Arc<Inner>,
}

impl Conn {
    pub fn start(p: ConnParams, tun: Arc<dyn TunDevice>) -> (Conn, Receiver<ConnEvent>) {
        let (events, rx_events) = channel();
        let inner = Arc::new(Inner {
            sock: p.sock,
            peer: Mutex::new(p.peer),
            tx: p.tx,
            tun,
            local_ip: p.local_ip,
            peer_ip: p.peer_ip,
            start: Instant::now(),
            closed: AtomicBool::new(false),
            last_rx_ms: AtomicU64::new(0),
            srtt_us: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            events,
            speed_rx: Mutex::new(Vec::new()),
            speed_done: (Mutex::new(None), Condvar::new()),
            filler_running: AtomicBool::new(false),
        });
        let _ = inner.sock.set_read_timeout(Some(Duration::from_millis(200)));

        let i = inner.clone();
        let rx = p.rx;
        thread::Builder::new().name("ll-recv".into()).spawn(move || recv_loop(i, rx)).unwrap();
        let i = inner.clone();
        thread::Builder::new().name("ll-tun".into()).spawn(move || tun_loop(i)).unwrap();
        let i = inner.clone();
        thread::Builder::new().name("ll-keepalive".into()).spawn(move || keepalive_loop(i)).unwrap();

        (Conn { inner }, rx_events)
    }

    pub fn send_ctrl(&self, c: &Ctrl) {
        self.inner.send_ctrl(c);
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Relaxed)
    }

    pub fn peer_addr(&self) -> SocketAddr {
        *self.inner.peer.lock().unwrap()
    }

    pub fn stats(&self) -> ConnStats {
        let i = &self.inner;
        ConnStats {
            rtt_ms: i.srtt_us.load(Ordering::Relaxed) as f64 / 1000.0,
            path: self.peer_addr().to_string(),
            tx_bytes: i.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: i.rx_bytes.load(Ordering::Relaxed),
            idle_ms: i.now_ms().saturating_sub(i.last_rx_ms.load(Ordering::Relaxed)),
        }
    }

    /// Close locally and tell the peer.
    pub fn close(&self, reason: &str) {
        if self.is_closed() {
            return;
        }
        let mut buf = Vec::new();
        for _ in 0..3 {
            self.inner.send(P_BYE, reason.as_bytes(), &mut buf);
        }
        self.inner.close_internal(format!("local: {reason}"));
    }

    /// Client side: ask the peer to send filler traffic at increasing rates and measure loss.
    pub fn speed_test(&self, steps: &[u32], step_ms: u32) -> Option<SpeedResult> {
        let i = &self.inner;
        *i.speed_rx.lock().unwrap() = vec![0; steps.len()];
        *i.speed_done.0.lock().unwrap() = None;
        i.send_ctrl(&Ctrl::SpeedReq { steps: steps.to_vec(), ms: step_ms });
        let deadline = Duration::from_millis(steps.len() as u64 * step_ms as u64 + 4000);
        let guard = i.speed_done.0.lock().unwrap();
        let (guard, _) = i.speed_done.1.wait_timeout_while(guard, deadline, |d| d.is_none()).unwrap();
        let sent = guard.clone()?;
        drop(guard);
        // let stragglers arrive
        thread::sleep(Duration::from_millis(150));
        let got = i.speed_rx.lock().unwrap().clone();
        let mut res = SpeedResult { steps: Vec::new(), best_mbps: 0 };
        for (k, rate) in steps.iter().enumerate() {
            let s = *sent.get(k).unwrap_or(&0) as f64;
            let g = *got.get(k).unwrap_or(&0) as f64;
            let loss = if s > 0.0 { (1.0 - g / s).max(0.0) } else { 1.0 };
            res.steps.push((*rate, loss));
            if loss <= 0.03 {
                res.best_mbps = *rate;
            } else {
                break; // rates above a lossy one are not trustworthy
            }
        }
        Some(res)
    }
}

fn is_soft_error(e: &std::io::Error) -> bool {
    // ConnectionReset: Windows reports ICMP "port unreachable" from an earlier send on UDP sockets.
    matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::ConnectionReset | ErrorKind::Interrupted)
}

fn recv_loop(inner: Arc<Inner>, mut rx: RxCipher) {
    let mut buf = vec![0u8; 65536];
    let mut out = Vec::with_capacity(2048);
    while !inner.closed.load(Ordering::Relaxed) {
        let (n, from) = match inner.sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) if is_soft_error(&e) => continue,
            Err(e) => {
                inner.close_internal(format!("socket error: {e}"));
                break;
            }
        };
        let Some((ptype, payload)) = rx.open(&mut buf[..n]) else { continue };
        inner.last_rx_ms.store(inner.now_ms(), Ordering::Relaxed);
        inner.rx_bytes.fetch_add(n as u64, Ordering::Relaxed);
        match ptype {
            P_DATA => {
                inner.roam(from);
                // Only accept packets the peer is allowed to send: from its tunnel IP to ours.
                if let Some((src, dst)) = ipv4_src_dst(payload) {
                    if src == inner.peer_ip && dst == inner.local_ip {
                        if let Err(e) = inner.tun.send(payload) {
                            log::debug!("tun send: {e}");
                        }
                    }
                }
            }
            P_PING => {
                inner.roam(from);
                inner.send_to(P_PONG, payload, &mut out, from);
            }
            P_PONG => {
                inner.roam(from);
                if payload.len() >= 8 {
                    let sent_us = u64::from_le_bytes(payload[..8].try_into().unwrap());
                    let now_us = inner.start.elapsed().as_micros() as u64;
                    let rtt = now_us.saturating_sub(sent_us);
                    let old = inner.srtt_us.load(Ordering::Relaxed);
                    let new = if old == 0 { rtt } else { (old * 7 + rtt) / 8 };
                    inner.srtt_us.store(new, Ordering::Relaxed);
                }
            }
            P_CTRL => {
                inner.roam(from);
                match serde_json::from_slice::<Ctrl>(payload) {
                    Ok(Ctrl::SpeedReq { steps, ms }) => start_filler(inner.clone(), steps, ms),
                    Ok(Ctrl::SpeedDone { sent }) => {
                        *inner.speed_done.0.lock().unwrap() = Some(sent);
                        inner.speed_done.1.notify_all();
                    }
                    Ok(c) => {
                        let _ = inner.events.send(ConnEvent::Ctrl(c));
                    }
                    Err(e) => log::warn!("bad ctrl message: {e}"),
                }
            }
            P_FILL => {
                if let Some(&step) = payload.first() {
                    if let Some(c) = inner.speed_rx.lock().unwrap().get_mut(step as usize) {
                        *c += 1;
                    }
                }
            }
            P_BYE => {
                let why = String::from_utf8_lossy(payload).to_string();
                inner.close_internal(format!("peer: {why}"));
            }
            P_PUNCH => {
                // The peer is still punching (it hasn't seen our ACK yet).
                inner.send_to(P_PUNCH_ACK, b"", &mut out, from);
            }
            _ => {}
        }
    }
}

fn tun_loop(inner: Arc<Inner>) {
    let mut buf = vec![0u8; 65536];
    let mut out = Vec::with_capacity(2048);
    while !inner.closed.load(Ordering::Relaxed) {
        match inner.tun.recv(&mut buf) {
            Ok(n) => {
                let pkt = &buf[..n];
                // Windows chatters on every adapter (IPv6 RS, mDNS, LLMNR, broadcasts): only
                // forward unicast IPv4 addressed to the peer.
                if let Some((_, dst)) = ipv4_src_dst(pkt) {
                    if dst == inner.peer_ip {
                        inner.send(P_DATA, pkt, &mut out);
                    }
                }
            }
            Err(e) => {
                if !inner.closed.load(Ordering::Relaxed) {
                    inner.close_internal(format!("adapter: {e}"));
                }
                break;
            }
        }
    }
}

fn keepalive_loop(inner: Arc<Inner>) {
    let mut buf = Vec::with_capacity(64);
    let mut last = None::<Instant>;
    inner.last_rx_ms.store(inner.now_ms(), Ordering::Relaxed);
    while !inner.closed.load(Ordering::Relaxed) {
        if last.map_or(true, |t| t.elapsed() >= KEEPALIVE) {
            let now_us = inner.start.elapsed().as_micros() as u64;
            inner.send(P_PING, &now_us.to_le_bytes(), &mut buf);
            last = Some(Instant::now());
            let idle = inner.now_ms().saturating_sub(inner.last_rx_ms.load(Ordering::Relaxed));
            if idle > DEAD_AFTER_MS {
                inner.close_internal("connection lost (no packets for 15 s)".into());
                break;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn start_filler(inner: Arc<Inner>, steps: Vec<u32>, ms: u32) {
    if inner.filler_running.swap(true, Ordering::SeqCst) {
        return;
    }
    let steps: Vec<u32> = steps.into_iter().take(12).map(|s| s.clamp(1, 1000)).collect();
    let ms = ms.clamp(100, 2000);
    thread::spawn(move || {
        let mut payload = vec![0u8; FILL_SIZE];
        let mut buf = Vec::with_capacity(FILL_SIZE + 64);
        let mut sent = Vec::new();
        for (k, mbps) in steps.iter().enumerate() {
            let pps = *mbps as f64 * 1_000_000.0 / 8.0 / FILL_SIZE as f64;
            let t0 = Instant::now();
            let dur = Duration::from_millis(ms as u64);
            let mut count: u32 = 0;
            payload[0] = k as u8;
            while t0.elapsed() < dur && !inner.closed.load(Ordering::Relaxed) {
                let due = (t0.elapsed().as_secs_f64() * pps) as u32;
                while count < due {
                    payload[1..5].copy_from_slice(&count.to_le_bytes());
                    inner.send(P_FILL, &payload, &mut buf);
                    count += 1;
                }
                thread::sleep(Duration::from_millis(1));
            }
            sent.push(count);
            // short gap so queues drain between steps
            thread::sleep(Duration::from_millis(60));
        }
        inner.send_ctrl(&Ctrl::SpeedDone { sent });
        inner.filler_running.store(false, Ordering::SeqCst);
    });
}
