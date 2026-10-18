//! UDP hole punching.
//!
//! Both peers run this at the same time.
//!
//! * easy ↔ easy (both NATs keep one public port per socket): spraying authenticated PUNCH
//!   packets at each other's candidates opens both NATs.
//! * easy ↔ hard (one side is a "symmetric"/CGNAT that picks a new public port per destination):
//!   the hard side keeps ONE socket aimed at the easy side's single known endpoint, so it has one
//!   stable public port; the easy side sprays random ports at the hard side's public IP until one
//!   lands on that port (the "birthday" technique, as in Tailscale). This is the common case and
//!   succeeds quickly.
//! * hard ↔ hard: neither side has a predictable port, so both open many sockets AND spray. This
//!   is the low-probability case; when it fails the session needs a relay (not yet built).

use crate::crypto::{RxCipher, TxCipher};
use crate::proto::{P_PUNCH, P_PUNCH_ACK};
use crate::{Error, Result};
use rand::Rng;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Extra sockets opened by a side behind a hard NAT.
pub const HARD_NAT_SOCKETS: usize = 128;
/// Random-port probes per spray tick (one tick = 40 ms) towards a hard-NAT peer.
const PROBES_PER_TICK: usize = 24;

#[derive(Debug, Clone, Default)]
pub struct PunchPlan {
    /// Peer's advertised candidates (public, UPnP, LAN).
    pub cands: Vec<SocketAddr>,
    /// Guessed next public ports of a hard-NAT peer (sequential allocators).
    pub predicted: Vec<SocketAddr>,
    /// The peer is behind a hard NAT: spray random ports on this IP.
    pub spray_ip: Option<Ipv4Addr>,
    /// Public ports STUN saw for the peer (random probes are biased towards them).
    pub peer_ports: Vec<u16>,
}

impl PunchPlan {
    /// Build the plan from what the peer told us.
    pub fn new(cands: Vec<SocketAddr>, peer_nat: &str, peer_ports: &[u16]) -> Self {
        let mut plan = PunchPlan { cands, peer_ports: peer_ports.to_vec(), ..Default::default() };
        let peer_hard = peer_nat == "hard" || peer_nat.is_empty() || peer_nat == "unknown";
        if !peer_hard {
            return plan;
        }
        let public_ip = plan.cands.iter().find_map(|a| match a.ip() {
            IpAddr::V4(ip) if !ip.is_private() && !ip.is_loopback() && !ip.is_link_local() => Some(ip),
            _ => None,
        });
        if let Some(ip) = public_ip {
            plan.spray_ip = Some(ip);
            // Sequential allocators hand out the next ports after the ones STUN saw.
            if let Some(&max) = peer_ports.iter().max() {
                for d in 1..=48u16 {
                    if let Some(p) = max.checked_add(d) {
                        plan.predicted.push(SocketAddr::new(IpAddr::V4(ip), p));
                    }
                }
            }
        }
        plan
    }
}

/// Our own extra sockets when we are behind a hard NAT.
pub fn open_extra_sockets(n: usize) -> Vec<UdpSocket> {
    (0..n).filter_map(|_| UdpSocket::bind("0.0.0.0:0").ok()).collect()
}

fn random_port(rng: &mut impl Rng, near: &[u16]) -> u16 {
    if !near.is_empty() && rng.gen_bool(0.5) {
        let c = near[rng.gen_range(0..near.len())] as i32;
        return (c + rng.gen_range(-4096..=4096)).clamp(1024, 65535) as u16;
    }
    rng.gen_range(1024..=65535)
}

/// Returns (index of the socket that got through, peer address).
pub fn punch(
    socks: &[UdpSocket],
    plan: &PunchPlan,
    tx: &TxCipher,
    rx: &mut RxCipher,
    timeout: Duration,
    cancel: &AtomicBool,
) -> Result<(usize, SocketAddr)> {
    if plan.cands.is_empty() && plan.spray_ip.is_none() {
        return Err(Error::NatTraversal("peer has no candidates".into()));
    }
    for s in socks {
        s.set_nonblocking(true)?;
    }
    let restore = |socks: &[UdpSocket]| {
        for s in socks {
            let _ = s.set_nonblocking(false);
        }
    };
    let mut rng = rand::thread_rng();
    let start = Instant::now();
    let mut last_tick = None::<Instant>;
    let mut tick: u64 = 0;
    let mut found: Option<(usize, SocketAddr, Instant)> = None;
    let mut acked = false;
    let mut out = Vec::with_capacity(64);
    let mut buf = vec![0u8; 2048];
    let mut sent_random = 0u64;

    let result = loop {
        if cancel.load(Ordering::Relaxed) {
            break Err(Error::Cancelled);
        }
        if start.elapsed() > timeout {
            break Err(Error::NatTraversal(format!(
                "no reply in {:?} (cands {}, extra sockets {}, random probes {})",
                timeout,
                plan.cands.len(),
                socks.len().saturating_sub(1),
                sent_random
            )));
        }
        if let Some((i, addr, at)) = found {
            if acked || at.elapsed() > Duration::from_millis(1500) {
                for _ in 0..3 {
                    tx.seal(P_PUNCH_ACK, b"", &mut out);
                    let _ = socks[i].send_to(&out, addr);
                }
                break Ok((i, addr));
            }
        }

        // ---- send
        if last_tick.map_or(true, |t| t.elapsed() >= Duration::from_millis(40)) {
            last_tick = Some(Instant::now());
            tick += 1;
            let early = start.elapsed() < Duration::from_secs(3);
            // main socket: candidates every tick early on, then every third tick
            if early || tick % 3 == 0 {
                for c in plan.cands.iter().chain(plan.predicted.iter()) {
                    tx.seal(P_PUNCH, &(tick as u32).to_le_bytes(), &mut out);
                    let _ = socks[0].send_to(&out, c);
                }
            }
            // extra sockets (hard NAT on our side): each one every 5th tick (200 ms)
            for (k, s) in socks.iter().enumerate().skip(1) {
                if (k as u64 + tick) % 5 == 0 {
                    for c in &plan.cands {
                        tx.seal(P_PUNCH, &(tick as u32).to_le_bytes(), &mut out);
                        let _ = s.send_to(&out, c);
                    }
                }
            }
            // hard NAT on the peer's side: random ports on its public IP
            if let Some(ip) = plan.spray_ip {
                for _ in 0..PROBES_PER_TICK {
                    let port = random_port(&mut rng, &plan.peer_ports);
                    tx.seal(P_PUNCH, &(tick as u32).to_le_bytes(), &mut out);
                    let _ = socks[0].send_to(&out, SocketAddr::new(IpAddr::V4(ip), port));
                    sent_random += 1;
                }
            }
        }

        // ---- receive (all sockets, non-blocking)
        let mut got_any = false;
        for (i, s) in socks.iter().enumerate() {
            loop {
                match s.recv_from(&mut buf) {
                    Ok((n, from)) => {
                        got_any = true;
                        let Some((ptype, _)) = rx.open(&mut buf[..n]) else { continue };
                        match ptype {
                            P_PUNCH => {
                                tx.seal(P_PUNCH_ACK, b"", &mut out);
                                let _ = s.send_to(&out, from);
                                if found.is_none() {
                                    found = Some((i, from, Instant::now()));
                                }
                            }
                            P_PUNCH_ACK => {
                                acked = true;
                                if found.is_none() {
                                    found = Some((i, from, Instant::now()));
                                }
                            }
                            // Peer already moved on to tunnel traffic: the path works.
                            _ => {
                                if found.is_none() || found.map(|f| f.0) == Some(i) {
                                    found = Some((i, from, Instant::now()));
                                    acked = true;
                                }
                            }
                        }
                    }
                    Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::ConnectionReset | ErrorKind::Interrupted) => {
                        if e.kind() == ErrorKind::ConnectionReset {
                            continue; // Windows: ICMP unreachable from an earlier probe
                        }
                        break;
                    }
                    Err(e) => {
                        log::debug!("punch recv on socket {i}: {e}");
                        break;
                    }
                }
            }
        }
        if !got_any {
            std::thread::sleep(Duration::from_millis(2));
        }
    };
    restore(socks);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_for_hard_peer_sprays_its_public_ip() {
        let cands = vec!["192.168.1.5:47810".parse().unwrap(), "203.0.113.9:40001".parse().unwrap()];
        let p = PunchPlan::new(cands.clone(), "hard", &[40001, 40007]);
        assert_eq!(p.spray_ip, Some("203.0.113.9".parse().unwrap()));
        assert_eq!(p.predicted.first(), Some(&"203.0.113.9:40008".parse().unwrap()));
        let easy = PunchPlan::new(cands, "easy", &[47810]);
        assert!(easy.spray_ip.is_none() && easy.predicted.is_empty());
    }

    #[test]
    fn random_ports_stay_in_range() {
        let mut rng = rand::thread_rng();
        for _ in 0..10_000 {
            let p = random_port(&mut rng, &[1500, 65000]);
            assert!(p >= 1024);
        }
    }
}
