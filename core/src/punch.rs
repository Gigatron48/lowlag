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
/// Classic punching gets this long before the hard-NAT techniques are switched on.
pub const ESCALATE_AFTER: Duration = Duration::from_secs(3);
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
        let public_ip = public_ips(&plan.cands).into_iter().next();
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

/// Extra sockets bound to ports in 20000-40000: outside Windows' ephemeral range and outside the
/// UDP ranges DPI-bypass tools such as Zapret intercept (443, 19294-19344, 50000-50100).
pub fn open_extra_sockets(n: usize) -> Vec<UdpSocket> {
    let mut rng = rand::thread_rng();
    let mut out = Vec::with_capacity(n);
    let mut tries = 0;
    while out.len() < n && tries < n * 4 {
        tries += 1;
        let port = rng.gen_range(20000..40000u16);
        if let Ok(s) = UdpSocket::bind(("0.0.0.0", port)) {
            let _ = s.set_nonblocking(true);
            out.push(s);
        }
    }
    out
}

fn random_port(rng: &mut impl Rng, near: &[u16]) -> u16 {
    if !near.is_empty() && rng.gen_bool(0.5) {
        let c = near[rng.gen_range(0..near.len())] as i32;
        return (c + rng.gen_range(-4096..=4096)).clamp(1024, 65535) as u16;
    }
    rng.gen_range(1024..=65535)
}

/// Virtual-LAN tools hand out addresses from 25.0.0.0/8 (Hamachi) and 26.0.0.0/8 (Radmin VPN);
/// they are not reachable over the internet, so never spray at them.
fn is_overlay_ip(ip: &Ipv4Addr) -> bool {
    matches!(ip.octets()[0], 25 | 26)
}

/// Public IPv4 addresses among the peer's candidates.
fn public_ips(cands: &[SocketAddr]) -> Vec<Ipv4Addr> {
    let mut v = Vec::new();
    for a in cands {
        if let IpAddr::V4(ip) = a.ip() {
            if !ip.is_private() && !ip.is_loopback() && !ip.is_link_local() && !is_overlay_ip(&ip) && !v.contains(&ip) {
                v.push(ip);
            }
        }
    }
    v
}

/// Run the punching state machine on `socks` (index 0 = the main socket). Returns the index of
/// the socket that got through and the peer address as seen from it.
///
/// * Success needs proof that OUR packets reach the peer (a PUNCH_ACK or tunnel traffic from it),
///   not just that we hear the peer: one-way paths are common with NATs that map each destination
///   differently, and declaring success on them leaves the other side stranded.
/// * If nothing works after `escalate_after`, both techniques for hard NATs are switched on no
///   matter what the NAT types looked like: extra sockets (new mappings on our NAT) and random
///   port probes at the peer's public IPs (to find the mappings its NAT made towards us).
pub fn punch(
    socks: &mut Vec<UdpSocket>,
    plan: &PunchPlan,
    tx: &TxCipher,
    rx: &mut RxCipher,
    timeout: Duration,
    escalate_after: Duration,
    cancel: &AtomicBool,
) -> Result<(usize, SocketAddr)> {
    if plan.cands.is_empty() && plan.spray_ip.is_none() {
        return Err(Error::NatTraversal("peer has no candidates".into()));
    }
    for s in socks.iter() {
        s.set_nonblocking(true)?;
    }
    let mut rng = rand::thread_rng();
    let start = Instant::now();
    let mut last_tick = None::<Instant>;
    let mut tick: u64 = 0;
    let mut out = Vec::with_capacity(64);
    let mut buf = vec![0u8; 2048];
    let mut sent_random = 0u64;
    let mut heard_from: Option<SocketAddr> = None;
    let mut escalated = false;
    let mut spray_ips: Vec<Ipv4Addr> = plan.spray_ip.into_iter().collect();
    let all_public = public_ips(&plan.cands);

    let result = loop {
        if cancel.load(Ordering::Relaxed) {
            break Err(Error::Cancelled);
        }
        if start.elapsed() > timeout {
            break Err(Error::NatTraversal(format!(
                "no two-way path in {:?} (heard peer: {}, cands {}, extra sockets {}, random probes {})",
                timeout,
                heard_from.map(|a| a.to_string()).unwrap_or_else(|| "no".into()),
                plan.cands.len(),
                socks.len().saturating_sub(1),
                sent_random
            )));
        }
        if !escalated && start.elapsed() >= escalate_after {
            escalated = true;
            if socks.len() == 1 {
                socks.extend(open_extra_sockets(HARD_NAT_SOCKETS));
            }
            for ip in &all_public {
                if !spray_ips.contains(ip) {
                    spray_ips.push(*ip);
                }
            }
            log::info!(
                "punch: no two-way path after {:?} (heard peer: {:?}); escalating: {} extra sockets, spraying {:?}",
                escalate_after,
                heard_from,
                socks.len() - 1,
                spray_ips
            );
        }

        // ---- send
        if last_tick.map_or(true, |t| t.elapsed() >= Duration::from_millis(40)) {
            last_tick = Some(Instant::now());
            tick += 1;
            let early = start.elapsed() < Duration::from_secs(3);
            if early || tick % 3 == 0 {
                for c in plan.cands.iter().chain(plan.predicted.iter()) {
                    tx.seal(P_PUNCH, &(tick as u32).to_le_bytes(), &mut out);
                    let _ = socks[0].send_to(&out, c);
                }
            }
            // extra sockets: each one every 5th tick (200 ms), aimed at the peer's candidates
            for (k, s) in socks.iter().enumerate().skip(1) {
                if (k as u64 + tick) % 5 == 0 {
                    for c in &plan.cands {
                        tx.seal(P_PUNCH, &(tick as u32).to_le_bytes(), &mut out);
                        let _ = s.send_to(&out, c);
                    }
                }
            }
            for ip in &spray_ips {
                let per_ip = (PROBES_PER_TICK / spray_ips.len().max(1)).max(8);
                for _ in 0..per_ip {
                    let port = random_port(&mut rng, &plan.peer_ports);
                    tx.seal(P_PUNCH, &(tick as u32).to_le_bytes(), &mut out);
                    let _ = socks[0].send_to(&out, SocketAddr::new(IpAddr::V4(*ip), port));
                    sent_random += 1;
                }
            }
        }

        // ---- receive (all sockets, non-blocking)
        let mut got_any = false;
        let mut done: Option<(usize, SocketAddr)> = None;
        'socks: for (i, s) in socks.iter().enumerate() {
            loop {
                match s.recv_from(&mut buf) {
                    Ok((n, from)) => {
                        got_any = true;
                        let Some((ptype, _)) = rx.open(&mut buf[..n]) else { continue };
                        match ptype {
                            P_PUNCH => {
                                // The peer reaches us here; tell it so (its proof of a working path).
                                tx.seal(P_PUNCH_ACK, b"", &mut out);
                                let _ = s.send_to(&out, from);
                                if heard_from.is_none() {
                                    log::info!("punch: hearing the peer from {from} on socket {i} after {:?}", start.elapsed());
                                }
                                heard_from.get_or_insert(from);
                            }
                            // ACK, or tunnel traffic from a peer that already finished: our packets
                            // reach it from this socket, and its packets reach us. Two-way path.
                            _ => {
                                done = Some((i, from));
                                break 'socks;
                            }
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::ConnectionReset => continue, // Windows ICMP noise
                    Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted) => break,
                    Err(e) => {
                        log::debug!("punch recv on socket {i}: {e}");
                        break;
                    }
                }
            }
        }
        if let Some((i, addr)) = done {
            // A few ACKs so a peer that is still punching finishes right away.
            for _ in 0..3 {
                tx.seal(P_PUNCH_ACK, b"", &mut out);
                let _ = socks[i].send_to(&out, addr);
            }
            break Ok((i, addr));
        }
        if !got_any {
            std::thread::sleep(Duration::from_millis(2));
        }
    };
    for s in socks.iter() {
        let _ = s.set_nonblocking(false);
    }
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
