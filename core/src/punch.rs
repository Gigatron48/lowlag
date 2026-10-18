//! UDP hole punching. Both peers run the same routine at the same time: spray authenticated
//! PUNCH packets at every candidate of the other side; the first authentic packet that comes back
//! tells us which path works. Our outgoing packets open our NAT for the peer's packets, theirs
//! open theirs for ours.

use crate::crypto::{RxCipher, TxCipher};
use crate::proto::{P_PUNCH, P_PUNCH_ACK};
use crate::{Error, Result};
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub fn punch(
    sock: &UdpSocket,
    cands: &[SocketAddr],
    tx: &TxCipher,
    rx: &mut RxCipher,
    timeout: Duration,
    cancel: &AtomicBool,
) -> Result<SocketAddr> {
    if cands.is_empty() {
        return Err(Error::NatTraversal("peer has no candidates".into()));
    }
    sock.set_read_timeout(Some(Duration::from_millis(15)))?;
    let start = Instant::now();
    let mut last_spray = None::<Instant>;
    let mut found: Option<(SocketAddr, Instant)> = None;
    let mut acked = false;
    let mut out = Vec::with_capacity(64);
    let mut buf = vec![0u8; 2048];
    let mut sprays = 0u32;

    while start.elapsed() < timeout {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        if let Some((addr, at)) = found {
            // Done when the peer confirmed our packets, or after giving it a moment to do so
            // (it may have finished first and stopped punching).
            if acked || at.elapsed() > Duration::from_millis(1500) {
                // A few extra ACKs so a peer still punching finishes quickly too.
                for _ in 0..3 {
                    tx.seal(P_PUNCH_ACK, b"", &mut out);
                    let _ = sock.send_to(&out, addr);
                }
                return Ok(addr);
            }
        }
        // Spray every 40 ms for the first 3 s, then every 120 ms.
        let interval = if start.elapsed() < Duration::from_secs(3) { 40 } else { 120 };
        if last_spray.map_or(true, |t| t.elapsed() >= Duration::from_millis(interval)) {
            for c in cands {
                tx.seal(P_PUNCH, &sprays.to_le_bytes(), &mut out);
                let _ = sock.send_to(&out, c);
            }
            sprays += 1;
            last_spray = Some(Instant::now());
        }
        match sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                let Some((ptype, _)) = rx.open(&mut buf[..n]) else { continue };
                match ptype {
                    P_PUNCH => {
                        tx.seal(P_PUNCH_ACK, b"", &mut out);
                        let _ = sock.send_to(&out, from);
                        if found.is_none() {
                            found = Some((from, Instant::now()));
                        }
                    }
                    P_PUNCH_ACK => {
                        acked = true;
                        if found.is_none() {
                            found = Some((from, Instant::now()));
                        }
                    }
                    // Peer already moved on to tunnel traffic: the path works.
                    _ => return Ok(from),
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::ConnectionReset) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Err(Error::NatTraversal(format!("no reply from {} candidate(s) in {:?}", cands.len(), timeout)))
}
