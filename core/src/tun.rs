//! Virtual network device abstraction + an in-memory implementation for tests.

use std::io;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// One per tunnel session. `recv` blocks until a packet is available or `shutdown` is called.
pub trait TunDevice: Send + Sync {
    /// Read one IP packet from the OS into `buf`, return its length.
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize>;
    /// Hand one IP packet to the OS.
    fn send(&self, pkt: &[u8]) -> io::Result<()>;
    /// Unblock `recv` and stop the session.
    fn shutdown(&self);
}

/// (src, dst) of an IPv4 packet, or None if it's not IPv4 / too short.
pub fn ipv4_src_dst(pkt: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return None;
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    Some((src, dst))
}

/// In-memory device. The test side injects "OS -> tunnel" packets and observes "tunnel -> OS".
pub struct MemTun {
    from_os: Mutex<Receiver<Vec<u8>>>,
    to_os: Sender<Vec<u8>>,
    closed: AtomicBool,
}

pub struct MemTunHandle {
    pub inject: Sender<Vec<u8>>,
    pub observe: Receiver<Vec<u8>>,
}

impl MemTun {
    pub fn new() -> (Arc<MemTun>, MemTunHandle) {
        let (inject, from_os) = channel();
        let (to_os, observe) = channel();
        (
            Arc::new(MemTun { from_os: Mutex::new(from_os), to_os, closed: AtomicBool::new(false) }),
            MemTunHandle { inject, observe },
        )
    }
}

impl TunDevice for MemTun {
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let rx = self.from_os.lock().unwrap();
        loop {
            if self.closed.load(Ordering::Relaxed) {
                return Err(io::Error::new(io::ErrorKind::Other, "shut down"));
            }
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(p) => {
                    let n = p.len().min(buf.len());
                    buf[..n].copy_from_slice(&p[..n]);
                    return Ok(n);
                }
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::new(io::ErrorKind::Other, "closed"))
                }
            }
        }
    }
    fn send(&self, pkt: &[u8]) -> io::Result<()> {
        let _ = self.to_os.send(pkt.to_vec());
        Ok(())
    }
    fn shutdown(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }
}

/// Build a minimal IPv4/UDP packet (checksums left zero) – used by tests.
pub fn fake_ipv4_udp(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let total = 20 + 8 + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p[20..22].copy_from_slice(&1234u16.to_be_bytes());
    p[22..24].copy_from_slice(&5678u16.to_be_bytes());
    p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p[28..].copy_from_slice(payload);
    p
}
