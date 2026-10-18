//! LowLag networking core.
//!
//! What lives here (all platform-independent, testable on any OS):
//! * `code`    – human-friendly 9-digit connection codes;
//! * `crypto`  – key derivation, signaling encryption and the per-packet AEAD with header protection;
//! * `stun`    – a tiny STUN client used to learn our public address;
//! * `signal`  – the rendezvous transport (ntfy-compatible HTTP pub/sub) used only to exchange offers;
//! * `proto`   – signaling and in-tunnel control messages;
//! * `netinfo` – candidate gathering (LAN addresses, STUN, UPnP);
//! * `punch`   – UDP hole punching;
//! * `conn`    – the established encrypted tunnel (data, keepalive, RTT, control, speed test);
//! * `session` – host listener and client connect flows that tie everything together.
//!
//! The platform layer (Windows app) supplies a [`tun::TunDevice`] and decides what to do once a
//! tunnel is up (pair Sunshine/Moonlight, launch the stream).

pub mod code;
pub mod conn;
pub mod crypto;
pub mod netinfo;
pub mod proto;
pub mod punch;
pub mod session;
pub mod signal;
pub mod stun;
pub mod tun;

use std::fmt;

/// Protocol version carried in offers. Bump when the wire format changes incompatibly.
pub const PROTO_VERSION: u32 = 1;

/// MTU of the virtual adapter. Outer packet = MTU + 8 (header) + 1 (type) + 16 (tag) + 28 (IPv4+UDP)
/// = 1453 bytes, which fits typical PPPoE (1492) and most tunnelled ISP links.
pub const TUN_MTU: usize = 1400;

/// Video packet size passed to Moonlight so a full video datagram fits into one tunnel packet.
pub const STREAM_PACKET_SIZE: u32 = 1280;

/// First two octets of the private subnet used inside tunnels. The third octet is derived from the
/// host's device id, so every host gets its own stable /24 and Moonlight can tell hosts apart.
pub const TUN_NET_PREFIX: [u8; 2] = [10, 213];

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Signal(String),
    Crypto,
    Protocol(String),
    Timeout(&'static str),
    Declined(String),
    NatTraversal(String),
    Cancelled,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io: {e}"),
            Error::Signal(e) => write!(f, "signaling: {e}"),
            Error::Crypto => write!(f, "crypto failure"),
            Error::Protocol(e) => write!(f, "protocol: {e}"),
            Error::Timeout(what) => write!(f, "timeout: {what}"),
            Error::Declined(why) => write!(f, "declined: {why}"),
            Error::NatTraversal(e) => write!(f, "nat traversal failed: {e}"),
            Error::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Seconds since the Unix epoch.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}

pub fn random_hex(n_bytes: usize) -> String {
    use rand::RngCore;
    let mut b = vec![0u8; n_bytes];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex(&b)
}
