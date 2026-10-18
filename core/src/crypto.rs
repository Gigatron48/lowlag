//! Cryptography.
//!
//! * The 9-digit code derives a rendezvous topic and a key that encrypts signaling messages, so the
//!   rendezvous server only ever sees opaque blobs.
//! * Each side has a long-term X25519 identity key and a fresh ephemeral key per session. Session
//!   keys mix three DH results (ee, se, es), so a peer can only finish the handshake if it really
//!   owns the identity it claims; "remember this device" is therefore safe to offer.
//! * Tunnel packets: ChaCha20-Poly1305 with a 64-bit counter nonce; the counter on the wire is
//!   hidden QUIC-style (XOR with a ChaCha20 keystream sampled from the ciphertext), so every byte of
//!   a packet looks random and nothing resembles a known VPN protocol.

use crate::hex;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use chacha20poly1305::aead::{Aead, AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Tag, XChaCha20Poly1305};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use std::sync::atomic::{AtomicU64, Ordering};
use x25519_dalek::{PublicKey, StaticSecret};

const SALT: &[u8] = b"lowlag/v1";

pub fn hkdf32(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out).expect("32 bytes is a valid HKDF output length");
    out
}

/// Rendezvous topic + signaling key derived from a connection code.
#[derive(Clone)]
pub struct CodeKeys {
    pub topic: String,
    pub key: [u8; 32],
}

pub fn code_keys(code: &str) -> CodeKeys {
    let t = hkdf32(SALT, code.as_bytes(), b"topic");
    CodeKeys {
        topic: format!("ll1{}", hex(&t[..15])),
        key: hkdf32(SALT, code.as_bytes(), b"signal-key"),
    }
}

/// Encrypt a signaling message: base64url(nonce[24] || ciphertext).
pub fn seal_signal(key: &[u8; 32], plaintext: &[u8]) -> String {
    let aead = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = aead
        .encrypt((&nonce).into(), plaintext)
        .expect("encryption of an in-memory buffer cannot fail");
    let mut out = Vec::with_capacity(24 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    URL_SAFE_NO_PAD.encode(out)
}

pub fn open_signal(key: &[u8; 32], text: &str) -> Option<Vec<u8>> {
    let raw = URL_SAFE_NO_PAD.decode(text.trim()).ok()?;
    if raw.len() < 24 + 16 {
        return None;
    }
    let aead = XChaCha20Poly1305::new(key.into());
    let nonce: [u8; 24] = raw[..24].try_into().ok()?;
    aead.decrypt((&nonce).into(), &raw[24..]).ok()
}

pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn unb64_32(s: &str) -> Option<[u8; 32]> {
    URL_SAFE_NO_PAD.decode(s).ok()?.try_into().ok()
}

/// An X25519 key pair (used both for the long-term identity and per-session ephemerals).
#[derive(Clone)]
pub struct KeyPair {
    secret: StaticSecret,
}

impl KeyPair {
    pub fn generate() -> Self {
        Self { secret: StaticSecret::random_from_rng(rand::rngs::OsRng) }
    }
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self { secret: StaticSecret::from(b) }
    }
    pub fn to_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }
    pub fn public(&self) -> [u8; 32] {
        PublicKey::from(&self.secret).to_bytes()
    }
    fn dh(&self, peer_public: &[u8; 32]) -> Option<[u8; 32]> {
        let shared = self.secret.diffie_hellman(&PublicKey::from(*peer_public));
        shared.was_contributory().then(|| shared.to_bytes())
    }
}

/// Directional session keys.
pub struct SessionKeys {
    pub tx: [u8; 32],
    pub rx: [u8; 32],
    pub hp_tx: [u8; 32],
    pub hp_rx: [u8; 32],
}

/// Derive session keys. Both sides call this with their own keys and the peer's public keys and
/// end up with mirrored tx/rx keys. Returns `None` if any DH result is degenerate.
pub fn session_keys(
    is_host: bool,
    my_static: &KeyPair,
    my_eph: &KeyPair,
    peer_static: &[u8; 32],
    peer_eph: &[u8; 32],
    signal_key: &[u8; 32],
    sid: &str,
) -> Option<SessionKeys> {
    // ee, (client static, host eph), (client eph, host static)
    let (ee, se, es) = if is_host {
        (my_eph.dh(peer_eph)?, my_eph.dh(peer_static)?, my_static.dh(peer_eph)?)
    } else {
        (my_eph.dh(peer_eph)?, my_static.dh(peer_eph)?, my_eph.dh(peer_static)?)
    };
    let mut ikm = [0u8; 96];
    ikm[..32].copy_from_slice(&ee);
    ikm[32..64].copy_from_slice(&se);
    ikm[64..].copy_from_slice(&es);
    let k = |label: &str| hkdf32(signal_key, &ikm, format!("lowlag/{label}/{sid}").as_bytes());
    let (h2c, c2h, hp_h2c, hp_c2h) = (k("h2c"), k("c2h"), k("hp-h2c"), k("hp-c2h"));
    Some(if is_host {
        SessionKeys { tx: h2c, rx: c2h, hp_tx: hp_h2c, hp_rx: hp_c2h }
    } else {
        SessionKeys { tx: c2h, rx: h2c, hp_tx: hp_c2h, hp_rx: hp_h2c }
    })
}

/// Wire overhead added to every payload: header(8) + type(1) + tag(16).
pub const OVERHEAD: usize = 8 + 1 + 16;
const HDR: usize = 8;
const SAMPLE: usize = 12;

fn header_mask(hp: &[u8; 32], sample: &[u8]) -> [u8; 8] {
    let mut mask = [0u8; 8];
    let nonce: [u8; SAMPLE] = sample[..SAMPLE].try_into().unwrap();
    let mut c = ChaCha20::new(hp.into(), (&nonce).into());
    c.apply_keystream(&mut mask);
    mask
}

fn nonce_for(ctr: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&ctr.to_le_bytes());
    n
}

/// Sending half. Shareable between threads.
pub struct TxCipher {
    aead: ChaCha20Poly1305,
    hp: [u8; 32],
    ctr: AtomicU64,
}

impl TxCipher {
    pub fn new(key: &[u8; 32], hp: &[u8; 32]) -> Self {
        Self { aead: ChaCha20Poly1305::new(key.into()), hp: *hp, ctr: AtomicU64::new(0) }
    }

    /// Build an encrypted packet into `out` (cleared first).
    pub fn seal(&self, ptype: u8, payload: &[u8], out: &mut Vec<u8>) {
        let ctr = self.ctr.fetch_add(1, Ordering::Relaxed);
        out.clear();
        out.extend_from_slice(&ctr.to_le_bytes());
        out.push(ptype);
        out.extend_from_slice(payload);
        let tag = self
            .aead
            .encrypt_in_place_detached((&nonce_for(ctr)).into(), &[], &mut out[HDR..])
            .expect("in-memory encryption cannot fail");
        out.extend_from_slice(&tag);
        let mask = header_mask(&self.hp, &out[HDR..HDR + SAMPLE]);
        for i in 0..HDR {
            out[i] ^= mask[i];
        }
    }
}

/// Receiving half. Owned by the single receive thread.
pub struct RxCipher {
    aead: ChaCha20Poly1305,
    hp: [u8; 32],
    window: ReplayWindow,
}

impl RxCipher {
    pub fn new(key: &[u8; 32], hp: &[u8; 32]) -> Self {
        Self { aead: ChaCha20Poly1305::new(key.into()), hp: *hp, window: ReplayWindow::default() }
    }

    /// Decrypt in place. Returns (packet type, payload) or `None` for anything that is not a
    /// fresh, authentic packet from our peer.
    pub fn open<'a>(&mut self, pkt: &'a mut [u8]) -> Option<(u8, &'a [u8])> {
        if pkt.len() < OVERHEAD {
            return None;
        }
        let mask = header_mask(&self.hp, &pkt[HDR..HDR + SAMPLE]);
        let mut hdr = [0u8; 8];
        for i in 0..HDR {
            hdr[i] = pkt[i] ^ mask[i];
        }
        let ctr = u64::from_le_bytes(hdr);
        if !self.window.check(ctr) {
            return None;
        }
        let len = pkt.len();
        let (head, tag) = pkt.split_at_mut(len - 16);
        let tag = Tag::from_slice(tag);
        self.aead
            .decrypt_in_place_detached((&nonce_for(ctr)).into(), &[], &mut head[HDR..], tag)
            .ok()?;
        self.window.update(ctr);
        let body = &pkt[HDR..len - 16];
        Some((body[0], &body[1..]))
    }
}

/// Sliding anti-replay window (2048 packets), same idea as IPsec/WireGuard.
pub struct ReplayWindow {
    max: u64,
    init: bool,
    bits: [u64; 32],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self { max: 0, init: false, bits: [0; 32] }
    }
}

const WIN: u64 = 2048;

impl ReplayWindow {
    fn bit(&self, n: u64) -> bool {
        let i = (n % WIN) as usize;
        self.bits[i / 64] & (1 << (i % 64)) != 0
    }
    fn set(&mut self, n: u64, v: bool) {
        let i = (n % WIN) as usize;
        if v {
            self.bits[i / 64] |= 1 << (i % 64);
        } else {
            self.bits[i / 64] &= !(1 << (i % 64));
        }
    }
    pub fn check(&self, n: u64) -> bool {
        if !self.init || n > self.max {
            return true;
        }
        if self.max - n >= WIN {
            return false;
        }
        !self.bit(n)
    }
    pub fn update(&mut self, n: u64) {
        if !self.init {
            self.init = true;
            self.max = n;
            self.bits = [0; 32];
        } else if n > self.max {
            if n - self.max >= WIN {
                self.bits = [0; 32];
            } else {
                for k in self.max + 1..n {
                    self.set(k, false);
                }
            }
            self.max = n;
        }
        self.set(n, true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (SessionKeys, SessionKeys) {
        let hs = KeyPair::generate();
        let he = KeyPair::generate();
        let cs = KeyPair::generate();
        let ce = KeyPair::generate();
        let sk = [7u8; 32];
        let h = session_keys(true, &hs, &he, &cs.public(), &ce.public(), &sk, "sid1").unwrap();
        let c = session_keys(false, &cs, &ce, &hs.public(), &he.public(), &sk, "sid1").unwrap();
        (h, c)
    }

    #[test]
    fn handshake_mirrors_keys() {
        let (h, c) = pair();
        assert_eq!(h.tx, c.rx);
        assert_eq!(h.rx, c.tx);
        assert_eq!(h.hp_tx, c.hp_rx);
        assert_ne!(h.tx, h.rx);
    }

    #[test]
    fn wrong_identity_gives_different_keys() {
        let hs = KeyPair::generate();
        let he = KeyPair::generate();
        let cs = KeyPair::generate();
        let impostor = KeyPair::generate();
        let ce = KeyPair::generate();
        let sk = [1u8; 32];
        // Host believes the client's identity is `cs`, but the client actually owns `impostor`.
        let h = session_keys(true, &hs, &he, &cs.public(), &ce.public(), &sk, "x").unwrap();
        let c = session_keys(false, &impostor, &ce, &hs.public(), &he.public(), &sk, "x").unwrap();
        assert_ne!(h.rx, c.tx);
    }

    #[test]
    fn packet_roundtrip_and_replay() {
        let (h, c) = pair();
        let tx = TxCipher::new(&h.tx, &h.hp_tx);
        let mut rx = RxCipher::new(&c.rx, &c.hp_rx);
        let mut buf = Vec::new();
        for i in 0..5u8 {
            tx.seal(3, &[i; 100], &mut buf);
            assert_eq!(buf.len(), 100 + OVERHEAD);
            let mut copy = buf.clone();
            let (t, p) = rx.open(&mut copy).expect("valid packet");
            assert_eq!(t, 3);
            assert_eq!(p, &[i; 100][..]);
            // replay is rejected
            let mut again = buf.clone();
            assert!(rx.open(&mut again).is_none());
        }
        // tampering is rejected
        tx.seal(3, b"hello", &mut buf);
        buf[12] ^= 1;
        assert!(rx.open(&mut buf).is_none());
        // empty payload works
        tx.seal(9, b"", &mut buf);
        let (t, p) = rx.open(&mut buf).unwrap();
        assert_eq!((t, p.len()), (9, 0));
    }

    #[test]
    fn header_looks_random() {
        let (h, _) = pair();
        let tx = TxCipher::new(&h.tx, &h.hp_tx);
        let mut a = Vec::new();
        let mut b = Vec::new();
        tx.seal(1, b"x", &mut a);
        tx.seal(1, b"x", &mut b);
        // counters 0 and 1 must not show up as mostly-zero bytes
        assert_ne!(&a[..8], &[0u8; 8]);
        assert_ne!(&a[1..8], &b[1..8]);
    }

    #[test]
    fn replay_window_out_of_order() {
        let mut w = ReplayWindow::default();
        for n in [5u64, 3, 9, 4, 3000, 2999, 900] {
            let ok = w.check(n);
            if n == 900 {
                assert!(!ok, "too old");
                continue;
            }
            assert!(ok, "{n}");
            w.update(n);
            assert!(!w.check(n));
        }
    }

    #[test]
    fn signal_seal_open() {
        let k = code_keys("482913507");
        assert!(k.topic.starts_with("ll1") && k.topic.len() == 33);
        let s = seal_signal(&k.key, b"{\"hi\":1}");
        assert_eq!(open_signal(&k.key, &s).unwrap(), b"{\"hi\":1}");
        let other = code_keys("482913508");
        assert!(open_signal(&other.key, &s).is_none());
        assert_ne!(other.topic, k.topic);
    }
}
