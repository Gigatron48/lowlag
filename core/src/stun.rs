//! Minimal STUN (RFC 5389) binding client: learn the public ip:port of a UDP socket.

use rand::RngCore;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

pub const DEFAULT_SERVERS: &[&str] = &[
    "stun.cloudflare.com:3478",
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun.sipnet.ru:3478",
];

const MAGIC: u32 = 0x2112_A442;

pub fn binding_request(txid: &[u8; 12]) -> [u8; 20] {
    let mut m = [0u8; 20];
    m[0..2].copy_from_slice(&0x0001u16.to_be_bytes());
    // length 0
    m[4..8].copy_from_slice(&MAGIC.to_be_bytes());
    m[8..20].copy_from_slice(txid);
    m
}

/// Parse a binding success response; returns the (XOR-)MAPPED-ADDRESS.
pub fn parse_response(buf: &[u8], txid: &[u8; 12]) -> Option<SocketAddr> {
    if buf.len() < 20 || buf[0..2] != [0x01, 0x01] || buf[4..8] != MAGIC.to_be_bytes() || &buf[8..20] != txid
    {
        return None;
    }
    let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let attrs = buf.get(20..20 + len)?;
    let mut i = 0;
    let mut fallback = None;
    while i + 4 <= attrs.len() {
        let typ = u16::from_be_bytes([attrs[i], attrs[i + 1]]);
        let alen = u16::from_be_bytes([attrs[i + 2], attrs[i + 3]]) as usize;
        let v = attrs.get(i + 4..i + 4 + alen)?;
        if (typ == 0x0020 || typ == 0x0001) && alen >= 8 && v[1] == 0x01 {
            let mut port = u16::from_be_bytes([v[2], v[3]]);
            let mut ip = [v[4], v[5], v[6], v[7]];
            if typ == 0x0020 {
                port ^= (MAGIC >> 16) as u16;
                let m = MAGIC.to_be_bytes();
                for k in 0..4 {
                    ip[k] ^= m[k];
                }
                return Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port));
            }
            fallback = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port));
        }
        i += 4 + ((alen + 3) & !3);
    }
    fallback
}

/// Resolve server names to IPv4 socket addresses, all in parallel, giving up on slow DNS after
/// `timeout` (names that fail or are late are skipped).
pub fn resolve_within(servers: &[String], timeout: Duration) -> Vec<(String, SocketAddr)> {
    let (tx, rx) = std::sync::mpsc::channel();
    for (i, s) in servers.iter().enumerate() {
        let (tx, s) = (tx.clone(), s.clone());
        std::thread::spawn(move || {
            let a = s.to_socket_addrs().ok().and_then(|mut it| it.find(|a| a.is_ipv4()));
            let _ = tx.send((i, s, a));
        });
    }
    drop(tx);
    let deadline = Instant::now() + timeout;
    let mut got = Vec::new();
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match rx.recv_timeout(left) {
            Ok((i, name, Some(a))) => got.push((i, name, a)),
            Ok(_) => {}
            Err(_) => break,
        }
    }
    got.sort_by_key(|g| g.0);
    let mut out: Vec<(String, SocketAddr)> = Vec::new();
    for (_, name, a) in got {
        if !out.iter().any(|(_, b)| *b == a) {
            out.push((name, a));
        }
    }
    out
}

pub fn resolve(servers: &[String]) -> Vec<SocketAddr> {
    resolve_within(servers, Duration::from_millis(1500)).into_iter().map(|(_, a)| a).collect()
}

/// Ask every server (in parallel) what our mapped address is. Uses `sock` itself, so the result
/// is the mapping that peers will see. Returns (server, mapped) pairs for servers that answered.
pub fn query(sock: &UdpSocket, servers: &[SocketAddr], timeout: Duration) -> Vec<(SocketAddr, SocketAddr)> {
    let mut pending: Vec<(SocketAddr, [u8; 12])> = servers
        .iter()
        .map(|s| {
            let mut tx = [0u8; 12];
            rand::rngs::OsRng.fill_bytes(&mut tx);
            (*s, tx)
        })
        .collect();
    let old_timeout = sock.read_timeout().ok().flatten();
    let _ = sock.set_read_timeout(Some(Duration::from_millis(50)));
    let start = Instant::now();
    let mut last_send = None::<Instant>;
    let mut results = Vec::new();
    let mut buf = [0u8; 1500];
    while !pending.is_empty() && start.elapsed() < timeout {
        // (re)send every 300 ms – STUN is UDP, packets get lost
        if last_send.map_or(true, |t| t.elapsed() >= Duration::from_millis(300)) {
            for (server, tx) in &pending {
                let _ = sock.send_to(&binding_request(tx), server);
            }
            last_send = Some(Instant::now());
        }
        match sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                if let Some(pos) = pending.iter().position(|(s, _)| *s == from) {
                    if let Some(mapped) = parse_response(&buf[..n], &pending[pos].1) {
                        results.push((from, mapped));
                        pending.remove(pos);
                    }
                }
            }
            Err(_) => {} // timeout / ICMP reset (Windows) – keep going
        }
    }
    let _ = sock.set_read_timeout(old_timeout);
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_xor_mapped() {
        let tx = [9u8; 12];
        // Response for 203.0.113.7:54321
        let ip = [203u8, 0, 113, 7];
        let port: u16 = 54321;
        let m = MAGIC.to_be_bytes();
        let xport = port ^ (MAGIC >> 16) as u16;
        let mut resp = vec![0x01, 0x01, 0, 12];
        resp.extend_from_slice(&m);
        resp.extend_from_slice(&tx);
        resp.extend_from_slice(&[0x00, 0x20, 0, 8, 0, 1]);
        resp.extend_from_slice(&xport.to_be_bytes());
        for k in 0..4 {
            resp.push(ip[k] ^ m[k]);
        }
        assert_eq!(parse_response(&resp, &tx), Some("203.0.113.7:54321".parse().unwrap()));
        assert_eq!(parse_response(&resp, &[0u8; 12]), None);
    }

    #[test]
    fn local_stun_server() {
        // A fake STUN server on localhost answering with the observed source address.
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let saddr = server.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut b = [0u8; 100];
            let (n, from) = server.recv_from(&mut b).unwrap();
            assert_eq!(n, 20);
            let tx: [u8; 12] = b[8..20].try_into().unwrap();
            let SocketAddr::V4(f) = from else { panic!() };
            let m = MAGIC.to_be_bytes();
            let mut r = vec![0x01, 0x01, 0, 12];
            r.extend_from_slice(&m);
            r.extend_from_slice(&tx);
            r.extend_from_slice(&[0x00, 0x20, 0, 8, 0, 1]);
            r.extend_from_slice(&(f.port() ^ (MAGIC >> 16) as u16).to_be_bytes());
            let o = f.ip().octets();
            for k in 0..4 {
                r.push(o[k] ^ m[k]);
            }
            server.send_to(&r, from).unwrap();
        });
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let res = query(&sock, &[saddr], Duration::from_secs(2));
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].1, sock.local_addr().unwrap());
    }
}
