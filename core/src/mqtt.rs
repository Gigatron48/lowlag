//! Minimal MQTT 3.1.1 rendezvous transport (QoS 0 only, plain TCP).
//!
//! Public MQTT brokers live on different networks and a different protocol than HTTPS pub/sub,
//! so they are a useful second path when one rendezvous service is blocked or throttled.
//! Payloads are already end-to-end encrypted by the signaling layer.

use crate::signal::{SignalEvent, SignalTransport};
use crate::{random_hex, Error, Result};
use std::io::{self, ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const TOPIC_PREFIX: &str = "lowlag/v1/";
const KEEPALIVE_S: u16 = 60;

pub struct Mqtt {
    /// host:port
    addr: String,
}

impl Mqtt {
    /// `url` like "mqtt://broker.emqx.io:1883" (port defaults to 1883).
    pub fn new(url: &str) -> Result<Self> {
        let rest = url.strip_prefix("mqtt://").ok_or_else(|| Error::Signal(format!("not an mqtt url: {url}")))?;
        let rest = rest.trim_end_matches('/');
        let addr = if rest.contains(':') { rest.to_string() } else { format!("{rest}:1883") };
        Ok(Self { addr })
    }

    fn connect(&self) -> io::Result<TcpStream> {
        let mut last = io::Error::new(ErrorKind::NotFound, "no address");
        for a in self.addr.to_socket_addrs()? {
            if !a.is_ipv4() {
                continue;
            }
            match TcpStream::connect_timeout(&a, Duration::from_secs(6)) {
                Ok(s) => {
                    let _ = s.set_nodelay(true);
                    s.set_write_timeout(Some(Duration::from_secs(6)))?;
                    let mut s = s;
                    s.write_all(&connect_packet(&format!("ll-{}", random_hex(8))))?;
                    match read_packet(&mut s, Duration::from_secs(6))? {
                        Some((0x20, body)) if body.len() >= 2 && body[1] == 0 => return Ok(s),
                        Some((t, body)) => {
                            last = io::Error::new(ErrorKind::Other, format!("connack refused ({t:#x} {body:?})"))
                        }
                        None => last = io::Error::new(ErrorKind::TimedOut, "no connack"),
                    }
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn packet(header: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![header];
    let mut len = body.len();
    loop {
        let mut b = (len % 128) as u8;
        len /= 128;
        if len > 0 {
            b |= 0x80;
        }
        out.push(b);
        if len == 0 {
            break;
        }
    }
    out.extend_from_slice(body);
    out
}

fn connect_packet(client_id: &str) -> Vec<u8> {
    let mut b = Vec::new();
    put_str(&mut b, "MQTT");
    b.push(4); // protocol level 3.1.1
    b.push(0x02); // clean session
    b.extend_from_slice(&KEEPALIVE_S.to_be_bytes());
    put_str(&mut b, client_id);
    packet(0x10, &b)
}

fn subscribe_packet(topic: &str) -> Vec<u8> {
    let mut b = vec![0, 1]; // packet id 1
    put_str(&mut b, topic);
    b.push(0); // QoS 0
    packet(0x82, &b)
}

fn publish_packet(topic: &str, payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    put_str(&mut b, topic);
    b.extend_from_slice(payload);
    packet(0x30, &b)
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

/// Read one packet. Waits up to `first_byte` for it to start (Ok(None) on timeout), then reads
/// the rest with a generous timeout so a slow link never desynchronises the stream.
fn read_packet(s: &mut TcpStream, first_byte: Duration) -> io::Result<Option<(u8, Vec<u8>)>> {
    s.set_read_timeout(Some(first_byte))?;
    let mut h = [0u8; 1];
    match s.read(&mut h) {
        Ok(0) => return Err(io::Error::new(ErrorKind::UnexpectedEof, "broker closed the connection")),
        Ok(_) => {}
        Err(e) if is_timeout(&e) => return Ok(None),
        Err(e) => return Err(e),
    }
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut len: usize = 0;
    let mut mult = 1usize;
    for _ in 0..4 {
        let mut b = [0u8; 1];
        s.read_exact(&mut b)?;
        len += (b[0] & 0x7f) as usize * mult;
        if b[0] & 0x80 == 0 {
            break;
        }
        mult *= 128;
    }
    if len > 256 * 1024 {
        return Err(io::Error::new(ErrorKind::InvalidData, "packet too large"));
    }
    let mut body = vec![0u8; len];
    s.read_exact(&mut body)?;
    Ok(Some((h[0] & 0xf0, body)))
}

fn parse_publish(flags_and_type: u8, body: &[u8]) -> Option<Vec<u8>> {
    let _ = flags_and_type;
    if body.len() < 2 {
        return None;
    }
    let tlen = u16::from_be_bytes([body[0], body[1]]) as usize;
    // QoS 0 only (we subscribe with QoS 0, so the broker never sends a packet id)
    body.get(2 + tlen..).map(|p| p.to_vec())
}

impl SignalTransport for Mqtt {
    fn publish(&self, topic: &str, body: &str) -> Result<()> {
        let mut s = self.connect().map_err(|e| Error::Signal(format!("mqtt {}: {e}", self.addr)))?;
        let full = format!("{TOPIC_PREFIX}{topic}");
        s.write_all(&publish_packet(&full, body.as_bytes()))
            .and_then(|_| s.write_all(&[0xE0, 0x00])) // DISCONNECT
            .and_then(|_| s.flush())
            .map_err(|e| Error::Signal(format!("mqtt {} publish: {e}", self.addr)))?;
        // Give the broker a moment to read everything before the socket closes.
        let _ = s.set_read_timeout(Some(Duration::from_millis(300)));
        let mut sink = [0u8; 16];
        let _ = s.read(&mut sink);
        Ok(())
    }

    fn subscribe(
        &self,
        topic: &str,
        _since: Option<&str>,
        stop: &AtomicBool,
        on_event: &mut dyn FnMut(SignalEvent) -> bool,
    ) -> Result<()> {
        let err = |e: io::Error| Error::Signal(format!("mqtt {}: {e}", self.addr));
        let mut s = self.connect().map_err(err)?;
        let full = format!("{TOPIC_PREFIX}{topic}");
        s.write_all(&subscribe_packet(&full)).map_err(err)?;
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if Instant::now() > deadline {
                return Err(Error::Signal(format!("mqtt {}: no suback", self.addr)));
            }
            match read_packet(&mut s, Duration::from_secs(1)).map_err(err)? {
                Some((0x90, _)) => break,
                Some(_) | None => continue,
            }
        }
        if !on_event(SignalEvent::Open) {
            return Ok(());
        }
        let mut last_ping = Instant::now();
        let mut last_rx = Instant::now();
        loop {
            if stop.load(Ordering::Relaxed) {
                let _ = s.write_all(&[0xE0, 0x00]);
                return Ok(());
            }
            if last_ping.elapsed() > Duration::from_secs(25) {
                s.write_all(&[0xC0, 0x00]).map_err(err)?; // PINGREQ
                last_ping = Instant::now();
            }
            if last_rx.elapsed() > Duration::from_secs(KEEPALIVE_S as u64 + 30) {
                return Err(Error::Signal(format!("mqtt {}: connection went silent", self.addr)));
            }
            match read_packet(&mut s, Duration::from_millis(500)).map_err(err)? {
                None => {}
                Some((t, body)) => {
                    last_rx = Instant::now();
                    if t == 0x30 {
                        if let Some(p) = parse_publish(t, &body) {
                            if !on_event(SignalEvent::Message(String::from_utf8_lossy(&p).into_owned())) {
                                let _ = s.write_all(&[0xE0, 0x00]);
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_lengths() {
        assert_eq!(packet(0x30, &[0u8; 5])[..2], [0x30, 5]);
        let p = packet(0x30, &vec![0u8; 200]);
        assert_eq!(&p[..3], &[0x30, 0xC8, 0x01]);
        let p = packet(0x30, &vec![0u8; 20000]);
        assert_eq!(&p[..4], &[0x30, 0xA0, 0x9C, 0x01]);
    }

    #[test]
    fn url_parsing() {
        assert_eq!(Mqtt::new("mqtt://broker.emqx.io").unwrap().addr, "broker.emqx.io:1883");
        assert_eq!(Mqtt::new("mqtt://h:8883/").unwrap().addr, "h:8883");
        assert!(Mqtt::new("https://x").is_err());
    }

    /// Needs a local broker: `LL_TEST_MQTT=127.0.0.1:1883 cargo test -p llcore mqtt_roundtrip`
    #[test]
    fn mqtt_roundtrip() {
        let Ok(addr) = std::env::var("LL_TEST_MQTT") else { return };
        let m = std::sync::Arc::new(Mqtt::new(&format!("mqtt://{addr}")).unwrap());
        let (tx, rx) = std::sync::mpsc::channel();
        let m2 = m.clone();
        std::thread::spawn(move || {
            let stop = AtomicBool::new(false);
            m2.subscribe("t1", None, &stop, &mut |ev| tx.send(ev).is_ok()).unwrap();
        });
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), SignalEvent::Open);
        m.publish("t1", "hello").unwrap();
        m.publish("other", "nope").unwrap();
        m.publish("t1", &"x".repeat(3000)).unwrap();
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), SignalEvent::Message("hello".into()));
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), SignalEvent::Message("x".repeat(3000)));
    }
}
