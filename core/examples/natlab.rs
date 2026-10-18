//! NAT lab driver (used with network namespaces, see docs in the repo history).
//!
//!   natlab host <code> <mqtt-url> <stun1> <stun2>
//!   natlab client <code> <mqtt-url> <stun1> <stun2>
//!
//! The host accepts the first request; both sides then exchange tunnel packets and print the
//! result. Exit code 0 = tunnel works.

use llcore::crypto::KeyPair;
use llcore::netinfo::GatherOpts;
use llcore::session::{connect, Decision, Established, HostHandler, HostListener, Identity, IncomingRequest};
use llcore::signal::{transport_for, SignalTransport};
use llcore::tun::{fake_ipv4_udp, MemTun};
use llcore::Error;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct Stderr;
impl log::Log for Stderr {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }
    fn log(&self, r: &log::Record) {
        if r.level() <= log::Level::Info {
            eprintln!("[{}] {}", r.level(), r.args());
        }
    }
    fn flush(&self) {}
}
static LOGGER: Stderr = Stderr;

struct Host(Mutex<Sender<Result<Established, String>>>);
impl HostHandler for Host {
    fn on_listening(&self, ok: bool, d: &str) {
        eprintln!("listening ok={ok} {d}");
    }
    fn decide(&self, _r: &IncomingRequest) -> Decision {
        Decision::Accept
    }
    fn on_progress(&self, _r: &IncomingRequest, _s: &str) {}
    fn on_established(&self, est: Established) {
        let _ = self.0.lock().unwrap().send(Ok(est));
    }
    fn on_failed(&self, _r: &IncomingRequest, err: Error) {
        let _ = self.0.lock().unwrap().send(Err(err.to_string()));
    }
}

fn exchange(est: Established) -> bool {
    let (lip, pip, role) = (est.local_ip(), est.peer_ip(), est.role);
    let t0 = Instant::now();
    let (tun, io) = MemTun::new();
    let (conn, _ev) = est.into_conn(tun);
    let mut ok = false;
    // keep sending for a while: the peer's tunnel may start a little later than ours
    for _ in 0..40 {
        io.inject.send(fake_ipv4_udp(lip, pip, format!("hello from {role:?}").as_bytes())).unwrap();
        if let Ok(p) = io.observe.recv_timeout(Duration::from_millis(100)) {
            if !ok {
                println!("{role:?}: received tunnel packet ({} bytes) after {:?}", p.len(), t0.elapsed());
            }
            ok = true;
        }
    }
    std::thread::sleep(Duration::from_millis(1500));
    println!("{role:?}: rtt {:.2} ms via {}", conn.stats().rtt_ms, conn.peer_addr());
    ok
}

fn main() {
    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(log::LevelFilter::Info);
    let a: Vec<String> = std::env::args().collect();
    let (role, code, url) = (a[1].as_str(), a[2].clone(), a[3].clone());
    let opts = GatherOpts { stun_servers: vec![a[4].clone(), a[5].clone()], upnp: false, preferred_port: 47810, loopback: false };
    let signal: Arc<dyn SignalTransport> = transport_for(&url).unwrap();
    let ok = if role == "host" {
        let id = Arc::new(Identity { dev: llcore::random_hex(16), name: "LAB-HOST".into(), code, key: KeyPair::generate() });
        let (tx, rx) = channel();
        let _l = HostListener::start(id, signal, opts, Arc::new(Host(Mutex::new(tx))), Arc::new(AtomicBool::new(false)));
        match rx.recv_timeout(Duration::from_secs(90)) {
            Ok(Ok(est)) => exchange(est),
            Ok(Err(e)) => {
                println!("HOST FAILED: {e}");
                false
            }
            Err(_) => {
                println!("HOST: no request");
                false
            }
        }
    } else {
        let id = Identity { dev: llcore::random_hex(16), name: "LAB-CLIENT".into(), code: llcore::code::generate(), key: KeyPair::generate() };
        match connect(&id, &code, signal, &opts, &AtomicBool::new(false), &|s| eprintln!("stage {s:?}")) {
            Ok(est) => exchange(est),
            Err(e) => {
                println!("CLIENT FAILED: {e}");
                false
            }
        }
    };
    std::process::exit(if ok { 0 } else { 1 });
}
