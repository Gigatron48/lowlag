//! Connection flows.
//!
//! Host: listens on the rendezvous topic derived from its own code. When an offer arrives it asks
//! the UI (or the trusted-devices list) whether to accept, then answers with its candidates and
//! punches. Client: gathers candidates, publishes an offer to the host's topic, waits for the
//! answer, punches. Either way the result is an [`Established`] path that becomes a [`Conn`].

use crate::code;
use crate::conn::{Conn, ConnEvent, ConnParams};
use crate::crypto::{b64, code_keys, open_signal, seal_signal, session_keys, unb64_32, CodeKeys, KeyPair, RxCipher, TxCipher};
use crate::netinfo::{bind_socket, gather, parse_cands, GatherOpts, Gathered};
use crate::crypto::RxCipher as Rx;
use crate::proto::SignalMsg;
use crate::punch::{open_extra_sockets, punch, PunchPlan, HARD_NAT_SOCKETS};
use crate::signal::{SignalEvent, SignalTransport};
use crate::tun::TunDevice;
use crate::{random_hex, unix_now, Error, Result, PROTO_VERSION, TUN_NET_PREFIX};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const PUNCH_TIMEOUT: Duration = Duration::from_secs(15);
const HARD_PUNCH_TIMEOUT: Duration = Duration::from_secs(22);
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);
/// Generous: a PC clock a few minutes off must not silently drop requests.
const MAX_OFFER_AGE_S: i64 = 600;
/// How long the client waits for the host to confirm it received the request.
const ACK_TIMEOUT: Duration = Duration::from_secs(25);

pub struct Identity {
    /// Random stable device id (hex).
    pub dev: String,
    /// Computer name shown to the peer.
    pub name: String,
    /// Our own 9-digit code.
    pub code: String,
    /// Long-term identity key.
    pub key: KeyPair,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Host,
    Client,
}

pub struct Established {
    pub role: Role,
    pub sid: String,
    pub sock: UdpSocket,
    pub peer_addr: SocketAddr,
    pub tx: TxCipher,
    pub rx: RxCipher,
    pub peer_name: String,
    pub peer_dev: String,
    pub peer_static: [u8; 32],
    pub net: [u8; 3],
    pub local: Gathered,
}

impl Established {
    pub fn host_ip(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.net[0], self.net[1], self.net[2], 1)
    }
    pub fn client_ip(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.net[0], self.net[1], self.net[2], 2)
    }
    pub fn local_ip(&self) -> Ipv4Addr {
        if self.role == Role::Host { self.host_ip() } else { self.client_ip() }
    }
    pub fn peer_ip(&self) -> Ipv4Addr {
        if self.role == Role::Host { self.client_ip() } else { self.host_ip() }
    }
    /// Is the chosen path inside a private network (same LAN)?
    pub fn is_lan_path(&self) -> bool {
        match self.peer_addr.ip() {
            std::net::IpAddr::V4(ip) => ip.is_private() || ip.is_loopback(),
            _ => false,
        }
    }
    pub fn into_conn(self, tun: Arc<dyn TunDevice>) -> (Conn, Receiver<ConnEvent>) {
        let (local_ip, peer_ip) = (self.local_ip(), self.peer_ip());
        Conn::start(
            ConnParams { sock: self.sock, peer: self.peer_addr, tx: self.tx, rx: self.rx, local_ip, peer_ip },
            tun,
        )
    }
}

/// Every host gets its own /24 inside 10.213.0.0/16, derived from its device id.
pub fn host_net(dev: &str) -> [u8; 3] {
    let h = Sha256::digest(dev.as_bytes());
    [TUN_NET_PREFIX[0], TUN_NET_PREFIX[1], h[0]]
}

fn publish_msg(signal: &dyn SignalTransport, topic: &str, key: &[u8; 32], msg: &SignalMsg) -> Result<()> {
    let body = serde_json::to_vec(msg).expect("signal message serializes");
    signal.publish(topic, &seal_signal(key, &body))
}

/// Punch with the right technique for both NAT types; returns the socket that got through.
fn run_punch(
    main: UdpSocket,
    me: &Gathered,
    peer_cands: &[String],
    peer_nat: &str,
    peer_ports: &[u16],
    tx: &TxCipher,
    rx: &mut Rx,
    cancel: &AtomicBool,
) -> Result<(UdpSocket, SocketAddr)> {
    let plan = PunchPlan::new(parse_cands(peer_cands), peer_nat, peer_ports);
    let mut socks = vec![main];
    if me.nat_kind() != "easy" {
        for _ in 0..HARD_NAT_SOCKETS {
            match bind_socket(0) {
                Ok(s) => socks.push(s),
                Err(_) => break,
            }
        }
        if socks.len() == 1 {
            socks.extend(open_extra_sockets(HARD_NAT_SOCKETS));
        }
    }
    let hard_mode = socks.len() > 1 || plan.spray_ip.is_some();
    log::info!(
        "punch: me nat={} | peer nat={:?} ports={:?} cands={:?} | extra sockets {} spray {:?}",
        me.nat_kind(),
        peer_nat,
        peer_ports,
        plan.cands,
        socks.len() - 1,
        plan.spray_ip
    );
    let timeout = if hard_mode { HARD_PUNCH_TIMEOUT } else { PUNCH_TIMEOUT };
    let (i, addr) = punch(&socks, &plan, tx, rx, timeout, cancel)?;
    log::info!("punch: success on socket {i} ({}) to {addr}", if i == 0 { "main" } else { "extra" });
    Ok((socks.swap_remove(i), addr))
}

// ============================================================================ host

/// What the peer told us about its addresses and NAT.
struct PeerNat {
    cands: Vec<String>,
    nat: String,
    ports: Vec<u16>,
}

#[derive(Debug, Clone)]
pub struct IncomingRequest {
    pub sid: String,
    pub name: String,
    pub dev: String,
    pub static_pub: [u8; 32],
}

pub enum Decision {
    Accept,
    Decline(String),
}

pub trait HostHandler: Send + Sync {
    /// Rendezvous subscription state changed (ok=false: server unreachable, retrying).
    fn on_listening(&self, ok: bool, detail: &str);
    /// Called on its own thread; may block while the user decides.
    fn decide(&self, req: &IncomingRequest) -> Decision;
    fn on_progress(&self, req: &IncomingRequest, stage: &str);
    fn on_established(&self, est: Established);
    fn on_failed(&self, req: &IncomingRequest, err: Error);
}

pub struct HostListener {
    stop: Arc<AtomicBool>,
}

impl HostListener {
    /// `busy` is set while a session is being set up or running; the app clears it when the
    /// session ends. Offers arriving while busy get a "busy" answer.
    pub fn start(
        id: Arc<Identity>,
        signal: Arc<dyn SignalTransport>,
        opts: GatherOpts,
        handler: Arc<dyn HostHandler>,
        busy: Arc<AtomicBool>,
    ) -> HostListener {
        let stop = Arc::new(AtomicBool::new(false));
        let st = stop.clone();
        thread::Builder::new()
            .name("ll-host-listen".into())
            .spawn(move || listen_loop(id, signal, opts, handler, busy, st))
            .unwrap();
        HostListener { stop }
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl Drop for HostListener {
    fn drop(&mut self) {
        self.stop();
    }
}

fn listen_loop(
    id: Arc<Identity>,
    signal: Arc<dyn SignalTransport>,
    opts: GatherOpts,
    handler: Arc<dyn HostHandler>,
    busy: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
) {
    let keys = code_keys(&id.code);
    let mut seen: VecDeque<String> = VecDeque::new();
    let mut backoff = Duration::from_secs(1);
    let mut first = true;
    while !stop.load(Ordering::Relaxed) {
        // After a reconnect, replay the last minute so an offer sent during the gap isn't lost.
        let since = if first { None } else { Some("60s") };
        first = false;
        let res = signal.subscribe(&keys.topic, since, &stop, &mut |ev| {
            match ev {
                SignalEvent::Open => {
                    backoff = Duration::from_secs(1);
                    handler.on_listening(true, "");
                }
                SignalEvent::Message(m) => {
                    on_offer(&m, &id, &keys, &signal, &opts, &handler, &busy, &mut seen);
                }
            }
            !stop.load(Ordering::Relaxed)
        });
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let detail = match res {
            Err(e) => e.to_string(),
            Ok(()) => "stream ended".into(),
        };
        log::warn!("rendezvous subscription ended: {detail}; retrying in {backoff:?}");
        handler.on_listening(false, &detail);
        let until = Instant::now() + backoff;
        while Instant::now() < until && !stop.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(100));
        }
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

#[allow(clippy::too_many_arguments)]
fn on_offer(
    m: &str,
    id: &Arc<Identity>,
    keys: &CodeKeys,
    signal: &Arc<dyn SignalTransport>,
    opts: &GatherOpts,
    handler: &Arc<dyn HostHandler>,
    busy: &Arc<AtomicBool>,
    seen: &mut VecDeque<String>,
) {
    let Some(plain) = open_signal(&keys.key, m) else { return };
    let Ok(SignalMsg::Offer { ver, sid, ts, name, dev, spk, epk, cands, reply, nat, ports }) = serde_json::from_slice(&plain)
    else {
        return;
    };
    if (unix_now() as i64 - ts as i64).abs() > MAX_OFFER_AGE_S || seen.contains(&sid) || dev == id.dev {
        return;
    }
    seen.push_back(sid.clone());
    if seen.len() > 64 {
        seen.pop_front();
    }
    let decline = |reason: &str| {
        let ans = SignalMsg::Answer {
            ver: PROTO_VERSION,
            sid: sid.clone(),
            ts: unix_now(),
            ok: false,
            reason: reason.to_string(),
            name: id.name.clone(),
            dev: String::new(),
            spk: String::new(),
            epk: String::new(),
            cands: vec![],
            net: vec![],
            nat: String::new(),
            ports: vec![],
        };
        if let Err(e) = publish_msg(signal.as_ref(), &reply, &keys.key, &ans) {
            log::warn!("failed to send decline: {e}");
        }
    };
    if ver != PROTO_VERSION {
        decline("version");
        return;
    }
    let (Some(spk), Some(epk)) = (unb64_32(&spk), unb64_32(&epk)) else { return };
    if busy.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        decline("busy");
        return;
    }
    let req = IncomingRequest { sid: sid.clone(), name, dev, static_pub: spk };
    log::info!("incoming request from '{}' ({})", req.name, req.dev);
    let (id, keys, signal, opts, handler, busy) =
        (id.clone(), keys.clone(), signal.clone(), opts.clone(), handler.clone(), busy.clone());
    thread::spawn(move || {
        // Tell the client right away that the request arrived (before the user decides).
        let ack = SignalMsg::Ack { sid: req.sid.clone() };
        if let Err(e) = publish_msg(signal.as_ref(), &reply, &keys.key, &ack) {
            log::warn!("could not acknowledge request: {e}");
        }
        let peer = PeerNat { cands, nat, ports };
        let result = host_session(&req, &id, &keys, signal.as_ref(), &opts, handler.as_ref(), &epk, &peer, &reply);
        match result {
            Ok(Some(est)) => handler.on_established(est),
            Ok(None) => busy.store(false, Ordering::SeqCst), // declined
            Err(e) => {
                busy.store(false, Ordering::SeqCst);
                log::warn!("host session with '{}' failed: {e}", req.name);
                handler.on_failed(&req, e);
            }
        }
    });
}

#[allow(clippy::too_many_arguments)]
fn host_session(
    req: &IncomingRequest,
    id: &Identity,
    keys: &CodeKeys,
    signal: &dyn SignalTransport,
    opts: &GatherOpts,
    handler: &dyn HostHandler,
    peer_eph: &[u8; 32],
    peer: &PeerNat,
    reply: &str,
) -> Result<Option<Established>> {
    let mut my_nat = (String::new(), Vec::new());
    let answer = |ok: bool, reason: &str, cands: Vec<String>, epk: String, net: Vec<u8>, nat: &(String, Vec<u16>)| {
        let msg = SignalMsg::Answer {
            ver: PROTO_VERSION,
            sid: req.sid.clone(),
            ts: unix_now(),
            ok,
            reason: reason.to_string(),
            name: id.name.clone(),
            dev: if ok { id.dev.clone() } else { String::new() },
            spk: if ok { b64(&id.key.public()) } else { String::new() },
            epk,
            cands,
            net,
            nat: nat.0.clone(),
            ports: nat.1.clone(),
        };
        publish_msg(signal, reply, &keys.key, &msg)
    };

    if let Decision::Decline(reason) = handler.decide(req) {
        let _ = answer(false, &reason, vec![], String::new(), vec![], &my_nat);
        return Ok(None);
    }
    handler.on_progress(req, "gathering");
    let sock = match bind_socket(opts.preferred_port) {
        Ok(s) => s,
        Err(e) => {
            let _ = answer(false, "internal", vec![], String::new(), vec![], &my_nat);
            return Err(e.into());
        }
    };
    let g = gather(&sock, opts);
    log::info!("host candidates: {} ({:?})", g.describe(), g.cands);
    let eph = KeyPair::generate();
    let Some(sk) = session_keys(true, &id.key, &eph, &req.static_pub, peer_eph, &keys.key, &req.sid) else {
        let _ = answer(false, "crypto", vec![], String::new(), vec![], &my_nat);
        return Err(Error::Crypto);
    };
    let net = host_net(&id.dev);
    my_nat = (g.nat_kind().to_string(), g.ports.clone());
    answer(true, "", g.cands.iter().map(|a| a.to_string()).collect(), b64(&eph.public()), net.to_vec(), &my_nat)?;

    handler.on_progress(req, "punching");
    let tx = TxCipher::new(&sk.tx, &sk.hp_tx);
    let mut rx = RxCipher::new(&sk.rx, &sk.hp_rx);
    let never = AtomicBool::new(false);
    let (sock, peer_addr) = run_punch(sock, &g, &peer.cands, &peer.nat, &peer.ports, &tx, &mut rx, &never)?;
    log::info!("host: path to '{}' established via {peer_addr}", req.name);
    Ok(Some(Established {
        role: Role::Host,
        sid: req.sid.clone(),
        sock,
        peer_addr,
        tx,
        rx,
        peer_name: req.name.clone(),
        peer_dev: req.dev.clone(),
        peer_static: req.static_pub,
        net,
        local: g,
    }))
}

// ============================================================================ client

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientStage {
    Preparing,
    Contacting,
    WaitingApproval,
    Punching,
}

pub fn connect(
    id: &Identity,
    code_input: &str,
    signal: Arc<dyn SignalTransport>,
    opts: &GatherOpts,
    cancel: &AtomicBool,
    progress: &dyn Fn(ClientStage),
) -> Result<Established> {
    let code = code::normalize(code_input).ok_or_else(|| Error::Protocol("invalid code".into()))?;
    if code == id.code {
        return Err(Error::Protocol("own code".into()));
    }
    let keys = code_keys(&code);
    progress(ClientStage::Preparing);
    let sock = bind_socket(opts.preferred_port)?;
    let g = gather(&sock, opts);
    log::info!("client candidates: {} ({:?})", g.describe(), g.cands);
    let check_cancel = || if cancel.load(Ordering::Relaxed) { Err(Error::Cancelled) } else { Ok(()) };
    check_cancel()?;

    let eph = KeyPair::generate();
    let sid = random_hex(12);
    let reply = format!("ll1r{}", random_hex(15));

    // Listen for the answer before sending the offer.
    let (ev_tx, ev_rx) = channel::<SignalEvent>();
    let stop = Arc::new(AtomicBool::new(false));
    {
        let (signal, stop, reply) = (signal.clone(), stop.clone(), reply.clone());
        thread::spawn(move || {
            if let Err(e) = signal.subscribe(&reply, None, &stop, &mut |ev| ev_tx.send(ev).is_ok()) {
                log::warn!("answer subscription ended: {e}");
            }
        });
    }
    struct StopOnDrop(Arc<AtomicBool>);
    impl Drop for StopOnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let _stop_guard = StopOnDrop(stop);

    let wait_event = |deadline: Instant| -> Result<SignalEvent> {
        loop {
            check_cancel()?;
            if Instant::now() > deadline {
                return Err(Error::Timeout("rendezvous"));
            }
            match ev_rx.recv_timeout(Duration::from_millis(200)) {
                Ok(ev) => return Ok(ev),
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(Error::Signal("rendezvous server unreachable".into()))
                }
            }
        }
    };

    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        match wait_event(deadline) {
            Ok(SignalEvent::Open) => break,
            Ok(_) => continue,
            Err(Error::Timeout(_)) => return Err(Error::Signal("no rendezvous server reachable".into())),
            Err(e) => return Err(e),
        }
    }

    progress(ClientStage::Contacting);
    let offer = SignalMsg::Offer {
        ver: PROTO_VERSION,
        sid: sid.clone(),
        ts: unix_now(),
        name: id.name.clone(),
        dev: id.dev.clone(),
        spk: b64(&id.key.public()),
        epk: b64(&eph.public()),
        cands: g.cands.iter().map(|a| a.to_string()).collect(),
        reply: reply.clone(),
        nat: g.nat_kind().to_string(),
        ports: g.ports.clone(),
    };
    publish_msg(signal.as_ref(), &keys.topic, &keys.key, &offer)?;

    // First the host confirms it got the request (so we can tell "not delivered" from "not yet
    // approved"), then it answers once the user decides.
    let started = Instant::now();
    let mut acked = false;
    let mut republished = false;
    let answer = loop {
        let limit = if acked { APPROVAL_TIMEOUT } else { ACK_TIMEOUT };
        if started.elapsed() > limit {
            return Err(Error::Timeout(if acked { "friend did not answer" } else { "no answer from that code" }));
        }
        if !acked && !republished && started.elapsed() > Duration::from_secs(8) {
            republished = true;
            let _ = publish_msg(signal.as_ref(), &keys.topic, &keys.key, &offer);
        }
        let ev = match wait_event(Instant::now() + Duration::from_millis(500)) {
            Ok(ev) => ev,
            Err(Error::Timeout(_)) => continue,
            Err(e) => return Err(e),
        };
        let SignalEvent::Message(m) = ev else { continue };
        let Some(plain) = open_signal(&keys.key, &m) else { continue };
        match serde_json::from_slice::<SignalMsg>(&plain) {
            Ok(SignalMsg::Ack { sid: s }) if s == sid => {
                if !acked {
                    acked = true;
                    log::info!("host received the request after {:?}", started.elapsed());
                    progress(ClientStage::WaitingApproval);
                }
            }
            Ok(a @ SignalMsg::Answer { .. }) => {
                if let SignalMsg::Answer { sid: ref s, .. } = a {
                    if *s == sid {
                        break a;
                    }
                }
            }
            _ => {}
        }
    };
    let SignalMsg::Answer { ok, reason, name, dev, spk, epk, cands, net, nat, ports, .. } = answer else { unreachable!() };
    if !ok {
        return Err(Error::Declined(if reason.is_empty() { "declined".into() } else { reason }));
    }
    let (Some(peer_static), Some(peer_eph)) = (unb64_32(&spk), unb64_32(&epk)) else {
        return Err(Error::Protocol("bad answer keys".into()));
    };
    let net: [u8; 3] = net.try_into().map_err(|_| Error::Protocol("bad subnet".into()))?;
    if net[..2] != TUN_NET_PREFIX {
        return Err(Error::Protocol("bad subnet".into()));
    }
    let sk = session_keys(false, &id.key, &eph, &peer_static, &peer_eph, &keys.key, &sid).ok_or(Error::Crypto)?;

    progress(ClientStage::Punching);
    let tx = TxCipher::new(&sk.tx, &sk.hp_tx);
    let mut rx = RxCipher::new(&sk.rx, &sk.hp_rx);
    let (sock, peer) = run_punch(sock, &g, &cands, &nat, &ports, &tx, &mut rx, cancel)?;
    log::info!("client: path to '{name}' established via {peer}");
    Ok(Established {
        role: Role::Client,
        sid,
        sock,
        peer_addr: peer,
        tx,
        rx,
        peer_name: name,
        peer_dev: dev,
        peer_static,
        net,
        local: g,
    })
}

// ============================================================================ tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::ConnEvent;
    use crate::proto::Ctrl;
    use crate::signal::MemSignal;
    use crate::tun::{fake_ipv4_udp, MemTun};
    use std::sync::Mutex;

    struct TestHost {
        accept: bool,
        est: Mutex<Option<Established>>,
        listening: AtomicBool,
        failed: Mutex<Option<String>>,
    }

    impl HostHandler for TestHost {
        fn on_listening(&self, ok: bool, _d: &str) {
            self.listening.store(ok, Ordering::SeqCst);
        }
        fn decide(&self, req: &IncomingRequest) -> Decision {
            assert_eq!(req.name, "Client PC");
            if self.accept { Decision::Accept } else { Decision::Decline("declined".into()) }
        }
        fn on_progress(&self, _r: &IncomingRequest, _s: &str) {}
        fn on_established(&self, est: Established) {
            *self.est.lock().unwrap() = Some(est);
        }
        fn on_failed(&self, _r: &IncomingRequest, err: Error) {
            *self.failed.lock().unwrap() = Some(err.to_string());
        }
    }

    fn ident(name: &str) -> Identity {
        Identity { dev: random_hex(8), name: name.into(), code: code::generate(), key: KeyPair::generate() }
    }

    fn opts() -> GatherOpts {
        GatherOpts { stun_servers: vec![], upnp: false, preferred_port: 0, loopback: true }
    }

    fn setup(accept: bool) -> (Arc<Identity>, Identity, Arc<MemSignal>, Arc<TestHost>, HostListener, Arc<AtomicBool>) {
        let host_id = Arc::new(ident("Host PC"));
        let client_id = ident("Client PC");
        let signal = MemSignal::new();
        let handler = Arc::new(TestHost {
            accept,
            est: Mutex::new(None),
            listening: AtomicBool::new(false),
            failed: Mutex::new(None),
        });
        let busy = Arc::new(AtomicBool::new(false));
        let listener = HostListener::start(host_id.clone(), signal.clone(), opts(), handler.clone(), busy.clone());
        let t0 = Instant::now();
        while !handler.listening.load(Ordering::SeqCst) {
            assert!(t0.elapsed() < Duration::from_secs(2));
            thread::sleep(Duration::from_millis(10));
        }
        (host_id, client_id, signal, handler, listener, busy)
    }

    #[test]
    fn declined_request() {
        let (host_id, client_id, signal, _h, _l, busy) = setup(false);
        let cancel = AtomicBool::new(false);
        let r = connect(&client_id, &host_id.code, signal, &opts(), &cancel, &|_| {});
        assert!(matches!(r, Err(Error::Declined(_))), "{:?}", r.err());
        thread::sleep(Duration::from_millis(50));
        assert!(!busy.load(Ordering::SeqCst));
    }

    #[test]
    fn wrong_code_times_out_quickly_when_cancelled() {
        let (_host_id, client_id, signal, _h, _l, _b) = setup(true);
        let cancel = Arc::new(AtomicBool::new(false));
        let c2 = cancel.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(300));
            c2.store(true, Ordering::SeqCst);
        });
        let r = connect(&client_id, "111 222 333", signal, &opts(), &cancel, &|_| {});
        assert!(matches!(r, Err(Error::Cancelled)), "{:?}", r.err());
    }

    #[test]
    fn full_tunnel() {
        let (host_id, client_id, signal, handler, _listener, _busy) = setup(true);
        let cancel = AtomicBool::new(false);
        let stages = Mutex::new(Vec::new());
        let est_c = connect(&client_id, &code::pretty(&host_id.code), signal, &opts(), &cancel, &|s| {
            stages.lock().unwrap().push(s)
        })
        .expect("client connects");
        assert_eq!(stages.lock().unwrap().last(), Some(&ClientStage::Punching));
        // host side established too
        let t0 = Instant::now();
        let est_h = loop {
            if let Some(e) = handler.est.lock().unwrap().take() {
                break e;
            }
            assert!(t0.elapsed() < Duration::from_secs(5), "host never established");
            thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(est_h.peer_name, "Client PC");
        assert_eq!(est_c.peer_name, "Host PC");
        assert_eq!(est_c.net, host_net(&host_id.dev));
        assert_eq!(est_h.peer_static, client_id.key.public());
        let (hip, cip) = (est_c.host_ip(), est_c.client_ip());

        let (tun_h, io_h) = MemTun::new();
        let (tun_c, io_c) = MemTun::new();
        let (conn_h, ev_h) = est_h.into_conn(tun_h);
        let (conn_c, ev_c) = est_c.into_conn(tun_c);

        // client OS -> host OS
        let pkt = fake_ipv4_udp(cip, hip, b"hello host");
        io_c.inject.send(pkt.clone()).unwrap();
        assert_eq!(io_h.observe.recv_timeout(Duration::from_secs(2)).unwrap(), pkt);
        // host OS -> client OS
        let pkt2 = fake_ipv4_udp(hip, cip, &[7u8; 1300]);
        io_h.inject.send(pkt2.clone()).unwrap();
        assert_eq!(io_c.observe.recv_timeout(Duration::from_secs(2)).unwrap(), pkt2);
        // packets not addressed to the peer are dropped
        io_c.inject.send(fake_ipv4_udp(cip, Ipv4Addr::new(10, 213, 9, 255), b"bcast")).unwrap();
        assert!(io_h.observe.recv_timeout(Duration::from_millis(300)).is_err());

        // control messages
        conn_c.send_ctrl(&Ctrl::Pair { pin: "1234".into(), name: "Client PC".into() });
        match ev_h.recv_timeout(Duration::from_secs(2)).unwrap() {
            ConnEvent::Ctrl(Ctrl::Pair { pin, .. }) => assert_eq!(pin, "1234"),
            other => panic!("{other:?}"),
        }

        // speed probe
        let sr = conn_c.speed_test(&[5, 10, 20], 150).expect("speed result");
        assert_eq!(sr.steps.len(), 3);
        assert!(sr.best_mbps >= 5, "{sr:?}");

        // RTT gets measured
        thread::sleep(Duration::from_millis(1200));
        assert!(conn_c.stats().rtt_ms > 0.0);

        // close propagates
        conn_c.close("bye");
        match ev_h.recv_timeout(Duration::from_secs(2)).unwrap() {
            ConnEvent::Closed(r) => assert!(r.contains("bye"), "{r}"),
            other => panic!("{other:?}"),
        }
        assert!(conn_h.is_closed());
        drop(ev_c);
    }
}

#[cfg(test)]
mod bench {
    use super::*;
    use crate::signal::MemSignal;
    use crate::tun::{fake_ipv4_udp, MemTun};
    use std::sync::Mutex;

    struct AcceptAll(Mutex<Option<Established>>, AtomicBool);
    impl HostHandler for AcceptAll {
        fn on_listening(&self, ok: bool, _d: &str) { self.1.store(ok, Ordering::SeqCst); }
        fn decide(&self, _r: &IncomingRequest) -> Decision { Decision::Accept }
        fn on_progress(&self, _r: &IncomingRequest, _s: &str) {}
        fn on_established(&self, e: Established) { *self.0.lock().unwrap() = Some(e); }
        fn on_failed(&self, _r: &IncomingRequest, _e: Error) {}
    }

    /// cargo test --release -p llcore -- --ignored --nocapture tunnel_latency
    #[test]
    #[ignore]
    fn tunnel_latency() {
        let o = GatherOpts { stun_servers: vec![], upnp: false, preferred_port: 0, loopback: true };
        let hid = Arc::new(Identity { dev: random_hex(8), name: "H".into(), code: code::generate(), key: KeyPair::generate() });
        let cid = Identity { dev: random_hex(8), name: "C".into(), code: code::generate(), key: KeyPair::generate() };
        let sig = MemSignal::new();
        let h = Arc::new(AcceptAll(Mutex::new(None), AtomicBool::new(false)));
        let _l = HostListener::start(hid.clone(), sig.clone(), o.clone(), h.clone(), Arc::new(AtomicBool::new(false)));
        while !h.1.load(Ordering::SeqCst) { thread::sleep(Duration::from_millis(5)); }
        let ec = connect(&cid, &hid.code, sig, &o, &AtomicBool::new(false), &|_| {}).unwrap();
        let eh = loop { if let Some(e) = h.0.lock().unwrap().take() { break e; } thread::sleep(Duration::from_millis(5)); };
        let (hip, cip) = (ec.host_ip(), ec.client_ip());
        let (th, ioh) = MemTun::new();
        let (tc, ioc) = MemTun::new();
        let (_ch, _eh) = eh.into_conn(th);
        let (_cc, _ec) = ec.into_conn(tc);
        // one-way latency, packet by packet
        let mut lat = Vec::new();
        for _ in 0..2000 {
            let p = fake_ipv4_udp(cip, hip, &[1u8; 1300]);
            let t = Instant::now();
            ioc.inject.send(p).unwrap();
            ioh.observe.recv_timeout(Duration::from_secs(1)).unwrap();
            lat.push(t.elapsed().as_micros() as u64);
        }
        lat.sort();
        println!("one-way through tunnel (incl. test channels): p50={}us p99={}us max={}us",
            lat[lat.len()/2], lat[lat.len()*99/100], lat[lat.len()-1]);
        // throughput burst
        let n = 50_000;
        let t = Instant::now();
        let rxer = thread::spawn(move || { for _ in 0..n { if ioh.observe.recv_timeout(Duration::from_secs(2)).is_err() { break; } } });
        for _ in 0..n { ioc.inject.send(fake_ipv4_udp(cip, hip, &[2u8; 1300])).unwrap(); }
        rxer.join().unwrap();
        let s = t.elapsed().as_secs_f64();
        println!("burst: {} pkts x 1328 B in {:.3}s = {:.0} Mbit/s", n, s, n as f64 * 1328.0 * 8.0 / s / 1e6);
    }
}
