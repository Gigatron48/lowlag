//! The session engine: owns identity/config, runs the host listener, drives client connections,
//! and exposes one serializable snapshot (`UiState`) that the UI polls.

use crate::config::{Config, Settings, TrustedDevice};
use crate::platform::{Platform, StreamOpts, StreamProcess};
use llcore::conn::{Conn, ConnEvent};
use llcore::crypto::b64;
use llcore::netinfo::GatherOpts;
use llcore::proto::Ctrl;
use llcore::session::{self, ClientStage, Decision, Established, HostHandler, HostListener, IncomingRequest, Identity};
use llcore::signal::{MultiSignal, SignalTransport};
use crate::netcheck::{self, CheckItem};
use llcore::{Error, STREAM_PACKET_SIZE};
use rand::Rng;
use serde::Serialize;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::{Duration, Instant};

pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const HISTORY: usize = 60;
const SPEED_STEPS: &[u32] = &[5, 10, 20, 35, 50, 80, 120];

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct UiError {
    pub code: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct UiIncoming {
    pub name: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct StreamInfo {
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub bitrate_kbps: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct UiState {
    pub version: String,
    pub name: String,
    pub code: String,
    /// connecting | ok | error
    pub signal: String,
    pub host_ready: bool,
    pub host_detail: String,
    /// idle | connecting | live
    pub phase: String,
    /// client | host
    pub role: Option<String>,
    pub stage: Option<String>,
    pub done_stages: Vec<String>,
    pub peer: Option<String>,
    pub target_code: Option<String>,
    pub error: Option<UiError>,
    pub incoming: Option<UiIncoming>,
    pub rtt_ms: f64,
    pub rtt_history: Vec<f64>,
    /// direct | lan
    pub path: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub stream: Option<StreamInfo>,
    pub settings: Settings,
}

impl UiState {
    fn idle(&mut self) {
        self.phase = "idle".into();
        self.role = None;
        self.stage = None;
        self.done_stages.clear();
        self.peer = None;
        self.target_code = None;
        self.rtt_ms = 0.0;
        self.rtt_history.clear();
        self.rx_bytes = 0;
        self.tx_bytes = 0;
        self.stream = None;
    }
    fn set_stage(&mut self, stage: &str) {
        if let Some(prev) = self.stage.take() {
            if prev != stage && !self.done_stages.contains(&prev) {
                self.done_stages.push(prev);
            }
        }
        self.stage = Some(stage.to_string());
    }
}

struct Pending {
    reply: Sender<(bool, bool)>,
}

struct SessionCtl {
    stop: Arc<AtomicBool>,
}

pub struct Engine {
    platform: Arc<dyn Platform>,
    cfg_path: PathBuf,
    cfg: Mutex<Config>,
    identity: Arc<Identity>,
    signal: Option<Arc<dyn SignalTransport>>,
    gather: GatherOpts,
    st: Mutex<UiState>,
    busy: Arc<AtomicBool>,
    listener: Mutex<Option<HostListener>>,
    pending: Mutex<Option<Pending>>,
    cancel: Mutex<Arc<AtomicBool>>,
    session: Mutex<Option<SessionCtl>>,
    host_uuid: Mutex<String>,
    last_check: Mutex<Vec<CheckItem>>,
}

fn ui_err(code: &str, detail: impl Into<String>) -> UiError {
    UiError { code: code.into(), detail: detail.into() }
}

fn map_core_err(e: &Error) -> Option<UiError> {
    let code = match e {
        Error::Cancelled => return None,
        Error::Declined(r) if r == "busy" => "busy",
        Error::Declined(r) if r == "version" => "version",
        Error::Declined(_) => "declined",
        Error::Timeout(w) if w.contains("did not answer") => "no_decision",
        Error::Timeout(_) => "timeout",
        Error::Signal(_) => "offline",
        Error::NatTraversal(_) => "nat",
        Error::Protocol(p) if p == "own code" => "own_code",
        Error::Protocol(p) if p == "invalid code" => "invalid_code",
        _ => "internal",
    };
    Some(ui_err(code, e.to_string()))
}

/// Default bitrate for a resolution/frame rate, roughly what Moonlight picks (20 Mbit/s at 1080p60).
pub fn base_kbps(w: u32, h: u32, fps: u32) -> u32 {
    let px = (w as f64 * h as f64) / (1920.0 * 1080.0);
    let f = (fps as f64 / 60.0).clamp(0.5, 2.5);
    (20_000.0 * px * f.powf(0.8)).round().clamp(3_000.0, 150_000.0) as u32
}

pub fn pick_bitrate(quality: &str, w: u32, h: u32, fps: u32, measured_mbps: Option<u32>) -> u32 {
    let base = base_kbps(w, h, fps);
    match quality {
        "max" => (base * 2).min(150_000),
        "saver" => (base / 2).max(5_000).min(base),
        "balanced" => base,
        _ => match measured_mbps {
            // leave 30 % headroom for FEC, audio and bursts
            Some(m) if m > 0 => ((m as f64 * 1000.0 * 0.7) as u32).clamp(3_000, (base * 16 / 10).min(150_000)),
            Some(_) => 3_000,
            None => base,
        },
    }
}

impl Engine {
    /// Production start-up: real rendezvous server, default gathering.
    pub fn start(platform: Arc<dyn Platform>) -> Arc<Engine> {
        let data = platform.data_dir();
        crate::logger::init(&data.join("logs"));
        let cfg = Config::load_or_create(&data.join("config.json"));
        let signal: Option<Arc<dyn SignalTransport>> = match MultiSignal::new(&cfg.signal_servers) {
            Ok(n) => Some(Arc::new(n)),
            Err(e) => {
                log::error!("rendezvous transport unavailable: {e}");
                None
            }
        };
        let gather = GatherOpts {
            stun_servers: cfg.stun_servers.clone(),
            upnp: true,
            preferred_port: cfg.preferred_port,
            loopback: false,
        };
        Self::start_with(platform, cfg, signal, gather)
    }

    pub fn start_with(
        platform: Arc<dyn Platform>,
        cfg: Config,
        signal: Option<Arc<dyn SignalTransport>>,
        gather: GatherOpts,
    ) -> Arc<Engine> {
        let name = platform.computer_name();
        let identity = Arc::new(cfg.identity(&name));
        log::info!("LowLag {APP_VERSION} starting; device {} '{}' code {}", cfg.dev, name, cfg.code);
        let st = UiState {
            version: APP_VERSION.into(),
            name: name.clone(),
            code: cfg.code.clone(),
            signal: if signal.is_some() { "connecting".into() } else { "error".into() },
            host_ready: false,
            host_detail: String::new(),
            phase: "idle".into(),
            role: None,
            stage: None,
            done_stages: Vec::new(),
            peer: None,
            target_code: None,
            error: None,
            incoming: None,
            rtt_ms: 0.0,
            rtt_history: Vec::new(),
            path: "direct".into(),
            rx_bytes: 0,
            tx_bytes: 0,
            stream: None,
            settings: cfg.settings.clone(),
        };
        let engine = Arc::new(Engine {
            cfg_path: platform.data_dir().join("config.json"),
            platform,
            cfg: Mutex::new(cfg),
            identity,
            signal,
            gather,
            st: Mutex::new(st),
            busy: Arc::new(AtomicBool::new(false)),
            listener: Mutex::new(None),
            pending: Mutex::new(None),
            cancel: Mutex::new(Arc::new(AtomicBool::new(false))),
            session: Mutex::new(None),
            host_uuid: Mutex::new(String::new()),
            last_check: Mutex::new(Vec::new()),
        });

        if let Some(sig) = &engine.signal {
            let handler: Arc<dyn HostHandler> = Arc::new(HostSide(Arc::downgrade(&engine)));
            let l = HostListener::start(engine.identity.clone(), sig.clone(), engine.gather.clone(), handler, engine.busy.clone());
            *engine.listener.lock().unwrap() = Some(l);
        }

        // Host readiness: prepare once, then keep an eye on it.
        let weak = Arc::downgrade(&engine);
        thread::Builder::new()
            .name("ll-host-watch".into())
            .spawn(move || host_watch(weak))
            .unwrap();
        engine
    }

    // ------------------------------------------------------------ UI API

    pub fn ui_state(&self) -> UiState {
        self.st.lock().unwrap().clone()
    }

    fn update(&self, f: impl FnOnce(&mut UiState)) {
        f(&mut self.st.lock().unwrap());
    }

    pub fn connect(self: &Arc<Self>, code_input: &str) {
        let Some(code) = llcore::code::normalize(code_input) else {
            self.update(|s| s.error = Some(ui_err("invalid_code", "")));
            return;
        };
        if code == self.identity.code {
            self.update(|s| s.error = Some(ui_err("own_code", "")));
            return;
        }
        if self.busy.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            log::warn!("connect ignored: busy");
            return;
        }
        let cancel = Arc::new(AtomicBool::new(false));
        *self.cancel.lock().unwrap() = cancel.clone();
        self.update(|s| {
            s.idle();
            s.error = None;
            s.phase = "connecting".into();
            s.role = Some("client".into());
            s.target_code = Some(code.clone());
            s.set_stage("preparing");
        });
        let me = self.clone();
        thread::Builder::new()
            .name("ll-client".into())
            .spawn(move || {
                let res = me.client_flow(&code, &cancel);
                if let Err(Some(e)) = &res {
                    log::warn!("client session ended with error: {} ({})", e.code, e.detail);
                }
                me.end_session(res.err().flatten());
            })
            .unwrap();
    }

    pub fn cancel(&self) {
        self.cancel.lock().unwrap().store(true, Ordering::SeqCst);
        self.stop_session();
    }

    pub fn disconnect(&self) {
        self.cancel.lock().unwrap().store(true, Ordering::SeqCst);
        self.stop_session();
    }

    fn stop_session(&self) {
        if let Some(s) = self.session.lock().unwrap().as_ref() {
            s.stop.store(true, Ordering::SeqCst);
        }
    }

    pub fn respond(&self, accept: bool, remember: bool) {
        if let Some(p) = self.pending.lock().unwrap().take() {
            let _ = p.reply.send((accept, remember));
        }
        self.update(|s| s.incoming = None);
    }

    pub fn set_settings(&self, mut settings: Settings) {
        settings.sanitize();
        let mut cfg = self.cfg.lock().unwrap();
        cfg.settings = settings.clone();
        if let Err(e) = cfg.save(&self.cfg_path) {
            log::error!("saving settings: {e}");
        }
        drop(cfg);
        self.update(|s| s.settings = settings);
    }

    pub fn forget_devices(&self) {
        let mut cfg = self.cfg.lock().unwrap();
        cfg.trusted.clear();
        let _ = cfg.save(&self.cfg_path);
    }

    /// Test reachability of every server we depend on (blocks up to ~10 s).
    pub fn check_network(&self) -> Vec<CheckItem> {
        let (sig, stun) = {
            let c = self.cfg.lock().unwrap();
            (c.signal_servers.clone(), c.stun_servers.clone())
        };
        let r = netcheck::run(&self.platform, &sig, &stun);
        *self.last_check.lock().unwrap() = r.clone();
        r
    }

    pub fn dismiss_error(&self) {
        self.update(|s| s.error = None);
    }

    /// Write a support report (state + recent log) into Downloads; returns its path.
    pub fn save_report(&self) -> Result<String, String> {
        let dir = self.platform.downloads_dir().ok_or("no Downloads folder")?;
        let stamp = crate::logger::timestamp().replace([':', ' '], "-");
        let path = dir.join(format!("LowLag-report-{}.txt", &stamp[..19]));
        let st = self.ui_state();
        let cfg = self.cfg.lock().unwrap().clone();
        let mut out = String::new();
        out.push_str(&format!("LowLag {APP_VERSION} report {}\n", crate::logger::timestamp()));
        out.push_str(&format!("device {} name '{}'\n", cfg.dev, st.name));
        out.push_str(&format!("rendezvous {:?} state {}\n", cfg.signal_servers, st.signal));
        out.push_str(&format!("host ready {} {}\n", st.host_ready, st.host_detail));
        out.push_str(&format!("settings {:?}\n", cfg.settings));
        out.push_str(&format!("trusted devices {}, paired hosts {}\n", cfg.trusted.len(), cfg.paired_hosts.len()));
        out.push_str(&format!("display {:?}\n", self.platform.display_mode()));
        out.push_str(&self.platform.diagnostics());
        let checks = self.last_check.lock().unwrap().clone();
        if !checks.is_empty() {
            out.push_str("\n----- network check -----\n");
            out.push_str(&netcheck::to_text(&checks));
        }
        out.push_str("\n----- state -----\n");
        out.push_str(&serde_json::to_string_pretty(&st).unwrap_or_default());
        out.push_str("\n----- log -----\n");
        out.push_str(&crate::logger::tail(400_000));
        std::fs::write(&path, out).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(path.display().to_string())
    }

    pub fn shutdown(&self) {
        self.disconnect();
        if let Some(l) = self.listener.lock().unwrap().take() {
            l.stop();
        }
        thread::sleep(Duration::from_millis(300));
        log::logger().flush();
    }

    // ------------------------------------------------------------ helpers

    fn end_session(&self, err: Option<UiError>) {
        *self.session.lock().unwrap() = None;
        self.busy.store(false, Ordering::SeqCst);
        self.update(|s| {
            s.idle();
            if err.is_some() {
                s.error = err;
            }
        });
    }

    fn sample_stats(&self, conn: &Conn, last: &mut Instant) {
        if last.elapsed() < Duration::from_millis(500) {
            return;
        }
        *last = Instant::now();
        let st = conn.stats();
        self.update(|s| {
            s.rtt_ms = st.rtt_ms;
            if st.rtt_ms > 0.0 {
                s.rtt_history.push(st.rtt_ms);
                if s.rtt_history.len() > HISTORY {
                    let n = s.rtt_history.len() - HISTORY;
                    s.rtt_history.drain(..n);
                }
            }
            s.rx_bytes = st.rx_bytes;
            s.tx_bytes = st.tx_bytes;
        });
    }

    fn stream_geometry(&self) -> (u32, u32, u32) {
        let settings = self.cfg.lock().unwrap().settings.clone();
        let (dw, dh, dhz) = self.platform.display_mode();
        let (w, h) = match settings.resolution.as_str() {
            "720" => (1280, 720),
            "1080" => (1920, 1080),
            "1440" => (2560, 1440),
            "2160" => (3840, 2160),
            _ => (dw.max(640), dh.max(480)),
        };
        let fps = if settings.fps == 0 { dhz.clamp(30, 240) } else { settings.fps };
        (w, h, fps)
    }

    // ------------------------------------------------------------ client flow

    fn client_flow(self: &Arc<Self>, code: &str, cancel: &Arc<AtomicBool>) -> Result<(), Option<UiError>> {
        let signal = self.signal.clone().ok_or_else(|| Some(ui_err("offline", "no transport")))?;
        let progress = |stage: ClientStage| {
            let name = match stage {
                ClientStage::Preparing => "preparing",
                ClientStage::Contacting => "contacting",
                ClientStage::WaitingApproval => "waiting",
                ClientStage::Punching => "punching",
            };
            self.update(|s| s.set_stage(name));
        };
        let est = session::connect(&self.identity, code, signal, &self.gather, cancel, &progress)
            .map_err(|e| map_core_err(&e))?;
        let (host_ip, peer_dev, lan) = (est.host_ip(), est.peer_dev.clone(), est.is_lan_path());
        let peer_name = est.peer_name.clone();
        self.update(|s| {
            s.peer = Some(peer_name.clone());
            s.path = if lan { "lan" } else { "direct" }.into();
        });

        let tun = self.platform.open_tun(est.local_ip()).map_err(|e| Some(ui_err("tun", e)))?;
        let (conn, events) = est.into_conn(tun);
        let stop = Arc::new(AtomicBool::new(false));
        *self.session.lock().unwrap() = Some(SessionCtl { stop: stop.clone() });
        let result = self.client_session(&conn, &events, &stop, cancel, host_ip, &peer_dev);
        let reason = match &result {
            Ok(()) => "stream ended",
            Err(Some(e)) if e.code == "lost" || e.code == "peer_closed" => "",
            Err(_) => "error",
        };
        if !reason.is_empty() {
            conn.close(reason);
        }
        result
    }

    fn client_session(
        &self,
        conn: &Conn,
        events: &Receiver<ConnEvent>,
        stop: &AtomicBool,
        cancel: &AtomicBool,
        host_ip: Ipv4Addr,
        peer_dev: &str,
    ) -> Result<(), Option<UiError>> {
        let stopped = || stop.load(Ordering::Relaxed) || cancel.load(Ordering::Relaxed);
        let closed_err = |reason: &str| {
            if reason.starts_with("peer") { ui_err("peer_closed", reason) } else { ui_err("lost", reason) }
        };
        let mut last_stats = Instant::now() - Duration::from_secs(1);

        // 1. Hello: learn whether the host can stream.
        let hello = Ctrl::Hello {
            name: self.identity.name.clone(),
            app_ver: APP_VERSION.into(),
            host_uuid: String::new(),
            host_ready: false,
        };
        conn.send_ctrl(&hello);
        let t0 = Instant::now();
        let mut last_hello = Instant::now();
        let host_ready = loop {
            if stopped() {
                return Err(None);
            }
            if t0.elapsed() > Duration::from_secs(8) {
                return Err(Some(ui_err("lost", "no hello from host")));
            }
            if last_hello.elapsed() > Duration::from_millis(800) {
                conn.send_ctrl(&hello);
                last_hello = Instant::now();
            }
            match events.recv_timeout(Duration::from_millis(100)) {
                Ok(ConnEvent::Ctrl(Ctrl::Hello { host_ready, app_ver, .. })) => {
                    log::info!("host hello: ready={host_ready} version={app_ver}");
                    break host_ready;
                }
                Ok(ConnEvent::Closed(r)) => return Err(Some(closed_err(&r))),
                Ok(_) => {}
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Err(Some(ui_err("lost", "events closed"))),
            }
        };
        if !host_ready {
            return Err(Some(ui_err("host_not_ready", "")));
        }

        // 2. Bitrate: measure the path if the user picked "auto".
        let (w, h, fps) = self.stream_geometry();
        let settings = self.cfg.lock().unwrap().settings.clone();
        let mut measured = None;
        if settings.quality == "auto" {
            self.update(|s| s.set_stage("testing"));
            match conn.speed_test(SPEED_STEPS, 250) {
                Some(r) => {
                    log::info!("speed probe: {:?} -> best {} Mbit/s", r.steps, r.best_mbps);
                    measured = Some(r.best_mbps);
                }
                None => log::warn!("speed probe got no answer; using the default bitrate"),
            }
            if stopped() {
                return Err(None);
            }
        }
        let bitrate = pick_bitrate(&settings.quality, w, h, fps, measured);
        self.sample_stats(conn, &mut last_stats);

        // 3. Pairing (first time with this host).
        let already = self.cfg.lock().unwrap().paired_hosts.iter().any(|d| d == peer_dev);
        let mut assumed_paired = already;
        if !already {
            self.update(|s| s.set_stage("pairing"));
            let pin = format!("{:04}", rand::thread_rng().gen_range(0..10_000));
            conn.send_ctrl(&Ctrl::Pair { pin: pin.clone(), name: self.identity.name.clone() });
            let (ptx, prx) = channel();
            let platform = self.platform.clone();
            let p2 = pin.clone();
            thread::spawn(move || {
                let started = Instant::now();
                let r = platform.client_pair(host_ip, &p2);
                let _ = ptx.send((r, started.elapsed()));
            });
            let mut host_ok: Option<(bool, String)> = None;
            let mut moon: Option<(Result<(), String>, Duration)> = None;
            let t0 = Instant::now();
            let mut moon_done_at = None::<Instant>;
            loop {
                if stopped() {
                    return Err(None);
                }
                if let Ok(r) = prx.try_recv() {
                    moon = Some(r);
                    moon_done_at = Some(Instant::now());
                }
                match events.recv_timeout(Duration::from_millis(100)) {
                    Ok(ConnEvent::Ctrl(Ctrl::PairResult { ok, msg })) => host_ok = Some((ok, msg)),
                    Ok(ConnEvent::Closed(r)) => return Err(Some(closed_err(&r))),
                    _ => {}
                }
                self.sample_stats(conn, &mut last_stats);
                let host_waited = moon_done_at.map_or(false, |t| t.elapsed() > Duration::from_secs(3));
                if (moon.is_some() && host_ok.is_some()) || host_waited || t0.elapsed() > Duration::from_secs(150) {
                    break;
                }
            }
            match (&host_ok, &moon) {
                (Some((true, _)), Some((Ok(()), _))) => {
                    log::info!("paired with host {peer_dev}");
                    let mut cfg = self.cfg.lock().unwrap();
                    if !cfg.paired_hosts.iter().any(|d| d == peer_dev) {
                        cfg.paired_hosts.push(peer_dev.to_string());
                        let _ = cfg.save(&self.cfg_path);
                    }
                    assumed_paired = true;
                }
                // Moonlight finished at once without the host ever seeing a request: most likely
                // it was already paired (e.g. our record was lost). Try streaming anyway.
                (_, Some((Ok(()), took))) if *took < Duration::from_secs(12) && host_ok.as_ref().map_or(true, |h| !h.0) => {
                    log::warn!("pairing inconclusive (host={host_ok:?}, moonlight took {took:?}); trying to stream");
                }
                _ => {
                    let detail = format!("host={host_ok:?} moonlight={:?}", moon.as_ref().map(|m| &m.0));
                    return Err(Some(ui_err("pair", detail)));
                }
            }
        }

        // 4. Stream.
        self.update(|s| s.set_stage("starting"));
        let opts = StreamOpts {
            width: w,
            height: h,
            fps,
            bitrate_kbps: bitrate,
            vsync: settings.vsync,
            overlay: settings.overlay,
            packet_size: STREAM_PACKET_SIZE,
        };
        log::info!("starting stream {opts:?}");
        let mut proc: Box<dyn StreamProcess> =
            self.platform.client_stream(host_ip, &opts).map_err(|e| Some(ui_err("stream", e)))?;
        let started = Instant::now();
        self.update(|s| {
            s.phase = "live".into();
            s.set_stage("streaming");
            s.stream = Some(StreamInfo { width: w, height: h, fps, bitrate_kbps: bitrate });
        });
        conn.send_ctrl(&Ctrl::Stream { active: true, info: format!("{w}x{h}@{fps} {bitrate}kbps") });

        loop {
            if stopped() {
                proc.kill();
                return Ok(());
            }
            if let Some(code) = proc.try_wait() {
                log::info!("stream window closed (exit {code}) after {:?}", started.elapsed());
                if started.elapsed() < Duration::from_secs(self.platform.min_stream_secs()) {
                    // Didn't really start: forget the pairing so the next attempt re-pairs.
                    if assumed_paired {
                        let mut cfg = self.cfg.lock().unwrap();
                        cfg.paired_hosts.retain(|d| d != peer_dev);
                        let _ = cfg.save(&self.cfg_path);
                    }
                    return Err(Some(ui_err("stream", format!("exit code {code}"))));
                }
                conn.send_ctrl(&Ctrl::Stream { active: false, info: String::new() });
                return Ok(());
            }
            match events.recv_timeout(Duration::from_millis(150)) {
                Ok(ConnEvent::Closed(r)) => {
                    proc.kill();
                    return Err(Some(closed_err(&r)));
                }
                Ok(_) | Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    proc.kill();
                    return Err(Some(ui_err("lost", "")));
                }
            }
            self.sample_stats(conn, &mut last_stats);
        }
    }

    // ------------------------------------------------------------ host flow

    fn host_established(self: &Arc<Self>, est: Established) {
        let peer_name = est.peer_name.clone();
        let client_ip = est.client_ip();
        let lan = est.is_lan_path();
        let tun = match self.platform.open_tun(est.local_ip()) {
            Ok(t) => t,
            Err(e) => {
                log::error!("cannot open adapter for host session: {e}");
                self.end_session(Some(ui_err("tun", e)));
                return;
            }
        };
        let (conn, events) = est.into_conn(tun);
        let stop = Arc::new(AtomicBool::new(false));
        *self.session.lock().unwrap() = Some(SessionCtl { stop: stop.clone() });
        self.update(|s| {
            s.idle();
            s.error = None;
            s.phase = "live".into();
            s.role = Some("host".into());
            s.peer = Some(peer_name.clone());
            s.path = if lan { "lan" } else { "direct" }.into();
            s.set_stage("connected");
        });
        let me = self.clone();
        thread::Builder::new()
            .name("ll-host-session".into())
            .spawn(move || {
                let err = me.host_session(&conn, &events, &stop, client_ip);
                me.end_session(err);
            })
            .unwrap();
    }

    fn host_hello(&self) -> Ctrl {
        let status = self.platform.host_status();
        if !status.uuid.is_empty() {
            *self.host_uuid.lock().unwrap() = status.uuid.clone();
        }
        self.update(|s| {
            s.host_ready = status.ready;
            s.host_detail = status.detail.clone();
        });
        Ctrl::Hello {
            name: self.identity.name.clone(),
            app_ver: APP_VERSION.into(),
            host_uuid: status.uuid,
            host_ready: status.ready,
        }
    }

    fn host_session(&self, conn: &Conn, events: &Receiver<ConnEvent>, stop: &AtomicBool, client_ip: Ipv4Addr) -> Option<UiError> {
        conn.send_ctrl(&self.host_hello());
        let mut last_stats = Instant::now() - Duration::from_secs(1);
        loop {
            if stop.load(Ordering::Relaxed) {
                conn.close("host ended the session");
                return None;
            }
            match events.recv_timeout(Duration::from_millis(150)) {
                Ok(ConnEvent::Ctrl(Ctrl::Hello { app_ver, .. })) => {
                    log::info!("client hello (version {app_ver})");
                    conn.send_ctrl(&self.host_hello());
                }
                Ok(ConnEvent::Ctrl(Ctrl::Pair { pin, name })) => {
                    log::info!("pairing request from '{name}'");
                    let (platform, conn2) = (self.platform.clone(), conn.clone());
                    thread::spawn(move || {
                        let r = platform.host_accept_pin(&pin, &name, client_ip);
                        if let Err(e) = &r {
                            log::warn!("host pairing failed: {e}");
                        }
                        conn2.send_ctrl(&Ctrl::PairResult { ok: r.is_ok(), msg: r.err().unwrap_or_default() });
                    });
                }
                Ok(ConnEvent::Ctrl(Ctrl::Stream { active, info })) => {
                    log::info!("client stream active={active} {info}");
                    self.update(|s| s.set_stage(if active { "streaming" } else { "connected" }));
                }
                Ok(ConnEvent::Ctrl(_)) => {}
                Ok(ConnEvent::Closed(r)) => {
                    return if r.starts_with("peer") || r.starts_with("local") { None } else { Some(ui_err("lost", r)) };
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Some(ui_err("lost", "")),
            }
            self.sample_stats(conn, &mut last_stats);
        }
    }
}

// ---------------------------------------------------------------- host handler

struct HostSide(Weak<Engine>);

impl HostHandler for HostSide {
    fn on_listening(&self, ok: bool, detail: &str) {
        if let Some(e) = self.0.upgrade() {
            e.update(|s| s.signal = if ok { "ok" } else { "error" }.into());
            if !ok {
                log::warn!("rendezvous: {detail}");
            }
        }
    }

    fn decide(&self, req: &IncomingRequest) -> Decision {
        let Some(e) = self.0.upgrade() else { return Decision::Decline("shutting down".into()) };
        if e.cfg.lock().unwrap().is_trusted(&req.dev, &req.static_pub) {
            log::info!("'{}' is a trusted device: accepting", req.name);
            return Decision::Accept;
        }
        let (tx, rx) = channel();
        *e.pending.lock().unwrap() = Some(Pending { reply: tx });
        e.update(|s| s.incoming = Some(UiIncoming { name: req.name.clone() }));
        let answer = rx.recv_timeout(Duration::from_secs(90));
        e.pending.lock().unwrap().take();
        e.update(|s| s.incoming = None);
        match answer {
            Ok((true, remember)) => {
                if remember {
                    let mut cfg = e.cfg.lock().unwrap();
                    cfg.trusted.retain(|t| t.dev != req.dev);
                    cfg.trusted.push(TrustedDevice { dev: req.dev.clone(), spk: b64(&req.static_pub), name: req.name.clone() });
                    let _ = cfg.save(&e.cfg_path);
                }
                log::info!("accepted '{}'", req.name);
                e.update(|s| {
                    s.error = None;
                    s.phase = "connecting".into();
                    s.role = Some("host".into());
                    s.peer = Some(req.name.clone());
                    s.set_stage("punching");
                });
                Decision::Accept
            }
            _ => {
                log::info!("declined '{}'", req.name);
                Decision::Decline("declined".into())
            }
        }
    }

    fn on_progress(&self, _req: &IncomingRequest, stage: &str) {
        log::debug!("host progress: {stage}");
    }

    fn on_established(&self, est: Established) {
        if let Some(e) = self.0.upgrade() {
            e.host_established(est);
        }
    }

    fn on_failed(&self, req: &IncomingRequest, err: Error) {
        if let Some(e) = self.0.upgrade() {
            log::warn!("incoming connection from '{}' failed: {err}", req.name);
            e.update(|s| {
                s.idle();
                s.error = map_core_err(&err);
            });
        }
    }
}

fn host_watch(engine: Weak<Engine>) {
    if let Some(e) = engine.upgrade() {
        if let Err(err) = e.platform.host_prepare() {
            log::error!("host setup failed: {err}");
            e.update(|s| s.host_detail = err);
        }
    } else {
        return;
    }
    loop {
        let Some(e) = engine.upgrade() else { return };
        let status = e.platform.host_status();
        let ready = status.ready;
        if !status.uuid.is_empty() {
            *e.host_uuid.lock().unwrap() = status.uuid.clone();
        }
        e.update(|s| {
            if s.host_ready != status.ready {
                log::info!("streaming host ready: {} {}", status.ready, status.detail);
            }
            s.host_ready = status.ready;
            s.host_detail = status.detail;
        });
        drop(e);
        thread::sleep(Duration::from_secs(if ready { 15 } else { 4 }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::FakePlatform;
    use llcore::signal::MemSignal;

    fn opts() -> GatherOpts {
        GatherOpts { stun_servers: vec![], upnp: false, preferred_port: 0, loopback: true }
    }

    fn engine(p: &Arc<FakePlatform>, sig: &Arc<MemSignal>) -> Arc<Engine> {
        let cfg = Config::load_or_create(&p.dir.join("config.json"));
        Engine::start_with(p.clone(), cfg, Some(sig.clone()), opts())
    }

    fn wait(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
        let t0 = Instant::now();
        while !f() {
            assert!(t0.elapsed() < Duration::from_secs(secs), "timed out waiting for {what}");
            thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn bitrate_choices() {
        assert_eq!(base_kbps(1920, 1080, 60), 20_000);
        assert!(base_kbps(3840, 2160, 60) >= 70_000);
        assert_eq!(pick_bitrate("auto", 1920, 1080, 60, Some(20)), 14_000);
        assert_eq!(pick_bitrate("auto", 1920, 1080, 60, Some(500)), 32_000);
        assert_eq!(pick_bitrate("auto", 1920, 1080, 60, Some(0)), 3_000);
        assert_eq!(pick_bitrate("saver", 1920, 1080, 60, None), 10_000);
        assert_eq!(pick_bitrate("max", 1920, 1080, 60, None), 40_000);
    }

    #[test]
    fn end_to_end_pair_stream_and_reconnect_trusted() {
        let sig = MemSignal::new();
        let hp = FakePlatform::new("HOST-PC");
        let cp = FakePlatform::new("CLIENT-PC");
        let host = engine(&hp, &sig);
        let client = engine(&cp, &sig);
        wait("host listening", 3, || host.ui_state().signal == "ok");
        wait("host ready", 3, || host.ui_state().host_ready);

        // bad input is reported without starting anything
        client.connect("123");
        assert_eq!(client.ui_state().error.unwrap().code, "invalid_code");
        client.connect(&client.ui_state().code);
        assert_eq!(client.ui_state().error.unwrap().code, "own_code");

        let host_code = host.ui_state().code;
        client.connect(&host_code);
        assert_eq!(client.ui_state().phase, "connecting");
        wait("incoming prompt", 5, || host.ui_state().incoming.is_some());
        assert_eq!(host.ui_state().incoming.unwrap().name, "CLIENT-PC");
        host.respond(true, true);

        wait("client streaming", 15, || client.ui_state().stage.as_deref() == Some("streaming"));
        let cs = client.ui_state();
        assert_eq!(cs.phase, "live");
        assert_eq!(cs.peer.as_deref(), Some("HOST-PC"));
        assert!(cs.done_stages.contains(&"pairing".to_string()), "{:?}", cs.done_stages);
        assert!(cs.done_stages.contains(&"testing".to_string()));
        let hs = host.ui_state();
        assert_eq!((hs.phase.as_str(), hs.role.as_deref()), ("live", Some("host")));
        // same PIN on both sides, stream started with display geometry from the fake (2560x1440@144)
        assert_eq!(*hp.pins.lock().unwrap(), *cp.pairs.lock().unwrap());
        let so = cp.streams.lock().unwrap()[0].clone();
        assert_eq!((so.width, so.height, so.fps, so.packet_size), (2560, 1440, 144, 1280));
        assert!(so.bitrate_kbps >= 3000);

        // the fake stream ends by itself after 1.5 s -> both sides back to idle, no errors
        wait("client idle", 10, || client.ui_state().phase == "idle");
        wait("host idle", 5, || host.ui_state().phase == "idle");
        assert_eq!(client.ui_state().error, None);
        assert_eq!(host.ui_state().error, None);

        // second connection: trusted (no prompt) and already paired (no pairing step)
        client.connect(&host_code);
        wait("client streaming again", 15, || client.ui_state().stage.as_deref() == Some("streaming"));
        assert!(!client.ui_state().done_stages.contains(&"pairing".to_string()));
        assert_eq!(hp.pins.lock().unwrap().len(), 1);

        // user disconnects mid-stream
        client.disconnect();
        wait("client idle after disconnect", 5, || client.ui_state().phase == "idle");
        wait("host idle after disconnect", 5, || host.ui_state().phase == "idle");
        assert_eq!(client.ui_state().error, None);
    }

    #[test]
    fn declined_and_host_not_ready() {
        let sig = MemSignal::new();
        let hp = FakePlatform::new("H2");
        let cp = FakePlatform::new("C2");
        let host = engine(&hp, &sig);
        let client = engine(&cp, &sig);
        wait("listening", 3, || host.ui_state().signal == "ok");
        client.connect(&host.ui_state().code);
        wait("prompt", 5, || host.ui_state().incoming.is_some());
        host.respond(false, false);
        wait("declined", 5, || client.ui_state().phase == "idle");
        assert_eq!(client.ui_state().error.unwrap().code, "declined");

        // a host without a running streaming module
        let hp3 = Arc::new(FakePlatform { host_ready: false, ..Arc::try_unwrap(FakePlatform::new("H3")).ok().unwrap() });
        let host3 = engine(&hp3, &sig);
        wait("listening 3", 3, || host3.ui_state().signal == "ok");
        client.connect(&host3.ui_state().code);
        wait("prompt 3", 5, || host3.ui_state().incoming.is_some());
        host3.respond(true, false);
        wait("not ready", 10, || client.ui_state().phase == "idle");
        assert_eq!(client.ui_state().error.unwrap().code, "host_not_ready");
    }
}
