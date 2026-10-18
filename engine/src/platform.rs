//! What the engine needs from the operating system, plus a fake for tests.

use llcore::tun::{MemTun, MemTunHandle, TunDevice};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default)]
pub struct HostStatus {
    /// The streaming host (Sunshine) answers on this machine.
    pub ready: bool,
    pub uuid: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StreamOpts {
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub bitrate_kbps: u32,
    pub vsync: bool,
    pub overlay: bool,
    pub packet_size: u32,
}

pub trait StreamProcess: Send {
    /// `Some(exit code)` once the stream window has closed.
    fn try_wait(&mut self) -> Option<i32>;
    fn kill(&mut self);
}

pub trait Platform: Send + Sync {
    fn computer_name(&self) -> String;
    fn data_dir(&self) -> PathBuf;
    fn downloads_dir(&self) -> Option<PathBuf>;

    /// Configure the virtual adapter with `local_ip`/24 and start a packet session on it.
    fn open_tun(&self, local_ip: Ipv4Addr) -> Result<Arc<dyn TunDevice>, String>;

    /// One-time host setup (start the streaming service, credentials). Called in the background.
    fn host_prepare(&self) -> Result<(), String>;
    fn host_status(&self) -> HostStatus;
    /// Accept a Moonlight pairing PIN for the client at `client_ip`. Blocks until done (≤ ~45 s).
    fn host_accept_pin(&self, pin: &str, client_name: &str, client_ip: Ipv4Addr) -> Result<(), String>;

    /// Primary display (width, height, refresh rate).
    fn display_mode(&self) -> (u32, u32, u32);
    /// Run the client's pairing step. Blocks until it finishes.
    fn client_pair(&self, host_ip: Ipv4Addr, pin: &str) -> Result<(), String>;
    fn client_stream(&self, host_ip: Ipv4Addr, opts: &StreamOpts) -> Result<Box<dyn StreamProcess>, String>;

    /// A stream window that closes sooner than this is treated as a failed start.
    fn min_stream_secs(&self) -> u64 {
        8
    }

    /// Extra lines for support reports.
    fn diagnostics(&self) -> String {
        String::new()
    }
}

// ------------------------------------------------------------------ fake

pub struct FakePlatform {
    pub name: String,
    pub dir: PathBuf,
    pub stream_ms: u64,
    pub host_ready: bool,
    pub tuns: Mutex<Vec<MemTunHandle>>,
    pub pins: Mutex<Vec<String>>,
    pub pairs: Mutex<Vec<String>>,
    pub streams: Mutex<Vec<StreamOpts>>,
}

impl FakePlatform {
    pub fn new(name: &str) -> Arc<Self> {
        Arc::new(Self {
            name: name.into(),
            dir: std::env::temp_dir().join(format!("lowlag-test-{}-{}", name, llcore::random_hex(4))),
            stream_ms: 1500,
            host_ready: true,
            tuns: Mutex::new(Vec::new()),
            pins: Mutex::new(Vec::new()),
            pairs: Mutex::new(Vec::new()),
            streams: Mutex::new(Vec::new()),
        })
    }
}

struct FakeStream {
    until: Instant,
    killed: bool,
}

impl StreamProcess for FakeStream {
    fn try_wait(&mut self) -> Option<i32> {
        (self.killed || Instant::now() >= self.until).then_some(0)
    }
    fn kill(&mut self) {
        self.killed = true;
    }
}

impl Platform for FakePlatform {
    fn computer_name(&self) -> String {
        self.name.clone()
    }
    fn data_dir(&self) -> PathBuf {
        self.dir.clone()
    }
    fn downloads_dir(&self) -> Option<PathBuf> {
        Some(self.dir.clone())
    }
    fn open_tun(&self, _ip: Ipv4Addr) -> Result<Arc<dyn TunDevice>, String> {
        let (tun, handle) = MemTun::new();
        self.tuns.lock().unwrap().push(handle);
        Ok(tun)
    }
    fn host_prepare(&self) -> Result<(), String> {
        Ok(())
    }
    fn host_status(&self) -> HostStatus {
        HostStatus { ready: self.host_ready, uuid: "FAKE-UUID".into(), detail: String::new() }
    }
    fn host_accept_pin(&self, pin: &str, _n: &str, _ip: Ipv4Addr) -> Result<(), String> {
        self.pins.lock().unwrap().push(pin.into());
        Ok(())
    }
    fn display_mode(&self) -> (u32, u32, u32) {
        (2560, 1440, 144)
    }
    fn client_pair(&self, _ip: Ipv4Addr, pin: &str) -> Result<(), String> {
        std::thread::sleep(Duration::from_millis(100));
        self.pairs.lock().unwrap().push(pin.into());
        Ok(())
    }
    fn min_stream_secs(&self) -> u64 {
        1
    }
    fn client_stream(&self, _ip: Ipv4Addr, opts: &StreamOpts) -> Result<Box<dyn StreamProcess>, String> {
        self.streams.lock().unwrap().push(opts.clone());
        Ok(Box::new(FakeStream { until: Instant::now() + Duration::from_millis(self.stream_ms), killed: false }))
    }
}
