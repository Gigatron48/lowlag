//! Windows platform: Wintun virtual adapter, Sunshine (streaming host) and Moonlight (client).
//!
//! On non-Windows hosts this module can still be type-checked with `--features wincheck`
//! (wintun is replaced by a signature-compatible stub below).

use crate::platform::{HostStatus, Platform, StreamOpts, StreamProcess, ZapretStatus};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use llcore::tun::TunDevice;
use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(not(windows))]
trait CommandExt {
    fn creation_flags(&mut self, _flags: u32) -> &mut Self;
}
#[cfg(not(windows))]
impl CommandExt for Command {
    fn creation_flags(&mut self, _flags: u32) -> &mut Self {
        self
    }
}

const ADAPTER_NAME: &str = "LowLag";
const ADAPTER_GUID: u128 = 0x3d1d5a6c_8f2e_4b7a_9c41_6c6f776c6167;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const SUNSHINE_SERVICE: &str = "SunshineService";
const SUNSHINE_USER: &str = "lowlag";
const SUNSHINE_HTTP: &str = "http://127.0.0.1:47989";
const SUNSHINE_API: &str = "https://127.0.0.1:47990";

fn env_dir(var: &str, fallback: &str) -> PathBuf {
    std::env::var_os(var).map(PathBuf::from).unwrap_or_else(|| PathBuf::from(fallback))
}

/// Run a console tool without flashing a window. Returns (exit code, combined output).
fn run_hidden(program: &str, args: &[&str], cwd: Option<&Path>) -> Result<(i32, String), String> {
    let mut c = Command::new(program);
    c.args(args).stdin(Stdio::null()).creation_flags(CREATE_NO_WINDOW);
    if let Some(d) = cwd {
        c.current_dir(d);
    }
    let out = c.output().map_err(|e| format!("{program}: {e}"))?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    let code = out.status.code().unwrap_or(-1);
    log::debug!("{program} {:?} -> {code}: {}", args, text.trim());
    Ok((code, text))
}

#[derive(Clone)]
struct Creds {
    user: String,
    pass: String,
}

pub struct WinPlatform {
    exe_dir: PathBuf,
    data_dir: PathBuf,
    wintun: Option<wintun::Wintun>,
    wintun_err: String,
    adapter: Mutex<Option<Arc<wintun::Adapter>>>,
    creds: Mutex<Option<Creds>>,
    last_kick: Mutex<Option<Instant>>,
    http: ureq::Agent,
}

impl WinPlatform {
    pub fn new() -> Self {
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf))
            .unwrap_or_default();
        let data_dir = env_dir("ProgramData", r"C:\ProgramData").join("LowLag");
        // 1 ms timer resolution: precise pacing for keepalives and the bandwidth probe.
        #[cfg(windows)]
        unsafe {
            windows_sys::Win32::Media::timeBeginPeriod(1);
        }
        let (wintun, wintun_err) = match unsafe { wintun::load_from_path(exe_dir.join("wintun.dll")) } {
            Ok(w) => (Some(w), String::new()),
            Err(e) => (None, e.to_string()),
        };
        let tls = native_tls::TlsConnector::builder()
            // Only ever used for Sunshine on 127.0.0.1, which has a self-signed certificate.
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()
            .expect("TLS connector");
        let http = ureq::AgentBuilder::new()
            .tls_connector(Arc::new(tls))
            .timeout_connect(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .build();
        let p = WinPlatform {
            exe_dir,
            data_dir,
            wintun,
            wintun_err,
            adapter: Mutex::new(None),
            creds: Mutex::new(None),
            last_kick: Mutex::new(None),
            http,
        };
        *p.creds.lock().unwrap() = p.load_creds();
        p
    }

    fn sunshine_dir(&self) -> PathBuf {
        env_dir("ProgramFiles", r"C:\Program Files").join("Sunshine")
    }
    fn sunshine_exe(&self) -> PathBuf {
        self.sunshine_dir().join("sunshine.exe")
    }
    fn moonlight_dir(&self) -> PathBuf {
        self.exe_dir.join("moonlight")
    }
    fn creds_path(&self) -> PathBuf {
        self.data_dir.join("sunshine.json")
    }

    fn load_creds(&self) -> Option<Creds> {
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(self.creds_path()).ok()?).ok()?;
        Some(Creds { user: v.get("user")?.as_str()?.to_string(), pass: v.get("pass")?.as_str()?.to_string() })
    }

    fn save_creds(&self, c: &Creds) -> io::Result<()> {
        std::fs::create_dir_all(&self.data_dir)?;
        std::fs::write(self.creds_path(), serde_json::json!({"user": c.user, "pass": c.pass}).to_string())
    }

    fn auth_header(&self) -> Option<String> {
        let c = self.creds.lock().unwrap().clone()?;
        Some(format!("Basic {}", B64.encode(format!("{}:{}", c.user, c.pass))))
    }

    /// Make sure our recommended keys are present in sunshine.conf (never overrides user choices).
    /// Returns true if the file was changed (Sunshine must be restarted to pick it up).
    fn ensure_sunshine_conf(&self) -> bool {
        let path = self.sunshine_dir().join("config").join("sunshine.conf");
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let has = |key: &str| {
            text.lines().any(|l| l.split('=').next().map(|k| k.trim() == key).unwrap_or(false))
        };
        let mut add = String::new();
        // The web panel only from this PC: tunnel peers are "LAN" to Sunshine.
        if !has("origin_web_ui_allowed") {
            add.push_str("origin_web_ui_allowed = pc\n");
        }
        // Intel QuickSync defaults to "medium"; the fastest preset cuts encode latency.
        if !has("qsv_preset") {
            add.push_str("qsv_preset = veryfast\n");
        }
        // Without a choice Sunshine pops up "Choose a Gamepad Driver" on every start. ViGEmBus is
        // the free option (Xbox 360 / DualShock 4 emulation); the paid Virtual HID Broker is not
        // something our users should be asked about.
        if !has("gamepad_driver") {
            add.push_str("gamepad_driver = vigembus\n");
        }
        if add.is_empty() {
            return false;
        }
        let mut new = text.clone();
        if !new.is_empty() && !new.ends_with('\n') {
            new.push('\n');
        }
        new.push_str(&add);
        if let Some(d) = path.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        match std::fs::write(&path, new) {
            Ok(()) => {
                log::info!("sunshine.conf: added {}", add.trim().replace('\n', ", "));
                true
            }
            Err(e) => {
                log::warn!("cannot update sunshine.conf: {e}");
                false
            }
        }
    }

    fn kick_service(&self) {
        let mut last = self.last_kick.lock().unwrap();
        if last.map_or(false, |t| t.elapsed() < Duration::from_secs(30)) {
            return;
        }
        *last = Some(Instant::now());
        let _ = run_hidden("sc", &["start", SUNSHINE_SERVICE], None);
    }

    fn adapter(&self) -> Result<Arc<wintun::Adapter>, String> {
        let w = self.wintun.as_ref().ok_or_else(|| format!("wintun.dll: {}", self.wintun_err))?;
        let mut g = self.adapter.lock().unwrap();
        if let Some(a) = g.as_ref() {
            return Ok(a.clone());
        }
        let a = match wintun::Adapter::open(w, ADAPTER_NAME) {
            Ok(a) => a,
            Err(_) => wintun::Adapter::create(w, ADAPTER_NAME, "LowLag", Some(ADAPTER_GUID))
                .map_err(|e| format!("create adapter: {e}"))?,
        };
        *g = Some(a.clone());
        Ok(a)
    }

    fn pending_pairings(&self, auth: &str) -> Result<Option<Vec<(String, String)>>, String> {
        match self.http.get(&format!("{SUNSHINE_API}/api/pin")).set("Authorization", auth).call() {
            Ok(r) => {
                let v: serde_json::Value = r.into_json().map_err(|e| e.to_string())?;
                let list = v
                    .get("pairings")
                    .and_then(|p| p.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|p| {
                                Some((p.get("id")?.as_str()?.to_string(), p.get("address")?.as_str().unwrap_or("").to_string()))
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                Ok(Some(list))
            }
            // Older Sunshine: no listing endpoint, PIN is posted without a pairing id.
            Err(ureq::Error::Status(404 | 405 | 400, _)) => Ok(None),
            Err(ureq::Error::Status(401, _)) => Err("Sunshine rejected our credentials".into()),
            Err(e) => Err(e.to_string()),
        }
    }

    fn post_pin(&self, auth: &str, body: serde_json::Value) -> Result<bool, String> {
        match self
            .http
            .post(&format!("{SUNSHINE_API}/api/pin"))
            .set("Authorization", auth)
            .send_json(body)
        {
            Ok(r) => {
                let v: serde_json::Value = r.into_json().map_err(|e| e.to_string())?;
                Ok(v.get("status").and_then(|s| s.as_bool().or_else(|| s.as_str().map(|x| x == "true"))).unwrap_or(false))
            }
            Err(ureq::Error::Status(code, r)) => Err(format!("{code}: {}", r.into_string().unwrap_or_default())),
            Err(e) => Err(e.to_string()),
        }
    }
}

impl Default for WinPlatform {
    fn default() -> Self {
        Self::new()
    }
}

// ------------------------------------------------------------------ tunnel device

struct WinTun {
    session: Arc<wintun::Session>,
}

impl TunDevice for WinTun {
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        match self.session.receive_blocking() {
            Ok(p) => {
                let b = p.bytes();
                let n = b.len().min(buf.len());
                buf[..n].copy_from_slice(&b[..n]);
                Ok(n)
            }
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e.to_string())),
        }
    }

    fn send(&self, pkt: &[u8]) -> io::Result<()> {
        let mut p = self
            .session
            .allocate_send_packet(pkt.len() as u16)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        p.bytes_mut().copy_from_slice(pkt);
        self.session.send_packet(p);
        Ok(())
    }

    fn shutdown(&self) {
        let _ = self.session.shutdown();
    }
}

// ------------------------------------------------------------------ Moonlight process

struct MoonlightProc {
    child: Child,
}

impl StreamProcess for MoonlightProc {
    fn try_wait(&mut self) -> Option<i32> {
        match self.child.try_wait() {
            Ok(Some(s)) => Some(s.code().unwrap_or(-1)),
            Ok(None) => None,
            Err(_) => Some(-1),
        }
    }
    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ------------------------------------------------------------------ Platform

impl Platform for WinPlatform {
    fn computer_name(&self) -> String {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "PC".into())
    }

    fn data_dir(&self) -> PathBuf {
        self.data_dir.clone()
    }

    fn downloads_dir(&self) -> Option<PathBuf> {
        let d = PathBuf::from(std::env::var_os("USERPROFILE")?).join("Downloads");
        d.is_dir().then_some(d)
    }

    fn open_tun(&self, local_ip: Ipv4Addr) -> Result<Arc<dyn TunDevice>, String> {
        let adapter = self.adapter()?;
        let idx = adapter.get_adapter_index().map_err(|e| e.to_string())?.to_string();
        let addr = format!("address={local_ip}");
        let (code, out) = run_hidden(
            "netsh",
            &["interface", "ipv4", "set", "address", &format!("name={idx}"), "source=static", &addr, "mask=255.255.255.0", "gateway=none"],
            None,
        )?;
        if code != 0 {
            log::warn!("netsh set address: {}", out.trim());
        }
        let mtu = format!("mtu={}", llcore::TUN_MTU);
        let _ = run_hidden("netsh", &["interface", "ipv4", "set", "subinterface", &idx, &mtu, "store=active"], None);

        // A previous session may still be shutting down: retry briefly.
        let t0 = Instant::now();
        let session = loop {
            match adapter.start_session(wintun::MAX_RING_CAPACITY) {
                Ok(s) => break Arc::new(s),
                Err(e) if t0.elapsed() < Duration::from_secs(3) => {
                    log::debug!("start_session: {e}; retrying");
                    std::thread::sleep(Duration::from_millis(200));
                }
                Err(e) => return Err(format!("start session: {e}")),
            }
        };
        // Wait until Windows has actually applied the address (duplicate address detection).
        let want = std::net::IpAddr::V4(local_ip);
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(6) {
            if adapter.get_addresses().map(|a| a.contains(&want)).unwrap_or(false) {
                break;
            }
            std::thread::sleep(Duration::from_millis(150));
        }
        std::thread::sleep(Duration::from_millis(400));
        log::info!("adapter {ADAPTER_NAME} (#{idx}) up as {local_ip}");
        Ok(Arc::new(WinTun { session }))
    }

    fn host_prepare(&self) -> Result<(), String> {
        let exe = self.sunshine_exe();
        if !exe.exists() {
            let msi = self.exe_dir.join("sunshine.msi");
            if msi.exists() {
                log::info!("installing Sunshine from {}", msi.display());
                let m = msi.to_string_lossy().to_string();
                let r = run_hidden("msiexec", &["/i", &m, "/qn", "/norestart"], None);
                log::info!("msiexec: {:?}", r.as_ref().map(|r| r.0));
            }
            if !exe.exists() {
                return Err("Sunshine is not installed".into());
            }
        }
        if self.creds.lock().unwrap().is_none() {
            use rand::Rng;
            const ALPHA: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
            let mut rng = rand::thread_rng();
            let pass: String = (0..24).map(|_| ALPHA[rng.gen_range(0..ALPHA.len())] as char).collect();
            let creds = Creds { user: SUNSHINE_USER.into(), pass };
            let _ = self.ensure_sunshine_conf();
            let _ = run_hidden("sc", &["stop", SUNSHINE_SERVICE], None);
            std::thread::sleep(Duration::from_secs(2));
            let (code, out) =
                run_hidden(&exe.to_string_lossy(), &["--creds", &creds.user, &creds.pass], Some(&self.sunshine_dir()))?;
            if code != 0 {
                log::warn!("sunshine --creds exited {code}: {}", out.trim());
            }
            self.save_creds(&creds).map_err(|e| format!("save credentials: {e}"))?;
            *self.creds.lock().unwrap() = Some(creds);
            log::info!("Sunshine credentials configured");
        }
        if self.ensure_sunshine_conf() {
            // existing install: apply the new settings
            let _ = run_hidden("sc", &["stop", SUNSHINE_SERVICE], None);
            std::thread::sleep(Duration::from_secs(2));
        }
        let _ = run_hidden("sc", &["config", SUNSHINE_SERVICE, "start=", "auto"], None);
        let _ = run_hidden("sc", &["start", SUNSHINE_SERVICE], None);
        *self.last_kick.lock().unwrap() = Some(Instant::now());
        Ok(())
    }

    fn host_status(&self) -> HostStatus {
        if !self.sunshine_exe().exists() {
            return HostStatus { ready: false, uuid: String::new(), detail: "not_installed".into() };
        }
        match self.http.get(&format!("{SUNSHINE_HTTP}/serverinfo")).call() {
            Ok(r) => {
                let body = r.into_string().unwrap_or_default();
                let uuid = body
                    .split("<uniqueid>")
                    .nth(1)
                    .and_then(|s| s.split("</uniqueid>").next())
                    .unwrap_or("")
                    .to_string();
                HostStatus { ready: true, uuid, detail: String::new() }
            }
            Err(ureq::Error::Status(code, _)) => {
                // It answers, just not happily (e.g. 401/503 while starting): treat as up.
                HostStatus { ready: code < 500, uuid: String::new(), detail: format!("http {code}") }
            }
            Err(e) => {
                self.kick_service();
                HostStatus { ready: false, uuid: String::new(), detail: format!("not_running: {e}") }
            }
        }
    }

    fn host_accept_pin(&self, pin: &str, client_name: &str, client_ip: Ipv4Addr) -> Result<(), String> {
        let auth = self.auth_header().ok_or("Sunshine credentials are not set up")?;
        let name: String = client_name.chars().take(60).collect();
        let name = if name.is_empty() { "LowLag".to_string() } else { name };
        let ip = client_ip.to_string();
        let t0 = Instant::now();
        let mut last_err = String::from("no pairing request arrived");
        while t0.elapsed() < Duration::from_secs(45) {
            match self.pending_pairings(&auth) {
                Ok(Some(list)) => {
                    let pick = list
                        .iter()
                        .find(|(_, addr)| addr.trim_start_matches("::ffff:") == ip)
                        .or_else(|| if list.len() == 1 { list.first() } else { None });
                    if let Some((id, _)) = pick {
                        match self.post_pin(&auth, serde_json::json!({"pairing_id": id, "pin": pin, "name": name})) {
                            Ok(true) => {
                                log::info!("Sunshine accepted PIN for '{name}'");
                                return Ok(());
                            }
                            Ok(false) => last_err = "Sunshine refused the PIN".into(),
                            Err(e) => last_err = e,
                        }
                    }
                }
                Ok(None) => match self.post_pin(&auth, serde_json::json!({"pin": pin, "name": name})) {
                    Ok(true) => {
                        log::info!("Sunshine (legacy API) accepted PIN for '{name}'");
                        return Ok(());
                    }
                    Ok(false) => last_err = "no pending pairing yet".into(),
                    Err(e) => last_err = e,
                },
                Err(e) => {
                    if e.contains("credentials") {
                        return Err(e);
                    }
                    last_err = e;
                }
            }
            std::thread::sleep(Duration::from_millis(700));
        }
        Err(last_err)
    }

    fn display_mode(&self) -> (u32, u32, u32) {
        #[cfg(windows)]
        unsafe {
            use windows_sys::Win32::Graphics::Gdi::{EnumDisplaySettingsW, DEVMODEW, ENUM_CURRENT_SETTINGS};
            let mut dm: DEVMODEW = std::mem::zeroed();
            dm.dmSize = std::mem::size_of::<DEVMODEW>() as u16;
            if EnumDisplaySettingsW(std::ptr::null(), ENUM_CURRENT_SETTINGS, &mut dm) != 0 && dm.dmPelsWidth > 0 {
                let hz = if dm.dmDisplayFrequency > 1 { dm.dmDisplayFrequency } else { 60 };
                return (dm.dmPelsWidth, dm.dmPelsHeight, hz);
            }
        }
        (1920, 1080, 60)
    }

    fn client_pair(&self, host_ip: Ipv4Addr, pin: &str) -> Result<(), String> {
        let dir = self.moonlight_dir();
        ensure_portable(&dir);
        let mut child = Command::new(dir.join("Moonlight.exe"))
            .current_dir(&dir)
            .args(["pair", &host_ip.to_string(), "--pin", pin])
            .spawn()
            .map_err(|e| format!("Moonlight: {e}"))?;
        let t0 = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(s)) => {
                    log::info!("Moonlight pair exited with {s}");
                    return Ok(());
                }
                Ok(None) if t0.elapsed() > Duration::from_secs(150) => {
                    let _ = child.kill();
                    return Err("Moonlight pairing timed out".into());
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(200)),
                Err(e) => return Err(e.to_string()),
            }
        }
    }

    fn client_stream(&self, host_ip: Ipv4Addr, o: &StreamOpts) -> Result<Box<dyn StreamProcess>, String> {
        let dir = self.moonlight_dir();
        ensure_portable(&dir);
        let args = moonlight_stream_args(host_ip, o);
        log::info!("Moonlight {}", args.join(" "));
        let child = Command::new(dir.join("Moonlight.exe"))
            .current_dir(&dir)
            .args(&args)
            .spawn()
            .map_err(|e| format!("Moonlight: {e}"))?;
        Ok(Box::new(MoonlightProc { child }))
    }

    fn diagnostics(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("exe dir {}\n", self.exe_dir.display()));
        s.push_str(&format!("wintun loaded {} {}\n", self.wintun.is_some(), self.wintun_err));
        s.push_str(&format!("sunshine installed {} creds {}\n", self.sunshine_exe().exists(), self.creds.lock().unwrap().is_some()));
        s.push_str(&format!("moonlight present {}\n", self.moonlight_dir().join("Moonlight.exe").exists()));
        s.push_str(&format!("local ipv4 {:?}\n", llcore::netinfo::local_ipv4s()));
        s.push_str(&format!("global ipv6 {:?}\n", llcore::netinfo::global_ipv6s()));
        let exe = self.exe_dir.join("lowlag.exe");
        if let Ok((_, out)) = run_hidden("netsh", &["advfirewall", "firewall", "show", "rule", "name=LowLag", "verbose"], None) {
            let has_rule = out.to_lowercase().contains(&exe.display().to_string().to_lowercase());
            s.push_str(&format!("firewall rule for {}: {}\n", exe.display(), if has_rule { "present" } else { "MISSING" }));
        }
        if let Ok((_, out)) = run_hidden("netsh", &["advfirewall", "show", "currentprofile", "state"], None) {
            s.push_str(&format!("firewall profile: {}\n", out.split_whitespace().collect::<Vec<_>>().join(" ")));
        }
        if let Ok((_, out)) = run_hidden("sc", &["query", SUNSHINE_SERVICE], None) {
            s.push_str(&format!("service: {}\n", out.split_whitespace().collect::<Vec<_>>().join(" ")));
        }
        match self.zapret_status() {
            Some(z) => s.push_str(&format!("zapret: {}\n", z.describe())),
            None => s.push_str("zapret: not running\n"),
        }
        s
    }

    fn zapret_status(&self) -> Option<ZapretStatus> {
        let (_, out) = run_hidden(
            "powershell",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                // UTF-8 output: Zapret often lives in a folder with a Cyrillic name ("Загрузки").
                "[Console]::OutputEncoding = [Text.Encoding]::UTF8; (Get-Process winws -ErrorAction SilentlyContinue | Select-Object -First 1).Path",
            ],
            None,
        )
        .ok()?;
        let exe = PathBuf::from(out.trim());
        if out.trim().is_empty() || !exe.exists() {
            return None;
        }
        // Flowseal's bundle: <root>\bin\winws.exe, <root>\lists, <root>\utils
        let root = exe.parent()?.parent()?.to_path_buf();
        let ipset = match std::fs::read_to_string(root.join("lists").join("ipset-all.txt")) {
            Ok(t) if t.trim().is_empty() => "any",
            Ok(t) if t.contains("203.0.113.113/32") => "none",
            Ok(_) => "loaded",
            Err(_) => "unknown",
        };
        let game_filter = root.join("utils").join("game_filter.enabled").exists();
        Some(ZapretStatus {
            path: root.display().to_string(),
            ipset: ipset.into(),
            game_filter,
            risky: ipset == "any" || game_filter,
        })
    }
}

/// Moonlight keeps its settings (incl. pairing keys) next to itself only if `portable.dat` exists
/// in its working directory.
fn ensure_portable(dir: &Path) {
    let f = dir.join("portable.dat");
    if !f.exists() {
        let _ = std::fs::write(f, b"");
    }
}

pub fn moonlight_stream_args(host_ip: Ipv4Addr, o: &StreamOpts) -> Vec<String> {
    let mut a: Vec<String> = vec![
        "stream".into(),
        host_ip.to_string(),
        "Desktop".into(),
        "--resolution".into(),
        format!("{}x{}", o.width, o.height),
        "--fps".into(),
        o.fps.to_string(),
        "--bitrate".into(),
        o.bitrate_kbps.to_string(),
        "--packet-size".into(),
        o.packet_size.to_string(),
        "--display-mode".into(),
        "fullscreen".into(),
        "--video-codec".into(),
        "auto".into(),
        "--video-decoder".into(),
        "auto".into(),
        "--capture-system-keys".into(),
        "fullscreen".into(),
    ];
    let flag = |on: bool, name: &str| if on { format!("--{name}") } else { format!("--no-{name}") };
    a.push(flag(o.vsync, "vsync"));
    // Frame pacing smooths judder at the cost of latency: off.
    a.push(flag(false, "frame-pacing"));
    a.push(flag(o.overlay, "performance-overlay"));
    a.push(flag(true, "game-optimization"));
    a.push(flag(true, "quit-after"));
    a.push(flag(true, "keep-awake"));
    a.push(flag(true, "multi-controller"));
    a.push(flag(false, "audio-on-host"));
    a
}

// ------------------------------------------------------------------ wintun stub (type-check only)

#[cfg(not(windows))]
#[allow(dead_code)]
mod wintun {
    use std::net::IpAddr;
    use std::sync::Arc;
    pub type Wintun = Arc<()>;
    pub const MAX_RING_CAPACITY: u32 = 0x400_0000;
    #[derive(Debug)]
    pub struct Error;
    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("stub")
        }
    }
    pub unsafe fn load_from_path<P: AsRef<std::ffi::OsStr>>(_p: P) -> Result<Wintun, Error> {
        Err(Error)
    }
    pub struct Adapter;
    impl Adapter {
        pub fn create(_w: &Wintun, _n: &str, _t: &str, _g: Option<u128>) -> Result<Arc<Adapter>, Error> {
            Err(Error)
        }
        pub fn open(_w: &Wintun, _n: &str) -> Result<Arc<Adapter>, Error> {
            Err(Error)
        }
        pub fn start_session(self: &Arc<Self>, _c: u32) -> Result<Session, Error> {
            Err(Error)
        }
        pub fn get_adapter_index(&self) -> Result<u32, Error> {
            Err(Error)
        }
        pub fn get_addresses(&self) -> Result<Vec<IpAddr>, Error> {
            Err(Error)
        }
    }
    pub struct Session;
    pub struct Packet;
    impl Packet {
        pub fn bytes(&self) -> &[u8] {
            &[]
        }
        pub fn bytes_mut(&mut self) -> &mut [u8] {
            &mut []
        }
    }
    impl Session {
        pub fn receive_blocking(self: &Arc<Self>) -> Result<Packet, Error> {
            Err(Error)
        }
        pub fn allocate_send_packet(self: &Arc<Self>, _s: u16) -> Result<Packet, Error> {
            Err(Error)
        }
        pub fn send_packet(&self, _p: Packet) {}
        pub fn shutdown(&self) -> Result<(), Error> {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_args_shape() {
        let o = StreamOpts { width: 1920, height: 1080, fps: 120, bitrate_kbps: 30000, vsync: false, overlay: true, packet_size: 1280 };
        let a = moonlight_stream_args(Ipv4Addr::new(10, 213, 7, 1), &o).join(" ");
        assert!(a.starts_with("stream 10.213.7.1 Desktop --resolution 1920x1080 --fps 120 --bitrate 30000 --packet-size 1280"), "{a}");
        assert!(a.contains("--no-vsync") && a.contains("--performance-overlay") && a.contains("--no-frame-pacing"));
    }
}
