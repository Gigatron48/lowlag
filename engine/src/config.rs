//! Persistent settings and identity (JSON in the data directory).

use llcore::crypto::{b64, unb64_32, KeyPair};
use llcore::session::Identity;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Settings {
    /// auto | max | balanced | saver
    pub quality: String,
    /// native | 720 | 1080 | 1440 | 2160
    pub resolution: String,
    /// 0 = same as monitor
    pub fps: u32,
    pub vsync: bool,
    pub overlay: bool,
    /// auto | ru | en
    pub lang: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            quality: "auto".into(),
            resolution: "native".into(),
            fps: 0,
            vsync: false,
            overlay: false,
            lang: "auto".into(),
        }
    }
}

impl Settings {
    pub fn sanitize(&mut self) {
        let d = Settings::default();
        if !["auto", "max", "balanced", "saver"].contains(&self.quality.as_str()) {
            self.quality = d.quality;
        }
        if !["native", "720", "1080", "1440", "2160"].contains(&self.resolution.as_str()) {
            self.resolution = d.resolution;
        }
        if self.fps != 0 {
            self.fps = self.fps.clamp(30, 240);
        }
        if !["auto", "ru", "en"].contains(&self.lang.as_str()) {
            self.lang = d.lang;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrustedDevice {
    pub dev: String,
    /// identity public key (base64url) – the device must prove it owns it during the handshake
    pub spk: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub dev: String,
    pub code: String,
    /// identity secret key (base64url)
    pub key: String,
    pub settings: Settings,
    pub trusted: Vec<TrustedDevice>,
    /// host device ids this machine's Moonlight is paired with
    pub paired_hosts: Vec<String>,
    /// Rendezvous servers used in parallel (ntfy https:// and mqtt:// URLs).
    pub signal_servers: Vec<String>,
    pub stun_servers: Vec<String>,
    pub preferred_port: u16,
    /// Bumped when defaults change in a way that should replace old saved values.
    /// (Missing in old files => 0, not the struct default.)
    #[serde(default = "zero")]
    pub config_version: u32,
}

fn zero() -> u32 {
    0
}

const CONFIG_VERSION: u32 = 2;

fn default_signal_servers() -> Vec<String> {
    llcore::signal::DEFAULT_SERVERS.iter().map(|s| s.to_string()).collect()
}

fn default_stun_servers() -> Vec<String> {
    llcore::stun::DEFAULT_SERVERS.iter().map(|s| s.to_string()).collect()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            dev: String::new(),
            code: String::new(),
            key: String::new(),
            settings: Settings::default(),
            trusted: Vec::new(),
            paired_hosts: Vec::new(),
            signal_servers: default_signal_servers(),
            stun_servers: default_stun_servers(),
            preferred_port: 47810,
            config_version: CONFIG_VERSION,
        }
    }
}

impl Config {
    /// Load, filling in (and saving) anything missing: first run generates the identity.
    pub fn load_or_create(path: &Path) -> Config {
        let mut cfg: Config = std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let mut dirty = false;
        if cfg.dev.len() != 32 {
            cfg.dev = llcore::random_hex(16);
            dirty = true;
        }
        if llcore::code::normalize(&cfg.code).is_none() {
            cfg.code = llcore::code::generate();
            dirty = true;
        }
        if unb64_32(&cfg.key).is_none() {
            cfg.key = b64(&KeyPair::generate().to_bytes());
            dirty = true;
        }
        if cfg.config_version < CONFIG_VERSION || cfg.signal_servers.is_empty() || cfg.stun_servers.is_empty() {
            // v1 used a single rendezvous server and a STUN server on UDP 443 (which DPI-bypass
            // tools such as Zapret treat as QUIC): move to the current defaults.
            cfg.signal_servers = default_signal_servers();
            cfg.stun_servers = default_stun_servers();
            cfg.config_version = CONFIG_VERSION;
            dirty = true;
        }
        cfg.settings.sanitize();
        if dirty {
            if let Err(e) = cfg.save(path) {
                log::error!("cannot save config {}: {e}", path.display());
            }
        }
        cfg
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, path)
    }

    pub fn identity(&self, name: &str) -> Identity {
        Identity {
            dev: self.dev.clone(),
            name: name.to_string(),
            code: self.code.clone(),
            key: KeyPair::from_bytes(unb64_32(&self.key).expect("key validated on load")),
        }
    }

    pub fn is_trusted(&self, dev: &str, spk: &[u8; 32]) -> bool {
        let spk = b64(spk);
        self.trusted.iter().any(|t| t.dev == dev && t.spk == spk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_reload() {
        let dir = std::env::temp_dir().join(format!("llcfg-{}", llcore::random_hex(4)));
        let p = dir.join("config.json");
        let a = Config::load_or_create(&p);
        assert_eq!(a.dev.len(), 32);
        let b = Config::load_or_create(&p);
        assert_eq!(a.code, b.code);
        assert_eq!(a.key, b.key);
        assert_eq!(a.identity("x").key.public(), b.identity("x").key.public());
        assert!(b.signal_servers.len() >= 2);
        // an old v1 file is migrated to the new server lists but keeps its identity
        std::fs::write(&p, format!(r#"{{"dev":"{}","code":"{}","key":"{}","signal_server":"https://ntfy.sh","stun_servers":["stun.nextcloud.com:443"]}}"#, a.dev, a.code, a.key)).unwrap();
        let c = Config::load_or_create(&p);
        assert_eq!(c.code, a.code);
        assert_eq!(c.config_version, CONFIG_VERSION);
        assert!(!c.stun_servers.iter().any(|s| s.contains("nextcloud")));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn sanitize_settings() {
        let mut s = Settings { quality: "ultra".into(), fps: 1000, lang: "de".into(), ..Default::default() };
        s.sanitize();
        assert_eq!((s.quality.as_str(), s.fps, s.lang.as_str()), ("auto", 240, "auto"));
    }
}
