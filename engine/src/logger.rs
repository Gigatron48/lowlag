//! Minimal file logger (no extra dependencies). One file, rotated at start-up when it grows big.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

struct FileLogger {
    file: Mutex<Option<File>>,
}

static LOGGER: FileLogger = FileLogger { file: Mutex::new(None) };
static PATH: Mutex<Option<PathBuf>> = Mutex::new(None);

impl log::Log for FileLogger {
    fn enabled(&self, m: &log::Metadata) -> bool {
        m.level() <= log::Level::Info || m.target().starts_with("ll")
    }
    fn log(&self, r: &log::Record) {
        if !self.enabled(r.metadata()) {
            return;
        }
        let line = format!("{} {:<5} [{}] {}\n", timestamp(), r.level(), r.target(), r.args());
        if let Some(f) = self.file.lock().unwrap().as_mut() {
            let _ = f.write_all(line.as_bytes());
        }
        #[cfg(debug_assertions)]
        eprint!("{line}");
    }
    fn flush(&self) {
        if let Some(f) = self.file.lock().unwrap().as_mut() {
            let _ = f.flush();
        }
    }
}

/// UTC "YYYY-MM-DD HH:MM:SS.mmm" without pulling in a date crate.
pub fn timestamp() -> String {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs() as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // civil-from-days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}.{:03}",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60,
        d.subsec_millis()
    )
}

pub fn init(dir: &Path) {
    let _ = std::fs::create_dir_all(dir);
    let path = dir.join("lowlag.log");
    if std::fs::metadata(&path).map(|m| m.len() > 4 << 20).unwrap_or(false) {
        let _ = std::fs::rename(&path, dir.join("lowlag.old.log"));
    }
    let file = OpenOptions::new().create(true).append(true).open(&path).ok();
    *LOGGER.file.lock().unwrap() = file;
    *PATH.lock().unwrap() = Some(path);
    if log::set_logger(&LOGGER).is_ok() {
        log::set_max_level(log::LevelFilter::Debug);
    }
}

pub fn path() -> Option<PathBuf> {
    PATH.lock().unwrap().clone()
}

/// Last `max_bytes` of the log, for support reports.
pub fn tail(max_bytes: usize) -> String {
    let Some(p) = path() else { return String::new() };
    log::logger().flush();
    let Ok(data) = std::fs::read(p) else { return String::new() };
    let start = data.len().saturating_sub(max_bytes);
    String::from_utf8_lossy(&data[start..]).into_owned()
}

#[cfg(test)]
mod tests {
    #[test]
    fn timestamp_shape() {
        let t = super::timestamp();
        assert_eq!(t.len(), 23, "{t}");
        assert!(t.starts_with("20"));
    }
}
