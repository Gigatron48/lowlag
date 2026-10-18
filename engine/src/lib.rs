//! LowLag session engine (platform-independent part + platform implementations).

pub mod config;
pub mod engine;
pub mod logger;
pub mod platform;

#[cfg(any(windows, feature = "wincheck"))]
pub mod win;

pub use config::Settings;
pub use engine::{Engine, UiState, APP_VERSION};
pub use platform::Platform;
