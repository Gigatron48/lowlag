// Release builds are GUI apps without a console window.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use llengine::{Engine, Settings, UiState};
use std::sync::Arc;
use tauri::{Manager, RunEvent, State};

struct App(Arc<Engine>);

#[tauri::command]
fn get_state(app: State<App>) -> UiState {
    app.0.ui_state()
}

#[tauri::command]
fn connect(app: State<App>, code: String) -> UiState {
    app.0.connect(&code);
    app.0.ui_state()
}

#[tauri::command]
fn cancel(app: State<App>) -> UiState {
    app.0.cancel();
    app.0.ui_state()
}

#[tauri::command]
fn disconnect(app: State<App>) -> UiState {
    app.0.disconnect();
    app.0.ui_state()
}

#[tauri::command]
fn respond(app: State<App>, accept: bool, remember: bool) -> UiState {
    app.0.respond(accept, remember);
    app.0.ui_state()
}

#[tauri::command]
fn set_settings(app: State<App>, settings: Settings) -> UiState {
    app.0.set_settings(settings);
    app.0.ui_state()
}

#[tauri::command]
fn forget_devices(app: State<App>) -> UiState {
    app.0.forget_devices();
    app.0.ui_state()
}

#[tauri::command]
async fn save_report(app: State<'_, App>) -> Result<String, String> {
    let e = app.0.clone();
    tauri::async_runtime::spawn_blocking(move || e.save_report()).await.map_err(|e| e.to_string())?
}

/// Blocks for several seconds, so it runs off the main thread.
#[tauri::command]
async fn check_network(app: State<'_, App>) -> Result<Vec<llengine::netcheck::CheckItem>, String> {
    let e = app.0.clone();
    tauri::async_runtime::spawn_blocking(move || e.check_network()).await.map_err(|e| e.to_string())
}

fn platform() -> Arc<dyn llengine::Platform> {
    #[cfg(windows)]
    {
        Arc::new(llengine::win::WinPlatform::new())
    }
    #[cfg(not(windows))]
    {
        // Development on other OSes: UI only, with a fake streaming backend.
        llengine::platform::FakePlatform::new("DEV-PC")
    }
}

fn main() {
    let engine = Engine::start(platform());
    let on_exit = engine.clone();
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.unminimize();
                let _ = w.show();
                let _ = w.set_focus();
            }
        }))
        .manage(App(engine))
        .invoke_handler(tauri::generate_handler![
            get_state,
            connect,
            cancel,
            disconnect,
            respond,
            set_settings,
            forget_devices,
            save_report,
            check_network
        ])
        .build(tauri::generate_context!())
        .expect("failed to start LowLag")
        .run(move |_app, event| {
            if let RunEvent::Exit = event {
                on_exit.shutdown();
            }
        });
}
