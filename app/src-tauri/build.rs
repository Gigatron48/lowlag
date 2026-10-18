fn main() {
    // LowLag creates a virtual network adapter and manages the streaming service, which needs
    // administrator rights: ask for them once at start-up instead of failing later.
    let windows = tauri_build::WindowsAttributes::new().app_manifest(include_str!("app.manifest"));
    tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows))
        .expect("failed to run tauri build script");
}
