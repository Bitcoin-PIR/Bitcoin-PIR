pub mod config;
pub mod health;
pub mod ipc;
pub mod process;

use ipc::DesktopState;
use process::ProcessManager;
use std::sync::Arc;
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, WindowEvent};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let config_dir = app.path().app_config_dir()?;
            let data_dir = app.path().app_data_dir()?.join("data");
            let config = config::ConfigStore::load(config_dir, data_dir)?;
            let process = Arc::new(ProcessManager::new(
                app.handle().clone(),
                &config.settings(),
            ));
            app.manage(DesktopState { config, process });
            setup_tray(app.handle())?;
            setup_close_to_tray(app.handle())?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            ipc::get_config,
            ipc::import_bundle,
            ipc::save_settings,
            ipc::save_raw_settings,
            ipc::save_catalog,
            ipc::save_raw_catalog,
            ipc::get_process_state,
            ipc::start_server,
            ipc::stop_server,
            ipc::restart_server,
            ipc::read_logs,
            ipc::probe_endpoint,
        ])
        .run(tauri::generate_context!())
        .expect("error while running BitcoinPIR Node");
}

fn setup_tray(app: &AppHandle) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, "show", "Show BitcoinPIR Node", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit and Stop Node", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &quit])?;
    TrayIconBuilder::new()
        .title("BPIR")
        .tooltip("BitcoinPIR Node")
        .icon(Image::from_bytes(include_bytes!("../icons/icon.png"))?)
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "show" => show_main_window(app),
            "quit" => {
                let process = app.state::<DesktopState>().process.clone();
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let _ = process.stop().await;
                    app.exit(0);
                });
            }
            _ => {}
        })
        .build(app)?;
    Ok(())
}

fn setup_close_to_tray(app: &AppHandle) -> tauri::Result<()> {
    let window = app
        .get_webview_window("main")
        .ok_or_else(|| tauri::Error::WindowNotFound)?;
    let event_window = window.clone();
    let event_app = app.clone();
    window.on_window_event(move |event| {
        if let WindowEvent::CloseRequested { api, .. } = event {
            let close_to_tray = event_app
                .state::<DesktopState>()
                .config
                .settings()
                .close_to_tray;
            if close_to_tray {
                api.prevent_close();
                let _ = event_window.hide();
            }
        }
    });
    Ok(())
}

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}
