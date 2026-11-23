use crate::config::{local_endpoint, ConfigSnapshot, ConfigStore, NodeSettings};
use crate::health::{probe, HealthReport};
use crate::process::{ProcessManager, ProcessSnapshot};
use runtime::config::ServerConfig;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::State;

pub struct DesktopState {
    pub config: ConfigStore,
    pub process: Arc<ProcessManager>,
}

#[derive(Serialize, Clone, Debug)]
pub struct DesktopError {
    pub code: String,
    pub message: String,
}

impl DesktopError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            code: "desktop_error".to_owned(),
            message: message.into(),
        }
    }
}

type CommandResult<T> = Result<T, DesktopError>;

fn result<T>(value: Result<T, String>) -> CommandResult<T> {
    value.map_err(DesktopError::new)
}

#[tauri::command]
pub fn get_config(state: State<'_, DesktopState>) -> CommandResult<ConfigSnapshot> {
    result(state.config.snapshot())
}

#[tauri::command]
pub fn import_bundle(
    path: PathBuf,
    state: State<'_, DesktopState>,
) -> CommandResult<ConfigSnapshot> {
    result(state.config.import_bundle(path))
}

#[tauri::command]
pub fn save_settings(
    settings: NodeSettings,
    state: State<'_, DesktopState>,
) -> CommandResult<ConfigSnapshot> {
    result(state.config.save_settings(settings))
}

#[tauri::command]
pub fn save_raw_settings(
    raw: String,
    state: State<'_, DesktopState>,
) -> CommandResult<ConfigSnapshot> {
    result(state.config.save_raw_settings(raw))
}

#[tauri::command]
pub fn save_catalog(
    catalog: ServerConfig,
    state: State<'_, DesktopState>,
) -> CommandResult<ConfigSnapshot> {
    result(state.config.save_catalog(catalog))
}

#[tauri::command]
pub fn save_raw_catalog(
    raw: String,
    state: State<'_, DesktopState>,
) -> CommandResult<ConfigSnapshot> {
    result(state.config.save_raw_catalog(raw))
}

#[tauri::command]
pub async fn get_process_state(state: State<'_, DesktopState>) -> CommandResult<ProcessSnapshot> {
    result(state.process.snapshot().await)
}

#[tauri::command]
pub async fn start_server(state: State<'_, DesktopState>) -> CommandResult<ProcessSnapshot> {
    result(state.process.start(state.config.settings()).await)
}

#[tauri::command]
pub async fn stop_server(state: State<'_, DesktopState>) -> CommandResult<ProcessSnapshot> {
    result(state.process.stop().await)
}

#[tauri::command]
pub async fn restart_server(state: State<'_, DesktopState>) -> CommandResult<ProcessSnapshot> {
    result(state.process.restart(state.config.settings()).await)
}

#[tauri::command]
pub async fn read_logs(state: State<'_, DesktopState>) -> CommandResult<Vec<String>> {
    Ok(state.process.logs().await)
}

#[tauri::command]
pub async fn probe_endpoint(
    endpoint: Option<String>,
    state: State<'_, DesktopState>,
) -> CommandResult<HealthReport> {
    let endpoint = endpoint.unwrap_or_else(|| local_endpoint(&state.config.settings()));
    result(probe(endpoint).await)
}
