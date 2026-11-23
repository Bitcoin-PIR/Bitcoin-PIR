use crate::config::{build_argv, local_endpoint, NodeSettings};
use serde::Serialize;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager, Runtime};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

const MAX_LOG_LINES: usize = 1_000;

#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ProcessStatus {
    Stopped,
    Starting,
    Running,
    Stopping,
    Failed,
}

#[derive(Serialize, Clone, Debug)]
pub struct ProcessSnapshot {
    pub status: ProcessStatus,
    pub pid: Option<u32>,
    pub exit_code: Option<i32>,
    pub last_error: Option<String>,
    pub endpoint: String,
    pub active_catalog: Option<PathBuf>,
}

impl ProcessSnapshot {
    fn stopped(settings: &NodeSettings) -> Self {
        Self {
            status: ProcessStatus::Stopped,
            pid: None,
            exit_code: None,
            last_error: None,
            endpoint: local_endpoint(settings),
            active_catalog: settings.active_catalog.clone(),
        }
    }
}

struct ProcessInner {
    child: Option<Child>,
    snapshot: ProcessSnapshot,
    logs: VecDeque<String>,
}

pub struct ProcessManager<R: Runtime = tauri::Wry> {
    app: AppHandle<R>,
    inner: Mutex<ProcessInner>,
}

impl<R: Runtime> ProcessManager<R> {
    pub fn new(app: AppHandle<R>, settings: &NodeSettings) -> Self {
        Self {
            app,
            inner: Mutex::new(ProcessInner {
                child: None,
                snapshot: ProcessSnapshot::stopped(settings),
                logs: VecDeque::new(),
            }),
        }
    }

    pub async fn snapshot(&self) -> Result<ProcessSnapshot, String> {
        let mut inner = self.inner.lock().await;
        refresh_exit(&mut inner);
        Ok(inner.snapshot.clone())
    }

    pub async fn logs(&self) -> Vec<String> {
        self.inner.lock().await.logs.iter().cloned().collect()
    }

    pub async fn start(
        self: &Arc<Self>,
        settings: NodeSettings,
    ) -> Result<ProcessSnapshot, String> {
        let mut inner = self.inner.lock().await;
        refresh_exit(&mut inner);
        if inner.child.is_some() {
            return Ok(inner.snapshot.clone());
        }
        let catalog = settings
            .active_catalog
            .as_ref()
            .ok_or_else(|| "Import a database bundle first".to_owned())?;
        if !catalog.exists() {
            return Err(format!("Catalog does not exist: {}", catalog.display()));
        }
        let binary = resolve_server_binary(&self.app, &settings);
        let argv = build_argv(&settings);
        let mut command = Command::new(&binary);
        command
            .args(argv)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        #[cfg(windows)]
        command.creation_flags(0x08000000);
        let mut child = command
            .spawn()
            .map_err(|error| format!("Failed to start {}: {error}", binary.display()))?;
        let pid = child.id();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        inner.snapshot = ProcessSnapshot {
            status: ProcessStatus::Starting,
            pid,
            exit_code: None,
            last_error: None,
            endpoint: local_endpoint(&settings),
            active_catalog: settings.active_catalog.clone(),
        };
        inner.child = Some(child);
        let snapshot = inner.snapshot.clone();
        drop(inner);
        self.emit_status(&snapshot);
        if let Some(stdout) = stdout {
            self.spawn_log_reader(stdout, "stdout");
        }
        if let Some(stderr) = stderr {
            self.spawn_log_reader(stderr, "stderr");
        }
        Ok(snapshot)
    }

    pub async fn stop(&self) -> Result<ProcessSnapshot, String> {
        let mut inner = self.inner.lock().await;
        refresh_exit(&mut inner);
        inner.snapshot.status = ProcessStatus::Stopping;
        let snapshot = inner.snapshot.clone();
        self.emit_status(&snapshot);
        if let Some(mut child) = inner.child.take() {
            let _ = child.kill().await;
            let status = child.wait().await.map_err(|error| error.to_string())?;
            inner.snapshot.exit_code = status.code();
        }
        inner.snapshot.status = ProcessStatus::Stopped;
        inner.snapshot.pid = None;
        let snapshot = inner.snapshot.clone();
        drop(inner);
        self.emit_status(&snapshot);
        Ok(snapshot)
    }

    pub async fn restart(
        self: &Arc<Self>,
        settings: NodeSettings,
    ) -> Result<ProcessSnapshot, String> {
        self.stop().await?;
        self.start(settings).await
    }

    fn spawn_log_reader(
        self: &Arc<Self>,
        stream: impl tokio::io::AsyncRead + Unpin + Send + 'static,
        label: &'static str,
    ) {
        let manager = Arc::clone(self);
        tokio::spawn(async move {
            let mut lines = BufReader::new(stream).lines();
            loop {
                match lines.next_line().await {
                    Ok(Some(line)) => manager.append_log(label, line).await,
                    Ok(None) | Err(_) => break,
                }
            }
        });
    }

    async fn append_log(&self, label: &str, line: String) {
        let listening = line.contains("Listening on");
        let entry = format!("[{label}] {line}");
        let snapshot = {
            let mut inner = self.inner.lock().await;
            inner.logs.push_back(entry.clone());
            while inner.logs.len() > MAX_LOG_LINES {
                inner.logs.pop_front();
            }
            if listening && inner.child.is_some() {
                inner.snapshot.status = ProcessStatus::Running;
            }
            inner.snapshot.clone()
        };
        let _ = self.app.emit("server-log", entry);
        if listening {
            self.emit_status(&snapshot);
        }
    }

    fn emit_status(&self, snapshot: &ProcessSnapshot) {
        let _ = self.app.emit("server-status", snapshot.clone());
    }
}

fn refresh_exit(inner: &mut ProcessInner) {
    let Some(child) = inner.child.as_mut() else {
        return;
    };
    match child.try_wait() {
        Ok(Some(status)) => {
            inner.child = None;
            inner.snapshot.pid = None;
            inner.snapshot.exit_code = status.code();
            inner.snapshot.status = if status.success() {
                ProcessStatus::Stopped
            } else {
                ProcessStatus::Failed
            };
            if !status.success() {
                inner.snapshot.last_error = Some(format!("unified_server exited with {status}"));
            }
        }
        Ok(None) => {}
        Err(error) => {
            inner.child = None;
            inner.snapshot.pid = None;
            inner.snapshot.status = ProcessStatus::Failed;
            inner.snapshot.last_error = Some(format!("Failed to read child status: {error}"));
        }
    }
}

fn resolve_server_binary<R: Runtime>(app: &AppHandle<R>, settings: &NodeSettings) -> PathBuf {
    if let Some(path) = &settings.server_binary {
        return path.clone();
    }
    if let Some(path) = std::env::var_os("BPIR_UNIFIED_SERVER") {
        return PathBuf::from(path);
    }
    let suffix = if cfg!(windows) { ".exe" } else { "" };
    let plain_filename = format!("unified_server{suffix}");
    let filename = format!("unified_server-{}{}", env!("BPIR_TARGET_TRIPLE"), suffix);
    let mut candidates = Vec::new();
    if let Ok(resource_dir) = app.path().resource_dir() {
        candidates.push(resource_dir.join(&plain_filename));
        candidates.push(resource_dir.join("binaries").join(&filename));
        candidates.push(resource_dir.join(&filename));
    }
    if let Ok(current) = std::env::current_exe() {
        if let Some(parent) = current.parent() {
            candidates.push(parent.join(&plain_filename));
            candidates.push(parent.join("binaries").join(&filename));
            candidates.push(parent.join(&filename));
        }
    }
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    candidates.push(manifest.join("binaries").join(&filename));
    let workspace = manifest.join("../..");
    candidates.push(
        workspace
            .join("target")
            .join(if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            })
            .join(format!("unified_server{suffix}")),
    );
    candidates
        .iter()
        .find(|path| path.exists())
        .cloned()
        .unwrap_or_else(|| {
            candidates
                .into_iter()
                .next()
                .expect("one sidecar candidate")
        })
}
