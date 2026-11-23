#![cfg(unix)]

use bpir_desktop_lib::config::NodeSettings;
use bpir_desktop_lib::process::{ProcessManager, ProcessStatus};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test]
async fn fake_sidecar_reports_listening_and_stops_cleanly() {
    let temporary = tempfile::tempdir().unwrap();
    let script = temporary.path().join("fake unified server.sh");
    std::fs::write(
        &script,
        "#!/bin/sh\necho 'Manifest verified: 1 files'\necho 'Listening on ws://127.0.0.1:8091'\nwhile true; do sleep 1; done\n",
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    let catalog = temporary.path().join("databases.toml");
    std::fs::write(&catalog, "").unwrap();
    let mut settings = NodeSettings::new(temporary.path().join("data"));
    settings.server_binary = Some(script);
    settings.active_catalog = Some(catalog);

    let app = tauri::test::mock_app();
    let manager = Arc::new(ProcessManager::new(app.handle().clone(), &settings));
    let started = manager.start(settings).await.unwrap();
    assert_eq!(started.status, ProcessStatus::Starting);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if manager.snapshot().await.unwrap().status == ProcessStatus::Running {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(manager
        .logs()
        .await
        .iter()
        .any(|line| line.contains("Listening on")));
    let stopped = manager.stop().await.unwrap();
    assert_eq!(stopped.status, ProcessStatus::Stopped);
    assert!(stopped.pid.is_none());
}
