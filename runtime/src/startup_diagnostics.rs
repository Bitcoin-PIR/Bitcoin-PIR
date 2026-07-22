//! Bounded, privacy-preserving startup diagnostics for measured deployments.
//!
//! This module intentionally records only fixed enums and numeric context. It
//! must never persist paths, command lines, environment variables, proof/root
//! material, keys, or query contents. The Tier 3 runner supplies a fresh file
//! for every server attempt on the writable root filesystem; the measured
//! server publishes a separate ready marker only after it has bound its
//! listener and completed all startup output.

use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const EVENT_SCHEMA: &str = "bpir-startup-v1";
const READY_SCHEMA: &str = "bpir-ready-v1";
const DEFAULT_MAX_BYTES: u64 = 128 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum StartupStage {
    RecorderOpen,
    ArgsValidated,
    ConfigLoad,
    DatabaseMap,
    DatabaseProofLoad,
    DatabaseSetReady,
    CuckooOramOpen,
    DirectOramConfig,
    DirectDbOpen,
    DirectLevelOpen,
    DirectMetadataLoad,
    DirectStateKeyParse,
    DirectControllerStateLoad,
    DirectCachePlan,
    DirectAuthStateLoad,
    DirectAuthDomainValidate,
    DirectStoreOpen,
    DirectAuthBind,
    DirectOramRestore,
    DirectReaderInit,
    OnionSetup,
    AllDataReady,
    ChannelKeyGenerate,
    VcekLoad,
    IdentityFilesLoad,
    SelfExeHash,
    AnnouncementBuild,
    ServerStateAssemble,
    AdminConfig,
    ArcInit,
    CashuInit,
    HintPoolInit,
    UnifiedServerAssemble,
    ListenerBind,
    PostBindStatus,
    ReadyPublish,
    StartupComplete,
}

impl StartupStage {
    fn id(self) -> u16 {
        self as u16 + 1
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::RecorderOpen => "recorder_open",
            Self::ArgsValidated => "args_validated",
            Self::ConfigLoad => "config_load",
            Self::DatabaseMap => "database_map",
            Self::DatabaseProofLoad => "database_proof_load",
            Self::DatabaseSetReady => "database_set_ready",
            Self::CuckooOramOpen => "cuckoo_oram_open",
            Self::DirectOramConfig => "direct_oram_config",
            Self::DirectDbOpen => "direct_db_open",
            Self::DirectLevelOpen => "direct_level_open",
            Self::DirectMetadataLoad => "direct_metadata_load",
            Self::DirectStateKeyParse => "direct_state_key_parse",
            Self::DirectControllerStateLoad => "direct_controller_state_load",
            Self::DirectCachePlan => "direct_cache_plan",
            Self::DirectAuthStateLoad => "direct_auth_state_load",
            Self::DirectAuthDomainValidate => "direct_auth_domain_validate",
            Self::DirectStoreOpen => "direct_store_open",
            Self::DirectAuthBind => "direct_auth_bind",
            Self::DirectOramRestore => "direct_oram_restore",
            Self::DirectReaderInit => "direct_reader_init",
            Self::OnionSetup => "onion_setup",
            Self::AllDataReady => "all_data_ready",
            Self::ChannelKeyGenerate => "channel_key_generate",
            Self::VcekLoad => "vcek_load",
            Self::IdentityFilesLoad => "identity_files_load",
            Self::SelfExeHash => "self_exe_hash",
            Self::AnnouncementBuild => "announcement_build",
            Self::ServerStateAssemble => "server_state_assemble",
            Self::AdminConfig => "admin_config",
            Self::ArcInit => "arc_init",
            Self::CashuInit => "cashu_init",
            Self::HintPoolInit => "hint_pool_init",
            Self::UnifiedServerAssemble => "unified_server_assemble",
            Self::ListenerBind => "listener_bind",
            Self::PostBindStatus => "post_bind_status",
            Self::ReadyPublish => "ready_publish",
            Self::StartupComplete => "startup_complete",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OramLevel {
    Index,
    Chunk,
}

impl OramLevel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Index => "index",
            Self::Chunk => "chunk",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreKind {
    Meta,
    Payload,
    MetaHash,
    PayloadHash,
}

impl StoreKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Meta => "meta",
            Self::Payload => "payload",
            Self::MetaHash => "meta_hash",
            Self::PayloadHash => "payload_hash",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StartupContext {
    pub db_id: Option<u8>,
    pub level: Option<OramLevel>,
    pub store: Option<StoreKind>,
}

impl StartupContext {
    pub const fn db(db_id: u8) -> Self {
        Self {
            db_id: Some(db_id),
            level: None,
            store: None,
        }
    }

    pub const fn with_level(mut self, level: OramLevel) -> Self {
        self.level = Some(level);
        self
    }

    pub const fn with_store(mut self, store: StoreKind) -> Self {
        self.store = Some(store);
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartupEvent {
    Begin,
    Ok,
    Error,
}

impl StartupEvent {
    fn as_str(self) -> &'static str {
        match self {
            Self::Begin => "begin",
            Self::Ok => "ok",
            Self::Error => "error",
        }
    }
}

#[derive(Debug)]
struct WriterState {
    file: File,
    sequence: u64,
    next_span: u64,
    bytes_written: u64,
    max_bytes: u64,
}

#[derive(Debug)]
struct Inner {
    started: Instant,
    writer: Mutex<WriterState>,
    current_stage: AtomicU16,
}

/// A recorder is disabled unless the operator explicitly supplies a path.
/// Configured recorders are fail-closed: losing the startup evidence is a
/// deployment error, not something the measured process silently ignores.
#[derive(Clone, Debug, Default)]
pub struct StartupDiagnostics {
    inner: Option<Arc<Inner>>,
}

#[derive(Clone, Copy, Debug)]
pub struct StageToken {
    stage: StartupStage,
    context: StartupContext,
    span_id: u64,
    started: Instant,
    previous_stage: u16,
}

impl StartupDiagnostics {
    pub fn disabled() -> Self {
        Self::default()
    }

    pub fn required_file(path: &Path) -> io::Result<Self> {
        Self::required_file_with_limit(path, DEFAULT_MAX_BYTES)
    }

    fn required_file_with_limit(path: &Path, max_bytes: u64) -> io::Result<Self> {
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "diagnostics path has no parent",
            )
        })?;
        let parent_meta = fs::symlink_metadata(parent)?;
        if !parent_meta.file_type().is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "diagnostics parent is not a directory",
            ));
        }

        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.sync_all()?;
        File::open(parent)?.sync_all()?;

        let recorder = Self {
            inner: Some(Arc::new(Inner {
                started: Instant::now(),
                writer: Mutex::new(WriterState {
                    file,
                    sequence: 0,
                    next_span: 1,
                    bytes_written: 0,
                    max_bytes,
                }),
                current_stage: AtomicU16::new(0),
            })),
        };
        let token = recorder.try_begin(StartupStage::RecorderOpen, StartupContext::default())?;
        recorder.try_ok(token)?;
        Ok(recorder)
    }

    pub fn begin(&self, stage: StartupStage, context: StartupContext) -> StageToken {
        self.try_begin(stage, context)
            .unwrap_or_else(|_| diagnostics_fatal())
    }

    pub fn ok(&self, token: StageToken) {
        self.try_ok(token).unwrap_or_else(|_| diagnostics_fatal());
    }

    pub fn error(&self, token: StageToken) {
        self.try_finish(token, StartupEvent::Error)
            .unwrap_or_else(|_| diagnostics_fatal());
    }

    /// Restore the panic-stage cursor after the ready marker has become the
    /// durable success record for `ReadyPublish`. This intentionally performs
    /// no file write: readiness must be the final externally visible startup
    /// action, with no later diagnostic failure able to invalidate it.
    pub fn ready_published(&self, token: StageToken) {
        debug_assert_eq!(token.stage, StartupStage::ReadyPublish);
        let Some(inner) = &self.inner else {
            return;
        };
        inner
            .current_stage
            .store(token.previous_stage, Ordering::SeqCst);
    }

    pub fn trace<T, E>(
        &self,
        stage: StartupStage,
        context: StartupContext,
        operation: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        let token = self.begin(stage, context);
        let result = operation();
        if result.is_ok() {
            self.ok(token);
        } else {
            self.error(token);
        }
        result
    }

    /// Persist a fixed panic marker before the release profile aborts. The
    /// original hook still prints its normal console message, but no payload or
    /// source path is copied into persistent diagnostics.
    pub fn install_panic_hook(&self) {
        if self.inner.is_none() {
            return;
        }
        let diagnostics = self.clone();
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let source_line = info.location().map(|location| location.line()).unwrap_or(0);
            diagnostics.record_panic_best_effort(source_line);
            previous(info);
        }));
    }

    fn try_begin(&self, stage: StartupStage, context: StartupContext) -> io::Result<StageToken> {
        let Some(inner) = &self.inner else {
            return Ok(StageToken {
                stage,
                context,
                span_id: 0,
                started: Instant::now(),
                previous_stage: 0,
            });
        };
        let previous_stage = inner.current_stage.swap(stage.id(), Ordering::SeqCst);
        let mut writer = inner
            .writer
            .lock()
            .map_err(|_| io::Error::other("startup diagnostics lock poisoned"))?;
        let span_id = writer.next_span;
        writer.next_span = writer.next_span.saturating_add(1);
        write_event(
            &mut writer,
            inner.started.elapsed(),
            StartupEvent::Begin,
            stage,
            context,
            span_id,
            None,
        )?;
        Ok(StageToken {
            stage,
            context,
            span_id,
            started: Instant::now(),
            previous_stage,
        })
    }

    fn try_ok(&self, token: StageToken) -> io::Result<()> {
        self.try_finish(token, StartupEvent::Ok)
    }

    fn try_finish(&self, token: StageToken, event: StartupEvent) -> io::Result<()> {
        let Some(inner) = &self.inner else {
            return Ok(());
        };
        let mut writer = inner
            .writer
            .lock()
            .map_err(|_| io::Error::other("startup diagnostics lock poisoned"))?;
        let result = write_event(
            &mut writer,
            inner.started.elapsed(),
            event,
            token.stage,
            token.context,
            token.span_id,
            Some(token.started.elapsed()),
        );
        if result.is_ok() {
            inner
                .current_stage
                .store(token.previous_stage, Ordering::SeqCst);
        }
        result
    }

    fn record_panic_best_effort(&self, source_line: u32) {
        let Some(inner) = &self.inner else {
            return;
        };
        let Ok(mut writer) = inner.writer.try_lock() else {
            return;
        };
        let next_sequence = writer.sequence.saturating_add(1);
        let mut line = String::with_capacity(160);
        let _ = writeln!(
            line,
            "schema={EVENT_SCHEMA} seq={next_sequence} event=panic current_stage_id={} source_line={source_line} monotonic_ms={}",
            inner.current_stage.load(Ordering::SeqCst),
            inner.started.elapsed().as_millis(),
        );
        let Some(new_size) = writer.bytes_written.checked_add(line.len() as u64) else {
            return;
        };
        if new_size > writer.max_bytes {
            return;
        }
        if writer.file.write_all(line.as_bytes()).is_ok() && writer.file.sync_data().is_ok() {
            writer.sequence = next_sequence;
            writer.bytes_written = new_size;
        }
    }
}

fn write_event(
    writer: &mut WriterState,
    monotonic: Duration,
    event: StartupEvent,
    stage: StartupStage,
    context: StartupContext,
    span_id: u64,
    elapsed: Option<Duration>,
) -> io::Result<()> {
    let next_sequence = writer.sequence.saturating_add(1);
    let db_id = context
        .db_id
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_string());
    let level = context.level.map(OramLevel::as_str).unwrap_or("-");
    let store = context.store.map(StoreKind::as_str).unwrap_or("-");
    let elapsed_ms = elapsed
        .map(|value| value.as_millis().to_string())
        .unwrap_or_else(|| "-".to_string());
    let mut line = String::with_capacity(224);
    writeln!(
        line,
        "schema={EVENT_SCHEMA} seq={next_sequence} event={} stage={} span={span_id} db={db_id} level={level} store={store} monotonic_ms={} elapsed_ms={elapsed_ms}",
        event.as_str(),
        stage.as_str(),
        monotonic.as_millis(),
    )
    .expect("writing to String cannot fail");

    let new_size = writer
        .bytes_written
        .checked_add(line.len() as u64)
        .ok_or_else(|| io::Error::other("startup diagnostics size overflow"))?;
    if new_size > writer.max_bytes {
        return Err(io::Error::other("startup diagnostics size limit reached"));
    }
    writer.file.write_all(line.as_bytes())?;
    writer.file.sync_data()?;
    writer.sequence = next_sequence;
    writer.bytes_written = new_size;
    Ok(())
}

fn diagnostics_fatal() -> ! {
    eprintln!("FATAL: required startup diagnostics could not be persisted");
    std::process::exit(74)
}

pub fn publish_ready_file(path: &Path, attempt: u64, port: u16) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "ready path has no parent"))?;
    let parent_meta = fs::symlink_metadata(parent)?;
    if !parent_meta.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ready parent is not a directory",
        ));
    }

    let boot_id = read_boot_id(Path::new("/proc/sys/kernel/random/boot_id"))?;
    let pid = std::process::id();
    let start_ticks = read_process_start_ticks(Path::new("/proc/self/stat"))?;
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "ready path has no file name")
    })?;
    let temp_name = format!(
        ".{}.tmp.{}.{}",
        file_name.to_string_lossy(),
        pid,
        start_ticks
    );
    let temp_path: PathBuf = parent.join(temp_name);
    let contents = format!("{READY_SCHEMA} {boot_id} {attempt} {pid} {start_ticks} {port}\n");

    let mut renamed = false;
    let publish_result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp_path)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temp_path, path)?;
        renamed = true;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if publish_result.is_err() {
        let _ = fs::remove_file(&temp_path);
        if renamed {
            let _ = fs::remove_file(path);
            let _ = File::open(parent).and_then(|directory| directory.sync_all());
        }
    }
    publish_result
}

fn read_boot_id(path: &Path) -> io::Result<String> {
    let value = fs::read_to_string(path)?;
    let value = value.trim();
    let valid = value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        });
    if !valid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid boot id",
        ));
    }
    Ok(value.to_ascii_lowercase())
}

fn read_process_start_ticks(path: &Path) -> io::Result<u64> {
    parse_process_start_ticks(&fs::read_to_string(path)?)
}

fn parse_process_start_ticks(stat: &str) -> io::Result<u64> {
    let closing = stat.rfind(')').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "process stat has no comm terminator",
        )
    })?;
    let suffix = stat
        .get(closing + 1..)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "process stat suffix missing"))?;
    suffix
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "process starttime missing"))?
        .parse::<u64>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid process starttime"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("bitcoinpir-{label}-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn recorder_writes_fixed_complete_events_with_private_permissions() {
        let dir = temp_dir("startup-recorder");
        let path = dir.join("events.log");
        let recorder = StartupDiagnostics::required_file(&path).unwrap();
        let context = StartupContext::db(1)
            .with_level(OramLevel::Chunk)
            .with_store(StoreKind::PayloadHash);
        let token = recorder.begin(StartupStage::DirectStoreOpen, context);
        recorder.ok(token);

        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.ends_with('\n'));
        assert!(contents.contains("event=begin stage=direct_store_open"));
        assert!(contents.contains("event=ok stage=direct_store_open"));
        assert!(contents.contains("db=1 level=chunk store=payload_hash"));
        assert!(!contents.contains(dir.to_string_lossy().as_ref()));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn recorder_refuses_to_replace_an_existing_file() {
        let dir = temp_dir("startup-existing");
        let path = dir.join("events.log");
        fs::write(&path, b"sentinel\n").unwrap();
        assert!(StartupDiagnostics::required_file(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"sentinel\n");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn recorder_refuses_a_symlink_event_path() {
        let dir = temp_dir("startup-symlink");
        let target = dir.join("target.log");
        let path = dir.join("events.log");
        fs::write(&target, b"sentinel\n").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(StartupDiagnostics::required_file(&path).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"sentinel\n");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn synced_begin_event_survives_process_abort() {
        const CHILD_ENV: &str = "BPIR_STARTUP_DIAGNOSTICS_ABORT_CHILD";
        const PATH_ENV: &str = "BPIR_STARTUP_DIAGNOSTICS_ABORT_PATH";
        if std::env::var_os(CHILD_ENV).is_some() {
            let path = PathBuf::from(std::env::var_os(PATH_ENV).unwrap());
            let recorder = StartupDiagnostics::required_file(&path).unwrap();
            let _token = recorder.begin(StartupStage::DirectOramRestore, StartupContext::db(1));
            std::process::abort();
        }

        let dir = temp_dir("startup-abort");
        let path = dir.join("events.log");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("startup_diagnostics::tests::synced_begin_event_survives_process_abort")
            .arg("--nocapture")
            .env(CHILD_ENV, "1")
            .env(PATH_ENV, &path)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.ends_with('\n'));
        assert!(contents.contains("event=begin stage=direct_oram_restore"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn recorder_size_cap_never_writes_a_partial_line() {
        let dir = temp_dir("startup-cap");
        let path = dir.join("events.log");
        let recorder = StartupDiagnostics::required_file_with_limit(&path, 512).unwrap();
        let mut saw_limit = false;
        for _ in 0..16 {
            match recorder.try_begin(StartupStage::ConfigLoad, StartupContext::default()) {
                Ok(token) => {
                    if recorder.try_ok(token).is_err() {
                        saw_limit = true;
                        break;
                    }
                }
                Err(_) => {
                    saw_limit = true;
                    break;
                }
            }
        }
        assert!(saw_limit);
        let contents = fs::read(&path).unwrap();
        assert_eq!(contents.last(), Some(&b'\n'));
        assert!(contents.len() <= 512);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn process_stat_parser_handles_spaces_and_closing_parens_in_comm() {
        let fields = (3u64..=21)
            .map(|value| value.to_string())
            .collect::<Vec<_>>();
        let stat = format!("123 (worker name) extra) {} 987654 23 24", fields.join(" "));
        assert_eq!(parse_process_start_ticks(&stat).unwrap(), 987654);
    }

    #[test]
    fn boot_id_parser_rejects_non_uuid_text() {
        let dir = temp_dir("boot-id");
        let path = dir.join("boot-id");
        fs::write(&path, "$(touch /tmp/not-executed)\n").unwrap();
        assert!(read_boot_id(&path).is_err());
        fs::write(&path, "01234567-89ab-cdef-0123-456789abcdef\n").unwrap();
        assert_eq!(
            read_boot_id(&path).unwrap(),
            "01234567-89ab-cdef-0123-456789abcdef"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ready_file_is_atomic_complete_and_private() {
        let dir = temp_dir("ready-file");
        let path = dir.join("unified-server.ready");
        fs::write(&path, b"stale\n").unwrap();
        publish_ready_file(&path, 7, 8091).unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        let fields = contents.split_whitespace().collect::<Vec<_>>();
        assert_eq!(fields.len(), 6);
        assert_eq!(fields[0], READY_SCHEMA);
        assert_eq!(fields[2], "7");
        assert_eq!(fields[3], std::process::id().to_string());
        assert_eq!(fields[5], "8091");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(dir).unwrap();
    }
}
