use runtime::config::ServerConfig;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum NodeRole {
    Primary,
    Secondary,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NodeSettings {
    pub schema_version: u32,
    pub data_dir: PathBuf,
    pub active_catalog: Option<PathBuf>,
    pub server_binary: Option<PathBuf>,
    pub bind_address: String,
    pub port: u16,
    pub role: NodeRole,
    pub serve_queries: bool,
    pub serve_hints: bool,
    pub extra_args: Vec<String>,
    pub close_to_tray: bool,
}

impl NodeSettings {
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            schema_version: 1,
            data_dir,
            active_catalog: None,
            server_binary: None,
            bind_address: "127.0.0.1".to_owned(),
            port: 8091,
            role: NodeRole::Primary,
            serve_queries: false,
            serve_hints: false,
            extra_args: Vec::new(),
            close_to_tray: true,
        }
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct ConfigSnapshot {
    pub settings: NodeSettings,
    pub raw_settings: String,
    pub catalog: Option<ServerConfig>,
    pub available_catalog: Option<ServerConfig>,
    pub raw_catalog: String,
    pub argv: Vec<String>,
}

pub struct ConfigStore {
    settings_path: PathBuf,
    settings: Mutex<NodeSettings>,
}

impl ConfigStore {
    pub fn load(config_dir: PathBuf, default_data_dir: PathBuf) -> Result<Self, String> {
        std::fs::create_dir_all(&config_dir)
            .map_err(|error| format!("create {}: {error}", config_dir.display()))?;
        let settings_path = config_dir.join("node.toml");
        let settings = if settings_path.exists() {
            let raw = std::fs::read_to_string(&settings_path)
                .map_err(|error| format!("read {}: {error}", settings_path.display()))?;
            toml::from_str(&raw)
                .map_err(|error| format!("parse {}: {error}", settings_path.display()))?
        } else {
            let settings = NodeSettings::new(default_data_dir);
            write_atomic(
                &settings_path,
                &toml::to_string_pretty(&settings).map_err(|error| error.to_string())?,
            )?;
            settings
        };
        Ok(Self {
            settings_path,
            settings: Mutex::new(settings),
        })
    }

    pub fn settings(&self) -> NodeSettings {
        self.settings.lock().expect("settings mutex").clone()
    }

    pub fn save_settings(&self, settings: NodeSettings) -> Result<ConfigSnapshot, String> {
        let raw = toml::to_string_pretty(&settings).map_err(|error| error.to_string())?;
        write_atomic(&self.settings_path, &raw)?;
        *self.settings.lock().expect("settings mutex") = settings;
        self.snapshot()
    }

    pub fn save_raw_settings(&self, raw: String) -> Result<ConfigSnapshot, String> {
        let settings: NodeSettings = toml::from_str(&raw).map_err(|error| error.to_string())?;
        write_atomic(&self.settings_path, &raw)?;
        *self.settings.lock().expect("settings mutex") = settings;
        self.snapshot()
    }

    pub fn save_catalog(&self, catalog: ServerConfig) -> Result<ConfigSnapshot, String> {
        let path = self.active_catalog()?;
        let raw = toml::to_string_pretty(&catalog).map_err(|error| error.to_string())?;
        write_atomic(&path, &raw)?;
        self.snapshot()
    }

    pub fn save_raw_catalog(&self, raw: String) -> Result<ConfigSnapshot, String> {
        let path = self.active_catalog()?;
        let _: ServerConfig = toml::from_str(&raw).map_err(|error| error.to_string())?;
        write_atomic(&path, &raw)?;
        self.snapshot()
    }

    pub fn import_bundle(&self, input: PathBuf) -> Result<ConfigSnapshot, String> {
        let source = if input.is_dir() {
            input.join("databases.toml")
        } else {
            input
        };
        let raw = std::fs::read_to_string(&source)
            .map_err(|error| format!("read {}: {error}", source.display()))?;
        let mut catalog: ServerConfig =
            toml::from_str(&raw).map_err(|error| format!("parse {}: {error}", source.display()))?;
        let parent = source.parent().unwrap_or(Path::new("."));
        make_paths_absolute(&mut catalog, parent);

        let digest = Sha256::new()
            .chain_update(raw.as_bytes())
            .chain_update(source.to_string_lossy().as_bytes())
            .finalize();
        let suffix = hex::encode(digest)[..12].to_owned();
        let generation = catalog
            .databases
            .iter()
            .map(|database| database.height)
            .max()
            .map(|height| format!("{height}-{suffix}"))
            .unwrap_or(suffix);
        let settings = self.settings();
        let directory = settings.data_dir.join("generations").join(generation);
        std::fs::create_dir_all(&directory)
            .map_err(|error| format!("create {}: {error}", directory.display()))?;
        let serialized = toml::to_string_pretty(&catalog).map_err(|error| error.to_string())?;
        write_atomic(&directory.join("upstream-databases.toml"), &serialized)?;
        let active = directory.join("databases.toml");
        if !active.exists() {
            write_atomic(&active, &serialized)?;
        }

        let mut next = settings;
        next.active_catalog = Some(active);
        self.save_settings(next)
    }

    pub fn snapshot(&self) -> Result<ConfigSnapshot, String> {
        let settings = self.settings();
        let raw_settings = std::fs::read_to_string(&self.settings_path)
            .map_err(|error| format!("read {}: {error}", self.settings_path.display()))?;
        let active = settings.active_catalog.clone();
        let catalog = active.as_deref().map(read_catalog).transpose()?;
        let available_path = active.as_deref().map(|path| {
            let upstream = path
                .parent()
                .unwrap_or(Path::new("."))
                .join("upstream-databases.toml");
            if upstream.exists() {
                upstream
            } else {
                path.to_path_buf()
            }
        });
        let available_catalog = available_path.as_deref().map(read_catalog).transpose()?;
        let raw_catalog = active
            .as_deref()
            .map(std::fs::read_to_string)
            .transpose()
            .map_err(|error| format!("read active catalog: {error}"))?
            .unwrap_or_default();
        let argv = build_argv(&settings);
        Ok(ConfigSnapshot {
            settings,
            raw_settings,
            catalog,
            available_catalog,
            raw_catalog,
            argv,
        })
    }

    fn active_catalog(&self) -> Result<PathBuf, String> {
        self.settings()
            .active_catalog
            .ok_or_else(|| "Import a database bundle first".to_owned())
    }
}

pub fn build_argv(settings: &NodeSettings) -> Vec<String> {
    let mut argv = vec![
        "--bind-address".to_owned(),
        settings.bind_address.clone(),
        "--port".to_owned(),
        settings.port.to_string(),
        "--role".to_owned(),
        match settings.role {
            NodeRole::Primary => "primary",
            NodeRole::Secondary => "secondary",
        }
        .to_owned(),
    ];
    if let Some(path) = &settings.active_catalog {
        argv.push("--config".to_owned());
        argv.push(path.to_string_lossy().into_owned());
    }
    if settings.serve_queries {
        argv.push("--serve-queries".to_owned());
    }
    if settings.serve_hints {
        argv.push("--serve-hints".to_owned());
    }
    argv.extend(settings.extra_args.iter().cloned());
    argv
}

pub fn local_endpoint(settings: &NodeSettings) -> String {
    let host = match settings.bind_address.as_str() {
        "0.0.0.0" | "::" | "[::]" => "127.0.0.1".to_owned(),
        value if value.contains(':') => format!("[{}]", value.trim_matches(['[', ']'])),
        value => value.to_owned(),
    };
    format!("ws://{}:{}", host, settings.port)
}

fn read_catalog(path: &Path) -> Result<ServerConfig, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    toml::from_str(&raw).map_err(|error| format!("parse {}: {error}", path.display()))
}

fn make_paths_absolute(catalog: &mut ServerConfig, parent: &Path) {
    for database in &mut catalog.databases {
        database.path = absolute_string(parent, Path::new(&database.path));
        if let Some(path) = &database.proof_dir {
            database.proof_dir = Some(PathBuf::from(absolute_string(parent, path)));
        }
        if let Some(path) = &database.proof_v2_dir {
            database.proof_v2_dir = Some(PathBuf::from(absolute_string(parent, path)));
        }
    }
}

fn absolute_string(parent: &Path, path: &Path) -> String {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        parent.join(path)
    }
    .to_string_lossy()
    .into_owned()
}

fn write_atomic(path: &Path, contents: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("create {}: {error}", parent.display()))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|error| format!("create temporary file in {}: {error}", parent.display()))?;
    temporary
        .write_all(contents.as_bytes())
        .map_err(|error| format!("write {}: {error}", path.display()))?;
    temporary
        .persist(path)
        .map_err(|error| format!("replace {}: {}", path.display(), error.error))?;
    Ok(())
}
