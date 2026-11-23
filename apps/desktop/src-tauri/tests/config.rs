use bpir_desktop_lib::config::{build_argv, ConfigStore};
use std::path::PathBuf;

#[test]
fn import_resolves_paths_and_preserves_spaces_as_single_argv_items() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source bundle");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(
        source.join("databases.toml"),
        r#"
[[database]]
name = "main"
type = "full"
path = "checkpoints/main database"
proof_dir = "proofs/main"
base_height = 0
height = 123
"#,
    )
    .unwrap();
    let store = ConfigStore::load(
        temporary.path().join("config"),
        temporary.path().join("data"),
    )
    .unwrap();
    let snapshot = store.import_bundle(source.join("databases.toml")).unwrap();
    let active = snapshot.settings.active_catalog.clone().unwrap();
    let database = &snapshot.catalog.unwrap().databases[0];
    assert_eq!(
        database.path,
        source
            .join("checkpoints/main database")
            .to_string_lossy()
            .into_owned()
    );
    assert_eq!(database.proof_dir, Some(source.join("proofs/main")));

    let mut settings = snapshot.settings;
    settings.serve_queries = true;
    settings.extra_args = vec!["--identity-server-id".into(), "node one".into()];
    let argv = build_argv(&settings);
    assert!(argv.contains(&active.to_string_lossy().into_owned()));
    assert!(argv.contains(&"--serve-queries".to_owned()));
    assert_eq!(
        &argv[argv.len() - 2..],
        ["--identity-server-id", "node one"]
    );
}

#[test]
fn invalid_raw_catalog_does_not_replace_the_active_file() {
    let temporary = tempfile::tempdir().unwrap();
    let store = ConfigStore::load(
        temporary.path().join("config"),
        temporary.path().join("data"),
    )
    .unwrap();
    let source = temporary.path().join("databases.toml");
    std::fs::write(&source, "database = []\n").unwrap();
    let snapshot = store.import_bundle(source).unwrap();
    let active = snapshot.settings.active_catalog.unwrap();
    let before = std::fs::read_to_string(&active).unwrap();
    assert!(store.save_raw_catalog("not valid TOML = [".into()).is_err());
    assert_eq!(std::fs::read_to_string(active).unwrap(), before);
}

#[test]
fn reimport_does_not_erase_user_catalog_edits() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("databases.toml");
    std::fs::write(&source, "database = []\n").unwrap();
    let store = ConfigStore::load(
        temporary.path().join("config"),
        temporary.path().join("data"),
    )
    .unwrap();
    let snapshot = store.import_bundle(PathBuf::from(&source)).unwrap();
    let active = snapshot.settings.active_catalog.unwrap();
    std::fs::write(&active, "database = []\n# operator edit\n").unwrap();
    store.import_bundle(source).unwrap();
    assert_eq!(
        std::fs::read_to_string(active).unwrap(),
        "database = []\n# operator edit\n"
    );
}
