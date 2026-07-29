//! Local three-domain rollback-authority process topology.
//!
//! Provider 0, provider 1, and the issuer each receive a separate authority
//! database, authority/client/value-root keys, namespace, TLS leaf/SPKI pin,
//! endpoint, authority child-test-harness process, and TLS-edge child process.
//! Each authority harness invokes production `rollback_authority::run`; the
//! parent test calls the production provider/issuer Store adapters directly.
//! Provider and issuer authority backends are stopped independently while the
//! other two business domains remain usable, then recovered from original state.
//! It does not launch `unified_server`, `payment-issuer`, or an installed
//! binary. This proves only local process/file separation, not separate
//! operators, hosts, networks, or backups.

use super::*;

use std::collections::BTreeSet;
use std::io::Write as _;
use std::os::unix::fs::MetadataExt as _;

use clap::Parser as _;
use pir_issuer_store::{
    IssuerStore, RemoteIssuerRollbackFloorAuthorityV1, StoreOptions as IssuerStoreOptions,
};
use pir_rollback_authority_client::{
    load_remote_rollback_authority_deployment_descriptor_v1,
    load_remote_rollback_authority_deployment_for_business_domain_v1,
    validate_independent_remote_rollback_authority_deployments_v1, RemoteAuthorityCallErrorV1,
    RemoteAuthorityDeploymentConfigErrorV1,
};
use pir_service_protocol::LightningNetworkV1;
use pir_service_store::{RemoteProviderRollbackFloorAuthorityV1, StoreError as ProviderStoreError};
use rollback_authority::{run as run_rollback_authority, Cli as RollbackAuthorityCli};

use super::remote_authority_process::{
    spawn_authority_helper, spawn_tls_edge_helper, AuthorityHelperFiles, HelperProcess,
};

const TEST_ROOT_CERTIFICATE_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBojCCAUmgAwIBAgIUDmhpSrwUCoL3GQBhgYYMnNq4WZYwCgYIKoZIzj0EAwIw
JzElMCMGA1UEAwwcQml0Y29pblBJUiB0b3BvbG9neSBFMkUgcm9vdDAeFw0yNjA3
MjgyMDE0MTBaFw0zNjA3MjUyMDE0MTBaMCcxJTAjBgNVBAMMHEJpdGNvaW5QSVIg
dG9wb2xvZ3kgRTJFIHJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQTh8tM
3PnGB85Dxdo9VbfNkp9wXscDGZH3ZXjS142DDyjPbOWl/Pl8ekkaLeMZ0WInlkYw
ujd/iaImWOreKAgoo1MwUTAdBgNVHQ4EFgQUed6EAm1avFb/Tp5SMpmxgGX2loYw
HwYDVR0jBBgwFoAUed6EAm1avFb/Tp5SMpmxgGX2loYwDwYDVR0TAQH/BAUwAwEB
/zAKBggqhkjOPQQDAgNHADBEAiBFxl452MU5tTvWh6E+ph4XnftKp79IN8fsoYcK
etCH5QIgAtbGHY9c1Z7uxZZVCkFgxpqQi64ISNhlIMjXcNLyTKs=
-----END CERTIFICATE-----
"#;

const PROVIDER0_LEAF_CERTIFICATE_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBtzCCAV2gAwIBAgIBATAKBggqhkjOPQQDAjAnMSUwIwYDVQQDDBxCaXRjb2lu
UElSIHRvcG9sb2d5IEUyRSByb290MB4XDTI2MDcyODIwMTQxMFoXDTM2MDcyNTIw
MTQxMFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAE7UeLAYIUMeJDca/zLZWtFxH6dzhWpPyS+CgPQvYCkGzvIuuIfrdrM8pr
H3Dje1xENLLVSl2Ck8yFjDwiRRj24aOBjDCBiTAUBgNVHREEDTALgglsb2NhbGhv
c3QwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwHQYDVR0OBBYEFKBDj6+FYVMFL8RF2W619kBXO7VYMB8GA1UdIwQYMBaA
FHnehAJtWrxW/06eUjKZsYBl9paGMAoGCCqGSM49BAMCA0gAMEUCIGg8owxWr7ly
vrvoZkTNAbuci9ZwMjcn3QtUSJlLz/vMAiEAqeFQK9tdBfdCTAhvG4zUSoJJXnD3
2xLusYyyJTBN5L0=
-----END CERTIFICATE-----
"#;

const PROVIDER0_LEAF_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgC5ND3rX+Puq/p5l9
53NPygjKdrH6GILVQYCHWvtgZ2ChRANCAATtR4sBghQx4kNxr/Mtla0XEfp3OFak
/JL4KA9C9gKQbO8i64h+t2szymsfcON7XEQ0stVKXYKTzIWMPCJFGPbh
-----END PRIVATE KEY-----
"#;

const PROVIDER1_LEAF_CERTIFICATE_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBtjCCAV2gAwIBAgIBAjAKBggqhkjOPQQDAjAnMSUwIwYDVQQDDBxCaXRjb2lu
UElSIHRvcG9sb2d5IEUyRSByb290MB4XDTI2MDcyODIwMTQxMFoXDTM2MDcyNTIw
MTQxMFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEuOFIgKA2ahtr02XzAd4sp8mTsN31XaLJowLom020gkxEs3AQmn8vj5Tl
vhTXGqU+vZgBWi96QE6aVOo1nBHSN6OBjDCBiTAUBgNVHREEDTALgglsb2NhbGhv
c3QwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwHQYDVR0OBBYEFBvOJIDFToL5DyK6JDNhzMPDBIi1MB8GA1UdIwQYMBaA
FHnehAJtWrxW/06eUjKZsYBl9paGMAoGCCqGSM49BAMCA0cAMEQCIEIFkqjyRSFo
k+jMdv+D7k2bcOi5CZ46+fbPa7v/7+YnAiBBJDpnAdUVsaFPTgR5PeKf2pYaLXto
TN8yY0cRPRaHbg==
-----END CERTIFICATE-----
"#;

const PROVIDER1_LEAF_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghQhVTaRMCyWuiqA0
sPe9V2WacUuLhpKS6GfWTGtgkAKhRANCAAS44UiAoDZqG2vTZfMB3iynyZOw3fVd
osmjAuibTbSCTESzcBCafy+PlOW+FNcapT69mAFaL3pATppU6jWcEdI3
-----END PRIVATE KEY-----
"#;

const ISSUER_LEAF_CERTIFICATE_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIBtzCCAV2gAwIBAgIBAzAKBggqhkjOPQQDAjAnMSUwIwYDVQQDDBxCaXRjb2lu
UElSIHRvcG9sb2d5IEUyRSByb290MB4XDTI2MDcyODIwMTQxMFoXDTM2MDcyNTIw
MTQxMFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEA73VGG8ACOa5sMMqUFC/xZCEjnFpI9KCRKhd6ynu7fOPtiURK3KQSavw
VZI9EoWJZDNqzE5xNLnlAt5QOwDmmqOBjDCBiTAUBgNVHREEDTALgglsb2NhbGhv
c3QwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwHQYDVR0OBBYEFIi8wEI3HN4H7mEoX4AwqZ/IJb8DMB8GA1UdIwQYMBaA
FHnehAJtWrxW/06eUjKZsYBl9paGMAoGCCqGSM49BAMCA0gAMEUCIB1En6R45/Eq
M4H30hs7/PGcmWMtN3cOWr0Bfh/joY5GAiEAn1iEcwHbiu/oSZWyOYVOMOcuPeIT
nYACGXIp4ODtCM8=
-----END CERTIFICATE-----
"#;

const ISSUER_LEAF_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgjbiMTEJDIkcbHyxn
QeAfpsV1tKWRquJAnAEhK8O+hyyhRANCAAQDvdUYbwAI5rmwwypQUL/FkISOcWkj
0oJEqF3rKe7t84+2JRErcpBJq/BVkj0ShYlkM2rMTnE0ueUC3lA7AOaa
-----END PRIVATE KEY-----
"#;

const PROVIDER0_PIN: &str = "23886aaf971540bd4cc609ef81f22afb1f4038a9cd2c92f4bdbea8640b70bf90";
const PROVIDER1_PIN: &str = "39860b1070e088e403cc7e84845572f54ff36e4e585356858fa91c3654a50663";
const ISSUER_PIN: &str = "20adc745ee5765b73fdc69cd7d4b4df6c56cae1081047306e37045c24b24c911";

struct AuthorityDomain {
    label: &'static str,
    business_id: [u8; 32],
    authority_port: u16,
    tls_port: u16,
    authority_secret: PathBuf,
    authority_metadata: PathBuf,
    authority_store: PathBuf,
    client_secret: PathBuf,
    value_root: PathBuf,
    remote_config: PathBuf,
    test_root: PathBuf,
    leaf_certificate: PathBuf,
    leaf_private_key: PathBuf,
    authority_instance_id_hex: String,
    authority_verifying_key_hex: String,
    namespace_hex: String,
    client_verifying_key_hex: String,
    pin: &'static str,
}

#[test]
fn three_authority_real_process_topology_e2e() {
    let root = tempfile::tempdir().expect("three-authority process test root");
    chmod(root.path(), 0o700);
    let authority_ports = distinct_ports(6);
    let provider0 = prepare_domain(
        root.path(),
        "provider0-authority",
        [0xa0; 32],
        authority_ports[0],
        authority_ports[1],
        PROVIDER0_LEAF_CERTIFICATE_PEM,
        PROVIDER0_LEAF_PRIVATE_KEY_PEM,
        PROVIDER0_PIN,
    );
    let provider1 = prepare_domain(
        root.path(),
        "provider1-authority",
        [0xa1; 32],
        authority_ports[2],
        authority_ports[3],
        PROVIDER1_LEAF_CERTIFICATE_PEM,
        PROVIDER1_LEAF_PRIVATE_KEY_PEM,
        PROVIDER1_PIN,
    );
    let issuer = prepare_domain(
        root.path(),
        "issuer-authority",
        [0xa2; 32],
        authority_ports[4],
        authority_ports[5],
        ISSUER_LEAF_CERTIFICATE_PEM,
        ISSUER_LEAF_PRIVATE_KEY_PEM,
        ISSUER_PIN,
    );
    let domains = [&provider0, &provider1, &issuer];
    assert_domain_material_is_independent(&domains);

    let descriptors = load_descriptors(&domains.map(|domain| domain.remote_config.as_path()));
    validate_independent_remote_rollback_authority_deployments_v1(&descriptors)
        .expect("three public authority deployments are independent");

    let same_pin_config = root.path().join("provider1-same-pin.toml");
    write_remote_config(
        &same_pin_config,
        &provider1,
        &provider1.namespace_hex,
        &provider1.client_verifying_key_hex,
        &provider1.client_secret,
        &provider1.value_root,
        provider0.pin,
    );
    let same_namespace_config = root.path().join("provider1-same-namespace.toml");
    write_remote_config(
        &same_namespace_config,
        &provider1,
        &provider0.namespace_hex,
        &provider1.client_verifying_key_hex,
        &provider1.client_secret,
        &provider1.value_root,
        provider1.pin,
    );
    let wrong_client_config = root.path().join("provider0-wrong-client.toml");
    write_remote_config(
        &wrong_client_config,
        &provider0,
        &provider0.namespace_hex,
        &provider1.client_verifying_key_hex,
        &provider1.client_secret,
        &provider1.value_root,
        provider0.pin,
    );
    let crossed_config = root.path().join("provider1-crossed-client-domain.toml");
    write_remote_config(
        &crossed_config,
        &provider1,
        &provider0.namespace_hex,
        &provider0.client_verifying_key_hex,
        &provider0.client_secret,
        &provider0.value_root,
        provider1.pin,
    );

    assert_deployment_set_rejected(
        [
            &provider0.remote_config,
            &same_pin_config,
            &issuer.remote_config,
        ],
        "same TLS pin",
    );
    assert_deployment_set_rejected(
        [
            &provider0.remote_config,
            &same_namespace_config,
            &issuer.remote_config,
        ],
        "same namespace",
    );

    // Capture a provisioned-but-uninitialized provider-0 authority database.
    // Restoring this snapshot later must not be accepted over the detailed
    // provider store which has already anchored generation zero.
    let stale_provider0_backup = root.path().join("provider0-authority-stale-snapshot");
    snapshot_database(&provider0.authority_store, &stale_provider0_backup);

    let mut authority0 = spawn_authority(&provider0, root.path(), 0);
    let authority1 = spawn_authority(&provider1, root.path(), 0);
    let authority_issuer = spawn_authority(&issuer, root.path(), 0);
    let tls0 = spawn_tls(&provider0, root.path(), 0);
    let tls1 = spawn_tls(&provider1, root.path(), 0);
    let tls_issuer = spawn_tls(&issuer, root.path(), 0);
    let process_ids = [
        authority0.id(),
        authority1.id(),
        authority_issuer.id(),
        tls0.id(),
        tls1.id(),
        tls_issuer.id(),
    ];
    assert_eq!(
        process_ids.into_iter().collect::<BTreeSet<_>>().len(),
        process_ids.len(),
        "each authority and TLS edge must be a separate OS process"
    );

    // Every case reaches a TCP/TLS write attempt. The strict client therefore
    // conservatively classifies a pin/handshake failure, an authority HTTP
    // rejection, or a response failure as OutcomeUnknown rather than claiming
    // that no application request could have been sent.
    for (config, business_id, label, expected_error) in [
        (
            &same_pin_config,
            provider1.business_id,
            "same pin",
            RemoteAuthorityCallErrorV1::OutcomeUnknown,
        ),
        (
            &same_namespace_config,
            provider1.business_id,
            "same namespace",
            RemoteAuthorityCallErrorV1::OutcomeUnknown,
        ),
        (
            &wrong_client_config,
            provider0.business_id,
            "wrong client",
            RemoteAuthorityCallErrorV1::OutcomeUnknown,
        ),
        (
            &crossed_config,
            provider0.business_id,
            "crossed domain",
            RemoteAuthorityCallErrorV1::OutcomeUnknown,
        ),
    ] {
        assert_remote_read_error(config, business_id, label, expected_error);
    }

    let provider0_store = root.path().join("provider0-store.sqlite3");
    let provider1_store = root.path().join("provider1-store.sqlite3");
    let issuer_store = root.path().join("issuer-store.sqlite3");
    create_provider_store(&provider0, &provider0_store, [0x30; 16]);
    create_provider_store(&provider1, &provider1_store, [0x31; 16]);
    create_issuer_store(&issuer, &issuer_store, [0x32; 16]);

    // A syntactically valid provider-1 configuration cannot authenticate the
    // provider-0 store: its opaque current record decodes to provider 1 and
    // the production adapter rejects the business binding.
    let crossed_authority = provider_authority(&provider1, provider0.business_id);
    assert!(
        matches!(
            ProviderStore::open_existing(
                &provider0_store,
                provider0.business_id,
                provider_store_options(),
                Arc::new(crossed_authority),
            ),
            Err(ProviderStoreError::RollbackAuthorityUnavailable(_))
        ),
        "cross-authority provider configuration must fail with RollbackAuthorityUnavailable"
    );

    // Stop only provider 1's backend. The other two domains remain usable,
    // while provider 1 fails closed even though its TLS edge still listens.
    let _ = authority1.stop();
    open_provider_store(&provider0, &provider0_store).expect("provider0 remains available");
    let issuer_identity_before_outage = open_issuer_store(&issuer, &issuer_store)
        .expect("issuer remains available")
        .identity()
        .expect("read issuer identity before its authority outage");
    assert_remote_read_error(
        &provider1.remote_config,
        provider1.business_id,
        "offline provider1 authority backend",
        RemoteAuthorityCallErrorV1::OutcomeUnknown,
    );
    assert!(
        matches!(
            open_provider_store(&provider1, &provider1_store),
            Err(ProviderStoreError::RollbackAuthorityUnavailable(_))
        ),
        "offline provider1 authority must return RollbackAuthorityUnavailable, not fall back to local SQLite"
    );
    let authority1 = spawn_authority(&provider1, root.path(), 1);
    open_provider_store(&provider1, &provider1_store)
        .expect("provider1 recovers against its durable authority database");

    // Stop only the issuer's authority backend while its TLS edge continues to
    // listen. Both provider authority domains remain usable, while the issuer
    // fails closed instead of trusting only its detailed SQLite database.
    let _ = authority_issuer.stop();
    open_provider_store(&provider0, &provider0_store)
        .expect("provider0 remains available during issuer authority outage");
    open_provider_store(&provider1, &provider1_store)
        .expect("provider1 remains available during issuer authority outage");
    assert_remote_read_error(
        &issuer.remote_config,
        issuer.business_id,
        "offline issuer authority backend",
        RemoteAuthorityCallErrorV1::OutcomeUnknown,
    );
    assert!(
        matches!(
            open_issuer_store(&issuer, &issuer_store),
            Err(pir_issuer_store::StoreError::RollbackAuthorityUnavailable(_))
        ),
        "offline issuer authority must return RollbackAuthorityUnavailable, not fall back to local SQLite"
    );
    let authority_issuer = spawn_authority(&issuer, root.path(), 1);
    let issuer_identity_after_recovery = open_issuer_store(&issuer, &issuer_store)
        .expect("issuer recovers against its durable authority database")
        .identity()
        .expect("read issuer identity after authority recovery");
    assert_eq!(
        issuer_identity_after_recovery, issuer_identity_before_outage,
        "issuer authority restart must recover the exact same store generation and commitment"
    );

    // Restore provider 0's pre-initialization authority backup. The detailed
    // provider store requires a current remote floor and rejects Empty. Then
    // put back the fresh authority database and prove explicit recovery.
    let _ = authority0.stop();
    let fresh_provider0_backup = root.path().join("provider0-authority-fresh-snapshot");
    snapshot_database(&provider0.authority_store, &fresh_provider0_backup);
    restore_database(&provider0.authority_store, &stale_provider0_backup);
    let stale_authority0 = spawn_authority(&provider0, root.path(), 1);
    let stale_configured = load_remote_rollback_authority_deployment_for_business_domain_v1(
        &provider0.remote_config,
        provider0.business_id,
    )
    .expect("load provider0 stale authority deployment");
    let (stale_client, _stale_codec, stale_timeout) = stale_configured.into_parts();
    let stale_read = stale_client
        .read_until(Instant::now() + stale_timeout)
        .expect("authenticated raw read from restored stale authority");
    assert!(
        stale_read.current().is_none(),
        "the restored pre-initialization authority must return Ok(None)"
    );
    assert!(
        matches!(
            open_provider_store(&provider0, &provider0_store),
            Err(ProviderStoreError::RollbackFloorMissing)
        ),
        "stale authority backup must fail with RollbackFloorMissing against the detailed store"
    );
    open_provider_store(&provider1, &provider1_store)
        .expect("provider1 is unaffected by provider0 stale restore");
    open_issuer_store(&issuer, &issuer_store)
        .expect("issuer is unaffected by provider0 stale restore");
    let _ = stale_authority0.stop();
    restore_database(&provider0.authority_store, &fresh_provider0_backup);
    authority0 = spawn_authority(&provider0, root.path(), 2);
    open_provider_store(&provider0, &provider0_store)
        .expect("provider0 recovers only after the current authority DB is restored");

    // Keep all recovered processes alive until every final cross-domain check
    // has completed, then kill/wait every local helper and inspect the complete
    // helper log set for payment or authority-binding material.
    assert_ne!(authority0.id(), authority1.id());
    assert_ne!(authority0.id(), authority_issuer.id());
    let _ = authority0.stop();
    let _ = authority1.stop();
    let _ = authority_issuer.stop();
    let _ = tls0.stop();
    let _ = tls1.stop();
    let _ = tls_issuer.stop();
    assert_topology_logs_are_coarse(root.path(), &domains);
}

#[allow(clippy::too_many_arguments)]
fn prepare_domain(
    root: &Path,
    label: &'static str,
    business_id: [u8; 32],
    authority_port: u16,
    tls_port: u16,
    leaf_certificate_pem: &str,
    leaf_private_key_pem: &str,
    pin: &'static str,
) -> AuthorityDomain {
    let domain = root.join(label);
    let authority_directory = domain.join("authority");
    let client_directory = domain.join("client");
    let edge_directory = domain.join("tls-edge");
    for directory in [
        &domain,
        &authority_directory,
        &client_directory,
        &edge_directory,
    ] {
        fs::create_dir(directory).expect("create authority topology directory");
        chmod(directory, 0o700);
    }
    let authority_secret = authority_directory.join("authority.seed");
    let authority_metadata = authority_directory.join("authority-public.txt");
    let authority_store = authority_directory.join("authority.sqlite3");
    let client_secret = client_directory.join("client.seed");
    let value_root = client_directory.join("value-root.raw");
    let client_metadata = client_directory.join("client-public.txt");
    run_authority_cli(vec![
        "rollback-authority".to_owned(),
        "generate-authority".to_owned(),
        "--secret-out".to_owned(),
        authority_secret.display().to_string(),
        "--metadata-out".to_owned(),
        authority_metadata.display().to_string(),
    ]);
    run_authority_cli(vec![
        "rollback-authority".to_owned(),
        "generate-client".to_owned(),
        "--secret-out".to_owned(),
        client_secret.display().to_string(),
        "--value-root-key-out".to_owned(),
        value_root.display().to_string(),
        "--metadata-out".to_owned(),
        client_metadata.display().to_string(),
    ]);
    run_authority_cli(vec![
        "rollback-authority".to_owned(),
        "init-store".to_owned(),
        "--store".to_owned(),
        authority_store.display().to_string(),
        "--authority-metadata".to_owned(),
        authority_metadata.display().to_string(),
        "--busy-timeout-ms".to_owned(),
        "1000".to_owned(),
    ]);
    run_authority_cli(vec![
        "rollback-authority".to_owned(),
        "provision".to_owned(),
        "--store".to_owned(),
        authority_store.display().to_string(),
        "--authority-metadata".to_owned(),
        authority_metadata.display().to_string(),
        "--client-metadata".to_owned(),
        client_metadata.display().to_string(),
        "--max-operation-rows".to_owned(),
        "128".to_owned(),
        "--max-call-rows".to_owned(),
        "2048".to_owned(),
    ]);

    let test_root = client_directory.join("test-root.pem");
    let leaf_certificate = edge_directory.join("localhost-leaf.pem");
    let leaf_private_key = edge_directory.join("localhost-leaf.key");
    write_private_file(&test_root, TEST_ROOT_CERTIFICATE_PEM.as_bytes());
    write_private_file(&leaf_certificate, leaf_certificate_pem.as_bytes());
    write_private_file(&leaf_private_key, leaf_private_key_pem.as_bytes());

    let authority_instance_id_hex = metadata_field(&authority_metadata, "authority_instance_id");
    let authority_verifying_key_hex =
        metadata_field(&authority_metadata, "authority_verifying_key");
    let namespace_hex = metadata_field(&client_metadata, "namespace");
    let client_verifying_key_hex = metadata_field(&client_metadata, "client_verifying_key");
    let material = AuthorityDomain {
        label,
        business_id,
        authority_port,
        tls_port,
        authority_secret,
        authority_metadata,
        authority_store,
        client_secret,
        value_root,
        remote_config: client_directory.join("remote-authority.toml"),
        test_root,
        leaf_certificate,
        leaf_private_key,
        authority_instance_id_hex,
        authority_verifying_key_hex,
        namespace_hex,
        client_verifying_key_hex,
        pin,
    };
    write_remote_config(
        &material.remote_config,
        &material,
        &material.namespace_hex,
        &material.client_verifying_key_hex,
        &material.client_secret,
        &material.value_root,
        material.pin,
    );
    material
}

fn write_remote_config(
    path: &Path,
    authority: &AuthorityDomain,
    namespace_hex: &str,
    client_verifying_key_hex: &str,
    client_secret: &Path,
    value_root: &Path,
    pin: &str,
) {
    let text = format!(
        "schema = \"bitcoinpir_remote_rollback_authority_v1\"\nendpoint = {:?}\nauthority_instance_id_hex = {:?}\nauthority_verifying_key_hex = {:?}\nnamespace_hex = {:?}\nclient_verifying_key_hex = {:?}\nclient_signing_seed_path = {:?}\nvalue_root_key_path = {:?}\nleaf_spki_sha256_pins_hex = [{pin:?}]\nconnect_timeout_ms = 500\nio_timeout_ms = 1000\nattempt_timeout_ms = 1500\noperation_timeout_ms = 4500\ntest_only_webpki_root_pem_path = {:?}\n",
        format!("https://localhost:{}", authority.tls_port),
        authority.authority_instance_id_hex,
        authority.authority_verifying_key_hex,
        namespace_hex,
        client_verifying_key_hex,
        client_secret.display().to_string(),
        value_root.display().to_string(),
        authority.test_root.display().to_string(),
    );
    write_private_file(path, text.as_bytes());
}

fn assert_domain_material_is_independent(domains: &[&AuthorityDomain; 3]) {
    for select in [
        domains
            .iter()
            .map(|domain| domain.authority_instance_id_hex.as_str())
            .collect::<Vec<_>>(),
        domains
            .iter()
            .map(|domain| domain.authority_verifying_key_hex.as_str())
            .collect(),
        domains
            .iter()
            .map(|domain| domain.namespace_hex.as_str())
            .collect(),
        domains
            .iter()
            .map(|domain| domain.client_verifying_key_hex.as_str())
            .collect(),
        domains.iter().map(|domain| domain.pin).collect(),
    ] {
        assert_eq!(select.iter().copied().collect::<BTreeSet<_>>().len(), 3);
    }
    assert_distinct_file_contents(&domains.map(|domain| domain.authority_secret.as_path()));
    assert_distinct_file_contents(&domains.map(|domain| domain.client_secret.as_path()));
    assert_distinct_file_contents(&domains.map(|domain| domain.value_root.as_path()));
    assert_distinct_file_contents(&domains.map(|domain| domain.authority_store.as_path()));
    assert_distinct_file_contents(&domains.map(|domain| domain.leaf_certificate.as_path()));
    for paths in [
        domains.map(|domain| domain.authority_store.as_path()),
        domains.map(|domain| domain.leaf_certificate.as_path()),
        domains.map(|domain| domain.remote_config.as_path()),
    ] {
        let inodes = paths
            .iter()
            .map(|path| fs::metadata(path).expect("topology file metadata").ino())
            .collect::<BTreeSet<_>>();
        assert_eq!(inodes.len(), 3, "authority topology paths must not alias");
    }
}

fn assert_distinct_file_contents(paths: &[&Path; 3]) {
    let values = paths
        .iter()
        .map(|path| fs::read(path).expect("read private topology fixture"))
        .collect::<Vec<_>>();
    assert!(values[0] != values[1] && values[0] != values[2] && values[1] != values[2]);
}

fn assert_topology_logs_are_coarse(root: &Path, domains: &[&AuthorityDomain; 3]) {
    let mut forbidden = [
        "invoice",
        "invoice_id",
        "invoice-id",
        "invoice id",
        "lightning invoice",
        "payment_hash",
        "payment-hash",
        "payment hash",
        "paymenthash",
        "payment_preimage",
        "payment-preimage",
        "preimage",
        "bolt11",
        "lnbc",
        "lnbcrt",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    for domain in domains {
        forbidden.extend(
            [
                domain.authority_instance_id_hex.as_str(),
                domain.authority_verifying_key_hex.as_str(),
                domain.namespace_hex.as_str(),
                domain.client_verifying_key_hex.as_str(),
                domain.pin,
            ]
            .into_iter()
            .map(|value| value.to_ascii_lowercase()),
        );
        forbidden.push(hex::encode(domain.business_id));
        for path in [
            &domain.authority_secret,
            &domain.authority_metadata,
            &domain.authority_store,
            &domain.client_secret,
            &domain.value_root,
            &domain.remote_config,
            &domain.test_root,
            &domain.leaf_certificate,
            &domain.leaf_private_key,
        ] {
            forbidden.push(path.to_string_lossy().to_ascii_lowercase());
        }
        forbidden.push(
            sqlite_sidecar(&domain.authority_store, "-wal")
                .to_string_lossy()
                .to_ascii_lowercase(),
        );
        forbidden.push(
            sqlite_sidecar(&domain.authority_store, "-shm")
                .to_string_lossy()
                .to_ascii_lowercase(),
        );
        for secret_path in [
            &domain.authority_secret,
            &domain.client_secret,
            &domain.value_root,
            &domain.leaf_private_key,
        ] {
            append_secret_log_oracles(&mut forbidden, secret_path);
        }
    }
    for entry in fs::read_dir(root).expect("read topology helper logs") {
        let path = entry.expect("topology log entry").path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("log") {
            continue;
        }
        let log = fs::read_to_string(&path)
            .expect("read topology helper log")
            .to_ascii_lowercase();
        for (forbidden_index, value) in forbidden.iter().enumerate() {
            assert!(
                !log.contains(value),
                "topology helper log {} exposed forbidden private material category {forbidden_index}",
                path.display(),
            );
        }
    }
}

fn append_secret_log_oracles(forbidden: &mut Vec<String>, path: &Path) {
    let secret = fs::read(path).expect("read topology secret for log oracle");
    forbidden.push(hex::encode(&secret));
    if let Ok(text) = std::str::from_utf8(&secret) {
        let trimmed = text.trim();
        if trimmed.len() >= 16 {
            forbidden.push(trimmed.to_ascii_lowercase());
        }
        forbidden.extend(
            text.lines()
                .map(str::trim)
                .filter(|line| line.len() >= 16 && !line.starts_with("-----"))
                .map(str::to_ascii_lowercase),
        );
    }
}

fn load_descriptors(
    configs: &[&Path; 3],
) -> Vec<pir_rollback_authority_client::RemoteRollbackAuthorityDeploymentDescriptorV1> {
    configs
        .iter()
        .map(|config| {
            load_remote_rollback_authority_deployment_descriptor_v1(config)
                .expect("load public authority deployment descriptor")
        })
        .collect()
}

fn assert_deployment_set_rejected(configs: [&PathBuf; 3], label: &str) {
    let descriptors = load_descriptors(&configs.map(PathBuf::as_path));
    assert_eq!(
        validate_independent_remote_rollback_authority_deployments_v1(&descriptors),
        Err(RemoteAuthorityDeploymentConfigErrorV1::DeploymentSetNotIndependent),
        "{label} must invalidate the three-authority deployment set"
    );
}

fn spawn_authority(domain: &AuthorityDomain, root: &Path, generation: u8) -> HelperProcess {
    let mut process = spawn_authority_helper(
        root,
        domain.label,
        generation,
        domain.authority_port,
        AuthorityHelperFiles {
            store: &domain.authority_store,
            secret: &domain.authority_secret,
            metadata: &domain.authority_metadata,
            verifying_key_hex: &domain.authority_verifying_key_hex,
        },
    );
    process.wait_until_listening(domain.authority_port);
    process
}

fn spawn_tls(domain: &AuthorityDomain, root: &Path, generation: u8) -> HelperProcess {
    let label = match domain.label {
        "provider0-authority" => "provider0-authority-tls",
        "provider1-authority" => "provider1-authority-tls",
        "issuer-authority" => "issuer-authority-tls",
        _ => panic!("unexpected topology domain"),
    };
    let mut process = spawn_tls_edge_helper(
        root,
        label,
        generation,
        domain.tls_port,
        domain.authority_port,
        &domain.leaf_certificate,
        &domain.leaf_private_key,
    );
    process.wait_until_listening(domain.tls_port);
    process
}

fn assert_remote_read_error(
    config: &Path,
    business_id: [u8; 32],
    label: &str,
    expected_error: RemoteAuthorityCallErrorV1,
) {
    let configured =
        load_remote_rollback_authority_deployment_for_business_domain_v1(config, business_id)
            .unwrap_or_else(|error| {
                panic!("{label} config did not reach remote boundary: {error}")
            });
    let (client, _codec, timeout) = configured.into_parts();
    assert_eq!(
        client
            .read_until(Instant::now() + timeout)
            .expect_err("remote authority configuration unexpectedly authenticated"),
        expected_error,
        "{label} returned the wrong remote-call classification"
    );
}

fn provider_authority(
    domain: &AuthorityDomain,
    expected_provider_id: [u8; 32],
) -> RemoteProviderRollbackFloorAuthorityV1 {
    let configured = load_remote_rollback_authority_deployment_for_business_domain_v1(
        &domain.remote_config,
        expected_provider_id,
    )
    .expect("load provider authority deployment");
    let (client, codec, timeout) = configured.into_parts();
    RemoteProviderRollbackFloorAuthorityV1::new(expected_provider_id, client, codec, timeout)
        .expect("bind provider rollback authority")
}

fn issuer_authority(domain: &AuthorityDomain) -> RemoteIssuerRollbackFloorAuthorityV1 {
    let configured = load_remote_rollback_authority_deployment_for_business_domain_v1(
        &domain.remote_config,
        domain.business_id,
    )
    .expect("load issuer authority deployment");
    let (client, codec, timeout) = configured.into_parts();
    RemoteIssuerRollbackFloorAuthorityV1::new(
        domain.business_id,
        LightningNetworkV1::Regtest,
        client,
        codec,
        timeout,
    )
    .expect("bind issuer rollback authority")
}

fn create_provider_store(domain: &AuthorityDomain, path: &Path, store_instance_id: [u8; 16]) {
    ProviderStore::create(
        path,
        store_instance_id,
        domain.business_id,
        provider_store_options(),
        Arc::new(provider_authority(domain, domain.business_id)),
    )
    .expect("create provider store through its remote authority");
}

fn open_provider_store(
    domain: &AuthorityDomain,
    path: &Path,
) -> pir_service_store::StoreResult<ProviderStore> {
    ProviderStore::open_existing(
        path,
        domain.business_id,
        provider_store_options(),
        Arc::new(provider_authority(domain, domain.business_id)),
    )
}

fn provider_store_options() -> StoreOptions {
    StoreOptions {
        busy_timeout: Duration::from_secs(1),
    }
}

fn create_issuer_store(domain: &AuthorityDomain, path: &Path, store_instance_id: [u8; 16]) {
    IssuerStore::create(
        path,
        store_instance_id,
        domain.business_id,
        LightningNetworkV1::Regtest,
        IssuerStoreOptions {
            busy_timeout: Duration::from_secs(1),
        },
        Arc::new(issuer_authority(domain)),
    )
    .expect("create issuer store through its remote authority");
}

fn open_issuer_store(
    domain: &AuthorityDomain,
    path: &Path,
) -> pir_issuer_store::StoreResult<IssuerStore> {
    IssuerStore::open_existing(
        path,
        domain.business_id,
        LightningNetworkV1::Regtest,
        IssuerStoreOptions {
            busy_timeout: Duration::from_secs(1),
        },
        Arc::new(issuer_authority(domain)),
    )
}

fn run_authority_cli(arguments: Vec<String>) {
    let cli = RollbackAuthorityCli::try_parse_from(arguments).expect("parse authority ceremony");
    run_rollback_authority(cli).expect("complete authority ceremony");
}

fn metadata_field(path: &Path, name: &str) -> String {
    fs::read_to_string(path)
        .expect("read public authority metadata")
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}=")))
        .unwrap_or_else(|| panic!("missing authority metadata field {name}"))
        .to_owned()
}

fn write_private_file(path: &Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .expect("create private topology file");
    file.write_all(bytes).expect("write private topology file");
    file.sync_all().expect("sync private topology file");
    chmod(path, 0o600);
}

fn snapshot_database(database: &Path, snapshot_directory: &Path) {
    fs::create_dir(snapshot_directory).expect("create authority snapshot directory");
    chmod(snapshot_directory, 0o700);
    // A stopped WAL database is the main file plus an optional WAL. The SHM
    // file is transient coordination state and must be rebuilt on reopen.
    for source in [database.to_path_buf(), sqlite_sidecar(database, "-wal")] {
        if source.exists() {
            let name = source.file_name().expect("authority snapshot file name");
            let destination = snapshot_directory.join(name);
            fs::copy(&source, &destination).expect("copy authority database snapshot file");
            chmod(&destination, 0o600);
        }
    }
}

fn restore_database(destination: &Path, snapshot_directory: &Path) {
    for path in [
        destination.to_path_buf(),
        sqlite_sidecar(destination, "-wal"),
        sqlite_sidecar(destination, "-shm"),
    ] {
        if path.exists() {
            fs::remove_file(path).expect("remove temporary authority database generation");
        }
    }
    let database_name = destination
        .file_name()
        .expect("authority destination file name");
    for source in fs::read_dir(snapshot_directory)
        .expect("read authority snapshot directory")
        .map(|entry| entry.expect("authority snapshot directory entry").path())
    {
        let source_name = source.file_name().expect("authority snapshot file name");
        let destination_path = if source_name == database_name {
            destination.to_path_buf()
        } else if source_name.to_string_lossy().ends_with("-wal") {
            sqlite_sidecar(destination, "-wal")
        } else {
            panic!("unexpected authority snapshot file")
        };
        fs::copy(&source, &destination_path).expect("restore authority database snapshot file");
        chmod(&destination_path, 0o600);
    }
    assert!(
        destination.is_file(),
        "authority snapshot has no main database"
    );
}

fn sqlite_sidecar(database: &Path, suffix: &str) -> PathBuf {
    let mut path = database.as_os_str().to_os_string();
    path.push(suffix);
    PathBuf::from(path)
}

fn distinct_ports(count: usize) -> Vec<u16> {
    let mut ports = Vec::with_capacity(count);
    while ports.len() < count {
        let port = unused_loopback_port();
        if !ports.contains(&port) {
            ports.push(port);
        }
    }
    ports
}
