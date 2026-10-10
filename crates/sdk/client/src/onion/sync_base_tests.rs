//! A plan that only carries changes must run on the previous sync's results.
//! `sync()` keeps none, so it only accepts a full sync.

use super::*;
use crate::transport::mock::MockTransport;

const BASE: u32 = 940_611;
const TIP: u32 = 948_454;
const ADDRS: [ScriptHash; 2] = [[0x11; 20], [0x22; 20]];

fn test_db(db_id: u8, kind: DatabaseKind) -> DatabaseInfo {
    DatabaseInfo {
        db_id,
        kind,
        name: format!("db{db_id}"),
        height: TIP,
        index_bins: 10_273,
        chunk_bins: 20_547,
        index_k: 75,
        chunk_k: 80,
        tag_seed: 7,
        dpf_n_index: pir_core::params::compute_dpf_n(10_273),
        dpf_n_chunk: pir_core::params::compute_dpf_n(20_547),
        has_bucket_merkle: true,
        index_master_seed: 0,
        chunk_master_seed: 0,
        anchor_kind: 0,
        anchor_bytes: Vec::new(),
    }
}

/// The production shape: a full snapshot at TIP and a delta BASE -> TIP.
fn catalog() -> DatabaseCatalog {
    DatabaseCatalog {
        databases: vec![
            test_db(0, DatabaseKind::Full),
            test_db(1, DatabaseKind::Delta { base_height: BASE }),
        ],
    }
}

fn mock_client() -> OnionClient {
    let mut client = OnionClient::new("wss://mock-onion");
    client.connect_with_transport(Box::new(MockTransport::new("wss://mock-onion")));
    client.catalog = Some(catalog());
    client
}

#[tokio::test]
async fn sync_rejects_any_height_before_planning() {
    let mut client = mock_client();
    // From 900,000 there is no delta chain, so the plan would fall back to a
    // full sync against the empty mock; it is refused before that.
    for height in [900_000, BASE, TIP] {
        let error = client.sync(&ADDRS, Some(height)).await.unwrap_err();
        assert!(
            matches!(error, PirError::InvalidState(_)),
            "{height}: {error}"
        );
    }
}

#[tokio::test]
async fn delta_and_tip_plans_need_the_previous_results() {
    let mut client = mock_client();
    let delta = compute_sync_plan(&catalog(), Some(BASE)).unwrap();
    let at_tip = compute_sync_plan(&catalog(), Some(TIP)).unwrap();
    for plan in [&delta, &at_tip] {
        let error = client.sync_with_plan(&ADDRS, plan, None).await.unwrap_err();
        assert!(matches!(error, PirError::InvalidState(_)), "{error}");
    }

    // At the tip the previous results come back unchanged, without any I/O.
    let previous = vec![Some(QueryResult::empty()), None];
    let synced = client
        .sync_with_plan(&ADDRS, &at_tip, Some(&previous))
        .await
        .unwrap();
    assert_eq!(synced.synced_height, TIP);
    assert!(synced.results[0].is_some() && synced.results[1].is_none());
}
