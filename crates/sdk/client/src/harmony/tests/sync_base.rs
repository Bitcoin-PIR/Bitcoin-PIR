//! A plan that only carries changes must run on the previous sync's results.
//! `sync()` keeps none, so it only accepts a full sync.

use super::super::*;
use super::fixtures::*;
use crate::transport::mock::MockTransport;

const ADDRS: [ScriptHash; 2] = [[0x11; 20], [0x22; 20]];

/// `sample_db_info()` (full snapshot at 100, db 0) plus a delta 100 -> 110.
fn full_plus_delta() -> DatabaseCatalog {
    let full = sample_db_info();
    let mut delta = full.clone();
    delta.db_id = 1;
    delta.kind = DatabaseKind::Delta {
        base_height: full.height,
    };
    delta.height = full.height + 10;
    DatabaseCatalog {
        databases: vec![full, delta],
    }
}

fn mock_client() -> HarmonyClient {
    let mut client = HarmonyClient::new("mock://hint", "mock://query");
    client.connect_with_transport(
        Box::new(MockTransport::new("mock://hint")),
        Box::new(MockTransport::new("mock://query")),
    );
    client.catalog = Some(full_plus_delta());
    client
}

#[tokio::test]
async fn sync_rejects_any_height_before_planning() {
    let mut client = mock_client();
    // From 50 there is no delta chain, so the plan would fall back to a full
    // sync against the empty mock; it is refused before that.
    for height in [50, 100, 110] {
        let error = client.sync(&ADDRS, Some(height)).await.unwrap_err();
        assert!(
            matches!(error, PirError::InvalidState(_)),
            "{height}: {error}"
        );

        let recorder = RecordingSyncProgress::default();
        let error = client
            .sync_with_progress(&ADDRS, Some(height), &recorder)
            .await
            .unwrap_err();
        assert!(
            matches!(error, PirError::InvalidState(_)),
            "{height}: {error}"
        );
        let events = recorder.events.lock().unwrap();
        assert!(
            events.len() == 1 && events[0].starts_with("error:"),
            "{events:?}"
        );
    }
}

#[tokio::test]
async fn delta_and_tip_plans_need_the_previous_results() {
    let mut client = mock_client();
    let catalog = full_plus_delta();
    let delta = compute_sync_plan(&catalog, Some(100)).unwrap();
    let at_tip = compute_sync_plan(&catalog, Some(110)).unwrap();
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
    assert_eq!(synced.synced_height, 110);
    assert!(synced.results[0].is_some() && synced.results[1].is_none());
}
