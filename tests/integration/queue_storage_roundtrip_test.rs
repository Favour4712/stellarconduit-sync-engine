//! End-to-end test wiring the pieces of the sync engine together the way a
//! wallet would: reserve a sequence number, sign an envelope offline, persist
//! it durably, hand it to the mesh, and mark it settled once a relay node
//! confirms it.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use stellarconduit_core::message::envelope::validate_envelope;
use stellarconduit_sync_engine::envelope::OfflineEnvelopeBuilder;
use stellarconduit_sync_engine::queue::SequenceReservationManager;
use stellarconduit_sync_engine::settlement::SettlementStatus;
use stellarconduit_sync_engine::storage::SyncEngineDb;

#[tokio::test]
async fn test_reserve_sign_persist_and_settle() {
    let db = SyncEngineDb::init(":memory:").await.unwrap();
    let mut sequences = SequenceReservationManager::new();
    let signing_key = SigningKey::generate(&mut OsRng);
    let source_account = "GABCEXAMPLE";

    // A device that last saw connectivity knows the account's on-chain
    // sequence number; seed from there before queuing anything offline.
    sequences.seed(source_account, 100);

    let (envelope, sequence) = OfflineEnvelopeBuilder::build_and_sign(
        &mut sequences,
        source_account,
        &signing_key,
        "mock_tx_xdr",
        10,
    )
    .unwrap();
    assert_eq!(sequence, 101);
    assert!(validate_envelope(&envelope).is_ok());

    db.enqueue_envelope(
        &envelope,
        source_account,
        sequence,
        stellarconduit_sync_engine::queue::TxPriority::Emergency,
        1_700_000_000,
    )
    .await
    .unwrap();
    db.save_sequence_reservation(source_account, sequence)
        .await
        .unwrap();
    db.set_settlement_status(envelope.message_id, SettlementStatus::Queued, 1_700_000_000)
        .await
        .unwrap();

    // Simulate a restart: everything needed to resume must be recoverable
    // from durable storage alone.
    let restored = db
        .get_queued_envelope(envelope.message_id)
        .await
        .unwrap()
        .expect("envelope should survive a simulated restart");
    assert_eq!(restored.envelope, envelope);
    assert_eq!(
        db.load_sequence_reservation(source_account).await.unwrap(),
        Some(101)
    );

    // Hand off to the mesh, then confirm settlement once a relay reports back.
    db.set_settlement_status(
        envelope.message_id,
        SettlementStatus::Propagating,
        1_700_000_100,
    )
    .await
    .unwrap();
    db.set_settlement_status(
        envelope.message_id,
        SettlementStatus::Settled,
        1_700_000_200,
    )
    .await
    .unwrap();

    let status = db.get_settlement_status(envelope.message_id).await.unwrap();
    assert_eq!(status, Some(SettlementStatus::Settled));

    db.remove_queued_envelope(envelope.message_id)
        .await
        .unwrap();
    assert!(db
        .get_queued_envelope(envelope.message_id)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn test_conflicting_envelopes_for_same_slot_are_detected_and_recorded() {
    use stellarconduit_sync_engine::conflict::{conflicts_between, QueuedSlot};

    let db = SyncEngineDb::init(":memory:").await.unwrap();
    let mut sequences = SequenceReservationManager::new();
    let key_a = SigningKey::generate(&mut OsRng);
    let key_b = SigningKey::generate(&mut OsRng);
    let source_account = "GSHARED";
    sequences.seed(source_account, 50);

    // Two devices sharing the same account, both offline, both build a
    // payment against the same reserved sequence before either learns about
    // the other — a classic split-mesh double-spend setup.
    let (envelope_a, seq_a) =
        OfflineEnvelopeBuilder::build_and_sign(&mut sequences, source_account, &key_a, "xdr_a", 10)
            .unwrap();

    // Reset the manager to simulate the second device's independent, stale view.
    let mut sequences_b = SequenceReservationManager::new();
    sequences_b.seed(source_account, 50);
    let (envelope_b, seq_b) = OfflineEnvelopeBuilder::build_and_sign(
        &mut sequences_b,
        source_account,
        &key_b,
        "xdr_b",
        10,
    )
    .unwrap();

    assert_eq!(seq_a, seq_b);

    let slot_a = QueuedSlot {
        source_account: source_account.to_string(),
        sequence: seq_a,
        message_id: envelope_a.message_id,
    };
    let slot_b = QueuedSlot {
        source_account: source_account.to_string(),
        sequence: seq_b,
        message_id: envelope_b.message_id,
    };

    let conflict = conflicts_between(&slot_a, &slot_b).expect("should detect a conflict");
    db.record_conflict(&conflict, 1_700_000_300).await.unwrap();

    let unresolved = db.list_unresolved_conflicts().await.unwrap();
    assert_eq!(unresolved.len(), 1);
    assert_eq!(unresolved[0], conflict);
}
