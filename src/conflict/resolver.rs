//! Deterministic off-chain resolution of a detected [`Conflict`].
//!
//! This is the flagship hard problem of the sync engine and is intentionally
//! **not implemented** in this scaffold. Per the protocol architecture, a real
//! resolution algorithm must combine:
//!
//! - envelope timestamps (`TransactionEnvelope.timestamp`),
//! - cryptographic relay-chain proofs
//!   (`stellarconduit_core::message::relay_proof::RelayChainProof`) showing how
//!   far and through which relays each side of the conflict propagated, and
//! - a consensus mechanism among the relay nodes that observed each side,
//!
//! to decide deterministically — and identically on every node that runs the
//! algorithm — which envelope is valid. Conflicts this algorithm cannot
//! settle are the ones that legitimately need on-chain arbitration via the
//! `dispute-resolver` Soroban contract in `stellarconduit-contracts`.
//!
//! For now, every conflict is unresolved off-chain; callers should move both
//! sides of the conflict to `SettlementStatus::Disputed`.

use crate::conflict::detector::Conflict;
use crate::errors::SyncEngineError;

/// Attempt to resolve `conflict` off-chain, returning the `message_id` of the
/// envelope determined to be valid.
///
/// Always returns `Err(SyncEngineError::UnresolvedConflict)` today — see
/// module docs.
pub fn resolve_conflict(conflict: &Conflict) -> Result<[u8; 32], SyncEngineError> {
    Err(SyncEngineError::UnresolvedConflict(format!(
        "conflict on account {} sequence {} between {} and {} requires relay-chain proof \
         consensus, which is not yet implemented",
        conflict.source_account,
        conflict.sequence,
        hex::encode(conflict.envelope_a),
        hex::encode(conflict.envelope_b),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conflict::detector::conflicts_between;
    use crate::conflict::detector::QueuedSlot;

    #[test]
    fn test_resolve_conflict_is_unresolved_by_default() {
        let a = QueuedSlot {
            source_account: "GABC".to_string(),
            sequence: 101,
            message_id: [1u8; 32],
        };
        let b = QueuedSlot {
            source_account: "GABC".to_string(),
            sequence: 101,
            message_id: [2u8; 32],
        };
        let conflict = conflicts_between(&a, &b).unwrap();
        let result = resolve_conflict(&conflict);
        assert!(matches!(
            result,
            Err(SyncEngineError::UnresolvedConflict(_))
        ));
    }
}
