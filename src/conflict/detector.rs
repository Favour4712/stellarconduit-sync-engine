//! Structural double-spend detection.
//!
//! `TransactionEnvelope.tx_xdr` is an opaque, already-built Stellar XDR blob
//! (see `stellarconduit_core::message::envelope`) — this crate does not parse
//! XDR. Instead, the source account and reserved sequence number for each
//! queued envelope are tracked explicitly at enqueue time (see
//! `crate::storage::db`), and conflicts are detected structurally: two
//! *different* envelopes claiming the same (account, sequence) slot can never
//! both settle on-chain, since Stellar accepts only one transaction per
//! sequence number.
//!
//! Deciding *which* of the two is valid is the hard part — see
//! `crate::conflict::resolver`.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedSlot {
    pub source_account: String,
    pub sequence: i64,
    pub message_id: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    pub source_account: String,
    pub sequence: i64,
    pub envelope_a: [u8; 32],
    pub envelope_b: [u8; 32],
}

/// Returns a conflict if `a` and `b` occupy the same (account, sequence) slot
/// but are different envelopes. Returns `None` if they're the same envelope
/// (e.g. seen twice via different gossip paths) or occupy different slots.
pub fn conflicts_between(a: &QueuedSlot, b: &QueuedSlot) -> Option<Conflict> {
    if a.source_account != b.source_account || a.sequence != b.sequence {
        return None;
    }
    if a.message_id == b.message_id {
        return None;
    }
    Some(Conflict {
        source_account: a.source_account.clone(),
        sequence: a.sequence,
        envelope_a: a.message_id,
        envelope_b: b.message_id,
    })
}

/// Scan a batch of queued slots (e.g. everything currently durably queued)
/// for double-spend conflicts.
pub fn detect_conflicts(slots: &[QueuedSlot]) -> Vec<Conflict> {
    let mut groups: HashMap<(String, i64), Vec<[u8; 32]>> = HashMap::new();
    for slot in slots {
        groups
            .entry((slot.source_account.clone(), slot.sequence))
            .or_default()
            .push(slot.message_id);
    }

    let mut conflicts = Vec::new();
    for ((account, sequence), mut ids) in groups {
        ids.sort();
        ids.dedup();
        for pair in ids.windows(2) {
            conflicts.push(Conflict {
                source_account: account.clone(),
                sequence,
                envelope_a: pair[0],
                envelope_b: pair[1],
            });
        }
    }
    conflicts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(account: &str, sequence: i64, message_id: u8) -> QueuedSlot {
        QueuedSlot {
            source_account: account.to_string(),
            sequence,
            message_id: [message_id; 32],
        }
    }

    #[test]
    fn test_same_slot_different_envelopes_conflicts() {
        let a = slot("GABC", 101, 1);
        let b = slot("GABC", 101, 2);
        let conflict = conflicts_between(&a, &b).unwrap();
        assert_eq!(conflict.source_account, "GABC");
        assert_eq!(conflict.sequence, 101);
    }

    #[test]
    fn test_same_envelope_seen_twice_is_not_a_conflict() {
        let a = slot("GABC", 101, 1);
        let b = slot("GABC", 101, 1);
        assert!(conflicts_between(&a, &b).is_none());
    }

    #[test]
    fn test_different_sequence_is_not_a_conflict() {
        let a = slot("GABC", 101, 1);
        let b = slot("GABC", 102, 2);
        assert!(conflicts_between(&a, &b).is_none());
    }

    #[test]
    fn test_different_account_is_not_a_conflict() {
        let a = slot("GABC", 101, 1);
        let b = slot("GXYZ", 101, 2);
        assert!(conflicts_between(&a, &b).is_none());
    }

    #[test]
    fn test_detect_conflicts_in_batch() {
        let slots = vec![
            slot("GABC", 101, 1),
            slot("GABC", 101, 2), // conflicts with the above
            slot("GABC", 102, 3), // no conflict, different sequence
            slot("GXYZ", 101, 4), // no conflict, different account
        ];
        let conflicts = detect_conflicts(&slots);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].source_account, "GABC");
        assert_eq!(conflicts[0].sequence, 101);
    }

    #[test]
    fn test_no_conflicts_in_clean_batch() {
        let slots = vec![slot("GABC", 101, 1), slot("GABC", 102, 2)];
        assert!(detect_conflicts(&slots).is_empty());
    }
}
