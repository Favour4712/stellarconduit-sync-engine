//! Deterministic off-chain resolution of a detected [`Conflict`].
//!
//! This is the flagship hard problem of the sync engine: a decision procedure
//! that lets every honest node in the mesh independently reach the same
//! conclusion about which of two conflicting envelopes wins, using only
//! evidence that plausibly propagated to it, with no coordination round.
//!
//! `stellarconduit_core::message::relay_proof::RelayChainProof` proves that
//! *some* relay signed off on `(tx_id, chain_hash, sequence)`, but carries no
//! signer identity of its own — verifying it requires already knowing which
//! `VerifyingKey` to check, and counting distinct relays (required for any
//! Sybil-resistant quorum reasoning) requires knowing each proof's signer.
//! This module closes that gap by requiring callers to pair each proof with
//! the relay's known pubkey at collection time (see [`RelayObservation`]) —
//! e.g. from `stellarconduit_core::peer::identity::PeerIdentity`, which a node
//! already tracks per-peer.
//!
//! Conflicts this algorithm cannot settle remain unresolved off-chain and must
//! go to on-chain arbitration via the `dispute-resolver` Soroban contract in
//! `stellarconduit-contracts`.

use std::collections::HashSet;

use ed25519_dalek::VerifyingKey;
use stellarconduit_core::message::relay_proof::RelayChainProof;

use crate::conflict::detector::Conflict;
use crate::errors::SyncEngineError;

/// Minimum number of *distinct* relays whose valid, verified relay-chain
/// proofs must corroborate a side before that side is even eligible to win.
///
/// This is the Sybil-resistance backstop: an attacker holding a single relay
/// keypair can mint arbitrarily many identical-looking proofs, but they all
/// collapse to one entry in the per-side relay set (see
/// [`count_distinct_valid_relays`]). Requiring at least two distinct relays
/// means a single relay — honest or compromised — can never win a conflict
/// outright, even against a side with zero evidence.
const MIN_QUORUM: usize = 2;

/// A single relay's cryptographically verifiable attestation that it relayed
/// a specific envelope, paired with the relay's known public key.
///
/// [`RelayChainProof`] alone carries no signer identity (see the module
/// docs), so callers must supply the `relay_pubkey` they associate with this
/// proof — normally the identity already recorded on the local peer/relay
/// table at the point the proof was collected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayObservation {
    pub relay_pubkey: [u8; 32],
    pub proof: RelayChainProof,
}

/// Everything a node has locally gathered about both sides of a [`Conflict`]
/// beyond the conflict's own account/sequence/envelope-id bookkeeping.
///
/// This crate never has a global view of the mesh — only whatever gossip
/// plausibly reached this node — so evidence is supplied explicitly by the
/// caller rather than fetched by [`resolve_conflict`] itself. That keeps the
/// function pure and its output fully determined by its arguments, which is
/// what makes it possible for every node to compute the identical result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictEvidence {
    /// `TransactionEnvelope.timestamp` as originally signed by the sender of
    /// `conflict.envelope_a`. Recorded for audit/escalation context (see
    /// [`resolve_conflict`]'s doc comment for why it is not decisive).
    pub envelope_a_timestamp: u64,
    pub envelope_b_timestamp: u64,
    /// Every relay observation that plausibly propagated to this node for
    /// the side identified by `conflict.envelope_a`. Order doesn't matter and
    /// duplicate/repeated entries from the same relay are harmless — they
    /// collapse during dedup.
    pub envelope_a_observations: Vec<RelayObservation>,
    pub envelope_b_observations: Vec<RelayObservation>,
}

/// Filter `observations` down to those that are valid evidence for `tx_id`
/// under `conflict`'s sequence, and return the set of distinct relay pubkeys
/// among the survivors.
///
/// An observation is excluded (not counted as evidence at all) unless both:
/// - `proof.sequence == conflict.sequence` — a proof harvested for a
///   different slot doesn't speak to this conflict, regardless of whether
///   its own signature is otherwise valid;
/// - `proof.verify(relay_pubkey, tx_id)` succeeds — the signature must
///   actually be from `relay_pubkey` over this exact `(tx_id, chain_hash,
///   sequence)` tuple. A malformed pubkey or a signature that doesn't verify
///   is dropped rather than trusted.
///
/// Distinct relay pubkeys are counted, not raw proof count, so that an
/// attacker resubmitting the same relay's proof many times gains nothing.
fn count_distinct_valid_relays(
    observations: &[RelayObservation],
    conflict_sequence: i64,
    tx_id: &[u8; 32],
) -> HashSet<[u8; 32]> {
    let expected_sequence = conflict_sequence as u64;
    observations
        .iter()
        .filter(|obs| obs.proof.sequence == expected_sequence)
        .filter(|obs| {
            VerifyingKey::from_bytes(&obs.relay_pubkey)
                .map(|key| obs.proof.verify(&key, tx_id))
                .unwrap_or(false)
        })
        .map(|obs| obs.relay_pubkey)
        .collect()
}

/// Attempt to resolve `conflict` off-chain, returning the `message_id` of the
/// envelope determined to be valid.
///
/// # Decision procedure
///
/// 1. **Validate, don't trust.** For each side, discard any relay observation
///    whose proof doesn't match `conflict`'s sequence or doesn't verify
///    against the paired relay pubkey for that side's envelope id (see
///    [`count_distinct_valid_relays`]).
/// 2. **Count distinct relays, not proofs.** The surviving observations for
///    each side are deduplicated by relay pubkey. This is the Sybil-resistance
///    mechanism required by the issue: a single relay keypair can mint
///    unlimited proofs, but they all count once.
/// 3. **Quorum + strict majority.** Side A wins iff it has at least
///    [`MIN_QUORUM`] distinct corroborating relays *and* strictly more than
///    side B (symmetrically for B). Both conditions must hold:
///    - the quorum floor means a lone relay — even an honest, perfectly valid
///      one — can never win a conflict outright, satisfying "a single relay
///      lying or being compromised must not be enough to win a conflict";
///    - the strict-majority requirement means a tie at any count (0-vs-0,
///      2-vs-2, 3-vs-3, ...) is *never* decided — it falls through to
///      `Err(UnresolvedConflict)` rather than an arbitrary guess.
/// 4. **Envelope timestamps are recorded, not decisive.** `evidence`'s
///    timestamps are included in the `UnresolvedConflict` message (useful
///    context for the on-chain escalation path) but never influence which
///    side wins or break a tie. A timestamp is self-reported by the
///    envelope's origin — exactly the kind of value an attacker crafting a
///    conflicting envelope is free to backdate — so treating it as evidence
///    would violate the "no trusted third party / cryptographically
///    verifiable evidence only" constraint this algorithm must satisfy. Only
///    the Sybil-resistant relay quorum computed in steps 1–3 is
///    cryptographically anchored, so only it decides.
///
/// Because every step is a pure function of `conflict` and `evidence` — no
/// wall-clock reads, no randomness, no network round-trip — every node that
/// receives the same evidence computes the same result.
pub fn resolve_conflict(
    conflict: &Conflict,
    evidence: &ConflictEvidence,
) -> Result<[u8; 32], SyncEngineError> {
    let relays_a = count_distinct_valid_relays(
        &evidence.envelope_a_observations,
        conflict.sequence,
        &conflict.envelope_a,
    );
    let relays_b = count_distinct_valid_relays(
        &evidence.envelope_b_observations,
        conflict.sequence,
        &conflict.envelope_b,
    );

    let n_a = relays_a.len();
    let n_b = relays_b.len();

    let a_wins = n_a >= MIN_QUORUM && n_a > n_b;
    let b_wins = n_b >= MIN_QUORUM && n_b > n_a;

    match (a_wins, b_wins) {
        (true, false) => Ok(conflict.envelope_a),
        (false, true) => Ok(conflict.envelope_b),
        _ => Err(SyncEngineError::UnresolvedConflict(format!(
            "conflict on account {} sequence {} between {} (timestamp {}, {} verified distinct \
             relay(s)) and {} (timestamp {}, {} verified distinct relay(s)) could not be \
             resolved off-chain: a winning side needs at least {} distinct corroborating relays \
             and strictly more than the other side",
            conflict.source_account,
            conflict.sequence,
            hex::encode(conflict.envelope_a),
            evidence.envelope_a_timestamp,
            n_a,
            hex::encode(conflict.envelope_b),
            evidence.envelope_b_timestamp,
            n_b,
            MIN_QUORUM,
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conflict::detector::conflicts_between;
    use crate::conflict::detector::QueuedSlot;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn relay_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn observation_for(key: &SigningKey, tx_id: &[u8; 32], sequence: u64) -> RelayObservation {
        let chain_hash = [7u8; 32];
        RelayObservation {
            relay_pubkey: key.verifying_key().to_bytes(),
            proof: RelayChainProof::sign(key, tx_id, &chain_hash, sequence),
        }
    }

    fn base_conflict() -> Conflict {
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
        conflicts_between(&a, &b).unwrap()
    }

    fn empty_evidence() -> ConflictEvidence {
        ConflictEvidence {
            envelope_a_timestamp: 1_700_000_000,
            envelope_b_timestamp: 1_700_000_001,
            envelope_a_observations: Vec::new(),
            envelope_b_observations: Vec::new(),
        }
    }

    fn observations_from_n_distinct_relays(
        n: usize,
        tx_id: &[u8; 32],
        sequence: u64,
    ) -> Vec<RelayObservation> {
        (0..n)
            .map(|_| observation_for(&relay_key(), tx_id, sequence))
            .collect()
    }

    #[test]
    fn test_resolve_conflict_is_unresolved_by_default() {
        let conflict = base_conflict();
        let result = resolve_conflict(&conflict, &empty_evidence());
        assert!(matches!(
            result,
            Err(SyncEngineError::UnresolvedConflict(_))
        ));
    }

    #[test]
    fn test_resolution_is_deterministic() {
        let conflict = base_conflict();
        let evidence = ConflictEvidence {
            envelope_a_observations: observations_from_n_distinct_relays(
                3,
                &conflict.envelope_a,
                conflict.sequence as u64,
            ),
            envelope_b_observations: observations_from_n_distinct_relays(
                1,
                &conflict.envelope_b,
                conflict.sequence as u64,
            ),
            ..empty_evidence()
        };

        let first = resolve_conflict(&conflict, &evidence);
        let second = resolve_conflict(&conflict, &evidence);
        assert_eq!(first.unwrap(), second.unwrap());
    }

    #[test]
    fn test_stronger_evidence_side_wins() {
        let conflict = base_conflict();
        let evidence = ConflictEvidence {
            envelope_a_observations: observations_from_n_distinct_relays(
                3,
                &conflict.envelope_a,
                conflict.sequence as u64,
            ),
            envelope_b_observations: observations_from_n_distinct_relays(
                1,
                &conflict.envelope_b,
                conflict.sequence as u64,
            ),
            ..empty_evidence()
        };

        let winner = resolve_conflict(&conflict, &evidence).unwrap();
        assert_eq!(winner, conflict.envelope_a);
    }

    #[test]
    fn test_single_relay_insufficient_against_multi_relay() {
        let conflict = base_conflict();
        // Side A is backed by a single relay keypair which resubmits the same
        // proof several times, trying to look like more than one witness.
        let single_relay = relay_key();
        let duplicated_proof = observation_for(
            &single_relay,
            &conflict.envelope_a,
            conflict.sequence as u64,
        );
        let evidence = ConflictEvidence {
            envelope_a_observations: vec![
                duplicated_proof.clone(),
                duplicated_proof.clone(),
                duplicated_proof,
            ],
            envelope_b_observations: observations_from_n_distinct_relays(
                3,
                &conflict.envelope_b,
                conflict.sequence as u64,
            ),
            ..empty_evidence()
        };

        let winner = resolve_conflict(&conflict, &evidence).unwrap();
        assert_eq!(
            winner, conflict.envelope_b,
            "3 distinct relays must beat 1 relay no matter how many times it resubmits"
        );
    }

    #[test]
    fn test_equal_evidence_is_unresolved() {
        let conflict = base_conflict();
        let evidence = ConflictEvidence {
            envelope_a_observations: observations_from_n_distinct_relays(
                2,
                &conflict.envelope_a,
                conflict.sequence as u64,
            ),
            envelope_b_observations: observations_from_n_distinct_relays(
                2,
                &conflict.envelope_b,
                conflict.sequence as u64,
            ),
            ..empty_evidence()
        };

        assert!(matches!(
            resolve_conflict(&conflict, &evidence),
            Err(SyncEngineError::UnresolvedConflict(_))
        ));
    }

    #[test]
    fn test_no_evidence_is_unresolved() {
        let conflict = base_conflict();
        assert!(matches!(
            resolve_conflict(&conflict, &empty_evidence()),
            Err(SyncEngineError::UnresolvedConflict(_))
        ));
    }

    #[test]
    fn test_malformed_proof_is_rejected_not_trusted() {
        let conflict = base_conflict();

        // Side A: 3 distinct relays sign for the *wrong* sequence number, so
        // none of them should count as valid evidence for this conflict, even
        // though each proof is a genuine, validly-signed RelayChainProof.
        let wrong_sequence = conflict.sequence as u64 + 1;
        let envelope_a_observations =
            observations_from_n_distinct_relays(3, &conflict.envelope_a, wrong_sequence);

        // Side B: 3 distinct relays sign correctly for this conflict's
        // sequence.
        let envelope_b_observations =
            observations_from_n_distinct_relays(3, &conflict.envelope_b, conflict.sequence as u64);

        let evidence = ConflictEvidence {
            envelope_a_observations,
            envelope_b_observations,
            ..empty_evidence()
        };

        // If the malformed proofs on side A had been trusted, this would be a
        // 3-vs-3 tie (Unresolved). Because they must be excluded, side A's
        // valid count is actually 0, so side B wins outright.
        let winner = resolve_conflict(&conflict, &evidence).unwrap();
        assert_eq!(winner, conflict.envelope_b);
    }

    #[test]
    fn test_wrong_signature_proof_is_rejected() {
        let conflict = base_conflict();
        // A proof correctly signed for a *different* tx_id (e.g. harvested
        // for envelope_b) must not verify against envelope_a's tx_id, so it
        // shouldn't count as evidence for side A even paired with the
        // correct signer pubkey.
        let key = relay_key();
        let mismatched = RelayObservation {
            relay_pubkey: key.verifying_key().to_bytes(),
            proof: RelayChainProof::sign(
                &key,
                &conflict.envelope_b,
                &[7u8; 32],
                conflict.sequence as u64,
            ),
        };

        let evidence = ConflictEvidence {
            envelope_a_observations: vec![
                mismatched,
                observation_for(&relay_key(), &conflict.envelope_a, conflict.sequence as u64),
            ],
            envelope_b_observations: observations_from_n_distinct_relays(
                3,
                &conflict.envelope_b,
                conflict.sequence as u64,
            ),
            ..empty_evidence()
        };

        // Side A only has 1 genuinely valid relay (the mismatched one is
        // excluded), well short of quorum, so side B wins.
        let winner = resolve_conflict(&conflict, &evidence).unwrap();
        assert_eq!(winner, conflict.envelope_b);
    }
}
