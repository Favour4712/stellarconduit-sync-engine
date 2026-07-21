//! Offline construction and signing of `TransactionEnvelope`s.
//!
//! Building the actual Stellar transaction XDR (setting operations, fee, and
//! embedding the reserved sequence number into it) is the wallet layer's
//! responsibility, same as in `stellarconduit-core` — this crate treats
//! `tx_xdr` as an already-built base64 XDR string. What this module adds on top
//! of `stellarconduit_core::message::envelope::EnvelopeBuilder` is coupling that
//! signing step to sequence-number reservation, so a caller cannot accidentally
//! sign two envelopes for the same account without first reserving distinct
//! sequence numbers.
//!
//! Crucially, the source account and sequence number are **derived from the XDR
//! itself** (see [`crate::envelope::xdr`]) rather than taken on trust from the
//! caller. The caller still passes the account it *believes* it is signing for,
//! but that claim is cross-checked against what the transaction actually
//! encodes: a mismatch is rejected instead of being propagated into storage and
//! conflict detection, where it could mask a double-spend.

use ed25519_dalek::SigningKey;
use stellarconduit_core::message::envelope::EnvelopeBuilder;
use stellarconduit_core::message::types::TransactionEnvelope;

use crate::envelope::xdr::extract_source_account_and_sequence;
use crate::errors::SyncEngineError;
use crate::queue::SequenceReservationManager;

pub struct OfflineEnvelopeBuilder;

impl OfflineEnvelopeBuilder {
    /// Derive the source account and sequence number from `tx_xdr`, reserve
    /// that sequence, and build and sign an envelope wrapping `tx_xdr`.
    ///
    /// The flow deliberately parses first and trusts the XDR over the caller:
    ///
    /// 1. Parse `tx_xdr` to recover the source account and sequence the wallet's
    ///    Stellar SDK layer actually embedded when it built the transaction.
    /// 2. Cross-check the caller-supplied `source_account` against it, rejecting
    ///    a [`SyncEngineError::SourceAccountMismatch`] if they disagree.
    /// 3. Reserve the next sequence number for that account and verify it equals
    ///    the sequence embedded in the XDR, rejecting a
    ///    [`SyncEngineError::SequenceMismatch`] (and rolling the reservation
    ///    back) if the wallet's bookkeeping has drifted from ours.
    ///
    /// Returns the signed envelope along with the sequence number it occupies —
    /// the one taken straight from the XDR — so the caller can correlate this
    /// envelope with its sequence slot (e.g. for conflict detection in
    /// `crate::conflict`).
    ///
    /// [`SyncEngineError::SourceAccountMismatch`]: crate::errors::SyncEngineError::SourceAccountMismatch
    /// [`SyncEngineError::SequenceMismatch`]: crate::errors::SyncEngineError::SequenceMismatch
    pub fn build_and_sign(
        sequences: &mut SequenceReservationManager,
        source_account: &str,
        signing_key: &SigningKey,
        tx_xdr: impl Into<String>,
        ttl_hops: u8,
    ) -> Result<(TransactionEnvelope, i64), SyncEngineError> {
        let tx_xdr = tx_xdr.into();

        // Trust the XDR, not the caller: the true source account and sequence
        // are encoded in the already-built transaction.
        let (xdr_account, xdr_sequence) = extract_source_account_and_sequence(&tx_xdr)?;

        if source_account != xdr_account {
            return Err(SyncEngineError::SourceAccountMismatch {
                claimed: source_account.to_string(),
                actual: xdr_account,
            });
        }

        let reserved = sequences.reserve_next(&xdr_account)?;
        if reserved != xdr_sequence {
            // Nothing got signed, so roll the reservation back to keep the
            // manager consistent with what actually occupies each slot.
            let _ = sequences.release(&xdr_account, reserved);
            return Err(SyncEngineError::SequenceMismatch {
                account: xdr_account,
                reserved,
                actual: xdr_sequence,
            });
        }

        let origin_pubkey = signing_key.verifying_key().to_bytes();
        let envelope = EnvelopeBuilder::new(origin_pubkey, tx_xdr)
            .ttl(ttl_hops)
            .build(signing_key);
        Ok((envelope, xdr_sequence))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use stellarconduit_core::message::envelope::validate_envelope;

    // Real, valid XDR fixtures whose embedded source account and sequence are
    // known; see `src/envelope/xdr.rs` and `tests/fixtures`.
    const SOURCE_G: &str = "GAIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCF6M";
    const FEE_SOURCE_G: &str = "GAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTHCM6";
    const SEQ: i64 = 103_720_918_407_610_369;

    fn signing_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name);
        std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("failed to read fixture {name}: {e}"))
            .trim()
            .to_string()
    }

    #[test]
    fn test_build_and_sign_produces_valid_envelope() {
        let mut sequences = SequenceReservationManager::new();
        sequences.seed(SOURCE_G, SEQ - 1);
        let key = signing_key();

        let (envelope, sequence) = OfflineEnvelopeBuilder::build_and_sign(
            &mut sequences,
            SOURCE_G,
            &key,
            fixture("transaction_v1_envelope.b64"),
            10,
        )
        .unwrap();

        // The returned sequence is the one embedded in the XDR, not merely the
        // next reservation.
        assert_eq!(sequence, SEQ);
        assert!(validate_envelope(&envelope).is_ok());
        assert_eq!(envelope.origin_pubkey, key.verifying_key().to_bytes());
    }

    #[test]
    fn test_successive_builds_consume_successive_sequences() {
        let mut sequences = SequenceReservationManager::new();
        sequences.seed(SOURCE_G, SEQ - 1);
        let key = signing_key();

        let (_, seq_a) = OfflineEnvelopeBuilder::build_and_sign(
            &mut sequences,
            SOURCE_G,
            &key,
            fixture("transaction_v1_envelope.b64"),
            10,
        )
        .unwrap();
        let (_, seq_b) = OfflineEnvelopeBuilder::build_and_sign(
            &mut sequences,
            SOURCE_G,
            &key,
            fixture("transaction_v1_envelope_seq_next.b64"),
            10,
        )
        .unwrap();

        assert_eq!(seq_a, SEQ);
        assert_eq!(seq_b, SEQ + 1);
    }

    #[test]
    fn test_build_without_seed_errors() {
        let mut sequences = SequenceReservationManager::new();
        let key = signing_key();
        // Correct account (matches the XDR), but never seeded.
        let result = OfflineEnvelopeBuilder::build_and_sign(
            &mut sequences,
            SOURCE_G,
            &key,
            fixture("transaction_v1_envelope.b64"),
            10,
        );
        assert!(matches!(
            result,
            Err(SyncEngineError::NoSequenceReserved(_))
        ));
    }

    #[test]
    fn test_mismatched_caller_claim_is_rejected() {
        // Caller claims account A (the fee source), but the XDR actually encodes
        // account B (the source): the mismatch must be caught, not accepted.
        let mut sequences = SequenceReservationManager::new();
        sequences.seed(FEE_SOURCE_G, SEQ - 1);
        let key = signing_key();

        let result = OfflineEnvelopeBuilder::build_and_sign(
            &mut sequences,
            FEE_SOURCE_G,
            &key,
            fixture("transaction_v1_envelope.b64"),
            10,
        );

        match result {
            Err(SyncEngineError::SourceAccountMismatch { claimed, actual }) => {
                assert_eq!(claimed, FEE_SOURCE_G);
                assert_eq!(actual, SOURCE_G);
            }
            other => panic!("expected SourceAccountMismatch, got {other:?}"),
        }
        // The reservation must be untouched: we rejected before reserving.
        assert_eq!(sequences.last_reserved(FEE_SOURCE_G), Some(SEQ - 1));
    }

    #[test]
    fn test_sequence_mismatch_is_rejected_and_rolled_back() {
        // The manager's view of the account has drifted from the XDR: reserving
        // hands out a sequence that does not match what actually got built.
        let mut sequences = SequenceReservationManager::new();
        sequences.seed(SOURCE_G, 50);
        let key = signing_key();

        let result = OfflineEnvelopeBuilder::build_and_sign(
            &mut sequences,
            SOURCE_G,
            &key,
            fixture("transaction_v1_envelope.b64"),
            10,
        );

        match result {
            Err(SyncEngineError::SequenceMismatch {
                account,
                reserved,
                actual,
            }) => {
                assert_eq!(account, SOURCE_G);
                assert_eq!(reserved, 51);
                assert_eq!(actual, SEQ);
            }
            other => panic!("expected SequenceMismatch, got {other:?}"),
        }
        // The failed reservation must have been rolled back.
        assert_eq!(sequences.last_reserved(SOURCE_G), Some(50));
    }

    #[test]
    fn test_malformed_xdr_is_rejected() {
        let mut sequences = SequenceReservationManager::new();
        sequences.seed(SOURCE_G, SEQ - 1);
        let key = signing_key();

        let result = OfflineEnvelopeBuilder::build_and_sign(
            &mut sequences,
            SOURCE_G,
            &key,
            "not-valid-xdr !!!",
            10,
        );
        assert!(matches!(result, Err(SyncEngineError::XdrParse(_))));
    }
}
