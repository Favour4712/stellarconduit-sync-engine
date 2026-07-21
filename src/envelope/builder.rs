//! Offline construction and signing of `TransactionEnvelope`s.
//!
//! Building the actual Stellar transaction XDR (setting operations, fee, and
//! embedding the reserved sequence number into it) is the wallet layer's
//! responsibility, same as in `stellarconduit-core` — this crate treats
//! `tx_xdr` as an opaque, already-built base64 XDR string. What this module
//! adds on top of `stellarconduit_core::message::envelope::EnvelopeBuilder`
//! is coupling that signing step to sequence-number reservation, so a
//! caller cannot accidentally sign two envelopes for the same account
//! without first reserving distinct sequence numbers.

use ed25519_dalek::SigningKey;
use stellarconduit_core::message::envelope::EnvelopeBuilder;
use stellarconduit_core::message::types::TransactionEnvelope;

use crate::errors::SyncEngineError;
use crate::queue::SequenceReservationManager;

pub struct OfflineEnvelopeBuilder;

impl OfflineEnvelopeBuilder {
    /// Reserve the next sequence number for `source_account`, then build and
    /// sign an envelope wrapping `tx_xdr`.
    ///
    /// Returns the signed envelope along with the sequence number consumed,
    /// so the caller can correlate this envelope with the sequence slot it
    /// occupies (e.g. for conflict detection in `crate::conflict`).
    pub fn build_and_sign(
        sequences: &mut SequenceReservationManager,
        source_account: &str,
        signing_key: &SigningKey,
        tx_xdr: impl Into<String>,
        ttl_hops: u8,
    ) -> Result<(TransactionEnvelope, i64), SyncEngineError> {
        let sequence = sequences.reserve_next(source_account)?;
        let origin_pubkey = signing_key.verifying_key().to_bytes();
        let envelope = EnvelopeBuilder::new(origin_pubkey, tx_xdr)
            .ttl(ttl_hops)
            .build(signing_key);
        Ok((envelope, sequence))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use stellarconduit_core::message::envelope::validate_envelope;

    fn signing_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    #[test]
    fn test_build_and_sign_produces_valid_envelope() {
        let mut sequences = SequenceReservationManager::new();
        sequences.seed("GABC", 100);
        let key = signing_key();

        let (envelope, sequence) =
            OfflineEnvelopeBuilder::build_and_sign(&mut sequences, "GABC", &key, "mock_xdr", 10)
                .unwrap();

        assert_eq!(sequence, 101);
        assert!(validate_envelope(&envelope).is_ok());
        assert_eq!(envelope.origin_pubkey, key.verifying_key().to_bytes());
    }

    #[test]
    fn test_successive_builds_consume_successive_sequences() {
        let mut sequences = SequenceReservationManager::new();
        sequences.seed("GABC", 100);
        let key = signing_key();

        let (_, seq_a) =
            OfflineEnvelopeBuilder::build_and_sign(&mut sequences, "GABC", &key, "xdr_a", 10)
                .unwrap();
        let (_, seq_b) =
            OfflineEnvelopeBuilder::build_and_sign(&mut sequences, "GABC", &key, "xdr_b", 10)
                .unwrap();

        assert_eq!(seq_a, 101);
        assert_eq!(seq_b, 102);
    }

    #[test]
    fn test_build_without_seed_errors() {
        let mut sequences = SequenceReservationManager::new();
        let key = signing_key();
        let result =
            OfflineEnvelopeBuilder::build_and_sign(&mut sequences, "GUNSEEDED", &key, "xdr", 10);
        assert!(matches!(
            result,
            Err(SyncEngineError::NoSequenceReserved(_))
        ));
    }
}
