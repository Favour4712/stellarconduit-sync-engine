//! Stellar sequence-number reservation for offline-queued transactions.
//!
//! A Stellar account's sequence number must increase by exactly 1 per
//! transaction, with no gaps. When several transactions from the same source
//! account are queued while offline, each must be assigned a distinct,
//! strictly-increasing sequence number *before* signing — otherwise two
//! envelopes signed against the same sequence become mutually exclusive
//! (only one can ever settle), which is one of the ways a double-spend
//! conflict enters the mesh in the first place. See `crate::conflict` for
//! detection/resolution of that scenario.

use std::collections::HashMap;

use crate::errors::SyncEngineError;

#[derive(Debug, Default)]
pub struct SequenceReservationManager {
    /// Last reserved sequence number per Stellar source account (G... strkey).
    reserved: HashMap<String, i64>,
}

impl SequenceReservationManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed the manager with an account's current on-chain sequence number,
    /// as last observed while the device had connectivity. Reservations for
    /// that account build on top of this baseline.
    pub fn seed(&mut self, account: impl Into<String>, current_chain_sequence: i64) {
        self.reserved.insert(account.into(), current_chain_sequence);
    }

    /// Reserve and return the next sequence number for `account`. The account
    /// must have been seeded first.
    pub fn reserve_next(&mut self, account: &str) -> Result<i64, SyncEngineError> {
        let last = self
            .reserved
            .get(account)
            .copied()
            .ok_or_else(|| SyncEngineError::NoSequenceReserved(account.to_string()))?;
        let next = last + 1;
        self.reserved.insert(account.to_string(), next);
        Ok(next)
    }

    pub fn last_reserved(&self, account: &str) -> Option<i64> {
        self.reserved.get(account).copied()
    }

    /// Roll back the most recent reservation for `account`, e.g. when
    /// envelope construction fails after a sequence number was reserved.
    /// `sequence` must equal the most recently reserved value.
    pub fn release(&mut self, account: &str, sequence: i64) -> Result<(), SyncEngineError> {
        let last = self
            .reserved
            .get(account)
            .copied()
            .ok_or_else(|| SyncEngineError::NoSequenceReserved(account.to_string()))?;
        if last != sequence {
            return Err(SyncEngineError::SequenceOutOfOrder {
                account: account.to_string(),
                requested: sequence,
                last_reserved: last,
            });
        }
        self.reserved.insert(account.to_string(), last - 1);
        Ok(())
    }
}

/// A Stellar account's cached multisig signer set: which Ed25519 public keys
/// are authorized signers, their weights, and the weight threshold a
/// transaction must accumulate before it may be dispatched.
///
/// Like an account's on-chain sequence number, its live signer list and
/// thresholds aren't fetchable without connectivity, so — mirroring
/// [`SequenceReservationManager::seed`] — this must be seeded from a
/// snapshot taken while the device last had connectivity. A stale cache
/// (e.g. a signer removed on-chain after the last sync) is a real risk or a
/// legitimate wallet is expected to re-sync and re-seed opportunistically;
/// this crate only provides the offline cache, not staleness detection.
///
/// Real Stellar accounts have three threshold levels (low/medium/high)
/// depending on operation type. This cache simplifies that to a single
/// effective `threshold` per account — documented here as a first version,
/// same simplification style as the count-only Emergency spending guard.
/// Callers should seed whichever of the three thresholds applies to the
/// operations they intend to queue.
#[derive(Debug, Default)]
pub struct MultisigAccountRegistry {
    accounts: HashMap<String, AccountSigners>,
}

#[derive(Debug, Clone)]
struct AccountSigners {
    /// Signer pubkey -> weight.
    signers: HashMap<[u8; 32], u32>,
    threshold: u32,
}

impl MultisigAccountRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Cache `account`'s signer set and threshold. Replaces any previous
    /// entry for the same account.
    pub fn seed(
        &mut self,
        account: impl Into<String>,
        signers: impl IntoIterator<Item = ([u8; 32], u32)>,
        threshold: u32,
    ) {
        self.accounts.insert(
            account.into(),
            AccountSigners {
                signers: signers.into_iter().collect(),
                threshold,
            },
        );
    }

    /// The cached weight for `pubkey` on `account`, or `None` if `account`
    /// hasn't been seeded or `pubkey` isn't one of its known signers.
    pub fn signer_weight(&self, account: &str, pubkey: &[u8; 32]) -> Option<u32> {
        self.accounts.get(account)?.signers.get(pubkey).copied()
    }

    /// The cached signing threshold for `account`, or `None` if it hasn't
    /// been seeded.
    pub fn threshold(&self, account: &str) -> Option<u32> {
        self.accounts.get(account).map(|a| a.threshold)
    }

    /// Whether `pubkey` is among `account`'s cached authorized signers.
    pub fn is_known_signer(&self, account: &str, pubkey: &[u8; 32]) -> bool {
        self.signer_weight(account, pubkey).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reserve_without_seed_errors() {
        let mut mgr = SequenceReservationManager::new();
        assert!(matches!(
            mgr.reserve_next("GABC"),
            Err(SyncEngineError::NoSequenceReserved(_))
        ));
    }

    #[test]
    fn test_reserve_increments_from_seed() {
        let mut mgr = SequenceReservationManager::new();
        mgr.seed("GABC", 100);
        assert_eq!(mgr.reserve_next("GABC").unwrap(), 101);
        assert_eq!(mgr.reserve_next("GABC").unwrap(), 102);
        assert_eq!(mgr.reserve_next("GABC").unwrap(), 103);
        assert_eq!(mgr.last_reserved("GABC"), Some(103));
    }

    #[test]
    fn test_accounts_are_independent() {
        let mut mgr = SequenceReservationManager::new();
        mgr.seed("GABC", 100);
        mgr.seed("GXYZ", 5);
        assert_eq!(mgr.reserve_next("GABC").unwrap(), 101);
        assert_eq!(mgr.reserve_next("GXYZ").unwrap(), 6);
    }

    #[test]
    fn test_release_rolls_back_last_reservation() {
        let mut mgr = SequenceReservationManager::new();
        mgr.seed("GABC", 100);
        let seq = mgr.reserve_next("GABC").unwrap();
        mgr.release("GABC", seq).unwrap();
        assert_eq!(mgr.last_reserved("GABC"), Some(100));
        // Reserving again should hand out the same sequence number.
        assert_eq!(mgr.reserve_next("GABC").unwrap(), 101);
    }

    #[test]
    fn test_release_rejects_non_matching_sequence() {
        let mut mgr = SequenceReservationManager::new();
        mgr.seed("GABC", 100);
        mgr.reserve_next("GABC").unwrap(); // 101
        mgr.reserve_next("GABC").unwrap(); // 102
        assert!(matches!(
            mgr.release("GABC", 101),
            Err(SyncEngineError::SequenceOutOfOrder { .. })
        ));
    }

    #[test]
    fn test_multisig_registry_seed_and_lookup() {
        let mut registry = MultisigAccountRegistry::new();
        let signer_a = [1u8; 32];
        let signer_b = [2u8; 32];
        registry.seed("GMULTISIG", [(signer_a, 1), (signer_b, 2)], 2);

        assert_eq!(registry.signer_weight("GMULTISIG", &signer_a), Some(1));
        assert_eq!(registry.signer_weight("GMULTISIG", &signer_b), Some(2));
        assert_eq!(registry.threshold("GMULTISIG"), Some(2));
        assert!(registry.is_known_signer("GMULTISIG", &signer_a));
    }

    #[test]
    fn test_multisig_registry_unknown_account_and_signer() {
        let registry = MultisigAccountRegistry::new();
        assert_eq!(registry.signer_weight("GUNKNOWN", &[9u8; 32]), None);
        assert_eq!(registry.threshold("GUNKNOWN"), None);
        assert!(!registry.is_known_signer("GUNKNOWN", &[9u8; 32]));

        let mut registry = MultisigAccountRegistry::new();
        registry.seed("GMULTISIG", [([1u8; 32], 1)], 1);
        assert!(!registry.is_known_signer("GMULTISIG", &[9u8; 32]));
    }
}
