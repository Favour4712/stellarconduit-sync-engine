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
}
