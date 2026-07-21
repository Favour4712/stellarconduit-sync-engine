//! Local, pre-gossip ordering of a device's own outgoing payments.
//!
//! This is distinct from `stellarconduit_core::gossip::queue::MessagePriority`,
//! which governs mesh *forwarding* order for any envelope passing through a
//! peer. `TxPriority` governs the order in which *this device's own* queued
//! payments are signed and handed off to the mesh in the first place — e.g. an
//! emergency payment queued while offline should be dispatched ahead of a
//! routine one queued earlier.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::time::{SystemTime, UNIX_EPOCH};

use stellarconduit_core::message::types::TransactionEnvelope;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TxPriority {
    Low = 0,
    Normal = 1,
    Emergency = 2,
}

#[derive(Debug, Clone)]
struct QueuedTx {
    priority: TxPriority,
    /// Unix seconds when this envelope was pushed. Used as a FIFO tie-break
    /// within the same priority tier — earlier enqueue wins.
    enqueued_at: u64,
    envelope: TransactionEnvelope,
}

impl PartialEq for QueuedTx {
    fn eq(&self, other: &Self) -> bool {
        self.envelope.message_id == other.envelope.message_id
    }
}
impl Eq for QueuedTx {}

impl Ord for QueuedTx {
    fn cmp(&self, other: &Self) -> Ordering {
        self.priority
            .cmp(&other.priority)
            .then_with(|| other.enqueued_at.cmp(&self.enqueued_at))
    }
}
impl PartialOrd for QueuedTx {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A local max-heap of outgoing envelopes, ordered by [`TxPriority`] and then
/// by insertion order (oldest first) within the same tier.
#[derive(Debug, Default)]
pub struct OutboundTxQueue {
    heap: BinaryHeap<QueuedTx>,
}

impl OutboundTxQueue {
    pub fn new() -> Self {
        Self {
            heap: BinaryHeap::new(),
        }
    }

    pub fn push(&mut self, envelope: TransactionEnvelope, priority: TxPriority) {
        let enqueued_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.heap.push(QueuedTx {
            priority,
            enqueued_at,
            envelope,
        });
    }

    /// Same as [`Self::push`] but with an explicit `enqueued_at`, useful for
    /// restoring a queue from durable storage after a restart.
    pub fn push_at(&mut self, envelope: TransactionEnvelope, priority: TxPriority, enqueued_at: u64) {
        self.heap.push(QueuedTx {
            priority,
            enqueued_at,
            envelope,
        });
    }

    pub fn pop(&mut self) -> Option<TransactionEnvelope> {
        self.heap.pop().map(|q| q.envelope)
    }

    pub fn peek(&self) -> Option<&TransactionEnvelope> {
        self.heap.peek().map(|q| &q.envelope)
    }

    pub fn len(&self) -> usize {
        self.heap.len()
    }

    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_envelope(message_id: u8) -> TransactionEnvelope {
        TransactionEnvelope {
            message_id: [message_id; 32],
            origin_pubkey: [1u8; 32],
            tx_xdr: "mock_xdr".to_string(),
            ttl_hops: 10,
            timestamp: 1_700_000_000,
            signature: [0u8; 64],
        }
    }

    #[test]
    fn test_higher_priority_pops_first() {
        let mut q = OutboundTxQueue::new();
        q.push(mock_envelope(1), TxPriority::Low);
        q.push(mock_envelope(2), TxPriority::Emergency);
        q.push(mock_envelope(3), TxPriority::Normal);

        assert_eq!(q.pop().unwrap().message_id, [2u8; 32]);
        assert_eq!(q.pop().unwrap().message_id, [3u8; 32]);
        assert_eq!(q.pop().unwrap().message_id, [1u8; 32]);
        assert!(q.pop().is_none());
    }

    #[test]
    fn test_fifo_within_same_priority() {
        let mut q = OutboundTxQueue::new();
        q.push_at(mock_envelope(1), TxPriority::Normal, 100);
        q.push_at(mock_envelope(2), TxPriority::Normal, 50);
        q.push_at(mock_envelope(3), TxPriority::Normal, 200);

        // Oldest enqueued_at (50) should come out first.
        assert_eq!(q.pop().unwrap().message_id, [2u8; 32]);
        assert_eq!(q.pop().unwrap().message_id, [1u8; 32]);
        assert_eq!(q.pop().unwrap().message_id, [3u8; 32]);
    }

    #[test]
    fn test_len_and_is_empty() {
        let mut q = OutboundTxQueue::new();
        assert!(q.is_empty());
        q.push(mock_envelope(1), TxPriority::Low);
        assert_eq!(q.len(), 1);
        assert!(!q.is_empty());
    }
}
