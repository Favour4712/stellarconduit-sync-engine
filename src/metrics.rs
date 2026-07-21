//! Protocol-level counters for the sync engine, mirroring the pattern used in
//! `stellarconduit-core::metrics`. Intended to be exposed by whichever binary
//! embeds this crate (mobile wallet, relay node).

use std::sync::atomic::AtomicUsize;

#[derive(Debug, Default)]
pub struct SyncEngineMetrics {
    pub queued_total: AtomicUsize,
    pub settled_total: AtomicUsize,
    pub failed_total: AtomicUsize,
    pub conflicts_detected: AtomicUsize,
    pub disputes_escalated: AtomicUsize,
}
