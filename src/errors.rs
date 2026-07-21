use thiserror::Error;

#[derive(Error, Debug)]
pub enum SyncEngineError {
    #[error("no sequence number reserved for account {0}")]
    NoSequenceReserved(String),

    #[error("sequence number {requested} is not greater than last reserved {last_reserved} for account {account}")]
    SequenceOutOfOrder {
        account: String,
        requested: i64,
        last_reserved: i64,
    },

    #[error("envelope validation failed: {0}")]
    InvalidEnvelope(String),

    #[error("failed to parse transaction XDR: {0}")]
    XdrParse(String),

    #[error("caller-claimed source account {claimed} does not match the source account {actual} encoded in the transaction XDR")]
    SourceAccountMismatch { claimed: String, actual: String },

    #[error("reserved sequence {reserved} does not match the sequence {actual} encoded in the transaction XDR for account {account}")]
    SequenceMismatch {
        account: String,
        reserved: i64,
        actual: i64,
    },

    #[error("no queued envelope found for message_id {0}")]
    EnvelopeNotFound(String),

    #[error("invalid settlement state transition from {from:?} to {to:?}")]
    InvalidStateTransition { from: String, to: String },

    #[error("conflict between envelopes could not be resolved off-chain: {0}")]
    UnresolvedConflict(String),

    #[error("SQLite connection error: {0}")]
    ConnectionError(#[from] tokio_rusqlite::Error),

    #[error("SQLite database error: {0}")]
    SqliteError(#[from] rusqlite::Error),

    #[error("serialization error: {0}")]
    SerializationError(#[from] rmp_serde::encode::Error),

    #[error("deserialization error: {0}")]
    DeserializationError(#[from] rmp_serde::decode::Error),
}
