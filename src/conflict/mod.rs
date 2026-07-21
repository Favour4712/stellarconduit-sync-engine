pub mod detector;
pub mod resolver;

pub use detector::{conflicts_between, detect_conflicts, Conflict, QueuedSlot};
pub use resolver::resolve_conflict;
