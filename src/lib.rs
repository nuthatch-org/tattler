//! Signed, replayable receipts for indexed chain data.
//!
//! See `receipt.rs` for what a receipt does and does not prove, and `canonical.rs` for why the
//! hash depends on the answer and on nothing else.

pub mod canonical;
pub mod merkle;
pub mod receipt;

pub use canonical::result_hash;
pub use merkle::{merkle_root, root_from_proof, Inclusion, Step};
pub use receipt::{issue, verify, Body, Receipt, Verdict};
