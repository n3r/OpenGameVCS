//! Private, pure, bounded OGVCS-042 local-agent IPC fact contract.
//!
//! This crate has no transport, filesystem, credential, cryptographic-key,
//! server, lock-renewal, workspace-mutation, or publication implementation.
//! It validates caller-supplied facts and advances only an in-memory ledger.
#![forbid(unsafe_code)]

mod client_hello;
mod commitment;
mod model;
mod state;

pub use client_hello::*;
pub use commitment::Digest32;
pub use model::*;
pub use state::*;
