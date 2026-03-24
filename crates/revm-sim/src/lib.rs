//! REVM-based transaction simulator for DeFi security research.
//!
//! Provides fork-based transaction replay, invariant auditing,
//! and evidence generation for security analysis workflows.
//!
//! # Architecture
//!
//! ```text
//! Hypothesis → SimTxInput → REVM Execution → Invariant Check → Evidence
//! ```
//!
//! For invariant rules, see `invariant-rules` crate.
//! For invariant fuzzing, see `invariant-fuzzer` crate.

pub mod types;
pub mod simulator;

pub use types::*;
pub use simulator::Simulator;
