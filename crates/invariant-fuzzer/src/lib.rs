//! REVM-based invariant fuzzing helpers.
//!
//! This module is intentionally defensive: it only provides observation,
//! shrinking, and minimal-reproduction tooling for permitted audit scopes.

use alloy_primitives::{Address, Bytes, U256};
use revm::{
    db::Database,
    interpreter::{CallInputs, CallOutcome, Interpreter},
    EvmContext,
    Inspector,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Lightweight TX input for simulation (no signature needed).
#[derive(Debug, Clone)]
pub struct SimTxInput {
    pub caller: Address,
    pub to: Address,
    pub value: U256,
    pub data: Bytes,
    pub gas_limit: u64,
    pub gas_price: u64,
    pub nonce: Option<u64>,
}

/// A single observed execution step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceEvent {
    pub step_index: usize,
    pub program_counter: Option<usize>,
}

/// Snapshot of invariant-related state before/after a fuzzed sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantSnapshot {
    pub reserves: Option<(U256, U256)>,
    pub balances: Vec<(Address, U256)>,
    pub total_supply: Option<U256>,
}

/// Result of an invariant-fuzzing run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantRunResult {
    pub violated: bool,
    pub traces: Vec<TraceEvent>,
    pub before: Option<InvariantSnapshot>,
    pub after: Option<InvariantSnapshot>,
    pub reason: Option<String>,
}

/// Lightweight inspector for observing execution density and coarse coverage.
///
/// The goal is not to mutate state. It records a minimal trace that can be
/// attached to a simulation run and used during shrinking.
#[derive(Debug, Default, Clone)]
pub struct InvariantInspector {
    pub traces: Vec<TraceEvent>,
    step_index: usize,
    visited_pcs: BTreeSet<usize>,
}

impl InvariantInspector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn visited_pcs(&self) -> &BTreeSet<usize> {
        &self.visited_pcs
    }
}

impl<DB> Inspector<DB> for InvariantInspector
where
    DB: Database,
{
    fn step(&mut self, interp: &mut Interpreter, _context: &mut EvmContext<DB>) {
        let program_counter = interp.program_counter();
        self.visited_pcs.insert(program_counter);
        self.traces.push(TraceEvent {
            step_index: self.step_index,
            program_counter: Some(program_counter),
        });
        self.step_index += 1;
    }

    fn call(
        &mut self,
        _context: &mut EvmContext<DB>,
        _inputs: &mut CallInputs,
    ) -> Option<CallOutcome> {
        None
    }

    fn call_end(
        &mut self,
        _context: &mut EvmContext<DB>,
        _inputs: &CallInputs,
        outcome: CallOutcome,
    ) -> CallOutcome {
        outcome
    }
}


pub mod shrink;
pub use shrink::*;

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Bytes;

    #[test]
    fn shrink_sequence_removes_unneeded_items() {
        let seq = vec![1u32, 2, 3, 4];
        let minimized = shrink_sequence(&seq, |candidate| candidate.len() >= 2);
        assert_eq!(minimized.len(), 2);
    }

    #[test]
    fn shrink_u256_bisect_finds_boundary() {
        let result = shrink_u256_bisect(U256::from(100u64), U256::from(0u64), |candidate| {
            candidate >= U256::from(17u64)
        });

        assert_eq!(result, U256::from(17u64));
    }

    #[test]
    fn rewrite_amount_updates_only_value() {
        let tx = SimTxInput {
            caller: Address::from([0x11; 20]),
            to: Address::from([0x22; 20]),
            value: U256::from(1u64),
            data: Bytes::new(),
            gas_limit: 21_000,
            gas_price: 1,
            nonce: Some(0),
        };

        let rewritten = rewrite_amount(&[tx.clone()], 0, U256::from(5u64));
        assert_eq!(rewritten[0].value, U256::from(5u64));
        assert_eq!(rewritten[0].caller, tx.caller);
        assert_eq!(rewritten[0].to, tx.to);
    }

    fn mk_tx(seed: u8, value: u64) -> SimTxInput {
        SimTxInput {
            caller: Address::from([seed; 20]),
            to: Address::from([seed.wrapping_add(1); 20]),
            value: U256::from(value),
            data: Bytes::new(),
            gas_limit: 100_000,
            gas_price: 1,
            nonce: Some(0),
        }
    }

    #[test]
    fn shrink_simtx_sequence_reports_removed_and_value_changes() {
        // Violation requires at least 2 txs AND tx[0].value >= 17.
        let violates = |seq: &[SimTxInput]| -> bool {
            seq.len() >= 2 && seq[0].value >= U256::from(17u64)
        };

        let original = vec![mk_tx(1, 100), mk_tx(2, 1), mk_tx(3, 1), mk_tx(4, 1)];
        assert!(violates(&original));

        let result = shrink_simtx_sequence(original.clone(), violates, ShrinkOptions::default());
        assert_eq!(result.original_sequence.len(), 4);
        assert_eq!(result.minimized_sequence.len(), 2);
        assert!(result.diff.removed_original_indices.len() >= 2);

        // First tx should have its value bisected down to the boundary.
        assert_eq!(result.minimized_sequence[0].value, U256::from(17u64));
        assert!(
            result
                .diff
                .value_changes
                .iter()
                .any(|c| c.original_index == 0 && c.before == U256::from(100u64) && c.after == U256::from(17u64))
        );

        // Diff summary should be meaningful and non-empty.
        assert!(!result.diff.is_noop());
        assert!(result.diff.concise().contains("len 4 -> 2"));
    }

    #[test]
    fn shrink_options_can_restrict_bisect_to_selected_indices() {
        let violates = |seq: &[SimTxInput]| -> bool {
            seq.len() >= 2 && seq[0].value >= U256::from(17u64) && seq[1].value >= U256::from(9u64)
        };

        let original = vec![mk_tx(1, 100), mk_tx(2, 100), mk_tx(3, 1)];
        assert!(violates(&original));

        let mut restrict = BTreeSet::new();
        restrict.insert(1usize); // only allow shrinking of tx1 (original index 1)

        let options = ShrinkOptions {
            bisect_value: true,
            min_value: U256::ZERO,
            restrict_to_original_indices: Some(restrict),
        };

        let result = shrink_simtx_sequence(original.clone(), violates, options);
        // tx0 remains unchanged since it wasn't in the restrict set.
        assert_eq!(result.minimized_sequence[0].value, U256::from(100u64));
        // tx1 shrinks to its boundary of 9.
        assert_eq!(result.minimized_sequence[1].value, U256::from(9u64));
        assert_eq!(result.diff.value_changes.len(), 1);
        assert_eq!(result.diff.value_changes[0].original_index, 1);
    }

    #[test]
    fn shrink_sim_sequence_wrapper_returns_lengths() {
        // Violation requires at least 2 txs.
        let violates = |seq: &[SimTxInput]| seq.len() >= 2;

        let original = vec![mk_tx(1, 1), mk_tx(2, 1), mk_tx(3, 1), mk_tx(4, 1)];
        let (minimized, original_len, minimized_len) = shrink_sim_sequence(original.clone(), violates);

        assert_eq!(original_len, 4);
        assert_eq!(minimized_len, 2);
        assert_eq!(minimized.len(), 2);
    }

    #[test]
    fn shrink_report_summary_is_compact() {
        let minimized = vec![mk_tx(1, 1), mk_tx(2, 1)];
        let report = ShrinkReport::new(minimized, vec![TraceEvent { step_index: 0, program_counter: Some(1) }]);
        assert_eq!(report.summary(4), "len 4 -> 2, traces=1");
    }

    #[test]
    fn shrink_metrics_includes_removed_and_traces() {
        let minimized = vec![mk_tx(1, 1), mk_tx(2, 1)];
        let report = ShrinkReport::new(
            minimized,
            vec![
                TraceEvent { step_index: 0, program_counter: Some(1) },
                TraceEvent { step_index: 1, program_counter: Some(2) },
                TraceEvent { step_index: 2, program_counter: Some(3) },
            ],
        );
        let metrics = report.metrics(5);
        assert_eq!(metrics.original_len, 5);
        assert_eq!(metrics.minimized_len, 2);
        assert_eq!(metrics.removed_count, 3);
        assert_eq!(metrics.trace_count, 3);
        assert!(metrics.concise().contains("removed=3"));
        assert!(metrics.concise().contains("traces=3"));
    }

    #[test]
    fn shrink_minimized_with_report_returns_minimized_and_metrics() {
        // Violation requires at least 2 txs.
        let violates = |seq: &[SimTxInput]| seq.len() >= 2;
        let original = vec![mk_tx(1, 100), mk_tx(2, 1), mk_tx(3, 1), mk_tx(4, 1)];

        let options = ShrinkOptions {
            bisect_value: false, // keep test focused on deletion shrink
            min_value: U256::ZERO,
            restrict_to_original_indices: None,
        };

        let (minimized, metrics, diff) = shrink_minimized_with_report(original, violates, options);
        assert_eq!(minimized.len(), 2);
        assert_eq!(metrics.original_len, 4);
        assert_eq!(metrics.minimized_len, 2);
        assert_eq!(metrics.removed_count, diff.removed_original_indices.len());
        assert_eq!(metrics.trace_count, 0);
        assert!(metrics.concise().contains("len 4 -> 2"));
    }
}
