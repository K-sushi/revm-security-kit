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

/// Greedy top-down shrinking: keep removing items while the predicate still fails.
pub fn shrink_sequence<T, F>(sequence: &[T], mut violates: F) -> Vec<T>
where
    T: Clone,
    F: FnMut(&[T]) -> bool,
{
    let mut minimized: Vec<T> = sequence.to_vec();
    let mut index = 0;

    while index < minimized.len() {
        let mut candidate = minimized.clone();
        candidate.remove(index);

        if violates(&candidate) {
            minimized = candidate;
        } else {
            index += 1;
        }
    }

    minimized
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueChange {
    /// Index in the original sequence.
    pub original_index: usize,
    pub before: U256,
    pub after: U256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShrinkDiffSummary {
    pub original_len: usize,
    pub minimized_len: usize,
    /// Indices from the original sequence removed by shrinking.
    pub removed_original_indices: Vec<usize>,
    /// Changes to numeric fields performed during second-pass shrinking.
    pub value_changes: Vec<ValueChange>,
}

impl ShrinkDiffSummary {
    pub fn is_noop(&self) -> bool {
        self.original_len == self.minimized_len
            && self.removed_original_indices.is_empty()
            && self.value_changes.is_empty()
    }

    pub fn concise(&self) -> String {
        let mut parts = vec![format!("len {} -> {}", self.original_len, self.minimized_len)];
        if !self.removed_original_indices.is_empty() {
            parts.push(format!(
                "removed={}",
                self.removed_original_indices.len()
            ));
        }
        if !self.value_changes.is_empty() {
            parts.push(format!("value_changes={}", self.value_changes.len()));
        }
        parts.join(", ")
    }
}

/// Compact, stable metrics for reporting shrink outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShrinkMetrics {
    pub original_len: usize,
    pub minimized_len: usize,
    /// Number of removed transactions (or removed indices when available).
    pub removed_count: usize,
    /// Number of trace events attached to the report/result.
    pub trace_count: usize,
}

impl ShrinkMetrics {
    pub fn concise(&self) -> String {
        format!(
            "len {} -> {}, removed={}, traces={}",
            self.original_len, self.minimized_len, self.removed_count, self.trace_count
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShrinkOptions {
    /// If true, run a second pass that bisects `SimTxInput.value` downwards.
    ///
    /// Assumption: the violation predicate is monotonic (or mostly monotonic) as
    /// amounts decrease. If not, this pass may fail to find a better minimum.
    pub bisect_value: bool,
    /// Minimum value for bisection (usually 0).
    pub min_value: U256,
    /// If set, only bisect transactions whose original indices are in this set.
    pub restrict_to_original_indices: Option<BTreeSet<usize>>,
}

impl Default for ShrinkOptions {
    fn default() -> Self {
        Self {
            bisect_value: true,
            min_value: U256::ZERO,
            restrict_to_original_indices: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SequenceShrinkResult {
    pub original_sequence: Vec<SimTxInput>,
    pub minimized_sequence: Vec<SimTxInput>,
    pub diff: ShrinkDiffSummary,
    pub traces: Vec<TraceEvent>,
}

impl SequenceShrinkResult {
    pub fn metrics(&self) -> ShrinkMetrics {
        ShrinkMetrics {
            original_len: self.diff.original_len,
            minimized_len: self.diff.minimized_len,
            removed_count: self.diff.removed_original_indices.len(),
            trace_count: self.traces.len(),
        }
    }
}

/// Pluggable predicate shape for future invariants without changing shrinkers.
pub trait SequenceViolationPredicate {
    fn violates(&mut self, sequence: &[SimTxInput]) -> bool;
}

impl<F> SequenceViolationPredicate for F
where
    F: FnMut(&[SimTxInput]) -> bool,
{
    fn violates(&mut self, sequence: &[SimTxInput]) -> bool {
        self(sequence)
    }
}

#[derive(Debug, Clone)]
struct IndexedTx {
    original_index: usize,
    tx: SimTxInput,
}

fn indexed(sequence: &[SimTxInput]) -> Vec<IndexedTx> {
    sequence
        .iter()
        .cloned()
        .enumerate()
        .map(|(original_index, tx)| IndexedTx { original_index, tx })
        .collect()
}

fn unindexed(sequence: &[IndexedTx]) -> Vec<SimTxInput> {
    sequence.iter().map(|it| it.tx.clone()).collect()
}

fn removed_indices(original_len: usize, kept: &[IndexedTx]) -> Vec<usize> {
    let mut kept_set = BTreeSet::new();
    for it in kept {
        kept_set.insert(it.original_index);
    }
    let mut removed = Vec::new();
    for idx in 0..original_len {
        if !kept_set.contains(&idx) {
            removed.push(idx);
        }
    }
    removed
}

/// Shrink a failing `SimTxInput` sequence.
///
/// 1. Greedy top-down deletion shrinking.
/// 2. Optional second pass: bisection shrinking of `tx.value` for each remaining tx.
///
/// The `violates` predicate should return true when the invariant is still violated.
pub fn shrink_simtx_sequence<F>(
    original_sequence: Vec<SimTxInput>,
    mut violates: F,
    options: ShrinkOptions,
) -> SequenceShrinkResult
where
    F: FnMut(&[SimTxInput]) -> bool,
{
    let original_len = original_sequence.len();
    let indexed_seq = indexed(&original_sequence);

    // First pass: remove transactions while the violation persists.
    let minimized_indexed = shrink_sequence(&indexed_seq, |candidate| {
        let candidate_unindexed = unindexed(candidate);
        violates(&candidate_unindexed)
    });

    let mut minimized = unindexed(&minimized_indexed);
    let removed = removed_indices(original_len, &minimized_indexed);

    // Second pass: bisect tx.value downwards per tx, if configured.
    let mut value_changes = Vec::new();
    if options.bisect_value {
        for (i, it) in minimized_indexed.iter().enumerate() {
            let original_index = it.original_index;
            if let Some(allowed) = &options.restrict_to_original_indices {
                if !allowed.contains(&original_index) {
                    continue;
                }
            }

            let current = minimized[i].value;
            if current <= options.min_value {
                continue;
            }

            // Attempt to shrink value while keeping the sequence violating.
            let best = shrink_u256_bisect(current, options.min_value, |candidate_value| {
                let candidate_seq = rewrite_amount(&minimized, i, candidate_value);
                violates(&candidate_seq)
            });

            if best != current {
                value_changes.push(ValueChange {
                    original_index,
                    before: current,
                    after: best,
                });
                minimized[i].value = best;
            }
        }
    }

    let diff = ShrinkDiffSummary {
        original_len,
        minimized_len: minimized.len(),
        removed_original_indices: removed,
        value_changes,
    };

    SequenceShrinkResult {
        original_sequence,
        minimized_sequence: minimized,
        diff,
        traces: Vec::new(),
    }
}

/// Shrink a sequence and return the minimized sequence plus compact metrics and diff summary.
///
/// This is a thin wrapper around `shrink_simtx_sequence` that uses a trait-based predicate,
/// making it easy to plug in future invariant engines (REVM runner, forked state, etc.).
pub fn shrink_minimized_with_report<P>(
    original_sequence: Vec<SimTxInput>,
    mut predicate: P,
    options: ShrinkOptions,
) -> (Vec<SimTxInput>, ShrinkMetrics, ShrinkDiffSummary)
where
    P: SequenceViolationPredicate,
{
    let result = shrink_simtx_sequence(original_sequence, |seq| predicate.violates(seq), options);
    let metrics = result.metrics();
    (result.minimized_sequence, metrics, result.diff)
}

/// Binary-search shrinking for monotonic numeric predicates.
///
/// The predicate should return `true` when the candidate still satisfies the
/// desired condition. The function returns the smallest value in `[min, start]`
/// that continues to satisfy it.
pub fn shrink_u256_bisect<F>(start: U256, min: U256, mut predicate: F) -> U256
where
    F: FnMut(U256) -> bool,
{
    let mut lo = min;
    let mut hi = start;
    let mut best = start;

    while lo <= hi {
        let mid = lo + ((hi - lo) >> 1);
        if predicate(mid) {
            best = mid;
            if mid == U256::ZERO {
                break;
            }
            hi = mid.saturating_sub(U256::from(1u8));
        } else {
            lo = mid.saturating_add(U256::from(1u8));
        }
    }

    best
}

/// Shrink a whole transaction sequence and then optionally shrink one numeric
/// field inside each surviving transaction.
#[derive(Debug, Clone)]
pub struct ShrinkReport {
    pub minimized_sequence: Vec<SimTxInput>,
    pub traces: Vec<TraceEvent>,
}

impl ShrinkReport {
    pub fn new(minimized_sequence: Vec<SimTxInput>, traces: Vec<TraceEvent>) -> Self {
        Self {
            minimized_sequence,
            traces,
        }
    }

    /// Compact human-readable summary (intentionally minimal).
    pub fn summary(&self, original_len: usize) -> String {
        format!(
            "len {} -> {}, traces={}",
            original_len,
            self.minimized_sequence.len(),
            self.traces.len()
        )
    }

    pub fn metrics(&self, original_len: usize) -> ShrinkMetrics {
        let minimized_len = self.minimized_sequence.len();
        ShrinkMetrics {
            original_len,
            minimized_len,
            removed_count: original_len.saturating_sub(minimized_len),
            trace_count: self.traces.len(),
        }
    }
}

/// Utility to rebuild a sequence with a single amount replaced and keep the
/// caller/to/value/data/gas settings intact.
pub fn rewrite_amount(sequence: &[SimTxInput], index: usize, new_amount: U256) -> Vec<SimTxInput> {
    let mut next = sequence.to_vec();
    if let Some(tx) = next.get_mut(index) {
        tx.value = new_amount;
    }
    next
}

/// Simple wrapper for shrinking `Vec<SimTxInput>` by deletion only.
///
/// Returns the minimized sequence plus original/minimized lengths.
pub fn shrink_sim_sequence<F>(sequence: Vec<SimTxInput>, mut violates: F) -> (Vec<SimTxInput>, usize, usize)
where
    F: FnMut(&[SimTxInput]) -> bool,
{
    let original_len = sequence.len();
    let minimized = shrink_sequence(&sequence, |candidate| violates(candidate));
    let minimized_len = minimized.len();
    (minimized, original_len, minimized_len)
}

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
