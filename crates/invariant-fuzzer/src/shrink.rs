//! Shrinking algorithms for finding minimal invariant-violating sequences.

use alloy_primitives::U256;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::{SimTxInput, TraceEvent};

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
