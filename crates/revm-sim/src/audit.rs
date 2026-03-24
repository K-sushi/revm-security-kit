//! Invariant-aware sequence simulation methods.
//!
//! Extends [`Simulator`] with methods that attach an [`InvariantInspector`]
//! during sequence replay and optionally evaluate invariant rules against
//! the resulting EVM state.

use anyhow::Result;
use invariant_fuzzer::InvariantInspector;
use invariant_rules::{CompositeInvariant, DbInvariantBindings, RuleViolation};
use revm::primitives::SpecId;
use revm::{inspector_handle_register, Context, Evm};

use crate::simulator::Simulator;
use crate::types::*;

impl Simulator {
    /// Simulate a sequence of transactions on a cloned DB and commit
    /// each transaction in order, while attaching an
    /// [`InvariantInspector`] to capture a step-level trace.
    ///
    /// This never mutates the simulator's internal DB.
    pub fn simulate_sequence_inspected(
        &self,
        txs: &[SimTxInput],
    ) -> Result<SequenceInspectionReport> {
        let mut db_clone = self.fork_db();
        let mut inspector = InvariantInspector::new();
        let mut results = Vec::with_capacity(txs.len());
        let mut trace_offsets = Vec::with_capacity(txs.len());

        for tx in txs {
            trace_offsets.push(inspector.traces.len());

            let tx_env = self.build_tx_env(tx);
            let exec = {
                let mut evm = Evm::builder()
                    .with_db(&mut db_clone)
                    .with_external_context(inspector)
                    .append_handler_register(inspector_handle_register)
                    .with_spec_id(SpecId::CANCUN)
                    .with_block_env(self.block_env.clone())
                    .with_tx_env(tx_env)
                    .modify_cfg_env(|cfg| {
                        cfg.chain_id = self.chain_id();
                    })
                    .build();

                match evm.transact_commit() {
                    Ok(exec) => {
                        let Context { external, .. } =
                            evm.into_context();
                        inspector = external;
                        exec
                    }
                    Err(err) => {
                        let Context { external, .. } =
                            evm.into_context();
                        inspector = external;
                        results.push(Self::tx_error_result(err));
                        continue;
                    }
                }
            };

            results.push(self.convert_result(exec)?);
        }

        let visited_pcs = inspector
            .visited_pcs()
            .iter()
            .copied()
            .collect::<Vec<_>>();

        Ok(SequenceInspectionReport {
            tx_results: results,
            traces: inspector.traces,
            visited_pcs,
            trace_offsets,
        })
    }

    /// Simulate a sequence, extract a post-state [`InvariantContext`],
    /// and evaluate the supplied rule set against that state.
    ///
    /// Returns both the inspection traces and the invariant evaluation.
    /// This never mutates the simulator's internal DB.
    pub fn simulate_sequence_with_invariants(
        &self,
        txs: &[SimTxInput],
        bindings: &DbInvariantBindings,
        rules: &CompositeInvariant,
    ) -> Result<InvariantAuditReport> {
        let mut db_clone = self.fork_db();
        let mut inspector = InvariantInspector::new();
        let mut results = Vec::with_capacity(txs.len());
        let mut trace_offsets = Vec::with_capacity(txs.len());

        for tx in txs {
            trace_offsets.push(inspector.traces.len());

            let tx_env = self.build_tx_env(tx);
            let exec = {
                let mut evm = Evm::builder()
                    .with_db(&mut db_clone)
                    .with_external_context(inspector)
                    .append_handler_register(inspector_handle_register)
                    .with_spec_id(SpecId::CANCUN)
                    .with_block_env(self.block_env.clone())
                    .with_tx_env(tx_env)
                    .modify_cfg_env(|cfg| {
                        cfg.chain_id = self.chain_id();
                    })
                    .build();

                match evm.transact_commit() {
                    Ok(exec) => {
                        let Context { external, .. } =
                            evm.into_context();
                        inspector = external;
                        exec
                    }
                    Err(err) => {
                        let Context { external, .. } =
                            evm.into_context();
                        inspector = external;
                        results.push(Self::tx_error_result(err));
                        continue;
                    }
                }
            };

            results.push(self.convert_result(exec)?);
        }

        let context = bindings.extract_context(&db_clone)?;
        let violation = rules.evaluate(&context)?;
        let visited_pcs = inspector
            .visited_pcs()
            .iter()
            .copied()
            .collect::<Vec<_>>();

        let inspection = SequenceInspectionReport {
            tx_results: results,
            traces: inspector.traces,
            visited_pcs,
            trace_offsets,
        };

        Ok(InvariantAuditReport {
            inspection,
            context,
            violation,
            final_db: Some(db_clone),
        })
    }

    /// Simulate a sequence and evaluate invariant rules after EACH
    /// transaction.
    ///
    /// This catches rounding drain attacks where repeated small
    /// operations each cause a sub-threshold violation that compounds
    /// across the sequence.
    ///
    /// This never mutates the simulator's internal DB.
    pub fn simulate_sequence_with_per_tx_invariants(
        &self,
        txs: &[SimTxInput],
        bindings: &DbInvariantBindings,
        rules: &CompositeInvariant,
    ) -> Result<SequenceInvariantResult> {
        let mut db_clone = self.fork_db();
        let mut inspector = InvariantInspector::new();
        let mut results = Vec::with_capacity(txs.len());
        let mut trace_offsets = Vec::with_capacity(txs.len());
        let mut per_tx_snapshots = Vec::with_capacity(txs.len());
        let mut first_violation: Option<RuleViolation> = None;
        let mut violation_count: usize = 0;

        for (tx_index, tx) in txs.iter().enumerate() {
            trace_offsets.push(inspector.traces.len());

            let tx_env = self.build_tx_env(tx);
            let exec = {
                let mut evm = Evm::builder()
                    .with_db(&mut db_clone)
                    .with_external_context(inspector)
                    .append_handler_register(inspector_handle_register)
                    .with_spec_id(SpecId::CANCUN)
                    .with_block_env(self.block_env.clone())
                    .with_tx_env(tx_env)
                    .modify_cfg_env(|cfg| {
                        cfg.chain_id = self.chain_id();
                    })
                    .build();

                match evm.transact_commit() {
                    Ok(exec) => {
                        let Context { external, .. } =
                            evm.into_context();
                        inspector = external;
                        exec
                    }
                    Err(err) => {
                        let Context { external, .. } =
                            evm.into_context();
                        inspector = external;
                        results.push(Self::tx_error_result(err));
                        let ctx =
                            bindings.extract_context(&db_clone)?;
                        let violation = rules.evaluate(&ctx)?;
                        if violation.is_some() {
                            violation_count += 1;
                            if first_violation.is_none() {
                                first_violation = violation.clone();
                            }
                        }
                        per_tx_snapshots.push(TxInvariantSnapshot {
                            tx_index,
                            context: ctx,
                            violation,
                        });
                        continue;
                    }
                }
            };

            results.push(self.convert_result(exec)?);

            let ctx = bindings.extract_context(&db_clone)?;
            let violation = rules.evaluate(&ctx)?;
            if violation.is_some() {
                violation_count += 1;
                if first_violation.is_none() {
                    first_violation = violation.clone();
                }
            }
            per_tx_snapshots.push(TxInvariantSnapshot {
                tx_index,
                context: ctx,
                violation,
            });
        }

        let visited_pcs = inspector
            .visited_pcs()
            .iter()
            .copied()
            .collect::<Vec<_>>();

        let inspection = SequenceInspectionReport {
            tx_results: results,
            traces: inspector.traces,
            visited_pcs,
            trace_offsets,
        };

        Ok(SequenceInvariantResult {
            inspection,
            per_tx_snapshots,
            first_violation,
            violation_count,
        })
    }
}
