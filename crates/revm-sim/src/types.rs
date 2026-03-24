//! Core types for REVM-based security simulation.

use alloy_primitives::{Address, Bytes, U256};
use revm::db::{CacheDB, EmptyDB};
use serde::{Deserialize, Serialize};

use invariant_rules::{InvariantContext, RuleViolation};
use invariant_fuzzer::TraceEvent;

/// Configuration for the REVM simulator.
#[derive(Debug, Clone)]
pub struct SimConfig {
    /// RPC URL for state fetching
    pub rpc_url: String,
    /// Chain ID (1 for Ethereum, 10 for Optimism, etc.)
    pub chain_id: u64,
    /// Number of blocks between state refreshes
    pub refresh_interval_blocks: u64,
    /// RPC timeout in seconds
    pub rpc_timeout_secs: u64,
}

impl SimConfig {
    pub fn new(rpc_url: impl Into<String>, chain_id: u64) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            chain_id,
            refresh_interval_blocks: 10,
            rpc_timeout_secs: 5,
        }
    }

    pub fn ethereum(rpc_url: impl Into<String>) -> Self {
        Self::new(rpc_url, 1)
    }

    pub fn with_refresh_interval(mut self, blocks: u64) -> Self {
        self.refresh_interval_blocks = blocks;
        self
    }

    pub fn with_rpc_timeout(mut self, secs: u64) -> Self {
        self.rpc_timeout_secs = secs;
        self
    }
}

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

/// Result of a single transaction simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimResult {
    pub success: bool,
    pub gas_used: u64,
    pub revert_reason: Option<String>,
    pub output: Bytes,
    pub logs: Vec<SimLog>,
}

/// Event log from simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimLog {
    pub address: Address,
    pub topics: Vec<alloy_primitives::B256>,
    pub data: Bytes,
}

/// Block header for configuring REVM BlockEnv.
#[derive(Debug, Clone)]
pub struct BlockHeader {
    pub number: u64,
    pub timestamp: u64,
    pub coinbase: Address,
    pub base_fee_per_gas: Option<U256>,
    pub gas_limit: u64,
}

/// Snapshot ID for database checkpoints.
pub type SnapshotId = u64;

/// Result of running a TX sequence under an InvariantInspector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequenceInspectionReport {
    pub tx_results: Vec<SimResult>,
    pub traces: Vec<TraceEvent>,
    pub visited_pcs: Vec<usize>,
    pub trace_offsets: Vec<usize>,
}

/// Sequence execution plus invariant evaluation on final DB state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantAuditReport {
    pub inspection: SequenceInspectionReport,
    pub context: InvariantContext,
    pub violation: Option<RuleViolation>,
    #[serde(skip_serializing, skip_deserializing, default)]
    pub final_db: Option<CacheDB<EmptyDB>>,
}

/// Per-TX invariant violation record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxInvariantSnapshot {
    pub tx_index: usize,
    pub context: InvariantContext,
    pub violation: Option<RuleViolation>,
}

/// Sequence execution with invariant evaluation after EACH transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequenceInvariantResult {
    pub inspection: SequenceInspectionReport,
    pub per_tx_snapshots: Vec<TxInvariantSnapshot>,
    pub first_violation: Option<RuleViolation>,
    pub violation_count: usize,
}

/// Revert reason classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevertLabel {
    OutOfGas,
    RevertedNoReason,
    InsufficientLiquidity,
    InvalidOpcode,
    Unknown,
}

impl std::fmt::Display for RevertLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutOfGas => write!(f, "OutOfGas"),
            Self::RevertedNoReason => write!(f, "RevertedNoReason"),
            Self::InsufficientLiquidity => write!(f, "InsufficientLiquidity"),
            Self::InvalidOpcode => write!(f, "InvalidOpcode"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}
