//! Core REVM simulator for security research.
//!
//! Provides fork-based transaction replay, sequence execution,
//! and invariant auditing on live EVM state.

use alloy_primitives::{Address, Bytes, U256};
use anyhow::{anyhow, Result};
use revm::db::{CacheDB, EmptyDB};
use revm::primitives::{
    AccountInfo, BlockEnv, ExecutionResult, Output, SpecId, TxEnv,
    TransactTo, Address as RevmAddress, B256 as RevmB256,
    U256 as RevmU256, Bytes as RevmBytes,
};
use revm::Evm;
use std::collections::{HashMap, HashSet};

use crate::types::*;

/// REVM-based simulator for DeFi security research.
///
/// Uses CacheDB<EmptyDB> with on-demand RPC state loading.
/// Addresses are preloaded before simulation to ensure contract
/// code and storage are available.
pub struct Simulator {
    config: SimConfig,
    db: CacheDB<EmptyDB>,
    http_client: reqwest::Client,
    loaded_block: u64,
    loaded_addresses: HashSet<Address>,
    pub(crate) block_env: BlockEnv,
    snapshots: HashMap<SnapshotId, CacheDB<EmptyDB>>,
    next_snapshot_id: SnapshotId,
}

impl Simulator {
    /// Create a new simulator with empty cache.
    pub fn new(config: SimConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(config.rpc_timeout_secs))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            config,
            db: CacheDB::new(EmptyDB::default()),
            http_client,
            loaded_block: 0,
            loaded_addresses: HashSet::new(),
            block_env: BlockEnv::default(),
            snapshots: HashMap::new(),
            next_snapshot_id: 0,
        }
    }

    /// Clone the internal database for external analysis.
    pub fn fork_db(&self) -> CacheDB<EmptyDB> {
        self.db.clone()
    }

    pub fn chain_id(&self) -> u64 {
        self.config.chain_id
    }

    /// Clear the state cache.
    pub fn clear_cache(&mut self) {
        self.db = CacheDB::new(EmptyDB::default());
        self.loaded_addresses.clear();
    }

    /// Get bytecode length for an address (0 if not loaded or EOA).
    pub fn get_code_len(&self, address: &Address) -> usize {
        let addr = RevmAddress::from_slice(address.as_slice());
        self.db.accounts.get(&addr)
            .and_then(|acc| acc.info.code.as_ref())
            .map(|code| code.len())
            .unwrap_or(0)
    }

    /// Get raw bytecode for an address if loaded.
    pub fn get_code(&self, address: &Address) -> Option<Vec<u8>> {
        let addr = RevmAddress::from_slice(address.as_slice());
        self.db.accounts.get(&addr)
            .and_then(|acc| acc.info.code.as_ref())
            .map(|code| code.original_byte_slice().to_vec())
    }

    /// Get a storage slot value if loaded.
    pub fn get_storage(&self, address: &Address, key: U256) -> Option<U256> {
        let addr = RevmAddress::from_slice(address.as_slice());
        self.db.accounts.get(&addr)
            .and_then(|acc| {
                acc.storage
                    .get(&RevmU256::from_limbs(key.into_limbs()))
            })
            .map(|slot| U256::from_limbs(slot.into_limbs()))
    }

    /// Set a storage value directly in the CacheDB.
    pub fn set_storage(&mut self, address: Address, key: U256, value: U256) {
        let addr = RevmAddress::from_slice(address.as_slice());
        let _ = self.db.insert_account_storage(
            addr,
            RevmU256::from_limbs(key.into_limbs()),
            RevmU256::from_limbs(value.into_limbs()),
        );
    }

    /// Set block environment from block header.
    pub fn set_block_env(&mut self, header: &BlockHeader) {
        self.block_env = BlockEnv {
            number: RevmU256::from(header.number),
            timestamp: RevmU256::from(header.timestamp),
            coinbase: RevmAddress::from_slice(header.coinbase.as_slice()),
            basefee: RevmU256::from_limbs(
                header.base_fee_per_gas.unwrap_or(U256::ZERO).into_limbs(),
            ),
            gas_limit: RevmU256::from(header.gas_limit),
            ..Default::default()
        };
    }

    /// Override basefee (set to 0 for simulation).
    pub fn set_basefee(&mut self, basefee: U256) {
        self.block_env.basefee = RevmU256::from_limbs(basefee.into_limbs());
    }

    /// Prefund an address with native token for simulation.
    pub fn prefund(&mut self, address: &Address, balance_wei: U256) {
        let info = AccountInfo {
            balance: RevmU256::from_limbs(balance_wei.into_limbs()),
            nonce: 0,
            code_hash: RevmB256::ZERO,
            code: None,
        };
        let addr = RevmAddress::from_slice(address.as_slice());
        self.db.insert_account_info(addr, info);
        self.loaded_addresses.insert(*address);
    }

    // -- Snapshot management --

    /// Create a snapshot of the current state.
    pub fn snapshot(&mut self) -> SnapshotId {
        let id = self.next_snapshot_id;
        self.next_snapshot_id += 1;
        self.snapshots.insert(id, self.db.clone());
        id
    }

    /// Restore to a previously created snapshot.
    pub fn restore(&mut self, id: SnapshotId) -> Result<()> {
        let snap = self.snapshots.get(&id)
            .ok_or_else(|| anyhow!("Snapshot {} not found", id))?;
        self.db = snap.clone();
        Ok(())
    }

    /// Release a snapshot to free memory.
    pub fn release_snapshot(&mut self, id: SnapshotId) {
        self.snapshots.remove(&id);
    }

    // -- Single TX simulation --

    /// Simulate a single transaction (does NOT commit state).
    pub fn simulate_tx(&self, tx: &SimTxInput) -> Result<SimResult> {
        let mut db_clone = self.db.clone();
        let tx_env = self.build_tx_env(tx);

        let mut evm = Evm::builder()
            .with_db(&mut db_clone)
            .with_spec_id(SpecId::CANCUN)
            .with_block_env(self.block_env.clone())
            .with_tx_env(tx_env)
            .modify_cfg_env(|cfg| {
                cfg.chain_id = self.config.chain_id;
            })
            .build();

        let result = evm.transact()
            .map_err(|e| anyhow!("REVM transact failed: {:?}", e))?;
        self.convert_result(result.result)
    }

    /// Execute a single transaction with state commit.
    pub fn execute_tx(&mut self, tx: &SimTxInput) -> Result<SimResult> {
        if let Some(nonce) = tx.nonce {
            let addr = RevmAddress::from_slice(tx.caller.as_slice());
            match self.db.accounts.get_mut(&addr) {
                Some(account) => { account.info.nonce = nonce; }
                None => {
                    let info = AccountInfo {
                        balance: RevmU256::ZERO,
                        nonce,
                        code_hash: RevmB256::ZERO,
                        code: None,
                    };
                    self.db.insert_account_info(addr, info);
                }
            }
        }

        let tx_env = self.build_tx_env(tx);
        let mut db_clone = self.db.clone();

        let result = {
            let mut evm = Evm::builder()
                .with_db(&mut db_clone)
                .with_spec_id(SpecId::CANCUN)
                .with_block_env(self.block_env.clone())
                .with_tx_env(tx_env)
                .modify_cfg_env(|cfg| {
                    cfg.chain_id = self.config.chain_id;
                })
                .build();

            match evm.transact_commit() {
                Ok(exec) => exec,
                Err(err) => return Ok(Self::tx_error_result(err)),
            }
        };

        self.db = db_clone;
        self.convert_result(result)
    }

    /// Estimate gas for a transaction (with 20% buffer).
    pub fn estimate_gas(&self, tx: &SimTxInput) -> Result<u64> {
        let sim = self.simulate_tx(tx)?;
        if sim.success {
            Ok((sim.gas_used as f64 * 1.2).ceil() as u64)
        } else {
            Err(anyhow!("TX would revert: {:?}", sim.revert_reason))
        }
    }

    // -- Sequence simulation --

    /// Simulate a sequence of transactions (commits each in order,
    /// does NOT mutate the simulator's internal DB).
    pub fn simulate_sequence(
        &self, txs: &[SimTxInput],
    ) -> Result<Vec<SimResult>> {
        let mut db_clone = self.db.clone();
        let mut results = Vec::with_capacity(txs.len());

        for tx in txs {
            let tx_env = self.build_tx_env(tx);
            let exec = {
                let mut evm = Evm::builder()
                    .with_db(&mut db_clone)
                    .with_spec_id(SpecId::CANCUN)
                    .with_block_env(self.block_env.clone())
                    .with_tx_env(tx_env)
                    .modify_cfg_env(|cfg| {
                        cfg.chain_id = self.config.chain_id;
                    })
                    .build();

                match evm.transact_commit() {
                    Ok(exec) => exec,
                    Err(err) => {
                        results.push(Self::tx_error_result(err));
                        continue;
                    }
                }
            };
            results.push(self.convert_result(exec)?);
        }
        Ok(results)
    }

    /// Classify revert reason for analysis.
    pub fn classify_revert(
        result: &ExecutionResult, gas_limit: u64,
    ) -> RevertLabel {
        use revm::primitives::HaltReason;
        match result {
            ExecutionResult::Success { .. } => RevertLabel::Unknown,
            ExecutionResult::Revert { gas_used, .. } => {
                if *gas_used >= gas_limit {
                    RevertLabel::OutOfGas
                } else {
                    RevertLabel::RevertedNoReason
                }
            }
            ExecutionResult::Halt { reason, .. } => match reason {
                HaltReason::OutOfGas(_) => RevertLabel::OutOfGas,
                HaltReason::InvalidFEOpcode
                | HaltReason::OpcodeNotFound => RevertLabel::InvalidOpcode,
                HaltReason::OutOfFunds => {
                    RevertLabel::InsufficientLiquidity
                }
                _ => RevertLabel::Unknown,
            },
        }
    }

    // -- Private helpers --

    pub(crate) fn build_tx_env(&self, tx: &SimTxInput) -> TxEnv {
        TxEnv {
            caller: RevmAddress::from_slice(tx.caller.as_slice()),
            transact_to: TransactTo::Call(
                RevmAddress::from_slice(tx.to.as_slice()),
            ),
            value: RevmU256::from_limbs(tx.value.into_limbs()),
            data: RevmBytes::from(tx.data.to_vec()),
            gas_limit: tx.gas_limit,
            gas_price: RevmU256::from(tx.gas_price as u128),
            gas_priority_fee: None,
            chain_id: Some(self.config.chain_id),
            nonce: tx.nonce,
            ..Default::default()
        }
    }

    pub(crate) fn tx_error_result<E: std::fmt::Debug>(err: E) -> SimResult {
        SimResult {
            success: false,
            gas_used: 0,
            revert_reason: Some(format!("TxEnvError: {:?}", err)),
            output: Bytes::new(),
            logs: vec![],
        }
    }

    pub(crate) fn convert_result(
        &self, result: ExecutionResult,
    ) -> Result<SimResult> {
        match result {
            ExecutionResult::Success {
                output, gas_used, logs, ..
            } => {
                let output_bytes = match output {
                    Output::Call(data) => Bytes::from(data.to_vec()),
                    Output::Create(data, _) => Bytes::from(data.to_vec()),
                };
                Ok(SimResult {
                    success: true,
                    gas_used,
                    revert_reason: None,
                    output: output_bytes,
                    logs: logs.into_iter().map(|l| SimLog {
                        address: Address::from_slice(
                            l.address.as_slice(),
                        ),
                        topics: l.data.topics().iter().map(|t| {
                            alloy_primitives::B256::from_slice(
                                t.as_slice(),
                            )
                        }).collect(),
                        data: Bytes::from(l.data.data.to_vec()),
                    }).collect(),
                })
            }
            ExecutionResult::Revert { output, gas_used } => {
                let reason = Self::decode_revert(&output);
                Ok(SimResult {
                    success: false,
                    gas_used,
                    revert_reason: Some(reason),
                    output: Bytes::new(),
                    logs: vec![],
                })
            }
            ExecutionResult::Halt { reason, gas_used } => Ok(SimResult {
                success: false,
                gas_used,
                revert_reason: Some(format!("Halted: {:?}", reason)),
                output: Bytes::new(),
                logs: vec![],
            }),
        }
    }

    fn decode_revert(output: &RevmBytes) -> String {
        if output.len() >= 68 && output[0..4] == [0x08, 0xc3, 0x79, 0xa0]
        {
            let len_start = 36;
            if len_start + 32 <= output.len() {
                let len_bytes: [u8; 8] = [
                    output[len_start + 24], output[len_start + 25],
                    output[len_start + 26], output[len_start + 27],
                    output[len_start + 28], output[len_start + 29],
                    output[len_start + 30], output[len_start + 31],
                ];
                let length = u64::from_be_bytes(len_bytes) as usize;
                let str_start = len_start + 32;
                if str_start + length <= output.len() {
                    if let Ok(reason) = String::from_utf8(
                        output[str_start..str_start + length].to_vec(),
                    ) {
                        return reason;
                    }
                }
            }
        }
        format!("0x{}", hex::encode(output))
    }
}

impl Clone for Simulator {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            db: self.db.clone(),
            http_client: self.http_client.clone(),
            loaded_block: self.loaded_block,
            loaded_addresses: self.loaded_addresses.clone(),
            block_env: self.block_env.clone(),
            snapshots: HashMap::new(),
            next_snapshot_id: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simulator_new() {
        let config = SimConfig::ethereum("http://localhost:8545");
        let sim = Simulator::new(config);
        assert_eq!(sim.chain_id(), 1);
    }

    #[test]
    fn test_snapshot_restore() {
        let config = SimConfig::new("http://localhost:8545", 1);
        let mut sim = Simulator::new(config);
        let addr = Address::ZERO;
        let key = U256::from(1u64);

        sim.set_storage(addr, key, U256::from(42u64));
        let snap = sim.snapshot();

        sim.set_storage(addr, key, U256::from(99u64));
        assert_eq!(sim.get_storage(&addr, key), Some(U256::from(99u64)));

        sim.restore(snap).unwrap();
        assert_eq!(sim.get_storage(&addr, key), Some(U256::from(42u64)));
    }

    #[test]
    fn test_prefund() {
        let config = SimConfig::new("http://localhost:8545", 1);
        let mut sim = Simulator::new(config);
        let addr = Address::ZERO;
        sim.prefund(&addr, U256::from(1_000_000u64));
        assert!(sim.loaded_addresses.contains(&addr));
    }

    #[test]
    fn test_config_builder() {
        let config = SimConfig::new("http://rpc.example.com", 42)
            .with_refresh_interval(50)
            .with_rpc_timeout(10);
        assert_eq!(config.chain_id, 42);
        assert_eq!(config.refresh_interval_blocks, 50);
        assert_eq!(config.rpc_timeout_secs, 10);
    }
}
