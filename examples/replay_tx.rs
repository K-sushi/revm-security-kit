//! REVM Simulator — Transaction Replay Example
//!
//! Demonstrates:
//! 1. Create a SimConfig and Simulator
//! 2. Prefund an account, create a SimTxInput (simple ETH transfer)
//! 3. Simulate a transaction (non-committing)
//! 4. Snapshot / restore state
//! 5. Print results
//!
//! This example uses an in-memory CacheDB (no live RPC needed).

use alloy_primitives::{Address, Bytes, U256};
use revm_sim::{SimConfig, SimTxInput, Simulator};

fn main() {
    // ----------------------------------------------------------------
    // Step 1: Create SimConfig and Simulator
    // ----------------------------------------------------------------
    let config = SimConfig::ethereum("http://localhost:8545")
        .with_refresh_interval(50)
        .with_rpc_timeout(10);

    let mut sim = Simulator::new(config);
    println!("[1] Simulator created (chain_id={})", sim.chain_id());

    // ----------------------------------------------------------------
    // Step 2: Prefund sender and build a simple transfer tx
    // ----------------------------------------------------------------
    let sender = Address::from([0xAA; 20]);
    let recipient = Address::from([0xBB; 20]);
    let fund_amount = U256::from(10_000_000_000_000_000_000u128); // 10 ETH

    sim.prefund(&sender, fund_amount);
    println!("[2] Prefunded sender {} with {} wei", sender, fund_amount);

    let tx = SimTxInput {
        caller: sender,
        to: recipient,
        value: U256::from(1_000_000_000_000_000_000u128), // 1 ETH
        data: Bytes::new(),
        gas_limit: 21_000,
        gas_price: 0, // zero gas price for simulation
        nonce: Some(0),
    };

    // ----------------------------------------------------------------
    // Step 3: Simulate the transaction (does NOT commit state)
    // ----------------------------------------------------------------
    match sim.simulate_tx(&tx) {
        Ok(result) => {
            println!("[3] simulate_tx result:");
            println!("    success     = {}", result.success);
            println!("    gas_used    = {}", result.gas_used);
            println!("    revert      = {:?}", result.revert_reason);
            println!("    output_len  = {}", result.output.len());
            println!("    logs_count  = {}", result.logs.len());
        }
        Err(e) => {
            println!("[3] simulate_tx error: {}", e);
        }
    }

    // ----------------------------------------------------------------
    // Step 4: Snapshot, mutate, restore
    // ----------------------------------------------------------------
    let snap_id = sim.snapshot();
    println!("[4a] Snapshot created (id={})", snap_id);

    // Write a storage value
    let storage_addr = Address::ZERO;
    let key = U256::from(42u64);
    let val = U256::from(12345u64);
    sim.set_storage(storage_addr, key, val);

    let stored = sim.get_storage(&storage_addr, key);
    println!("[4b] Storage after set: slot {} = {:?}", key, stored);

    // Restore snapshot (rolls back the storage write)
    sim.restore(snap_id).expect("restore should succeed");
    let after_restore = sim.get_storage(&storage_addr, key);
    println!("[4c] Storage after restore: slot {} = {:?}", key, after_restore);

    // Release snapshot to free memory
    sim.release_snapshot(snap_id);
    println!("[4d] Snapshot released");

    // ----------------------------------------------------------------
    // Step 5: Execute with state commit, then inspect
    // ----------------------------------------------------------------
    match sim.execute_tx(&tx) {
        Ok(result) => {
            println!("[5] execute_tx (committed) result:");
            println!("    success  = {}", result.success);
            println!("    gas_used = {}", result.gas_used);
        }
        Err(e) => {
            println!("[5] execute_tx error: {}", e);
        }
    }

    println!("\nDone. REVM replay example complete.");
}
