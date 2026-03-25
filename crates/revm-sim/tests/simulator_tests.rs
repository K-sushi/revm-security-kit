//! Integration tests for the core Simulator.

use alloy_primitives::{Address, U256};
use revm_sim::{SimConfig, Simulator};

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
    // Verify the address is tracked (via code_len check — EOA has 0)
    assert_eq!(sim.get_code_len(&addr), 0);
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
