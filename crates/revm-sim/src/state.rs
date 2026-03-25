//! RPC-based state loading for the REVM simulator.
//!
//! Extends [`Simulator`] with async methods that fetch on-chain
//! account state (balance, nonce, bytecode, storage) via JSON-RPC
//! and insert it into the CacheDB for offline simulation.

use alloy_primitives::{Address, U256};
use anyhow::{anyhow, Result};
use revm::primitives::{
    AccountInfo, Bytecode, Address as RevmAddress, B256 as RevmB256,
    Bytes as RevmBytes, U256 as RevmU256,
};
use tracing::debug;

use crate::simulator::Simulator;

// -- JSON-RPC helpers ------------------------------------------------

/// Standalone JSON-RPC call decoupled from `&self` for use inside
/// parallel futures (`try_join_all`).
async fn rpc_call(
    client: &reqwest::Client,
    rpc_url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value> {
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    });

    let response = client
        .post(rpc_url)
        .json(&request)
        .send()
        .await
        .map_err(|e| anyhow!("RPC request failed: {}", e))?;

    let json: serde_json::Value = response
        .json()
        .await
        .map_err(|e| anyhow!("RPC response parse failed: {}", e))?;

    if let Some(error) = json.get("error") {
        return Err(anyhow!("RPC error: {}", error));
    }

    json.get("result")
        .cloned()
        .ok_or_else(|| anyhow!("Missing result in RPC response"))
}

/// Parse a hex string into `U256`.
fn parse_u256_hex(hex: &str) -> Result<U256> {
    let trimmed = hex.trim_start_matches("0x");
    if trimmed.is_empty() {
        return Ok(U256::ZERO);
    }
    Ok(U256::from_str_radix(trimmed, 16)?)
}

/// Parse a hex string into `u64`.
fn parse_u64_hex(hex: &str) -> Result<u64> {
    let trimmed = hex.trim_start_matches("0x");
    if trimmed.is_empty() {
        return Ok(0);
    }
    Ok(u64::from_str_radix(trimmed, 16)?)
}

/// Parse a hex-encoded bytecode string into raw bytes.
fn parse_code_hex(hex: &str) -> Result<Vec<u8>> {
    let trimmed = hex.trim_start_matches("0x");
    if trimmed.is_empty() {
        return Ok(vec![]);
    }
    Ok(hex::decode(trimmed)?)
}

// -- Parallel account fetcher ----------------------------------------

/// Fetch balance, nonce, and code for multiple addresses in parallel.
/// Returns `Vec<(Address, U256, u64, Vec<u8>)>`.
async fn fetch_accounts_parallel(
    client: &reqwest::Client,
    rpc_url: &str,
    addresses: &[Address],
    block_hex: &str,
) -> Result<Vec<(Address, U256, u64, Vec<u8>)>> {
    let mut handles = Vec::with_capacity(addresses.len());

    for addr in addresses {
        let c = client.clone();
        let url = rpc_url.to_string();
        let block = block_hex.to_string();
        let addr_copy = *addr;
        let addr_hex = format!("{:?}", addr);

        handles.push(tokio::spawn(async move {
            let (bal, nonce, code) = tokio::try_join!(
                rpc_call(
                    &c, &url, "eth_getBalance",
                    serde_json::json!([&addr_hex, &block]),
                ),
                rpc_call(
                    &c, &url, "eth_getTransactionCount",
                    serde_json::json!([&addr_hex, &block]),
                ),
                rpc_call(
                    &c, &url, "eth_getCode",
                    serde_json::json!([&addr_hex, &block]),
                ),
            )?;

            let balance = parse_u256_hex(
                bal.as_str().ok_or_else(|| {
                    anyhow!("Invalid balance for {:?}", addr_copy)
                })?,
            )?;
            let nonce_val = parse_u64_hex(
                nonce.as_str().ok_or_else(|| {
                    anyhow!("Invalid nonce for {:?}", addr_copy)
                })?,
            )?;
            let bytecode = parse_code_hex(
                code.as_str().ok_or_else(|| {
                    anyhow!("Invalid code for {:?}", addr_copy)
                })?,
            )?;

            Ok::<_, anyhow::Error>((
                addr_copy, balance, nonce_val, bytecode,
            ))
        }));
    }

    let mut results = Vec::with_capacity(handles.len());
    for handle in handles {
        results.push(
            handle
                .await
                .map_err(|e| anyhow!("Spawn join error: {}", e))??,
        );
    }
    Ok(results)
}

// -- Insert helper ---------------------------------------------------

/// Insert fetched account data into the simulator's CacheDB.
fn insert_accounts(
    sim: &mut Simulator,
    results: Vec<(Address, U256, u64, Vec<u8>)>,
) {
    for (addr, balance, nonce, code) in results {
        let bytecode = if code.is_empty() {
            Bytecode::default()
        } else {
            Bytecode::new_raw(RevmBytes::from(code))
        };

        let mut info = AccountInfo {
            balance: RevmU256::from_limbs(balance.into_limbs()),
            nonce,
            code_hash: RevmB256::ZERO,
            code: Some(bytecode),
        };

        sim.db.insert_contract(&mut info);
        sim.db.insert_account_info(
            RevmAddress::from_slice(addr.as_slice()),
            info,
        );

        sim.loaded_addresses.insert(addr);
    }
}

// -- Simulator impl --------------------------------------------------

impl Simulator {
    /// Fetch the latest block number from the RPC endpoint.
    pub async fn fetch_block_number(&self) -> Result<u64> {
        let resp = rpc_call(
            &self.http_client,
            &self.config.rpc_url,
            "eth_blockNumber",
            serde_json::json!([]),
        )
        .await?;
        let hex = resp
            .as_str()
            .ok_or_else(|| anyhow!("Invalid blockNumber response"))?;
        parse_u64_hex(hex)
    }

    /// Load on-chain state for the given addresses from RPC.
    ///
    /// Skips addresses that are already cached.  Fetches balance,
    /// nonce, and bytecode in parallel for each new address.
    pub async fn load_state_from_rpc(
        &mut self,
        addresses: &[Address],
    ) -> Result<()> {
        let block_num = if self.loaded_block == 0 {
            let num = self.fetch_block_number().await?;
            self.loaded_block = num;
            num
        } else {
            self.loaded_block
        };
        let block_hex = format!("0x{:x}", block_num);

        let to_load: Vec<Address> = addresses
            .iter()
            .filter(|a| !self.loaded_addresses.contains(*a))
            .copied()
            .collect();

        if to_load.is_empty() {
            return Ok(());
        }

        let results = fetch_accounts_parallel(
            &self.http_client,
            &self.config.rpc_url,
            &to_load,
            &block_hex,
        )
        .await?;

        let count = results.len();
        insert_accounts(self, results);

        debug!(
            "[REVM] Loaded state for {} addresses at block {} (total cached: {})",
            count, block_num, self.loaded_addresses.len()
        );

        Ok(())
    }

    /// Load on-chain state at a specific block number.
    ///
    /// Clears existing state and reloads all addresses at the
    /// specified block. Useful for historical replay.
    pub async fn load_state_at_block(
        &mut self,
        addresses: &[Address],
        block_number: u64,
    ) -> Result<()> {
        self.clear_cache();
        self.loaded_block = block_number;

        let block_hex = format!("0x{:x}", block_number);

        let results = fetch_accounts_parallel(
            &self.http_client,
            &self.config.rpc_url,
            addresses,
            &block_hex,
        )
        .await?;

        let count = results.len();
        insert_accounts(self, results);

        debug!(
            "[REVM] Loaded historical state for {} addresses at block {}",
            count, block_number
        );

        Ok(())
    }

    /// Load specific storage slots for an address into the CacheDB.
    pub async fn load_storage_slots(
        &mut self,
        address: &Address,
        slots: &[U256],
    ) -> Result<()> {
        let block_hex = format!("0x{:x}", self.loaded_block);
        let addr_hex = format!("{:?}", address);
        let revm_addr =
            RevmAddress::from_slice(address.as_slice());

        for slot in slots {
            let slot_hex = format!("0x{:064x}", slot);
            let resp = rpc_call(
                &self.http_client,
                &self.config.rpc_url,
                "eth_getStorageAt",
                serde_json::json!([&addr_hex, &slot_hex, &block_hex]),
            )
            .await?;

            let hex = resp.as_str().ok_or_else(|| {
                anyhow!(
                    "Invalid storage response for {:?} slot {}",
                    address,
                    slot
                )
            })?;
            let value = parse_u256_hex(hex)?;

            self.db
                .insert_account_storage(
                    revm_addr,
                    RevmU256::from_limbs(slot.into_limbs()),
                    RevmU256::from_limbs(value.into_limbs()),
                )
                .map_err(|e| {
                    anyhow!("insert_account_storage: {}", e)
                })?;
        }

        debug!(
            "[REVM] Loaded {} storage slots for {:?}",
            slots.len(),
            address
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SimConfig;

    #[test]
    fn test_parse_u256_hex() {
        let val = parse_u256_hex("0x64").unwrap();
        assert_eq!(val, U256::from(100u64));
    }

    #[test]
    fn test_parse_u256_hex_empty() {
        let val = parse_u256_hex("0x").unwrap();
        assert_eq!(val, U256::ZERO);
    }

    #[test]
    fn test_parse_u64_hex() {
        let val = parse_u64_hex("0xff").unwrap();
        assert_eq!(val, 255u64);
    }

    #[test]
    fn test_parse_code_hex_empty() {
        let code = parse_code_hex("0x").unwrap();
        assert!(code.is_empty());
    }

    #[test]
    fn test_parse_code_hex() {
        let code = parse_code_hex("0x6001").unwrap();
        assert_eq!(code, vec![0x60, 0x01]);
    }

    #[test]
    fn test_insert_accounts_basic() {
        let config = SimConfig::new("http://localhost:8545", 1);
        let mut sim = Simulator::new(config);
        let addr = Address::ZERO;
        let results = vec![(
            addr,
            U256::from(1000u64),
            5u64,
            vec![0x60, 0x00],
        )];
        insert_accounts(&mut sim, results);
        assert!(sim.loaded_addresses.contains(&addr));
        assert_eq!(sim.get_code_len(&addr), 2);
    }
}
