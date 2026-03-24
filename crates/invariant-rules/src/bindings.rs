use alloy_primitives::{Address, U256, keccak256};
use anyhow::{anyhow, Result};
use revm::db::{CacheDB, EmptyDB};
use revm::primitives::{
    Address as RevmAddress, Bytes as RevmBytes, ExecutionResult, Output, SpecId,
    TxKind, U256 as RevmU256,
};
use revm::Evm;
use serde::{Deserialize, Serialize};

use crate::context::{CdpPosition, FeeRecord, InvariantContext, LoanPosition};
use crate::rules::{CompositeInvariant, RuleViolation};

/// Mapping layout variants supported by the extractor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MappingLayout {
    Solidity,
    Vyper,
}

/// Generic storage locator used by the DB extractor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DbField {
    /// Read a raw 256-bit storage slot.
    RawSlot {
        contract: Address,
        slot: U256,
    },
    /// Read a bitfield from a raw storage slot.
    RawBits {
        contract: Address,
        slot: U256,
        offset_bits: u16,
        width_bits: u16,
    },
    /// Read a mapping entry.
    Mapping {
        contract: Address,
        key: Address,
        mapping_slot: U256,
        layout: MappingLayout,
    },
    GetReservesWord {
        contract: Address,
        word_index: u8,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenBalanceBinding {
    pub token: Address,
    pub owner: Address,
    pub field: DbField,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenReserveBinding {
    pub pool: Address,
    pub token: Address,
    pub field: DbField,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolReserveBinding {
    pub pool: Address,
    pub reserve0: DbField,
    pub reserve1: DbField,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotalSupplyBinding {
    pub token: Address,
    pub field: DbField,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CdpBinding {
    pub owner: Address,
    pub collateral_field: DbField,
    pub debt_field: DbField,
    pub collateral_price_asset: Option<Address>,
    pub debt_price_asset: Option<Address>,
    pub liquidation_threshold_bps: u64,
}

/// Binding for individual loan position fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoanPositionBinding {
    pub protocol: Address,
    pub borrower: Address,
    pub borrowed_field: DbField,
    pub collateral_field: DbField,
    pub liquidation_threshold_bps: u64,
}

/// Binding for protocol-level loan total.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoanTotalBinding {
    pub protocol: Address,
    pub field: DbField,
}

/// Binding for protocol fee accounting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeBinding {
    pub protocol: Address,
    pub collected_field: DbField,
    pub expected_field: DbField,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DbInvariantBindings {
    pub token_balances: Vec<TokenBalanceBinding>,
    pub token_reserves: Vec<TokenReserveBinding>,
    pub pool_reserves: Vec<PoolReserveBinding>,
    pub total_supplies: Vec<TotalSupplyBinding>,
    pub cdp_positions: Vec<CdpBinding>,
    pub prices: Vec<(Address, U256)>,
    #[serde(default)]
    pub loan_positions: Vec<LoanPositionBinding>,
    #[serde(default)]
    pub loan_totals: Vec<LoanTotalBinding>,
    #[serde(default)]
    pub fee_records: Vec<FeeBinding>,
}

impl DbInvariantBindings {
    pub fn extract_context(&self, db: &CacheDB<EmptyDB>) -> Result<InvariantContext> {
        let mut ctx = InvariantContext::default();

        for (asset, price) in &self.prices {
            ctx.set_price(*asset, *price);
        }

        for binding in &self.token_balances {
            let value = read_db_field(db, binding.field)?;
            ctx.set_token_balance(binding.token, binding.owner, value);
        }

        for binding in &self.token_reserves {
            let value = read_db_field(db, binding.field)?;
            ctx.set_token_reserve(binding.pool, binding.token, value);
        }

        for binding in &self.pool_reserves {
            let reserve0 = read_db_field(db, binding.reserve0)?;
            let reserve1 = read_db_field(db, binding.reserve1)?;
            ctx.set_pool_reserves(binding.pool, reserve0, reserve1);
        }

        for binding in &self.total_supplies {
            let value = read_db_field(db, binding.field)?;
            ctx.set_total_supply(binding.token, value);
        }

        for binding in &self.cdp_positions {
            let collateral_raw = read_db_field(db, binding.collateral_field)?;
            let debt_raw = read_db_field(db, binding.debt_field)?;
            let collateral_value = multiply_by_price(&ctx, collateral_raw, binding.collateral_price_asset)?;
            let debt_value = multiply_by_price(&ctx, debt_raw, binding.debt_price_asset)?;

            ctx.set_cdp_position(
                binding.owner,
                CdpPosition {
                    collateral_value,
                    debt_value,
                    liquidation_threshold_bps: binding.liquidation_threshold_bps,
                },
            );
        }

        for binding in &self.loan_positions {
            let borrowed = read_db_field(db, binding.borrowed_field)?;
            let collateral = read_db_field(db, binding.collateral_field)?;
            ctx.set_loan_position(
                binding.protocol,
                binding.borrower,
                LoanPosition {
                    borrowed,
                    collateral,
                    liquidation_threshold_bps: binding.liquidation_threshold_bps,
                },
            );
        }

        for binding in &self.loan_totals {
            let total = read_db_field(db, binding.field)?;
            ctx.set_loan_total(binding.protocol, total);
        }

        for binding in &self.fee_records {
            let collected = read_db_field(db, binding.collected_field)?;
            let expected = read_db_field(db, binding.expected_field)?;
            ctx.set_fee_record(
                binding.protocol,
                FeeRecord { collected, expected },
            );
        }

        Ok(ctx)
    }

    pub fn evaluate(&self, db: &CacheDB<EmptyDB>, rules: &CompositeInvariant) -> Result<Option<RuleViolation>> {
        let ctx = self.extract_context(db)?;
        rules.evaluate(&ctx)
    }
}

fn multiply_by_price(
    ctx: &InvariantContext,
    raw: U256,
    price_asset: Option<Address>,
) -> Result<U256> {
    if let Some(asset) = price_asset {
        let price = ctx
            .price(asset)
            .ok_or_else(|| anyhow!("missing price for asset {:?}", asset))?;
        Ok(raw.saturating_mul(price))
    } else {
        Ok(raw)
    }
}

pub fn read_db_field(db: &CacheDB<EmptyDB>, field: DbField) -> Result<U256> {
    match field {
        DbField::RawSlot { contract, slot } => Ok(read_raw_slot(db, contract, slot)),
        DbField::RawBits {
            contract,
            slot,
            offset_bits,
            width_bits,
        } => {
            let raw = read_raw_slot(db, contract, slot);
            Ok(extract_bits(raw, offset_bits, width_bits))
        }
        DbField::Mapping {
            contract,
            key,
            mapping_slot,
            layout,
        } => {
            let slot = mapping_slot_key(key, mapping_slot, layout);
            Ok(read_raw_slot(db, contract, slot))
        }
        DbField::GetReservesWord { contract, word_index } => {
            read_get_reserves_word(db, contract, word_index)
        }
    }
}

fn read_get_reserves_word(db: &CacheDB<EmptyDB>, contract: Address, word_index: u8) -> Result<U256> {
    let mut db_clone = db.clone();
    let mut evm = Evm::builder()
        .with_db(&mut db_clone)
        .with_spec_id(SpecId::CANCUN)
        .modify_tx_env(|tx| {
            tx.caller = RevmAddress::ZERO;
            tx.transact_to = TxKind::Call(RevmAddress::from_slice(contract.as_slice()));
            tx.data = RevmBytes::from(vec![0x09, 0x02, 0xf1, 0xac]);
            tx.value = RevmU256::ZERO;
            tx.gas_limit = 100_000;
        })
        .build();

    let exec = evm
        .transact_commit()
        .map_err(|e| anyhow!("getReserves call failed for {:?}: {:?}", contract, e))?;

    match exec {
        ExecutionResult::Success { output, .. } => {
            let data = match output {
                Output::Call(data) | Output::Create(data, _) => data,
            };
            let start = usize::from(word_index) * 32;
            let end = start + 32;
            if data.len() < end {
                return Err(anyhow!(
                    "getReserves output too short for {:?}: len={} word_index={}",
                    contract,
                    data.len(),
                    word_index
                ));
            }
            Ok(U256::from_be_slice(&data[start..end]))
        }
        ExecutionResult::Revert { output, .. } => Err(anyhow!(
            "getReserves reverted for {:?}: 0x{}",
            contract,
            hex::encode(output)
        )),
        ExecutionResult::Halt { reason, .. } => Err(anyhow!(
            "getReserves halted for {:?}: {:?}",
            contract,
            reason
        )),
    }
}

fn read_raw_slot(db: &CacheDB<EmptyDB>, contract: Address, slot: U256) -> U256 {
    let contract = RevmAddress::from_slice(contract.as_slice());
    let slot = RevmU256::from_limbs(slot.into_limbs());

    db.accounts
        .get(&contract)
        .and_then(|account| account.storage.get(&slot).copied())
        .map(|value| U256::from_limbs(value.into_limbs()))
        .unwrap_or(U256::ZERO)
}

pub fn mapping_slot_key(key: Address, mapping_slot: U256, layout: MappingLayout) -> U256 {
    let mut encoded = [0u8; 64];

    match layout {
        MappingLayout::Solidity => {
            encoded[12..32].copy_from_slice(&key.into_array());
            encoded[32..64].copy_from_slice(&mapping_slot.to_be_bytes::<32>());
        }
        MappingLayout::Vyper => {
            encoded[0..32].copy_from_slice(&mapping_slot.to_be_bytes::<32>());
            encoded[44..64].copy_from_slice(&key.into_array());
        }
    }

    U256::from_be_slice(&keccak256(encoded).0)
}

fn extract_bits(raw: U256, offset_bits: u16, width_bits: u16) -> U256 {
    if width_bits == 0 {
        return U256::ZERO;
    }
    if width_bits >= 256 {
        return raw >> offset_bits;
    }

    let mask = (U256::from(1u8) << width_bits) - U256::from(1u8);
    (raw >> offset_bits) & mask
}
