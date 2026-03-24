//! Reusable invariant-rule DSL for REVM-driven audit workflows.
//!
//! The goal is to keep rule evaluation protocol-agnostic:
//! - AMM rules operate on pool balances/reserves
//! - CDP rules operate on collateral/debt snapshots
//! - Future Foundry parsing can map into the same rule types

use alloy_primitives::{Address, U256, keccak256};
use anyhow::{anyhow, Result};
use revm::db::{CacheDB, EmptyDB};
use revm::primitives::{Address as RevmAddress, Bytes as RevmBytes, ExecutionResult, Output, SpecId, TxKind, U256 as RevmU256};
use revm::Evm;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Snapshot of the values the invariant engine reasons over.
///
/// This is intentionally abstract. A simulator or RPC-backed adapter can
/// populate the fields from on-chain state, forked state, or mocked test data.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvariantContext {
    token_balances: HashMap<(Address, Address), U256>,
    token_reserves: HashMap<(Address, Address), U256>,
    pool_reserves: HashMap<Address, (U256, U256)>,
    total_supplies: HashMap<Address, U256>,
    cdp_positions: HashMap<Address, CdpPosition>,
    prices: HashMap<Address, U256>,
    /// Tracked loan positions keyed by (protocol, borrower).
    loan_positions: HashMap<(Address, Address), LoanPosition>,
    /// Aggregate loan total tracked by the protocol keyed by protocol address.
    loan_totals: HashMap<Address, U256>,
    /// Fee records keyed by protocol address.
    fee_records: HashMap<Address, FeeRecord>,
}

impl InvariantContext {
    pub fn is_empty(&self) -> bool {
        self.token_balances.is_empty()
            && self.token_reserves.is_empty()
            && self.pool_reserves.is_empty()
            && self.total_supplies.is_empty()
            && self.cdp_positions.is_empty()
            && self.prices.is_empty()
            && self.loan_positions.is_empty()
            && self.loan_totals.is_empty()
            && self.fee_records.is_empty()
    }

    pub fn set_token_balance(&mut self, token: Address, owner: Address, amount: U256) {
        self.token_balances.insert((token, owner), amount);
    }

    pub fn set_token_reserve(&mut self, pool: Address, token: Address, reserve: U256) {
        self.token_reserves.insert((pool, token), reserve);
    }

    pub fn set_pool_reserves(&mut self, pool: Address, reserve0: U256, reserve1: U256) {
        self.pool_reserves.insert(pool, (reserve0, reserve1));
    }

    pub fn set_total_supply(&mut self, token: Address, amount: U256) {
        self.total_supplies.insert(token, amount);
    }

    pub fn set_cdp_position(&mut self, owner: Address, position: CdpPosition) {
        self.cdp_positions.insert(owner, position);
    }

    pub fn set_price(&mut self, asset: Address, price: U256) {
        self.prices.insert(asset, price);
    }

    pub fn token_balance(&self, token: Address, owner: Address) -> Option<U256> {
        self.token_balances.get(&(token, owner)).copied()
    }

    pub fn token_reserve(&self, pool: Address, token: Address) -> Option<U256> {
        self.token_reserves.get(&(pool, token)).copied()
    }

    pub fn pool_reserves(&self, pool: Address) -> Option<(U256, U256)> {
        self.pool_reserves.get(&pool).copied()
    }

    pub fn total_supply(&self, token: Address) -> Option<U256> {
        self.total_supplies.get(&token).copied()
    }

    pub fn cdp_position(&self, owner: Address) -> Option<&CdpPosition> {
        self.cdp_positions.get(&owner)
    }

    pub fn price(&self, asset: Address) -> Option<U256> {
        self.prices.get(&asset).copied()
    }

    pub fn set_loan_position(
        &mut self,
        protocol: Address,
        borrower: Address,
        position: LoanPosition,
    ) {
        self.loan_positions.insert((protocol, borrower), position);
    }

    pub fn loan_position(
        &self,
        protocol: Address,
        borrower: Address,
    ) -> Option<&LoanPosition> {
        self.loan_positions.get(&(protocol, borrower))
    }

    pub fn loan_positions_for_protocol(
        &self,
        protocol: Address,
    ) -> impl Iterator<Item = (&Address, &LoanPosition)> {
        self.loan_positions
            .iter()
            .filter(move |((p, _), _)| *p == protocol)
            .map(|((_, borrower), pos)| (borrower, pos))
    }

    pub fn set_loan_total(&mut self, protocol: Address, total: U256) {
        self.loan_totals.insert(protocol, total);
    }

    pub fn loan_total(&self, protocol: Address) -> Option<U256> {
        self.loan_totals.get(&protocol).copied()
    }

    pub fn set_fee_record(&mut self, protocol: Address, record: FeeRecord) {
        self.fee_records.insert(protocol, record);
    }

    pub fn fee_record(&self, protocol: Address) -> Option<&FeeRecord> {
        self.fee_records.get(&protocol)
    }
}

/// Loan position snapshot for lending/borrowing protocols (e.g. GammaSwap).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoanPosition {
    pub borrowed: U256,
    pub collateral: U256,
    pub liquidation_threshold_bps: u64,
}

/// Fee accounting record for protocol fee invariant checking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeRecord {
    pub collected: U256,
    pub expected: U256,
}

/// CDP snapshot used by the CDP-specific invariant rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CdpPosition {
    pub collateral_value: U256,
    pub debt_value: U256,
    pub liquidation_threshold_bps: u64,
}

impl CdpPosition {
    pub fn is_empty(&self) -> bool {
        self.collateral_value.is_zero() && self.debt_value.is_zero()
    }
}

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

fn read_db_field(db: &CacheDB<EmptyDB>, field: DbField) -> Result<U256> {
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

fn mapping_slot_key(key: Address, mapping_slot: U256, layout: MappingLayout) -> U256 {
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

/// Common contract for invariant rules.
pub trait InvariantRule: Send + Sync {
    fn name(&self) -> &str;
    fn check(&self, ctx: &InvariantContext) -> Result<bool>;
}

/// Generic rule violation record used by the composite evaluator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleViolation {
    pub rule: String,
    pub message: String,
}

/// A rule that ensures the actual token balance held by a pool does not fall
/// below the reserve tracked by the protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BalanceGapRule {
    pub pool: Address,
    pub token: Address,
}

impl InvariantRule for BalanceGapRule {
    fn name(&self) -> &str {
        "balance_gap"
    }

    fn check(&self, ctx: &InvariantContext) -> Result<bool> {
        let balance = ctx
            .token_balance(self.token, self.pool)
            .ok_or_else(|| anyhow!("missing actual balance for token/pool pair"))?;
        let reserve = ctx
            .token_reserve(self.pool, self.token)
            .ok_or_else(|| anyhow!("missing reserve for token/pool pair"))?;
        Ok(balance >= reserve)
    }
}

/// Constant-product invariant for AMM pools.
///
/// The caller provides a baseline K value. On each check, the rule recomputes
/// `reserve0 * reserve1` from the current snapshot and verifies it has not
/// decreased below the baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstantProductRule {
    pub pool: Address,
    pub baseline_k: U256,
}

impl InvariantRule for ConstantProductRule {
    fn name(&self) -> &str {
        "constant_product"
    }

    fn check(&self, ctx: &InvariantContext) -> Result<bool> {
        let (reserve0, reserve1) = ctx
            .pool_reserves(self.pool)
            .ok_or_else(|| anyhow!("missing pool reserves"))?;
        Ok(reserve0.saturating_mul(reserve1) >= self.baseline_k)
    }
}

/// Supply consistency invariant: sum of tracked balances must equal total supply.
///
/// This is intentionally explicit about the tracked holders so future parser
/// code can decide which accounts are relevant for a given protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupplyConsistencyRule {
    pub token: Address,
    pub holders: Vec<Address>,
}

impl InvariantRule for SupplyConsistencyRule {
    fn name(&self) -> &str {
        "supply_consistency"
    }

    fn check(&self, ctx: &InvariantContext) -> Result<bool> {
        let mut sum = U256::ZERO;
        for holder in &self.holders {
            let bal = ctx
                .token_balance(self.token, *holder)
                .ok_or_else(|| anyhow!("missing holder balance for supply consistency"))?;
            sum = sum.saturating_add(bal);
        }
        let total = ctx
            .total_supply(self.token)
            .ok_or_else(|| anyhow!("missing total supply"))?;
        Ok(sum == total)
    }
}

/// CDP health / LTV invariant.
///
/// `max_ltv_bps` is the largest debt-to-collateral ratio allowed.
/// The rule fails if:
/// `debt_value * 10_000 > collateral_value * max_ltv_bps`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CdpLtvRule {
    pub owner: Address,
    pub max_ltv_bps: u64,
}

impl InvariantRule for CdpLtvRule {
    fn name(&self) -> &str {
        "cdp_ltv"
    }

    fn check(&self, ctx: &InvariantContext) -> Result<bool> {
        let position = ctx
            .cdp_position(self.owner)
            .ok_or_else(|| anyhow!("missing cdp position"))?;

        if position.debt_value.is_zero() {
            return Ok(true);
        }
        if position.collateral_value.is_zero() {
            return Ok(false);
        }

        let lhs = position.debt_value * U256::from(10_000u64);
        let rhs = position.collateral_value * U256::from(self.max_ltv_bps);
        Ok(lhs <= rhs)
    }
}

/// Loan collateral consistency: the protocol's tracked total must equal the
/// sum of all individual loan positions' borrowed amounts.
///
/// Catches accounting bugs where the aggregate counter drifts from reality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoanCollateralConsistencyRule {
    pub protocol: Address,
}

impl InvariantRule for LoanCollateralConsistencyRule {
    fn name(&self) -> &str {
        "loan_collateral_consistency"
    }

    fn check(&self, ctx: &InvariantContext) -> Result<bool> {
        let tracked_total = ctx
            .loan_total(self.protocol)
            .ok_or_else(|| anyhow!("missing loan total for protocol"))?;
        let mut computed_sum = U256::ZERO;
        for (_, pos) in ctx.loan_positions_for_protocol(self.protocol) {
            computed_sum = computed_sum.saturating_add(pos.borrowed);
        }
        Ok(tracked_total == computed_sum)
    }
}

/// Liquidation threshold rule: no individual loan position should have
/// `borrowed * 10_000 > collateral * liquidation_threshold_bps`.
///
/// Catches positions that should have been liquidated but survived.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidationThresholdRule {
    pub protocol: Address,
}

impl InvariantRule for LiquidationThresholdRule {
    fn name(&self) -> &str {
        "liquidation_threshold"
    }

    fn check(&self, ctx: &InvariantContext) -> Result<bool> {
        for (_, pos) in ctx.loan_positions_for_protocol(self.protocol) {
            if pos.borrowed.is_zero() {
                continue;
            }
            if pos.collateral.is_zero() {
                return Ok(false);
            }
            let lhs = pos.borrowed * U256::from(10_000u64);
            let rhs = pos.collateral * U256::from(pos.liquidation_threshold_bps);
            if lhs > rhs {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Fee accounting invariant: collected fees must match expected fees.
///
/// A mismatch indicates a rounding drain or fee calculation bug.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeAccountingRule {
    pub protocol: Address,
    /// Maximum allowed deviation in basis points (0 = exact match).
    pub tolerance_bps: u64,
}

impl InvariantRule for FeeAccountingRule {
    fn name(&self) -> &str {
        "fee_accounting"
    }

    fn check(&self, ctx: &InvariantContext) -> Result<bool> {
        let record = ctx
            .fee_record(self.protocol)
            .ok_or_else(|| anyhow!("missing fee record for protocol"))?;
        if record.expected.is_zero() {
            return Ok(record.collected.is_zero());
        }
        let diff = if record.collected > record.expected {
            record.collected - record.expected
        } else {
            record.expected - record.collected
        };
        let max_diff = record.expected * U256::from(self.tolerance_bps)
            / U256::from(10_000u64);
        Ok(diff <= max_diff)
    }
}

/// Composite evaluator that runs rules in order and stops at the first failure.
#[derive(Default)]
pub struct CompositeInvariant {
    rules: Vec<Box<dyn InvariantRule>>,
}

impl CompositeInvariant {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_rule<R>(mut self, rule: R) -> Self
    where
        R: InvariantRule + 'static,
    {
        self.rules.push(Box::new(rule));
        self
    }

    pub fn push_rule<R>(&mut self, rule: R)
    where
        R: InvariantRule + 'static,
    {
        self.rules.push(Box::new(rule));
    }

    pub fn evaluate(&self, ctx: &InvariantContext) -> Result<Option<RuleViolation>> {
        for rule in &self.rules {
            let ok = rule.check(ctx)?;
            if !ok {
                return Ok(Some(RuleViolation {
                    rule: rule.name().to_string(),
                    message: format!("{} violated", rule.name()),
                }));
            }
        }
        Ok(None)
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// Helper for dynamic rule injection when the caller wants to adapt a closure
/// into the shared DSL without defining a new rule type.
pub struct PredicateRule<F> {
    name: String,
    predicate: F,
}

impl<F> PredicateRule<F> {
    pub fn new(name: impl Into<String>, predicate: F) -> Self {
        Self {
            name: name.into(),
            predicate,
        }
    }
}

impl<F> InvariantRule for PredicateRule<F>
where
    F: Fn(&InvariantContext) -> Result<bool> + Send + Sync,
{
    fn name(&self) -> &str {
        &self.name
    }

    fn check(&self, ctx: &InvariantContext) -> Result<bool> {
        (self.predicate)(ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address::from([byte; 20])
    }

    #[test]
    fn balance_gap_rule_uses_pool_balance_vs_reserve() {
        let pool = addr(1);
        let token = addr(2);
        let mut ctx = InvariantContext::default();
        ctx.set_token_balance(token, pool, U256::from(100u64));
        ctx.set_token_reserve(pool, token, U256::from(90u64));

        let rule = BalanceGapRule { pool, token };
        assert!(rule.check(&ctx).unwrap());

        ctx.set_token_reserve(pool, token, U256::from(110u64));
        assert!(!rule.check(&ctx).unwrap());
    }

    #[test]
    fn constant_product_rule_checks_k_against_baseline() {
        let pool = addr(3);
        let mut ctx = InvariantContext::default();
        ctx.set_pool_reserves(pool, U256::from(10u64), U256::from(11u64));

        let rule = ConstantProductRule {
            pool,
            baseline_k: U256::from(100u64),
        };
        assert!(rule.check(&ctx).unwrap());

        ctx.set_pool_reserves(pool, U256::from(9u64), U256::from(10u64));
        assert!(!rule.check(&ctx).unwrap());
    }

    #[test]
    fn supply_consistency_rule_sums_tracked_holders() {
        let token = addr(4);
        let holder_a = addr(5);
        let holder_b = addr(6);
        let mut ctx = InvariantContext::default();
        ctx.set_token_balance(token, holder_a, U256::from(40u64));
        ctx.set_token_balance(token, holder_b, U256::from(60u64));
        ctx.set_total_supply(token, U256::from(100u64));

        let rule = SupplyConsistencyRule {
            token,
            holders: vec![holder_a, holder_b],
        };
        assert!(rule.check(&ctx).unwrap());

        ctx.set_total_supply(token, U256::from(101u64));
        assert!(!rule.check(&ctx).unwrap());
    }

    #[test]
    fn cdp_ltv_rule_flags_overleveraged_positions() {
        let owner = addr(7);
        let mut ctx = InvariantContext::default();
        ctx.set_cdp_position(
            owner,
            CdpPosition {
                collateral_value: U256::from(150u64),
                debt_value: U256::from(100u64),
                liquidation_threshold_bps: 7_500,
            },
        );

        let rule = CdpLtvRule {
            owner,
            max_ltv_bps: 7_000,
        };
        assert!(rule.check(&ctx).unwrap());

        ctx.set_cdp_position(
            owner,
            CdpPosition {
                collateral_value: U256::from(120u64),
                debt_value: U256::from(100u64),
                liquidation_threshold_bps: 7_500,
            },
        );
        assert!(!rule.check(&ctx).unwrap());
    }

    #[test]
    fn composite_invariant_stops_at_first_violation() {
        let pool = addr(8);
        let token = addr(9);
        let owner = addr(10);
        let mut ctx = InvariantContext::default();
        ctx.set_token_balance(token, pool, U256::from(100u64));
        ctx.set_token_reserve(pool, token, U256::from(100u64));
        ctx.set_pool_reserves(pool, U256::from(10u64), U256::from(10u64));
        ctx.set_cdp_position(
            owner,
            CdpPosition {
                collateral_value: U256::from(100u64),
                debt_value: U256::from(70u64),
                liquidation_threshold_bps: 7_500,
            },
        );

        let composite = CompositeInvariant::new()
            .with_rule(BalanceGapRule { pool, token })
            .with_rule(CdpLtvRule {
                owner,
                max_ltv_bps: 8_000,
            });

        assert!(composite.evaluate(&ctx).unwrap().is_none());

        ctx.set_token_reserve(pool, token, U256::from(101u64));
        let violation = composite.evaluate(&ctx).unwrap().unwrap();
        assert_eq!(violation.rule, "balance_gap");
    }

    #[test]
    fn predicate_rule_can_wrap_custom_logic() {
        let rule = PredicateRule::new("custom", |ctx: &InvariantContext| Ok(ctx.is_empty()));
        assert!(rule.check(&InvariantContext::default()).unwrap());
    }

    #[test]
    fn loan_consistency_rule_detects_total_mismatch() {
        let protocol = addr(20);
        let borrower_a = addr(21);
        let borrower_b = addr(22);
        let mut ctx = InvariantContext::default();
        ctx.set_loan_position(
            protocol,
            borrower_a,
            LoanPosition {
                borrowed: U256::from(100u64),
                collateral: U256::from(200u64),
                liquidation_threshold_bps: 8_000,
            },
        );
        ctx.set_loan_position(
            protocol,
            borrower_b,
            LoanPosition {
                borrowed: U256::from(50u64),
                collateral: U256::from(100u64),
                liquidation_threshold_bps: 8_000,
            },
        );
        ctx.set_loan_total(protocol, U256::from(150u64));

        let rule = LoanCollateralConsistencyRule { protocol };
        assert!(rule.check(&ctx).unwrap());

        // Drift: total says 160 but sum is 150
        ctx.set_loan_total(protocol, U256::from(160u64));
        assert!(!rule.check(&ctx).unwrap());
    }

    #[test]
    fn liquidation_threshold_rule_flags_underwater_position() {
        let protocol = addr(23);
        let borrower = addr(24);
        let mut ctx = InvariantContext::default();
        ctx.set_loan_position(
            protocol,
            borrower,
            LoanPosition {
                borrowed: U256::from(80u64),
                collateral: U256::from(100u64),
                liquidation_threshold_bps: 8_000,
            },
        );

        let rule = LiquidationThresholdRule { protocol };
        // 80 * 10000 = 800000 <= 100 * 8000 = 800000 → OK
        assert!(rule.check(&ctx).unwrap());

        // borrowed=81 → 810000 > 800000 → violation
        ctx.set_loan_position(
            protocol,
            borrower,
            LoanPosition {
                borrowed: U256::from(81u64),
                collateral: U256::from(100u64),
                liquidation_threshold_bps: 8_000,
            },
        );
        assert!(!rule.check(&ctx).unwrap());
    }

    #[test]
    fn fee_accounting_rule_detects_mismatch() {
        let protocol = addr(25);
        let mut ctx = InvariantContext::default();
        ctx.set_fee_record(
            protocol,
            FeeRecord {
                collected: U256::from(100u64),
                expected: U256::from(100u64),
            },
        );

        let rule = FeeAccountingRule {
            protocol,
            tolerance_bps: 0,
        };
        assert!(rule.check(&ctx).unwrap());

        // Exact mismatch at 0 tolerance
        ctx.set_fee_record(
            protocol,
            FeeRecord {
                collected: U256::from(99u64),
                expected: U256::from(100u64),
            },
        );
        assert!(!rule.check(&ctx).unwrap());

        // With 1% tolerance (100 bps), diff=1 on expected=100 → max_diff=1 → OK
        let rule_tolerant = FeeAccountingRule {
            protocol,
            tolerance_bps: 100,
        };
        assert!(rule_tolerant.check(&ctx).unwrap());
    }

    #[test]
    fn fee_accounting_rule_zero_expected_requires_zero_collected() {
        let protocol = addr(26);
        let mut ctx = InvariantContext::default();
        ctx.set_fee_record(
            protocol,
            FeeRecord {
                collected: U256::ZERO,
                expected: U256::ZERO,
            },
        );

        let rule = FeeAccountingRule {
            protocol,
            tolerance_bps: 0,
        };
        assert!(rule.check(&ctx).unwrap());

        ctx.set_fee_record(
            protocol,
            FeeRecord {
                collected: U256::from(1u64),
                expected: U256::ZERO,
            },
        );
        assert!(!rule.check(&ctx).unwrap());
    }

    #[test]
    fn db_extractor_reads_mapping_and_raw_bits() {
        let pool = addr(11);
        let token = addr(12);
        let owner = addr(13);
        let contract = addr(14);

        let mut db: CacheDB<EmptyDB> = CacheDB::new(EmptyDB::default());
        db.insert_account_info(
            RevmAddress::from_slice(contract.as_slice()),
            revm::primitives::AccountInfo {
                balance: RevmU256::ZERO,
                nonce: 0,
                code_hash: revm::primitives::B256::ZERO,
                code: None,
            },
        );

        // raw slot for token reserve
        let reserve_slot = U256::from(8u64);
        let reserve_raw = U256::from(123u64);
        let _ = db.insert_account_storage(
            RevmAddress::from_slice(contract.as_slice()),
            RevmU256::from_limbs(reserve_slot.into_limbs()),
            RevmU256::from_limbs(reserve_raw.into_limbs()),
        );

        // mapping slot for token balance
        let mapping_slot = U256::from(2u64);
        let balance_slot = mapping_slot_key(owner, mapping_slot, MappingLayout::Solidity);
        let _ = db.insert_account_storage(
            RevmAddress::from_slice(token.as_slice()),
            RevmU256::from_limbs(balance_slot.into_limbs()),
            RevmU256::from_limbs(U256::from(500u64).into_limbs()),
        );

        let bindings = DbInvariantBindings {
            token_balances: vec![TokenBalanceBinding {
                token,
                owner,
                field: DbField::Mapping {
                    contract: token,
                    key: owner,
                    mapping_slot,
                    layout: MappingLayout::Solidity,
                },
            }],
            token_reserves: vec![TokenReserveBinding {
                pool: contract,
                token,
                field: DbField::RawSlot {
                    contract,
                    slot: reserve_slot,
                },
            }],
            pool_reserves: vec![],
            total_supplies: vec![],
            cdp_positions: vec![],
            prices: vec![],
            loan_positions: vec![],
            loan_totals: vec![],
            fee_records: vec![],
        };

        let ctx = bindings.extract_context(&db).unwrap();
        assert_eq!(ctx.token_balance(token, owner), Some(U256::from(500u64)));
        assert_eq!(ctx.token_reserve(contract, token), Some(reserve_raw));
    }
}
