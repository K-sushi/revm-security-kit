use alloy_primitives::{Address, U256};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use crate::context::InvariantContext;

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
