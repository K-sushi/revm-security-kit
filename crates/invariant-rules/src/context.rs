use alloy_primitives::{Address, U256};
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
