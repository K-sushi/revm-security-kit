//! Reusable invariant-rule DSL for REVM-driven audit workflows.
//!
//! The goal is to keep rule evaluation protocol-agnostic:
//! - AMM rules operate on pool balances/reserves
//! - CDP rules operate on collateral/debt snapshots
//! - Future Foundry parsing can map into the same rule types

pub mod bindings;
pub mod context;
pub mod rules;

pub use bindings::*;
pub use context::*;
pub use rules::*;

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};
    use revm::db::{CacheDB, EmptyDB};
    use revm::primitives::{Address as RevmAddress, U256 as RevmU256};

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
        // 80 * 10000 = 800000 <= 100 * 8000 = 800000 -> OK
        assert!(rule.check(&ctx).unwrap());

        // borrowed=81 -> 810000 > 800000 -> violation
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

        // With 1% tolerance (100 bps), diff=1 on expected=100 -> max_diff=1 -> OK
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
        let _pool = addr(11);
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
