# revm-security-kit

**Evidence-based DeFi security research engine.**

LLM generates hypotheses. REVM proves or kills them. Rust scores and bundles evidence.

## Architecture

```
Hypothesis → SimTxInput → REVM Execution → Invariant Check → Evidence Bundle → Kill / Escalate
```

This toolkit provides the execution core for systematic DeFi protocol security analysis:

1. **Replay** any transaction on a forked EVM state
2. **Define invariants** using a protocol-agnostic DSL (AMM, CDP, lending rules)
3. **Fuzz** transaction sequences to find invariant violations
4. **Audit** multi-step scenarios with per-transaction invariant snapshots
5. **Score** findings with evidence metrics (actor gain, victim loss, debt delta)

## Crates

| Crate | Description | Status |
|-------|-------------|--------|
| `invariant-rules` | Protocol-agnostic invariant rule DSL | 11 tests |
| `invariant-fuzzer` | REVM-based invariant fuzzing with trace inspection | 9 tests |
| `revm-sim` | Transaction simulator with fork state loading | Alpha |

## Invariant Rule DSL

Define rules that REVM checks after each simulated transaction:

```rust
use alloy_primitives::{Address, U256};
use invariant_rules::{InvariantContext, CompositeInvariant, ConstantProductRule};

let pool = Address::ZERO; // your pool address

// Set up context with pool reserves after a swap
let mut ctx = InvariantContext::default();
ctx.set_pool_reserves(pool, U256::from(1000u64), U256::from(2000u64));

// Check: did xy=k decrease below baseline?
let baseline_k = U256::from(2_000_000u64); // k before the swap
let invariant = CompositeInvariant::new()
    .with_rule(ConstantProductRule { pool, baseline_k });

let violation = invariant.evaluate(&ctx)?;
// violation.is_none() → pool is safe
// violation.is_some() → k decreased → potential drain
```

Available rule types:
- **ConstantProduct**: xy=k must not decrease
- **BalanceGap**: token balance vs reserve consistency
- **CDP**: collateral/debt ratio bounds
- **Fee**: fee accumulation monotonicity
- **Loan**: borrow/repay position tracking

## Invariant Fuzzer

Generate and shrink transaction sequences to find minimal invariant violations:

```rust
use invariant_fuzzer::{InvariantInspector, TraceEvent, SimTxInput};

// The inspector traces all CALL/DELEGATECALL/CREATE during REVM execution
let inspector = InvariantInspector::new();
// Attach to REVM Evm instance for step-by-step tracing
```

## Kill Discipline

This toolkit was built and validated by systematically analyzing 7 DeFi protocols:

| Target | Hypotheses Tested | Result | Key Finding |
|--------|-------------------|--------|-------------|
| Protocol A | Precision loss, routing manipulation | KILL | Constant product + truncation = defensive |
| Protocol B | Adapter accounting, cap/timelock | KILL | maxRate + transient + timelock = 3-layer defense |
| Protocol C | Deferred checks, JIT borrowing | KILL | 3x defense on forgive, atomic JIT execution |
| Protocol D | Cross-adapter staleness | KILL | Live deployment avoids manipulable oracles |
| + 3 more | Various AMM math hypotheses | KILL | All defensive rounding, k non-decreasing |

**0 findings is not failure — it's a clean bill of health.** Each kill is evidence that the invariant toolkit correctly identifies defended protocols.

## Related Projects

- [sti-os](https://github.com/FibonacciFlux/sti-os) — State-Transition Intelligence OS (capability proving framework)
- [revm](https://github.com/bluealloy/revm) — Rust EVM implementation
- [alloy](https://github.com/alloy-rs/alloy) — Rust Ethereum toolkit
- [Foundry](https://github.com/foundry-rs/foundry) — Ethereum development toolkit

## How This Differs from Foundry

Foundry is a development toolkit (compile, test, deploy). This is a **security research toolkit**:
- Foundry tests your own contracts. This replays and audits **live deployed contracts**.
- Foundry provides `forge test`. This provides **hypothesis-driven invariant auditing**.
- Foundry doesn't orchestrate LLM-generated attack scenarios. This does.

## License

Apache-2.0
