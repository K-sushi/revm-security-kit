# revm-security-kit

**Protocol-agnostic invariant testing toolkit for EVM security research.**

## What This Does

Define invariant rules (constant product, CDP ratios, fee accounting) and test them against EVM state using REVM.

```
InvariantContext → Rule DSL → Evaluate → Violation or Clean
```

## Crates

| Crate | Description | Tests |
|-------|-------------|-------|
| `invariant-rules` | Protocol-agnostic invariant rule DSL (AMM, CDP, fee, loan) | 11 |
| `invariant-fuzzer` | REVM-based invariant fuzzing with trace inspection and shrinking | 9 |
| `revm-sim` | Transaction simulator with snapshot/restore (alpha) | 4 |

## Invariant Rule DSL

```rust
use alloy_primitives::{Address, U256};
use invariant_rules::{InvariantContext, CompositeInvariant, ConstantProductRule};

let pool = Address::ZERO;

// Set up context with pool reserves after a swap
let mut ctx = InvariantContext::default();
ctx.set_pool_reserves(pool, U256::from(1000u64), U256::from(2000u64));

// Check: did xy=k decrease below baseline?
let baseline_k = U256::from(2_000_000u64);
let invariant = CompositeInvariant::new()
    .with_rule(ConstantProductRule { pool, baseline_k });

let violation = invariant.evaluate(&ctx)?;
// violation.is_none() → pool is safe
// violation.is_some() → k decreased → potential drain
```

### Available Rules

- **ConstantProduct** — xy=k must not decrease
- **BalanceGap** — token balance vs reserve consistency
- **CDP** — collateral/debt ratio bounds with liquidation threshold
- **Fee** — fee accumulation monotonicity
- **Loan** — borrow/repay position tracking with total consistency
- **Supply** — holder sum vs total supply
- **Predicate** — custom closure-based rules

## Invariant Fuzzer

REVM `Inspector` implementation that traces CALL/DELEGATECALL/CREATE during execution, plus shrinking algorithms to find minimal violation sequences:

```rust
use invariant_fuzzer::{InvariantInspector, InvariantRunResult};

// Attach inspector to REVM for step-by-step tracing
let inspector = InvariantInspector::new();

// After execution, shrink to minimal reproducing sequence
let shrunk = shrink_sequence(&txs, |seq| check_invariant(seq));
```

## Transaction Simulator (Alpha)

Basic REVM CacheDB simulator with snapshot/restore for hypothesis testing:

```rust
use revm_sim::{Simulator, SimConfig, SimTxInput};

let config = SimConfig::ethereum("http://localhost:8545");
let mut sim = Simulator::new(config);

// Snapshot, modify, test, restore
let snap = sim.snapshot();
sim.set_storage(addr, slot, value);
let result = sim.simulate_tx(&tx)?;
sim.restore(snap)?;
```

## Background

Built and validated by analyzing 7 DeFi protocols with systematic hypothesis testing. Each protocol was evaluated with specific attack hypotheses, tested against the invariant toolkit, and classified as kill (defended) or escalate.

## Roadmap

- [ ] RPC state loading (fork live mainnet state)
- [ ] Sequence simulation with per-TX invariant snapshots
- [ ] LLM-orchestrated hypothesis generation
- [ ] Evidence bundling and report generation
- [ ] File splitting (400L per file target)

## Related

- [sti-os](https://github.com/K-sushi/sti-os) — State-Transition Intelligence OS
- [revm](https://github.com/bluealloy/revm) — Rust EVM
- [alloy](https://github.com/alloy-rs/alloy) — Rust Ethereum toolkit

## License

Apache-2.0
