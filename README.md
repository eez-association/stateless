# stateless

[![CI status](https://github.com/eez-association/stateless/actions/workflows/ci.yml/badge.svg)][gh-ci]
[![Telegram Chat][tg-badge]][tg-url]

**Stateless Ethereum block validation using execution witnesses.**

This EEZ fork is based on `paradigmxyz/stateless` commit
`3d2fc174df31f5b0d5d4d831dc7e1607ea541531`. Its EEZ-specific extension
returns the validated pre-state root, the recomputed and header-matched
post-state root, and optional sparse transaction-state checkpoints from the
same execution. Checkpoint selection, quotas, and exact returned-index checks
remain caller responsibilities.

## EEZ Reth compatibility branch

`feat/reth-v2.11-checkpoints` builds on the association checkpoint branch at
`0bda6b200c1eb4689c147c080c3c248b50be2ea8`. It targets Reth v2.11.0
(`b9abbcc1b982755baa9021e6874e2e58936ca65f`) and Rust 1.96.0.
All Reth consumers must use that same revision. The release tag matches Gnosis
Cargo source identities; `Cargo.lock` pins the exact commit. Alloy consensus/RPC crates remain 2.5.0 and primitives remain 1.7.3;
alloy-trie moves 0.9.7 → 0.9.9 and alloy-hardforks 0.4.9 → 0.4.11;
Reth core types are 0.8.2 at `275ce4cf5befeb9f1e8acd935ff2882d2d25fc61`.
The lockfile retains RollupX's reviewed security fixes: Tokio 1.53.3, rustix 1.1.6
and libz-sys 1.1.31. No advisory exceptions are added. An audit from this checkout
without RollupX's inherited exceptions still reports RUSTSEC-2026-0387 in
crypto-bigint 0.5.5. Its existing parent risk acceptance is not a remediation.

Execution uses official evm2 at
[`e681662b6d9ec59edafd112f7c8d64f49f1e6dd1`](https://github.com/alloy-rs/evm2/commit/e681662b6d9ec59edafd112f7c8d64f49f1e6dd1).
The root patch uses the official `DaniPopes/evm2` repository redirect to override
Reth's nominal `66687c18b34d3bdbb899f5eb7605070615c03475` revision. There are no
local engine modifications. Consumers must repeat root patches because Cargo
does not inherit dependency-workspace patches. Keep the engine, helper crates
and Reth core patches aligned with the consuming workspace and its lockfile.

Checkpoint callers now implement `CheckpointExecutor` for their custom block
executor. The included Ethereum implementation exposes its accumulated
`BlockState`; snapshots clone that state and convert only the copy to a bundle.
They neither replay transactions nor finalize the live executor. The existing
checkpoint oracle is unchanged. Terminal block roots and consensus commitments
are checked after normal block finalization. A custom trie can project state;
its caller must additionally verify the unprojected terminal state, as RollupX
does. The accumulator oracle compares snapshots with fresh executors stopped
at each prefix, including storage restoration, deletion/recreation and system
call overlap. Snapshots omit unused reverts; the live executor retains them.

The trie adaptation incorporates upstream Stateless
`923f1b759c916b2b5e42c26fa3a55a8d0b820bc3`: batch leaf updates and explicit
storage resets. Destroyed storage is cleared before both checkpoint and final
state roots are computed. The independent checkpoint fixture and blinded-storage
regressions cover these boundaries.

Run the host checks defined in [branch CI](.github/workflows/eez-reth.yml):

```bash
cargo +1.96.0 fmt --all --check
cargo +1.96.0 clippy --locked -p stateless -p tries -p zeth-mpt --all-targets -- -D warnings
cargo +1.96.0 test --locked -p stateless -p tries -p zeth-mpt
```

Consumers must pin an exact commit, rather than the moving branch name. This
branch validates EEZ's host use; the retained EF and RISC-V procedures below
have not been validated against this Reth pin.

[gh-ci]: https://github.com/eez-association/stateless/actions/workflows/ci.yml
[tg-badge]: https://img.shields.io/endpoint?color=neon&logo=telegram&label=chat&url=https%3A%2F%2Ftg.sumanjay.workers.dev%2Fparadigm%5Freth
[tg-url]: https://t.me/paradigm_reth

## What is stateless?

`stateless` provides types and functions for validating Ethereum blocks without access to a full node's persistent database. Instead, it relies on pre-generated witness data that proves the specific state accessed during block execution.

It is built on top of [reth](https://github.com/paradigmxyz/reth) and [evm2](https://github.com/alloy-rs/evm2). This compatibility branch targets host validation; see the `no_std` limitations below.

## How it works

1. **Witness verification** — The execution witness is verified against the parent block's state root using a sparse Merkle Patricia trie.
2. **Block execution** — The block is executed in-memory using a witness-backed database (`WitnessDatabase`).
3. **Consensus validation** — Post-execution consensus checks are performed.
4. **State root computation** — The post-state root is calculated and compared against the block header.

## Usage

The primary entry point is `stateless_validation`:

```rust
use stateless::{stateless_validation, ExecutionWitness};

let validation = stateless_validation(
    block,
    public_keys,
    witness,
    chain_spec,
    evm_config,
)?;

let block_hash = validation.block_hash;
let pre_state_root = validation.pre_state_root;
let post_state_root = validation.post_state_root;
let output = validation.execution_output;
let block_access_list = validation.block_access_list;
```

Callers that need execution-boundary state roots can use the opt-in recovered
block API:

```rust
use stateless::stateless_validation_recovered_with_state_checkpoints;

let output = stateless_validation_recovered_with_state_checkpoints(
    recovered_block,
    witness,
    chain_spec,
    evm_config,
    &[0, 3],
)?;

let checkpoints = output.checkpoints.transaction_state_checkpoints;
```

Each checkpoint retains its transaction index and the cumulative state root
after that transaction, before post-block changes. Consequently, the last
requested transaction root need not equal the validated block's final root.
Indices must be strictly increasing and in bounds. The checkpoint API rebuilds
a trie only for each requested boundary and is intentionally separate from the
cheaper validation-only API. The checkpoint output also exposes the state root
after pre-execution system changes and before transaction zero; this is distinct
from the parent state root and allows consumers to reconstruct an empty prefix. Callers processing untrusted input must also cap
the number of requested checkpoints; selecting indices avoids unnecessary work
but does not itself impose an application-specific resource limit.

Recovered-block APIs accept the transaction and receipt types of the supplied
`ConfigureEvm`, including native rollup transactions. Blocks must still use
Ethereum headers and bodies and satisfy the existing consensus, witness, and
commitment checks. Sender authentication is the caller's responsibility. The
public-key recovery API and default output receipt type remain Ethereum-specific.

## `no_std`

The crate retains `#![no_std]`, but this branch uses the standard-library-backed Reth executor. A working RISC-V/zkVM build is not established by that attribute or by the host checks. The inherited `scripts/check_no_std.sh` and custom RISC-V target are retained for tracking this separate compatibility gap; this port does not claim they pass.

> **Note:** The build temporarily relies on the LLVM `lower-atomic` pass
> to lower atomic instructions into non-atomic equivalents.

## Running EF tests

To run the Ethereum Foundation blockchain tests with stateless validation:

```bash
# From the repository root:
./scripts/run_ef_tests.sh default
./scripts/run_ef_tests.sh zeth
```

Or manually:

```bash
# From the repository root:
./scripts/setup_ef_tests.sh
EF_TEST_TRIE=default cargo test -p ef-tests --release --features "asm-keccak ef-tests"
```

## Contributing

Contributions are welcome! Join the conversation in the [Telegram group][tg-url].

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
