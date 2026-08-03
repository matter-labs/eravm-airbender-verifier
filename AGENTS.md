# Working in this repo

This verifier re-executes an Era batch inside an Airbender RISC-V guest and must
arrive at **the same batch commitment as the legacy prover**. Read that as the
constraint it is, not a goal.

## The rule that overrides ordinary judgement

**Conformance beats improvement.** If legacy behaviour looks wrong, redundant, or
slow, it is still the behaviour to reproduce — a deviation that changes any hashed
value breaks consensus, and "obviously equivalent" is not a proof. See the
`consensus fold is identical` note in `crates/airbender_verifier/src/merkle_witness.rs`
and `byte-for-byte L1 equivalence` in `crates/airbender_verifier/src/test_utils.rs`.

Corollary: witness data is **operator-supplied and untrusted**. Anything that only
*gates* behaviour without being hashed into the commitment needs an explicit check —
see the protocol-version pin in `crates/airbender_verifier/src/lib.rs`.

## Build and test

```sh
export ZKSYNC_USE_CUDA_STUBS=1          # CI sets this too; avoids linking CUDA
export CARGO_NET_GIT_FETCH_WITH_CLI=true # for the private git deps

cargo test --workspace --exclude eravm-prover-guest --locked
```

**Always exclude `eravm-prover-guest`.** It only builds for `riscv32`; a plain
`cargo test --workspace` tries to compile it as a host binary and fails with an
unrelated-looking linker error (`invalid section specifier '.init.rust'` on macOS).
CI uses the command above.

Run `cargo fmt` and `cargo clippy --all-targets -- -D warnings` on touched crates
before pushing.

## Package names do not match directory names

`cargo` needs the package name. Passing a directory name gets you
`package <name> is not a member of the workspace` followed by a full help dump,
which is easy to skim past:

| Directory | Package |
| --- | --- |
| `crates/airbender_verifier/` | `zksync_airbender_verifier` |
| `crates/constants/` | `zksync_system_constants` |
| `crates/cycle_estimator/` | `zksync-era-airbender-cycles-estimator` |
| `crates/cycle_tracer/` | `zksync-era-airbender-cycles-tracer` |
| `crates/cycle_model/` | `zksync_cycle_model` |
| `host/` | `eravm-prover-host` |
| `guest/` | `eravm-prover-guest` |

Others follow `crates/<x>` → `zksync_<x>`. Note the two kebab-case exceptions.

## Building the guest

Needs a clang that can target `riscv32`. Apple's cannot, and the failure is not
obvious:

```sh
export CC=/opt/homebrew/opt/llvm/bin/clang   # brew install llvm
export AR=/opt/homebrew/opt/llvm/bin/llvm-ar
cd guest && cargo airbender build
```

## Batches

The corpus is Git LFS with `fetchexclude`, so a fresh clone has pointers only:

```sh
./scripts/fetch_lfs_batches.sh 84730.bin.gz
```

**Not every batch loads.** The corpus spans incompatible eras — `84730`+ works on a
default build, `513xxx` needs `--features relax-version-pin`, and `506xxx` cannot be
decoded at all. Check the table in
[`testdata/era_mainnet_batches/README.md`](testdata/era_mainnet_batches/README.md)
before concluding a loader is broken.

## Guest artifact checks

`scripts/check_guest_riscv_code.sh` must be given the **build** ELF, not the dist
copy — `guest/dist/app/app.elf` has `.text` stripped, so it decodes 0 instructions:

```sh
cd guest && bash ../scripts/check_guest_riscv_code.sh \
  ../target/riscv32im-risc0-zkvm-elf/release/eravm-prover-guest \
  --baseline ../scripts/guest_softfloat_baseline.txt --min-insns 500000
```

**Never add CSR `0x7ff` to `ALLOWED_CSRS`.** It is the cycle-marker CSR, and its
absence is what stops a calibration guest — which can have the protocol-version pin
disabled — from being released. A build tripping that check is the check working.

## Where to look

- [`README.md`](README.md) — layout, quick start, proving flow.
- [`docs/benchmarking.md`](docs/benchmarking.md) — measuring guest heap and cycles,
  and the benchmarking-only feature flags that must never ship.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — review expectations. Prefer a focused PR
  over a broad one.
