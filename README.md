# eravm-airbender-verifier

This repository combines the reduced Era verifier libraries and the Airbender proving app in one workspace.

## Layout

- `crates/`: reduced verifier libraries extracted from `zksync-era` (entrypoint crate: `zksync_tee_verifier`).
- `guest/`: Airbender guest program that reads `TeeVerifierInput` and runs `verify()`.
- `host/`: host runner/prover app for batch execution and proof generation.

## Quick Start

Build guest artifacts:

```sh
cargo airbender build --project guest
```

Run host execution:

```sh
cargo run -p eravm-prover-host -- --action run --batch-number <number>
```

Run host proving:

```sh
cargo run -p eravm-prover-host -- --action prove --batch-number <number>
```

Process all available batches:

```sh
cargo run -p eravm-prover-host -- --action prove --all-batches
```
