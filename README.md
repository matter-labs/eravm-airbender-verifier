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

Build host:

```sh
cargo build --release
```

For running host, you'll need to have a directory with encoded input files.
Each file should be named as `<batch_number>.bin`.

Run host execution:

```sh
./target/release/eravm-prover-host -- --batches-dir <path/to/dir/with/batches> --action run --batch-number <number>
```

Run host proving:

```sh
./target/release/eravm-prover-host -- --batches-dir <path/to/dir/with/batches> --action prove --batch-number <number>
```

Process all available batches:

```sh
./target/release/eravm-prover-host -- --batches-dir <path/to/dir/with/batches> --action prove --all-batches
```
