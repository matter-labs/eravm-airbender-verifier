# Generating fresh batches from a local Era node

How to produce new `AirbenderVerifierInput` fixtures by running a local zksync-era
node and exporting its proof inputs.

**Why you would need this.** Most of the in-repo corpus cannot be re-measured: of
138 LFS batches, the 127 in the `506xxx` range are in the pre-v31 wire format and
fail inside `bincode` decode, and `513xxx` is protocol v29 (see the table in
[`../testdata/era_mainnet_batches/README.md`](../testdata/era_mainnet_batches/README.md)).
So any *new* corpus — a broad benchmarking sweep, a stress fixture like `900065`, a
regression batch with a specific shape — has to be generated.

> **Confidence.** The commands, route, component name, and port below were checked
> against zksync-era `6cee4709c`. The **behavioural** notes — which components can
> be dropped, and the recovery sequence — come from a working session on
> 2026-07-17 and are *not* re-verified here; they are recorded because they each
> cost hours. zksync-era is a separate, fast-moving repo: when something diverges,
> **its CI workflows are the authority** (`.github/workflows/ci-core-reusable.yml`
> has the known-good sequence), not this page.

## 1. Build the *matching* `zkstack`

Do not use a globally installed `zkstack`. Era's Rust workspace lives in `core/`
(there is no root `Cargo.toml`), and older global builds run `cargo` from the repo
root, so every `init` fails in `genesis_generator`. Build the one from the checkout
you're going to run:

```sh
cd zksync-era/zkstack_cli && cargo build --release -p zkstack
# then use ./target/release/zkstack throughout
```

For anything else you build in that repo, run `cargo` from inside `core/` — the
workspace manifest is `core/Cargo.toml`, so invoking cargo from the root finds no
workspace at all. The same env vars as this repo apply
(`ZKSYNC_USE_CUDA_STUBS=1`, `CARGO_NET_GIT_FETCH_WITH_CLI=true`).

## 2. Initialise the chain

A fresh worktree has an empty `contracts` submodule:

```sh
GIT_CONFIG_GLOBAL=/dev/null git submodule update --init --recursive contracts
```

(Neutralising the global git config avoids an `ssh insteadOf` rewrite hanging on a
signing-agent prompt.)

```sh
zkstack containers                       # L1 (reth) + postgres
zkstack ecosystem init --dev             # deploys L1 contracts, registers the chain, genesis
```

If init fails on a missing `bootloader_hash`, the chain config directory was
clobbered. Restore it pristine (`git checkout -- chains && git clean -fd chains`)
and re-run. Do **not** `rm -rf chains/era/configs` — that breaks the `contracts.yaml`
copy during "Initializing chain".

## 3. Run the server with the right components

This is the step that wastes the most time. Run the **default** set *plus* the
airbender handler:

```sh
zkstack server --components \
  api,tree,eth,state_keeper,housekeeper,commitment_generator,\
vm_runner_protective_reads,vm_runner_bwip,airbender_proof_data_handler
```

Dropping `housekeeper` or `vm_runner_protective_reads` to "keep it minimal"
**freezes the state keeper**: L2 blocks stop being produced and deposits never
execute. Nothing errors — it just goes quiet, which is why this is expensive to
diagnose.

## 4. Fund an L2 account

```sh
zkstack dev init-test-wallet --chain era
```

This is the CI-blessed path. `zkstack dev rich-account --amount N` reverts on a
fresh chain (a base-cost/`msg.value` mismatch), so prefer the above.

## 5. Produce batches, then export them

Send whatever traffic gives you the batch shape you want, and wait for the batch to
seal. Then export its proof input:

```sh
curl "localhost:4320/airbender/proof_inputs_no_lock/<N>" > batch-<N>.json
```

`4320` is the handler's default `http_port`. The JSON deserialises directly into the
verifier's `AirbenderVerifierInput`. Convert it to a `.bin.gz` fixture with
`cli_utils::encode_batch`/`save_batch`, or the `encode_batch` example:

```sh
cargo run --release -p zksync_cycle_model --example encode_batch -- \
    batch-<N>.json testdata/era_mainnet_batches/binary/<N>.bin
```

**Batch `N` needs batch `N-1`'s commitment**, so export a contiguous run rather
than isolated batches.

If you add a batch to the repo corpus, `scripts/import_mainnet_batches.sh` stages it
as an LFS object and documents it — see the corpus README.

## Recovering a bricked chain

A batch that exceeds `max_pubdata_per_batch` (~760 KB) halts the state keeper with
"Failed to publish pubdata via L1Messenger", and the node then crash-loops on
restart. Lighter recovery paths fail (dropping just the server DB gives "0
set_chain_id events"; `chain init` gives `BridgeHubAlreadyRegistered()`). The full
rebuild:

```sh
docker compose down -v                              # wipe reth + postgres volumes
docker compose up -d
zkstack ecosystem init --dev --ignore-prerequisites
rm -rf chains/era/db/main                           # else "L1 batch in cache (N) > requested (0)"
zkstack server --components ...                     # as above
```

## Note on large-bytecode fixtures

If you are generating a batch to stress decommitment, bytecode size is not what you
control directly — the pubdata cap is. Incompressible ~280 KB contracts publish
>1 MB of pubdata per batch and trip the cap (bricking the chain as above), while an
all-same-byte constant gets *shrunk at compile time* by `zksolc`. What works is
**compressible but not shrinkable** bytecode: a period-256 incrementing pattern
compiles to ~116 KB of runtime code from a 128 KB source and compresses to ~29 KB of
pubdata, so it deploys cheaply and still decommits at full size.
