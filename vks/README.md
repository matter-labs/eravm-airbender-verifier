# Committed verification keys

The prover server only loads verification keys from disk; it never derives
them on the fly. The files in this directory are the canonical VKs the
server (and the integration test) consume:

- `fri_vk.bin` — bincode-encoded `airbender_host::VerificationKey` for the
  FRI proof. Deterministically derived from `guest/dist/app/app.bin`.
- `snark_vk.json` — JSON-encoded `zkos_wrapper::SnarkWrapperVK` for the
  phase-3 SNARK wrapper. Derived from the trusted setup chain.

## Regenerating after a guest or wrapper change

```bash
# Needs a GPU runner with the trusted setup (CRS) on disk.
cargo run -p eravm-prover-host --features snark_gpu -- gen-vks \
    --output-dir vks \
    --trusted-setup /path/to/setup.key
git status vks/
```

CI re-runs the same command on every PR and fails if the resulting files
differ from the committed ones, so any guest change that touches the VKs
must be paired with a refresh of this directory.
