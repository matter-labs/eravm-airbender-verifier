# Pricing precompiles from zksync-os native costs

zksync-os (`basic_system/src/cost_constants.rs`, branch `draft-0.4.0`) has
RISC-V-cycle "native costs" for every precompile, measured via cycle markers,
with delegations folded in: `native_with_delegations!(raw, bigint, blake) = raw +
bigint*4 + blake*16` (keccak uses its own coeff 4). These are the sound,
size-parameterized costs we lack for the precompiles our corpus never exercised.

## Why they transfer

Both worlds run on the airbender machine and route crypto through the same
`airbender-crypto` delegations (keccak via `sha3/delegated`, bn254/modexp via
`bigint_delegation`). zksync-protocol PR #209 ("Support airbender delegations in
precompiles") wires vm2's precompiles to those same delegations behind the
`airbender-precompile-delegations` feature. So a precompile's delegation cost is
shared hardware — zksync-os's numbers are the right basis for ours.

## Units and the conversion factor

Our `keccak256_cycles` / `sha256_cycles` features are the round counts vm2's
precompiles return (`keccak256_rounds_function`, 136-byte chunks;
`sha256_rounds_function`, 64-byte chunks) — identical to zksync-os's per-round
unit. So they compare directly.

Anchor on **keccak** (the only crypto op our corpus identifies well — present in
every batch, "ok" confidence):

    k = our_fitted_keccak_per_round / zksync_os_keccak_native_per_round
      = 26,951 / (649*4 + 1250) = 26,951 / 3,846 ≈ 7.0   [our raw_cycles per native unit]

sha256 and ecrecover imply k ≈ 20 and ≈ 31, but those fitted coefficients are
collinearity artifacts (near-zero corpus variance), so keccak is the anchor. The
~7× gap is the fast-VM interpreter/dispatch overhead our guest pays per round on
top of the delegated work — see the caveat below.

## Derived precompile costs (current guest, our raw_cycles units = k × native)

| precompile | zksync-os native | our units (×7.0) |
|---|---:|---:|
| ec_recover (per call) | 368,000 | 2,578,813 |
| p256 / secp256r1 (per call) | 784,000 | 5,493,992 |
| bn254 ec_add (per call) | 58,000 | 406,443 |
| bn254 ec_mul (per call) | 811,000 | 5,683,199 |
| bn254 pairing (base) | 6,244,000 | 43,755,729 |
| bn254 pairing (per pair) | 6,908,000 | 48,408,805 |
| modexp (base) | 20,000 | 140,152 |
| modexp (per operand digit²) | 340 | 2,382 |

These move the five unpriced precompiles from **0** (silent under-estimate) to a
physically-grounded, conservative value.

## Caveat: k is guest-backend-dependent

k≈7 reflects our **current** guest, where keccak is delegated but the EC/modexp
precompiles are the legacy (non-delegated) backend. Once the verifier guest
enables `airbender-precompile-delegations` (PR #209):
- the EC/modexp precompiles become delegated → bounded and matching zksync-os;
- per-op cost drops toward zksync-os native (**k → ~1** for the delegated part,
  plus the fixed per-call interpreter overhead already in `precompile_call`).

So **re-derive k after the guest adopts PR #209**, and treat the table above as a
conservative interim basis. Until then, the coverage guard (which rejects any
batch using an unpriced precompile) is the active protection.

## Applying it

- keccak/sha256/ecrecover are already priced (per-round features exist). Do NOT
  blindly replace their fitted coefficients with lower k×native values —
  under-pricing is unsafe; refine them with a direct microbench instead.
- EC/modexp/secp256r1 are per-call / per-pair / per-digit², which the current
  `<op>_cycles` (CycleStats) features do not express. Pinning them needs a
  featurization upgrade: have the tracer count invocations (and pairs / operand
  size) so the cost applies as `base + per_pair·pairs`, etc. Write the resulting
  coefficients into `cost_table.json` (they have no dataset column to fit).
