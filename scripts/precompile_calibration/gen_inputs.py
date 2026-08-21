#!/usr/bin/env python3
"""Generate precompile input vectors (hex, no 0x) for the PrecompileHammer.

Emits one <precompile>_<tier>.hex file per (precompile, tier) plus a
manifest.json describing how to drive each: which hammer function, the input
file, and a *starting* per-tx `count` (tune after the first measured batch).

Design:
- Input-dependent precompiles (modexp, sha256, ecpairing) tier by INPUT SIZE
  (light/medium/heavy). Fixed-cost precompiles (ecadd, ecmul, secp256r1) tier by
  CALL COUNT, so they share one input and the driver sweeps `count`.
- Curve inputs use the canonical bn254 generators (G1 = (1,2); EIP-197 G2
  generator). They are VALID by construction but MUST be confirmed against the
  live node (`cast call <precompile> <input>`) before mass-generation — a bad
  point makes the precompile fail and cost nothing. secp256r1 needs a real P-256
  signature; generated here if `cryptography` is available, else left as a TODO.
"""
import json
import os

OUT = os.path.dirname(os.path.abspath(__file__))


def w(name, hexstr):
    path = os.path.join(OUT, f"{name}.hex")
    with open(path, "w") as f:
        f.write(hexstr)
    return os.path.relpath(path, OUT), len(hexstr) // 2


def u256(x):
    return x.to_bytes(32, "big")


# --- modexp (0x05): [baseLen|expLen|modLen|base|exp|mod], any bytes valid ------
def modexp(base_len, exp_len, mod_len):
    base = (b"\x02" * base_len)
    exp = (b"\x03" * exp_len)  # nonzero exponent so it does real work
    mod = (b"\xff" * (mod_len - 1) + b"\xfd")  # large odd modulus
    return (u256(base_len) + u256(exp_len) + u256(mod_len) + base + exp + mod).hex()


# --- sha256 (0x02): arbitrary bytes -------------------------------------------
def sha256_in(n):
    return (bytes((i * 31 + 7) & 0xFF for i in range(n))).hex()


# --- bn254 constants ----------------------------------------------------------
G1 = (1, 2)  # generator; on curve (y^2 = x^3 + 3): 4 == 1 + 3
# EIP-197 G2 generator, encoded (x_c1, x_c0, y_c1, y_c0) — imaginary part first.
G2 = (
    0x198E9393920D483A7260BFB731FB5D25F1AA493335A9E71297E485B7AEF312C2,
    0x1800DEEF121F1E76426A00665E5C4479674322D4F75EDADD46DEBD5CD992F6ED,
    0x090689D0585FF075EC9E99AD690C3395BC4B313370B38EF355ACDADCD122975B,
    0x12C85EA5DB8C6DEB4AAB71808DCB408FE3D1E7690C43D37B4CE6CC0166FA7DAA,
)


def ec_add():  # 128 bytes: G1 + G1
    return (u256(G1[0]) + u256(G1[1]) + u256(G1[0]) + u256(G1[1])).hex()


def ec_mul(scalar):  # 96 bytes: scalar * G1
    return (u256(G1[0]) + u256(G1[1]) + u256(scalar)).hex()


def ec_pairing(k):  # k * 192 bytes: k copies of (G1, G2); valid points, result != 1
    pair = u256(G1[0]) + u256(G1[1]) + u256(G2[0]) + u256(G2[1]) + u256(G2[2]) + u256(G2[3])
    return (pair * k).hex()


# --- secp256r1 (RIP-7212, addr 0x100): 160 bytes hash|r|s|x|y ------------------
def secp256r1_vector():
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    except Exception:
        return None
    key = ec.generate_private_key(ec.SECP256R1())
    msg_hash = bytes((i * 13 + 1) & 0xFF for i in range(32))
    from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
    from cryptography.hazmat.primitives import hashes  # noqa
    # Sign the raw hash via Prehashed
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
    sig = key.sign(msg_hash, ECDSA(Prehashed(hashes.SHA256())))
    r, s = decode_dss_signature(sig)
    nums = key.public_key().public_numbers()
    return (u256(int.from_bytes(msg_hash, "big")) + u256(r) + u256(s) + u256(nums.x) + u256(nums.y)).hex()


def main():
    manifest = []

    def add(precompile, fn, tier, hexstr, count, note=""):
        rel, nbytes = w(f"{precompile}_{tier}", hexstr)
        manifest.append({
            "precompile": precompile, "hammer_fn": fn, "tier": tier,
            "input_file": rel, "input_bytes": nbytes,
            "start_count_per_tx": count, "note": note,
        })

    # modexp: tier by operand size
    add("modexp", "modexp", "light", modexp(32, 4, 32), 20000)
    add("modexp", "modexp", "medium", modexp(256, 8, 256), 3000)
    add("modexp", "modexp", "heavy", modexp(1024, 16, 1024), 400)

    # sha256: tier by input size
    add("sha256", "sha256_", "light", sha256_in(64), 50000)
    add("sha256", "sha256_", "medium", sha256_in(4096), 4000)
    add("sha256", "sha256_", "heavy", sha256_in(32768), 500)

    # ecpairing: tier by number of pairs (input size)
    add("ecpairing", "ecPairing", "light", ec_pairing(1), 2000, "verify on-curve on live node")
    add("ecpairing", "ecPairing", "medium", ec_pairing(4), 500, "verify on-curve on live node")
    add("ecpairing", "ecPairing", "heavy", ec_pairing(10), 200, "verify on-curve on live node")

    # ecadd / ecmul: fixed cost/call — one input, driver sweeps count
    add("ecadd", "ecAdd", "fixed", ec_add(), 50000, "verify on-curve on live node")
    add("ecmul", "ecMul", "fixed", ec_mul(7), 20000, "verify on-curve on live node")

    # secp256r1: fixed cost/call — needs a valid P-256 signature
    p256 = secp256r1_vector()
    if p256:
        add("secp256r1", "hammer(0x100)", "fixed", p256, 20000, "verify returns 1 on live node")
    else:
        manifest.append({
            "precompile": "secp256r1", "hammer_fn": "hammer(0x100)", "tier": "fixed",
            "input_file": None, "note": "TODO: python `cryptography` unavailable — "
            "generate a valid RIP-7212 hash|r|s|x|y (160B) vector before use",
        })

    with open(os.path.join(OUT, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    for m in manifest:
        print(f"{m['precompile']:11s} {m['tier']:7s} "
              f"{m.get('input_bytes', '?')!s:>6} B  count~{m.get('start_count_per_tx', '?')}"
              f"  {m.get('note', '')}")


if __name__ == "__main__":
    main()
