"""EC-SRP5 curve regression vectors.

These are FROZEN vectors (current implementation output), so they guard against
accidental regressions during refactoring. The authoritative correctness proof
is the golden KAT captured from real RouterOS (a disposable CHR VM); see
DESIGN.md #7 and ADR 0003. That fixture arrives in the tests milestone.
"""

from __future__ import annotations

from tikl.mac.curve import WCurve

PRIV5 = bytes.fromhex("00" * 31 + "05")


def test_gen_public_key_fixed_scalar() -> None:
    w = WCurve()
    pub, parity = w.gen_public_key(PRIV5)
    assert pub.hex() == "41b6ec3c50ee7af203c0026e5e079e7fa8cbc9bc581d49cb0d537d5778497c87"
    assert parity == 1


def test_validator_derivation() -> None:
    w = WCurve()
    val = w.gen_password_validator_priv("admin", "test123", bytes(range(16)))
    assert val.hex() == "20a3c27a8aa03713e84bf99a0aa23ec3c9f82175acf3d2cd148635a26376487b"


def test_lift_x_generator() -> None:
    w = WCurve()
    x, parity = w.to_montgomery(w.lift_x(9, 0))
    assert x.hex() == "00" * 31 + "09"
    assert parity == 0


def test_redp1_deterministic() -> None:
    w = WCurve()
    pub, _ = w.gen_public_key(PRIV5)
    x, parity = w.to_montgomery(w.redp1(pub, 1))
    assert x.hex() == "0e04ba75f6e45460bcbe361102b21466f85fda9a0763e59200cbae07d311f813"
    assert parity == 1


def test_finite_field_value_reduces_mod_r() -> None:
    w = WCurve()
    assert w.finite_field_value(2**300) == int(
        "fffffffffffffffffffeb2106215d087808a1cc3fdd3fe08425631a5cf5d3ed", 16
    )
