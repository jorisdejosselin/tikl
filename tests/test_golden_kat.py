"""Golden known-answer test for the EC-SRP5 handshake (DESIGN.md #7, ADR 0003).

The fixture is a real, successful handshake captured from a *disposable CHR VM*
with a *burner* credential (so it is safe to commit). Generate it with the
runbook in tests/fixtures/README.md, then drop it at the path below. Until then
this test skips — the client crypto path is still covered by the deterministic
loopback test and the frozen curve vectors, and was validated live against real
hardware during development.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tikl.mac.curve import WCurve
from tikl.mac.ecsrp5 import compute_confirmation

GOLDEN = Path(__file__).parent / "fixtures" / "golden_kat.json"


@pytest.mark.skipif(
    not GOLDEN.exists(), reason="golden KAT fixture not present (generate from CHR)"
)
def test_golden_kat_reproduces_confirmation() -> None:
    cap = json.loads(GOLDEN.read_text())
    got = compute_confirmation(
        WCurve(),
        cap["username"],
        cap["password"],
        bytes.fromhex(cap["client_private"]),
        bytes.fromhex(cap["client_public"]),
        bytes.fromhex(cap["server_public"]),
        cap["server_parity"],
        bytes.fromhex(cap["salt"]),
    )
    assert got.hex() == cap["confirmation"]
