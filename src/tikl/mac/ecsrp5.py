"""EC-SRP5 authentication for MAC-Telnet (RouterOS 6.43+).

The confirmation computation is the ``_ec_srp_confirmation`` logic from the seed
script, extracted as a pure function so it is unit-testable against a captured
golden known-answer vector (see DESIGN.md #7).
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

from .curve import WCurve
from .protocol import sha256


@dataclasses.dataclass(frozen=True)
class HandshakeCapture:
    """The full EC-SRP5 chain of one successful handshake.

    Written by ``--capture`` (against a disposable CHR VM) and frozen as the
    golden KAT. Contains a burner credential only — never a real password.
    """

    username: str
    password: str
    client_private: str  # hex
    client_public: str  # hex
    client_parity: int
    server_public: str  # hex
    server_parity: int
    salt: str  # hex
    confirmation: str  # hex

    def to_json(self) -> str:
        return json.dumps(dataclasses.asdict(self), indent=2, sort_keys=True)

    def write(self, path: Path) -> None:
        path.write_text(self.to_json() + "\n")


def compute_confirmation(
    curve: WCurve,
    username: str,
    password: str,
    client_private: bytes,
    client_public: bytes,
    server_public: bytes,
    server_parity: int,
    salt: bytes,
) -> bytes:
    """Compute the EC-SRP5 password confirmation the router expects.

    This proves knowledge of the password-derived validator without sending the
    password. Byte-for-byte equivalent to the seed script's implementation.
    """
    validator = curve.gen_password_validator_priv(username, password, salt)
    val_pub, _ = curve.gen_public_key(validator)
    val_point = curve.redp1(val_pub, 1)
    srv_point = curve.lift_x(int.from_bytes(server_public, "big"), server_parity)
    srv_point = srv_point + val_point
    pubkeys_hash = sha256(client_public + server_public)
    vh = int.from_bytes(validator, "big") * int.from_bytes(pubkeys_hash, "big") + int.from_bytes(
        client_private, "big"
    )
    vh = curve.finite_field_value(vh)
    pt = vh * srv_point
    z, _ = curve.to_montgomery(pt)
    return sha256(pubkeys_hash + z)
