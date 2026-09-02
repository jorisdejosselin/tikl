"""Full MAC-Telnet state machine + session loop over the in-process peer.

No root, no hardware — this is the DESIGN.md #8 loopback test. It exercises
START/ACK, the EC-SRP5 key exchange (the client really runs its crypto path
against the peer's server key), the confirmation send, prompt wait, the command
loop, and END.
"""

from __future__ import annotations

from tikl.mac.client import MacTransport
from tikl.session import run_batch, run_command, wait_for_prompt

from .loopback import LoopbackPeer, link_pair

CLIENT_MAC = "aa:aa:aa:aa:aa:aa"
SERVER_MAC = "bb:bb:bb:bb:bb:bb"

# Fixed key + salt so the handshake is fully deterministic.
FIXED_CLIENT_PRIV = bytes.fromhex("11" * 32)
FIXED_SERVER_PRIV = bytes.fromhex("22" * 32)
FIXED_SALT = bytes(range(16))


def _make_pair(**peer_kwargs: object) -> tuple[MacTransport, LoopbackPeer]:
    client_link, server_link = link_pair(CLIENT_MAC, SERVER_MAC)
    peer = LoopbackPeer(
        server_link,
        CLIENT_MAC,
        SERVER_MAC,
        server_private=FIXED_SERVER_PRIV,
        salt=FIXED_SALT,
        **peer_kwargs,  # type: ignore[arg-type]
    )
    peer.start()
    client = MacTransport(
        SERVER_MAC,
        user="admin",
        password="test123",
        client_private=FIXED_CLIENT_PRIV,
        link=client_link,
    )
    return client, peer


def test_connect_completes_handshake() -> None:
    client, peer = _make_pair()
    try:
        client.connect()  # START -> ENCKEY exchange -> PASSWORD; raises on failure
        wait_for_prompt(client, timeout=5)  # ensures the peer processed PASSWORD
        assert peer.received_confirmation is not None
        assert len(peer.received_confirmation) == 32  # SHA-256 confirmation
    finally:
        client.close()


def test_batch_runs_commands_over_loopback() -> None:
    client, peer = _make_pair(command_output=b"uptime: 5m\r\n")
    try:
        client.connect()
        results = list(run_batch(client, ["/system resource print"], timeout=5))
        assert results[0][0] == "/system resource print"
        assert "uptime: 5m" in results[0][1]
        assert peer.commands == [b"/system resource print\r"]
    finally:
        client.close()


def test_deterministic_confirmation_with_fixed_keys() -> None:
    # Same fixed client/server keys + salt must yield the same confirmation
    # every run (the property the golden KAT relies on).
    confirmations = []
    for _ in range(2):
        client, peer = _make_pair()
        try:
            client.connect()
            wait_for_prompt(client, timeout=5)
            assert peer.received_confirmation is not None
            confirmations.append(peer.received_confirmation)
        finally:
            client.close()
    assert confirmations[0] == confirmations[1]


def test_wait_for_prompt_then_command() -> None:
    client, peer = _make_pair(command_output=b"ok\r\n")
    try:
        client.connect()
        wait_for_prompt(client, timeout=5)
        out = run_command(client, "/system identity print", timeout=5)
        assert "ok" in out
    finally:
        client.close()


def test_multiple_commands_advance_counters() -> None:
    client, peer = _make_pair(command_output=b"x\r\n")
    try:
        client.connect()
        list(run_batch(client, ["a", "b", "c"], timeout=5))
        assert peer.commands == [b"a\r", b"b\r", b"c\r"]
    finally:
        client.close()
