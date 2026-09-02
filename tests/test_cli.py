"""CLI wiring, with the MAC transport replaced by a fake (no scapy, no root)."""

from __future__ import annotations

import pytest
from click.testing import CliRunner

import tikl.cli as cli_mod
from tikl.cli import _resolve_password, cli
from tikl.errors import AuthFailed


class FakeMac:
    instances: list[FakeMac] = []

    def __init__(self, mac: str, **kwargs: object) -> None:
        self.mac = mac
        self.kwargs = kwargs
        self.connected = False
        self.closed = False
        FakeMac.instances.append(self)

    def connect(self) -> None:
        self.connected = True

    def close(self) -> None:
        self.closed = True


def test_version() -> None:
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "tikl" in result.output


def test_mac_help_lists_capture_warning() -> None:
    result = CliRunner().invoke(cli, ["mac", "--help"])
    assert result.exit_code == 0
    assert "MAC-Telnet" in result.output
    assert "--capture" in result.output


def test_resolve_password_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TIKL_PASS", "fromenv")
    assert _resolve_password("explicit") == "explicit"  # flag wins
    assert _resolve_password(None) == "fromenv"  # env next
    monkeypatch.delenv("TIKL_PASS", raising=False)
    monkeypatch.setenv("MT_PASS", "legacy")
    assert _resolve_password(None) == "legacy"  # legacy env alias


def test_mac_runs_batch(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeMac.instances.clear()
    monkeypatch.setattr(cli_mod, "MacTransport", FakeMac)
    monkeypatch.setattr(
        cli_mod,
        "run_batch",
        lambda t, cmds, timeout: [(c, f"out:{c}") for c in cmds],
    )
    result = CliRunner().invoke(
        cli,
        ["mac", "38:32:7A:26:8E:BD", "/system resource print", "--password", "x"],
    )
    assert result.exit_code == 0, result.output
    assert "out:/system resource print" in result.output
    assert FakeMac.instances[0].connected
    assert FakeMac.instances[0].closed  # closed in finally


def test_mac_reports_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_mod, "MacTransport", FakeMac)

    def boom(*a: object, **k: object) -> None:
        raise AuthFailed("username may not exist on router")

    monkeypatch.setattr(cli_mod, "run_batch", boom)
    result = CliRunner().invoke(
        cli, ["mac", "38:32:7A:26:8E:BD", "/system resource print", "--password", "x"]
    )
    assert result.exit_code == 1
    assert "username may not exist" in result.output
