"""discover command + bare-tikl picker, with MNDP stubbed (no network)."""

from __future__ import annotations

import pytest
from click.testing import CliRunner

import tikl.cli as cli_mod
from tikl.cli import cli
from tikl.mac.mndp import MndpDevice

DEV = MndpDevice(
    mac="38:32:7a:26:8e:bd",
    identity="hAP",
    version="7.24.1 (stable) 2026-08-21 13:06:38",
    board="MA53UG+HbeH",
    ipv4="192.168.137.80",
)


def test_discover_prints_table(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_mod.mndp, "discover", lambda timeout=4.0: [DEV])
    result = CliRunner().invoke(cli, ["discover"])
    assert result.exit_code == 0
    assert "38:32:7a:26:8e:bd" in result.output
    assert "hAP" in result.output
    assert "7.24.1" in result.output


def test_discover_none_found(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_mod.mndp, "discover", lambda timeout=4.0: [])
    result = CliRunner().invoke(cli, ["discover"])
    assert result.exit_code == 1
    assert "No devices found" in result.output


def test_picker_connects_to_selection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_mod.mndp, "discover", lambda timeout=4.0: [DEV])
    calls: dict[str, object] = {}

    def fake_build_mac(mac, user, password, iface, capture_path=None):  # type: ignore[no-untyped-def]
        calls.update(mac=mac, user=user, password=password)
        return object()

    def fake_run(transport, desc, commands, timeout):  # type: ignore[no-untyped-def]
        calls["desc"] = desc

    monkeypatch.setattr(cli_mod, "_build_mac", fake_build_mac)
    monkeypatch.setattr(cli_mod, "_run", fake_run)
    monkeypatch.setenv("TIKL_PASS", "secret")
    result = CliRunner().invoke(cli, [], input="1\n\n")
    assert result.exit_code == 0, result.output
    assert calls["mac"] == "38:32:7a:26:8e:bd"
    assert calls["user"] == "admin"
    assert calls["password"] == "secret"
    assert calls["desc"] == "38:32:7a:26:8e:bd (MAC-Telnet)"


def test_picker_quit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_mod.mndp, "discover", lambda timeout=4.0: [DEV])
    result = CliRunner().invoke(cli, [], input="q\n")
    assert result.exit_code == 0
    assert "38:32:7a:26:8e:bd" in result.output
