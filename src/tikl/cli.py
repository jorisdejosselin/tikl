"""Tikl command-line interface.

Milestones 1-3: MAC-Telnet + SSH transports, batch and interactive modes, MNDP
discovery + the bare-``tikl`` picker, and target auto-select (a MAC -> MAC-Telnet,
an IP/host -> SSH). ``--transport`` and the explicit ``mac``/``ssh`` subcommands
override the auto choice.
"""

from __future__ import annotations

import getpass
import os
import re
import sys
from pathlib import Path

import click

from . import __version__
from .errors import TiklError
from .mac import mndp
from .mac.client import MacTransport
from .mac.ecsrp5 import HandshakeCapture
from .mac.mndp import MndpDevice
from .session import (
    DEFAULT_COMMANDS,
    interactive_shell,
    run_batch,
    terminal_size,
    terminal_type,
)
from .transport import Transport

_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")


def _looks_like_mac(target: str) -> bool:
    return bool(_MAC_RE.match(target))


def _resolve_password(password: str | None) -> str:
    """CLI flag > $TIKL_PASS > legacy $MT_PASS > interactive prompt."""
    if password is not None:
        return password
    env = os.environ.get("TIKL_PASS") or os.environ.get("MT_PASS")
    if env is not None:
        return env
    try:
        return getpass.getpass("Password: ")
    except EOFError as exc:
        # No usable terminal for the prompt (common under sudo when the env was
        # stripped). Point at the fixes instead of a bare "Aborted!".
        raise click.ClickException(
            "no password available. Pass --password, set TIKL_PASS, or (under sudo) "
            "keep it via sudoers: Defaults env_keep += \"TIKL_PASS TIKL_USER\""
        ) from exc


def _default_user() -> str:
    """Username default: $TIKL_USER > legacy $MT_USER > 'admin'."""
    return os.environ.get("TIKL_USER") or os.environ.get("MT_USER") or "admin"


def _commands(positional: tuple[str, ...], command_opts: tuple[str, ...]) -> list[str]:
    """Build the command list: each -c is one command; the positional words are
    joined into a single command (so `tikl mac <mac> /ip address print` works
    unquoted). Empty result => interactive shell."""
    cmds = list(command_opts)
    if positional:
        cmds.append(" ".join(positional))
    return cmds


def _make_capture_hook(capture_path: Path | None):  # type: ignore[no-untyped-def]
    if capture_path is None:
        return None
    click.secho(
        "WARNING: --capture writes credentials to disk. Use a throwaway CHR VM "
        "and a burner credential only.",
        fg="yellow",
        err=True,
    )

    def on_capture(cap: HandshakeCapture) -> None:
        cap.write(capture_path)
        click.secho(f"Captured handshake -> {capture_path}", fg="green", err=True)

    return on_capture


def _build_mac(
    mac: str, user: str, password: str, iface: str | None, capture_path: Path | None = None
) -> MacTransport:
    return MacTransport(
        mac,
        user=user,
        password=password,
        iface=iface,
        term=terminal_type(),
        term_size=terminal_size(),
        on_capture=_make_capture_hook(capture_path),
    )


def _build_ssh(host: str, user: str, password: str, port: int, legacy: bool):  # type: ignore[no-untyped-def]
    from .ssh.client import SshTransport  # noqa: PLC0415 - keep paramiko import lazy

    return SshTransport(
        host,
        user=user,
        password=password,
        port=port,
        term=terminal_type(),
        term_size=terminal_size(),
        legacy_algorithms=legacy,
    )


def _run(
    transport: Transport, desc: str, commands: tuple[str, ...] | list[str], timeout: float
) -> None:
    """Connect, then either run a command batch or open an interactive shell."""
    click.echo(f"Connecting to {desc}...", err=True)
    try:
        transport.connect()
        if commands:
            click.echo("Connected.\n", err=True)
            for command, output in run_batch(transport, commands, timeout):
                click.secho(f"=== {command} ===", fg="cyan")
                click.echo(output)
        else:
            click.echo("Connected. Interactive shell — Ctrl-] to quit.\n", err=True)
            interactive_shell(transport)
    except (TiklError, RuntimeError) as exc:
        click.secho(f"error: {exc}", fg="red", err=True)
        sys.exit(1)
    finally:
        transport.close()


def _print_device_table(devices: list[MndpDevice]) -> None:
    click.secho(
        f"{'#':>2}  {'identity':<16} {'board':<14} {'MAC':<17} {'RouterOS':<12} {'ipv4':<15}",
        bold=True,
    )
    for i, d in enumerate(devices, 1):
        version = d.version.split()[0] if d.version else ""
        click.echo(
            f"{i:>2}  {d.identity[:16]:<16} {d.board[:14]:<14} {d.mac:<17} "
            f"{version[:12]:<12} {d.ipv4:<15}"
        )


class TargetGroup(click.Group):
    """A group where an unrecognised first arg is treated as a connection target."""

    def resolve_command(
        self, ctx: click.Context, args: list[str]
    ) -> tuple[str | None, click.Command | None, list[str]]:
        try:
            return super().resolve_command(ctx, args)
        except click.UsageError:
            if args and not args[0].startswith("-"):
                connect_cmd = self.get_command(ctx, "connect")
                assert connect_cmd is not None
                return "connect", connect_cmd, args
            raise


@click.command(
    cls=TargetGroup,
    invoke_without_command=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.version_option(__version__, "-V", "--version", prog_name="tikl")
@click.option(
    "-i",
    "--iface",
    default=lambda: os.environ.get("MT_IFACE"),
    help="Interface for discovery/MAC-Telnet (default: system default).",
)
@click.option("--timeout", default=4.0, show_default=True, help="Discovery timeout (s).")
@click.pass_context
def cli(ctx: click.Context, iface: str | None, timeout: float) -> None:
    """Recovery CLI for MikroTik/RouterOS over MAC-Telnet (L2, no IP) or SSH.

    With a target: `tikl <MAC>` uses MAC-Telnet, `tikl <IP/host>` uses SSH; add
    commands to run them, or omit them for an interactive shell. With no target,
    Tikl scans the segment (MNDP) and lets you pick a device.
    """
    if ctx.invoked_subcommand is not None:
        return
    _picker(iface, timeout)


def _picker(iface: str | None, timeout: float) -> None:
    click.echo("Scanning for MikroTik devices (MNDP)...", err=True)
    devices = mndp.discover(timeout=timeout)
    if not devices:
        click.secho("No devices found. Try `tikl mac <MAC>` directly, or -i <iface>.", fg="yellow")
        sys.exit(1)
    _print_device_table(devices)
    choice = click.prompt("\nConnect to which? (number, or q to quit)", default="q")
    if choice.strip().lower() in {"q", ""}:
        return
    try:
        dev = devices[int(choice) - 1]
    except (ValueError, IndexError):
        click.secho("Invalid selection.", fg="red")
        sys.exit(1)
    user = click.prompt("Username", default=_default_user())
    password = _resolve_password(None)
    transport = _build_mac(dev.mac, user, password, iface)
    _run(transport, f"{dev.mac} (MAC-Telnet)", DEFAULT_COMMANDS, 30.0)


@cli.command()
@click.option("-i", "--iface", default=lambda: os.environ.get("MT_IFACE"), help="Interface.")
@click.option("--timeout", default=4.0, show_default=True, help="Discovery timeout (s).")
def discover(iface: str | None, timeout: float) -> None:
    """Scan the segment for MikroTik devices (MNDP) and print them."""
    click.echo("Scanning for MikroTik devices (MNDP)...", err=True)
    devices = mndp.discover(timeout=timeout)
    if not devices:
        click.secho("No devices found.", fg="yellow")
        sys.exit(1)
    _print_device_table(devices)


@cli.command()
@click.argument("mac")
@click.argument("commands", nargs=-1)
@click.option(
    "-u",
    "--user",
    default=_default_user,
    show_default="admin",
    help="RouterOS username.",
)
@click.option(
    "-i",
    "--iface",
    default=lambda: os.environ.get("MT_IFACE"),
    help="Interface to broadcast on (default: scapy default).",
)
@click.option(
    "-c",
    "--command",
    "command_opts",
    multiple=True,
    help="A RouterOS command to run (repeatable, for several commands).",
)
@click.option("--password", default=None, help="Password ($TIKL_PASS or prompt if omitted).")
@click.option("--timeout", default=30.0, show_default=True, help="Per-command timeout (s).")
@click.option(
    "--capture",
    "capture_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write the EC-SRP5 handshake to this file (test-vector "
    "generation; USE A THROWAWAY CHR + CREDENTIAL ONLY).",
)
def mac(
    mac: str,
    commands: tuple[str, ...],
    command_opts: tuple[str, ...],
    user: str,
    iface: str | None,
    password: str | None,
    timeout: float,
    capture_path: Path | None,
) -> None:
    """Connect by MAC over MAC-Telnet (layer 2, no IP). No command = shell."""
    transport = _build_mac(mac, user, _resolve_password(password), iface, capture_path)
    _run(transport, f"{mac} (MAC-Telnet)", _commands(commands, command_opts), timeout)


@cli.command()
@click.argument("host")
@click.argument("commands", nargs=-1)
@click.option(
    "-u",
    "--user",
    default=_default_user,
    show_default="admin",
    help="RouterOS username.",
)
@click.option("-p", "--port", default=22, show_default=True, help="SSH port.")
@click.option(
    "-c",
    "--command",
    "command_opts",
    multiple=True,
    help="A RouterOS command to run (repeatable, for several commands).",
)
@click.option("--password", default=None, help="Password ($TIKL_PASS or prompt if omitted).")
@click.option("--timeout", default=30.0, show_default=True, help="Per-command timeout (s).")
@click.option("--legacy", is_flag=True, help="Re-enable legacy SSH algorithms for old RouterOS.")
def ssh(
    host: str,
    commands: tuple[str, ...],
    command_opts: tuple[str, ...],
    user: str,
    port: int,
    password: str | None,
    timeout: float,
    legacy: bool,
) -> None:
    """Connect by IP/hostname over SSH. No command = interactive shell."""
    transport = _build_ssh(host, user, _resolve_password(password), port, legacy)
    _run(transport, f"{host} (SSH)", _commands(commands, command_opts), timeout)


@cli.command(hidden=True)
@click.argument("target")
@click.argument("commands", nargs=-1)
@click.option("-u", "--user", default=_default_user)
@click.option("-i", "--iface", default=lambda: os.environ.get("MT_IFACE"))
@click.option("-p", "--port", default=22)
@click.option("-c", "--command", "command_opts", multiple=True)
@click.option("--password", default=None)
@click.option("--timeout", default=30.0)
@click.option("--legacy", is_flag=True)
@click.option(
    "--transport", "transport_opt", type=click.Choice(["auto", "mac", "ssh"]), default="auto"
)
def connect(
    target: str,
    commands: tuple[str, ...],
    command_opts: tuple[str, ...],
    user: str,
    iface: str | None,
    port: int,
    password: str | None,
    timeout: float,
    legacy: bool,
    transport_opt: str,
) -> None:
    """Auto-select transport from TARGET (a MAC -> MAC-Telnet, else SSH)."""
    mode = transport_opt
    if mode == "auto":
        mode = "mac" if _looks_like_mac(target) else "ssh"
    pwd = _resolve_password(password)
    if mode == "mac":
        transport: Transport = _build_mac(target, user, pwd, iface)
        desc = f"{target} (MAC-Telnet)"
    else:
        transport = _build_ssh(target, user, pwd, port, legacy)
        desc = f"{target} (SSH)"
    _run(transport, desc, _commands(commands, command_opts), timeout)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
