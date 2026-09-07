# Tikl

Recovery CLI for MikroTik / RouterOS routers. Reach a box over **MAC-Telnet**
at layer 2 (no IP required — fresh out of the box, post-factory-reset, wrong
VLAN) or over **SSH** when it has an IP.

Tikl is a **break-glass access tool, not a fleet manager** — its job is to
*reach* a router and run commands by hand. Declarative automation is a different
tool's job. See [`DESIGN.md`](DESIGN.md) for the full design and
[`docs/adr/`](docs/adr) for the decisions behind it.

> **Status:** early development, but feature-complete for v1 — MAC-Telnet + SSH
> transports, batch and interactive shells, MNDP discovery + the pick-a-device
> flow, target auto-select, tests (incl. an in-process loopback peer), binaries,
> Docker (GHCR), release-please and Renovate. See `DESIGN.md`.

## Install

Not on PyPI yet — install from source, a prebuilt binary, or Docker.

**With [uv](https://docs.astral.sh/uv/) (any OS, recommended):**

```bash
uv tool install git+https://github.com/jorisdejosselin/tikl
# update later:   uv tool upgrade tikl
# with pipx:      pipx install git+https://github.com/jorisdejosselin/tikl
```

**Prebuilt binary** (no Python needed) — from the
[latest release](https://github.com/jorisdejosselin/tikl/releases/latest):

```bash
# Linux x86_64  (arm64: swap the filename for tikl-linux-arm64)
curl -L https://github.com/jorisdejosselin/tikl/releases/latest/download/tikl-linux-x86_64 -o /usr/local/bin/tikl && chmod +x /usr/local/bin/tikl
```

```powershell
# Windows (PowerShell)
irm https://github.com/jorisdejosselin/tikl/releases/latest/download/tikl-windows-x86_64.exe -OutFile tikl.exe
```

_(No macOS binary — use the uv install above; macOS ships libpcap. See DESIGN.md #10.)_

**Docker** (SSH anywhere; MAC-Telnet only on a Linux host):

```bash
docker run --rm ghcr.io/jorisdejosselin/tikl ssh 192.168.88.1 /system resource print
docker run --rm --network host --cap-add=NET_RAW ghcr.io/jorisdejosselin/tikl mac 38:32:7A:26:8E:BD
```

### Prerequisites for MAC-Telnet (layer-2) mode

It sends raw L2 frames, so it needs a packet-capture driver **and** admin rights:

| OS | Driver | Run as |
|----|--------|--------|
| Windows | [Npcap](https://npcap.com) (install with "WinPcap API-compatible mode") | Administrator (elevated shell) |
| Linux | libpcap (usually preinstalled; `apt install libpcap0.8`) | `sudo` |
| macOS | libpcap (built in) | `sudo` |

**SSH mode needs none of this** — no driver, no admin. `tikl discover` (finding devices) also needs no admin.

## Usage

```bash
# Discover MikroTik devices on the segment (MNDP — no root needed)
tikl discover

# No target: scan, then pick a device to connect to over MAC-Telnet
sudo tikl

# MAC-Telnet (layer 2, no IP) — run commands on a fresh box
sudo tikl mac 38:32:7A:26:8E:BD /system resource print

# default command set (resource + address + dhcp-client) if none given
sudo tikl mac 38:32:7A:26:8E:BD

# choose the interface if the router is on a non-default NIC
sudo tikl mac 38:32:7A:26:8E:BD --iface en6

# interactive shell (no commands) — over MAC-Telnet or SSH
sudo tikl mac 38:32:7A:26:8E:BD --iface en6
tikl ssh 192.168.88.1

# auto-select: a MAC uses MAC-Telnet, an IP/host uses SSH
sudo tikl 38:32:7A:26:8E:BD /system resource print
tikl 192.168.88.1 /system resource print

# several commands in one session: repeat -c
sudo tikl mac 38:32:7A:26:8E:BD -c "/system identity print" -c "/ip address print"

# upload a file over SSH (SFTP) — e.g. RouterOS firmware, then reboot to install
tikl ssh 192.168.88.1 --upload routeros-7.24.1.npk
tikl ssh 192.168.88.1 /system reboot
```

`--upload` (SSH only, repeatable) copies a local file into the router's root
over SFTP. A `.npk` there is installed on the next reboot; a routerboard
firmware `.npk` upgrades the bootloader via `/system routerboard upgrade`.

The words after the target are **joined into one command**, so no quoting is
needed for a single command (`… /ip address print`). Use `-c` (repeatable) to
run several commands in one session. No command at all → interactive shell.

`tikl discover` needs no privileges (plain UDP). MAC-Telnet needs root/pcap;
SSH needs neither.

### Credentials via environment

| Setting  | Env var (legacy)          | CLI flag       | Default |
|----------|---------------------------|----------------|---------|
| Username | `TIKL_USER` (`MT_USER`)   | `--user`/`-u`  | `admin` |
| Password | `TIKL_PASS` (`MT_PASS`)   | `--password`   | prompt  |
| Interface| `MT_IFACE`                | `--iface`/`-i` | auto    |

Precedence is CLI flag > `TIKL_*` > legacy `MT_*` > default/prompt.

```bash
export TIKL_USER=admin
export TIKL_PASS='your-password'
tikl ssh 192.168.88.1 /system resource print   # non-root: env is used directly
```

**`sudo` strips these env vars by default** (even `sudo -E` is refused unless
sudoers permits it). MAC-Telnet needs root, so to use the env vars with it, allow
them through sudo once via a sudoers drop-in:

```
Defaults env_keep += "TIKL_USER TIKL_PASS MT_IFACE"
```

Then `sudo tikl mac 38:32:7A:26:8E:BD` picks them up. Otherwise pass `--user` /
`--password` on the command line (visible in the process list), or let it prompt.

## Development

```bash
uv sync                     # install deps + dev tools
uv run pytest               # tests (no hardware needed)
uv run ruff check .         # lint
uv run mypy                 # type-check
```

Installing the CLI while iterating:

```bash
# live edits — source changes take effect without reinstalling
uv tool install --editable . --force

# or update a normal install (plain `uv tool install .` won't rebuild the same
# version); precompiling bytecode avoids root-owned .pyc from sudo runs
UV_COMPILE_BYTECODE=1 uv tool install . --force --reinstall
```

(Tikl disables bytecode writing when it runs as root, so `sudo tikl` no longer
leaves root-owned `.pyc` that block the next reinstall.)

Tests never contact a router: crypto is checked against frozen/golden vectors
and the session loop against a fake transport. Hardware tests are marked `hw`
and skipped by default.

## License

MIT. The EC-SRP5 curve math (`src/tikl/mac/curve.py`) is adapted from
`MarginResearch/mikrotik_authentication` (MIT). MAC-Telnet is implemented
clean-room; `haakonnessjoen/MAC-Telnet` (GPL-2.0) is a protocol reference only
(see ADR 0001).
