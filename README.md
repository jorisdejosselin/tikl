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

```bash
uv tool install tikl        # or: pipx install tikl
```

Or grab a standalone **binary** (Linux x86_64/arm64, Windows x86_64) from the
[Releases](https://github.com/jorisdejosselin/tikl/releases) page — no macOS binary
(use `uv`/`pip`), see DESIGN.md #10.

Or the **Docker image** (SSH anywhere; MAC only on a Linux host):

```bash
docker run --rm ghcr.io/jorisdejosselin/tikl ssh 192.168.88.1 /system resource print
# MAC-Telnet in Docker (Linux host only):
docker run --rm --network host --cap-add=NET_RAW ghcr.io/jorisdejosselin/tikl \
    mac 38:32:7A:26:8E:BD
```

MAC mode needs **libpcap** (Linux/macOS) or **Npcap** (Windows) and
**root/Administrator** — it sends raw layer-2 frames. SSH mode needs neither.

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
```

`tikl discover` needs no privileges (plain UDP). MAC-Telnet needs root/pcap;
SSH needs neither.

Password resolution: `--password` > `$TIKL_PASS` (or legacy `$MT_PASS`) >
interactive prompt. Username: `--user` > `$MT_USER` > `admin`.

## Development

```bash
uv sync                     # install deps + dev tools
uv run pytest               # tests (no hardware needed)
uv run ruff check .         # lint
uv run mypy                 # type-check
```

Tests never contact a router: crypto is checked against frozen/golden vectors
and the session loop against a fake transport. Hardware tests are marked `hw`
and skipped by default.

## License

MIT. The EC-SRP5 curve math (`src/tikl/mac/curve.py`) is adapted from
`MarginResearch/mikrotik_authentication` (MIT). MAC-Telnet is implemented
clean-room; `haakonnessjoen/MAC-Telnet` (GPL-2.0) is a protocol reference only
(see ADR 0001).
