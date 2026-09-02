# Tikl — Design Document

> Status: **decisions locked; implementation underway.** All numbered decisions
> in §13 are resolved (see the `DECIDED` markers) and captured in ADRs where
> warranted. Milestone 1 (package skeleton + MAC-Telnet batch mode) is built.

## 1. What Tikl is

Tikl is a command-line tool for reaching **MikroTik / RouterOS** routers over
two transports:

- **MAC mode** — MAC-Telnet at layer 2 with EC-SRP5 authentication. Reaches a
  router that has **no usable IP** (fresh out of the box, post-factory-reset,
  misconfigured WAN/LAN, or on a VLAN you can't route to). This is the
  differentiator; almost nothing else does it from a modern cross-platform CLI.
- **SSH mode** — ordinary SSH to a router that *does* have an IP. This is the
  everyday path and the one that works everywhere without special privileges.

You run one command, it connects, runs RouterOS commands (or drops you into an
interactive shell), prints the output, and exits.

**Positioning: Tikl is a recovery / break-glass access tool, not a fleet
manager** (ADR 0002). Its job is to *reach a box* — especially one with no usable IP — and
run commands by hand. Routine, declarative automation is the existing Terraform
config's job, not Tikl's. This is why MAC mode is the star and why API/REST,
keyrings, and fleet features stay out of scope (see #1, #5).

The name: **MikroTik** + *tickle* the box at L2. Short, no collision with
existing MikroTik tooling.

### Origin

Tikl grows out of two working scripts:

- `ecsrp5_curve.py` — Curve25519-in-Weierstrass-form math for EC-SRP5,
  adapted from `MarginResearch/mikrotik_authentication` (MIT).
- `mac_telnet.py` — a working MAC-Telnet client (session state machine,
  EC-SRP5 handshake, command loop) built on `scapy` + `ecdsa`.

These already work against real hardware. Tikl productionises them: a real
package, a second transport (SSH), tests, releases, and distribution.

**Protocol reference (do not copy):** `haakonnessjoen/MAC-Telnet` is the
canonical C MAC-Telnet client and confirms full interactive-over-L2 is feasible
(it is interactive-only; Tikl adds batch mode). It is **GPL-2.0**, so it is a
behavioural reference only — Tikl's implementation is clean-room to preserve the
MIT license (#14). No code is copied or line-by-line ported from it.

### Command modes (both transports)

Every transport supports two modes:
- **Batch** — `tikl <target> <cmd> [cmd ...]`: run each command, print, exit.
  (This is Tikl's addition over the reference clients.)
- **Interactive** — no commands given → a real PTY shell: raw terminal mode,
  the actual `$TERM` and live window size sent to the router, `SIGWINCH`
  resize handling. Not the hardcoded `vt100`/220×50 the seed script uses.

**Windows terminal support:** Unix uses `termios` raw mode. Windows has no
`termios`, so raw keystroke input uses the `msvcrt`/console-API path.
SSH interactive is **fully supported on Windows** (paramiko + a small raw-input
shim). MAC interactive on Windows is **best-effort** (rarest + most fragile
combo); the guaranteed Windows MAC path is **batch** (`tikl mac <mac> <cmd>`),
which is always enough to restore an IP and then switch to SSH.

## 2. Goals and non-goals

### Goals

1. Connect to a RouterOS device by **MAC** (L2, no IP) or **SSH** (has IP).
2. Run one or more commands non-interactively, or open an interactive shell.
3. **Discover** MikroTik devices on the local segment (MNDP) so you don't have
   to already know the MAC.
4. Ship as: `uv`/`pip`-installable Python package, standalone **binaries** for
   Linux/macOS/Windows, and a **Docker image**.
5. Automated **testing** on every PR and on `main`; automated dependency
   updates via **Renovate**.

### Non-goals (for v1)

- The RouterOS **binary API** (8728/8729) and **REST** API (443, ROS7+). SSH is
  the requested remote transport; API is a possible later transport but out of
  scope now (see #1).
- Config *management* / IaC. That's what the existing Terraform config is for.
  Tikl is an interactive/scripting access tool, not a declarative provisioner.
- A GUI / TUI dashboard. Plain CLI output first.
- Windows-native raw-socket path without Npcap. Npcap is required for MAC mode
  on Windows.

## 3. Background — how each transport works

### 3.1 MAC-Telnet + EC-SRP5

- MikroTik MAC-Telnet runs over Ethernet, UDP-shaped payload on port
  **20561**, sent as an L2 broadcast (`ff:ff:ff:ff:ff:ff`) so no IP is needed.
- The session is a small reliable-delivery state machine over unreliable
  broadcast: `START` → `DATA`/`ACK` (with counters) → `END`. `mac_telnet.py`
  implements this today (sequence counters, ACKing, a sniffer thread + queue).
- **Version floor: EC-SRP5 only, RouterOS 6.43+** (decided). Covers all current
  hardware; the seed code already does exactly this. Older boxes use a legacy
  MD5 challenge-response that Tikl does **not** implement in v1 — they get a
  clear "router uses pre-6.43 auth, not supported" error rather than a mystery
  failure. Legacy auth is a possible later addition if an old box is ever hit.
- Auth is **EC-SRP5** (RouterOS 6.43+): a password-authenticated key agreement
  over Curve25519 (in Weierstrass form). Client and server exchange public
  points; the client proves knowledge of the password-derived validator without
  sending the password. `ecsrp5_curve.py` is the curve math; the handshake is
  `MikroTik._ec_srp_confirmation`.
- **Hard requirements:** raw L2 send/receive → **libpcap** (Linux/macOS) or
  **Npcap** (Windows) installed, **root/Administrator** privileges, and a NIC
  on the same physical segment as the router. There is no way around any of
  these — they are inherent to L2 access.

### 3.2 SSH

- Ordinary SSH to RouterOS. RouterOS presents a shell with a distinctive prompt
  (`[user@identity] >`), the same prompt family the MAC path already parses.
- No special privileges, no pcap, works through routed networks and from inside
  containers/VMs. This is the "boring, always works" path.
- SSH library: **paramiko** (decided — see #2). Pure-Python on top of
  `cryptography`, synchronous (fits the Click CLI), no system deps. Rejected:
  `asyncssh` (async churn for no gain here), system `ssh` (unportable, hard to
  test). Note RouterOS sometimes needs older KEX/host-key algorithms enabled
  explicitly — the client must be able to opt into them.

## 4. Architecture

Single package `tikl`, transport-agnostic core with two transport
implementations behind one interface.

```
tikl/
├── cli.py            # Click entry point, subcommands, arg/target resolution
├── transport.py      # Transport protocol (connect/run/shell/close) + result types
├── mac/
│   ├── client.py     # MAC-Telnet state machine  (from mac_telnet.py)
│   ├── ecsrp5.py     # EC-SRP5 handshake         (uses curve.py)
│   ├── curve.py      # WCurve math               (from ecsrp5_curve.py)
│   ├── protocol.py   # pack/unpack, constants, CP-packet framing
│   └── mndp.py       # MikroTik Neighbor Discovery (UDP 5678) for `discover`
├── ssh/
│   └── client.py     # paramiko-based transport
├── session.py        # shared command loop, prompt detection, ANSI stripping
├── config.py         # config file + env + defaults, named-host resolution
└── output.py         # rendering (raw / table for discover), quiet/verbose
```

**Key idea — a `Transport` is just a bidirectional byte channel** (decided —
see #3). Once connected, both transports reduce to "write bytes / read bytes /
resize," and *everything above the stream is shared*:

```python
class Transport(Protocol):
    def connect(self) -> None: ...
    def write(self, data: bytes) -> None: ...
    def read(self, timeout: float) -> bytes: ...  # b'' on idle
    def resize(self, cols: int, rows: int) -> None: ...
    def close(self) -> None: ...
```

`session.py` implements **all** of it once: batch command loop, interactive
pump (local raw terminal `termios`/`msvcrt` ↔ remote byte stream), prompt
detection + ANSI stripping (moved out of `mac_telnet.py`), and `SIGWINCH`
resize. Transport-specific code shrinks to exactly:
- **MAC** = framing + reliable-broadcast layer (counters/ACK/retransmit) +
  EC-SRP5 auth;
- **SSH** = paramiko channel setup + algorithm negotiation.

That is the entire difference between the two transports.

## 5. CLI surface (UX)

**MAC-first** (decided): MAC mode is the default and the point of Tikl; SSH is
opt-in convenience for when the box has an IP and you'd rather use it. Transport
is auto-selected from the target, with an override.

```
tikl                                    # no target → MNDP scan, pick a box, connect (MAC)
tikl <target> [ROUTEROS-CMD ...]        # MAC → mac mode; named host → MAC if it has one; IP → ssh
tikl discover [--iface I] [--timeout S] # MNDP scan → table of neighbours (no connect)
tikl mac  <mac>  [cmd ...]              # force MAC-Telnet
tikl ssh  <host> [cmd ...]             # force SSH
```

Selection rules (MAC-first):
- A **MAC** (`38:32:7A:26:8E:BD`) → MAC mode.
- A **named host** → **prefer MAC** when the entry has a `mac`; SSH only when it
  has no `mac`.
- A bare **IP/hostname** → SSH (MAC mode needs a MAC; an IP implies IP
  connectivity). Tikl does **not** ARP-resolve an IP to a MAC to force MAC mode.
- **No target** → MNDP discovery + interactive pick, then connect over MAC. This
  is the core recovery flow: plug in → `tikl` → pick the box → you're in, no
  need to know the MAC.
- No commands given → **interactive shell**. Commands given → run each, print,
  exit. Multiple commands run in one session.
- Global flags: `--user/-u`, `--iface/-i` (MAC), `--port/-p` (SSH),
  `--timeout`, `--verbose/-v`, `--quiet/-q`, `--transport {mac,ssh,auto}`.
- Password: `--password`, `$TIKL_PASS` (keep `$MT_PASS`/`$MT_USER` as
  aliases for the old scripts), else interactive prompt (never echoed, never a
  CLI arg default).

**Auto-select is the default (decided — see #4), MAC-first:** a MAC → MAC mode;
a named host → MAC when it has one; a bare IP → SSH; no target → discover + pick.
Explicit `mac`/`ssh` subcommands and `--transport` always override.

**Discovery (v1, MNDP over UDP 5678):** RouterOS announces itself; Tikl parses
`identity`, `model`/board, RouterOS version, uptime, MAC, and the interface it
was heard on. `tikl discover` prints the table (columns:
`#, identity, model, MAC, RouterOS ver, iface`); bare `tikl` runs the same scan
and shows a **numbered interactive picker** that connects to the chosen row over
MAC. The picker is in v1 — it is the headline recovery flow and is mostly glue
over discovery + MAC connect.

Example:

```
tikl                                             # scan, pick a box, connect (MAC)
tikl 38:32:7A:26:8E:BD /system resource print   # L2, fresh box
tikl 192.168.178.1 /ip address print            # SSH
tikl hap-be3                                      # named host, interactive
tikl discover                                     # what's on this segment?
```

## 6. Configuration and secrets

**Interface selection — discovery-driven, never type a NIC** (decided): the
seed script's hardcoded `\Device\NPF_{GUID}` is removed. Discovery sniffs MNDP
on **all viable interfaces at once** (per-iface sniffer threads) and tags each
device with the interface it was heard on, so in the `tikl` → pick flow the
interface comes *with* the chosen device. For a bare-MAC target with no iface
known, Tikl **broadcasts on all interfaces and sniffs all** — the session key
(`sk`) disambiguates replies, so whichever NIC the router is on just works.
`--iface` and `config defaults.iface` remain as an override to restrict the scan
on busy multi-segment machines.

- Optional config file at `~/.config/tikl/config.toml` (XDG). Holds defaults
  (user, iface) and **named hosts**:

  ```toml
  [defaults]
  user = "admin"
  iface = "en7"

  [hosts.hap-be3]
  mac  = "38:32:7A:26:8E:BD"
  host = "192.168.178.1"
  user = "admin"
  ```

- Precedence: CLI flag > env var > config file > built-in default.
- **Passwords are never stored in config.** Env var or prompt only.
  No OS keyring (decided — see #5): env + prompt only. A credential vault is
  daily-driver ergonomics a break-glass tool doesn't need, and it matches the
  current Infisical-driven workflow (secrets live there, not in Tikl).

## 7. The hard part — platform matrix (be honest about this)

MAC mode's requirements (pcap + root + same L2 segment) fight directly with the
"just download a binary" and "run it in Docker" goals. This must be documented,
not hidden.

| Scenario                          | SSH mode | MAC mode |
|-----------------------------------|:--------:|:--------:|
| `pip`/`uv` install, Linux/macOS   | ✅       | ✅ (root + libpcap) |
| `pip`/`uv` install, Windows       | ✅       | ✅ (Admin + Npcap)  |
| Standalone binary (Linux/Windows) | ✅       | ✅ **but** pcap still required on host, run as root |
| Standalone binary (macOS)         | — (use `pip`/`uv`) | — (use `pip`/`uv`) |
| Docker on **Linux** host          | ✅       | ✅ only with `--network host --cap-add=NET_RAW` |
| Docker Desktop on **macOS/Win**   | ✅       | ❌ container can't see host L2 (runs in a VM) |

Consequences we accept and document:

1. **Binaries cannot bundle pcap.** PyInstaller bundles Python + scapy + ecdsa,
   but libpcap/Npcap is a native, separately-licensed system component. The
   binary README must tell users to install it (and to run MAC mode elevated).
2. **Docker is primarily the SSH image.** MAC mode in Docker only works on a
   Linux host with `--network host` and `NET_RAW`. On macOS/Windows Docker
   Desktop it cannot reach the physical segment at all. Document loudly.
3. **The hardcoded Windows interface in `mac_telnet.py` must go** — replaced by
   auto-detection with an interactive picker and `--iface`/config override.

**Decided (see #6):** build all three channels, but scope them honestly.
Primary MAC delivery is **`pip`/`uv` + the Linux/Windows binary** (pcap + root
required). **Docker is the SSH channel** — "SSH anywhere; MAC only on a Linux
host with `--network host --cap-add=NET_RAW`." This split falls straight out of
MAC-first + Docker Desktop's VM isolation.

## 8. Testing strategy (called out as important)

The core problem: the interesting behaviour needs a real router on an L2
segment, which CI does not have. We split accordingly.

**Unit (run in CI, no hardware, no root):**
- **EC-SRP5 known-answer tests.** Vectors come from **capturing one real,
  successful handshake against a disposable RouterOS CHR VM** (decided — see #7),
  not from freezing the implementation's own output. Capturing against a
  throwaway CHR (rather than the hAP) means the committed fixture contains only a
  burner credential on a discarded VM — safe to commit even in a public repo
  (this is why there is no password-leak concern; #13). A hidden `--capture`
  debug path logs the full chain of a real auth — `client_private`, `username`,
  `password`, `salt`, `server_public`, `server_parity`, and the `confirmation`
  the router accepted — frozen as the **golden end-to-end KAT**. Per-function
  vectors (`lift_x`, `redp1`, `gen_public_key`, validator) are derived from that
  same known-good run.
- **The capture is a one-time, local, manual step — CI never runs it and never
  contacts any router** (ADR 0003). CI only replays the committed KAT + runs the
  loopback peer, so it works on public GitHub runners with no network to home
  hardware.
- **Protocol pack/unpack** round-trips, CP-packet framing, counter/ACK logic.
- **MNDP frame parsing** from captured bytes.
- **Config resolution & target/transport auto-select** (pure logic).
- **CLI** via Click's `CliRunner`.

**Loopback protocol test (run in CI, decided — see #8):** an in-process fake
MAC-Telnet *peer* over a pipe exercises the session state machine
(START/DATA/ACK/END, retransmit, prompt detection) and the interactive shell
loop — no hardware, no root. It is **anchored to the golden KAT**: an
**injectable `client_private`** seam (replacing the hardcoded
`secrets.token_bytes(32)`) lets the peer replay the exact captured handshake and
validate the confirmation, so CI covers auth + shell end-to-end
deterministically. The fake peer is expected to be imperfect and gets tweaked
when it diverges from real router behaviour; the KAT keeps its auth path honest.

**Integration (not in PR CI by default):**
- `@pytest.mark.hw` tests run against real hardware (or a local CHR), skipped by
  default, manual only.
- **CHR-in-CI (deferred to a later milestone):** an optional live-integration
  job that boots RouterOS **CHR inside the runner** (public GitHub Linux runners
  expose `/dev/kvm`) with an L2 tap between client and VM, exercising a genuine
  EC-SRP5 handshake + MAC-Telnet on every PR. Real complexity (QEMU, CHR image +
  licensing, tap networking), so it is **not in v1** — the KAT + loopback peer
  cover the crypto and state machine well enough to ship without it.

**Quality gates in CI:** `ruff` (lint+format), `mypy` (typing), `pytest` with
coverage **reported but not gated** (decided — see #9). A floor on a young
codebase gets gamed, and the hardest code to cover (MAC state machine, crypto
vs hardware) is exactly what a floor would push away from. Add a floor later
once the suite settles. The real signal is "KAT + loopback peer pass," not a %.

## 9. Packaging and distribution

- **Build/deps:** `uv` for env + lock; `pyproject.toml` with **exactly pinned**
  versions (per repo policy — no ranges); `hatchling` backend. Console entry
  point `tikl = "tikl.cli:main"`. Runtime deps: `click`, `scapy`, `ecdsa`,
  `paramiko` (all pinned to latest stable at implementation time).
- **Binaries:** PyInstaller one-file per OS/arch in a GH Actions matrix —
  `linux-x86_64`, `linux-arm64`, `windows-x86_64`. Needs scapy PyInstaller
  hooks. **No prebuilt macOS binary** (decided — see #10): a distributed macOS
  binary needs Apple signing + notarization ($99/yr Developer Program) or
  Gatekeeper blocks it; not worth it. **macOS is still fully supported via
  `uv`/`pip install`** (installs from source, no signing, macOS ships libpcap so
  MAC mode works) and via the Docker image (SSH). The docs must make this
  explicit so macOS users don't think they're unsupported.
- **Docker:** slim Python base, `libpcap` installed, non-root default user for
  SSH; documented `--network host --cap-add=NET_RAW` for MAC on Linux.
  Multi-arch (amd64/arm64) via buildx. Published to **GHCR**
  (`ghcr.io/<owner>/tikl`, decided — see #11): same GitHub account, no extra
  registry credentials, `GITHUB_TOKEN` pushes it straight from the release
  workflow.

## 10. CI/CD

GitHub Actions:

- **`ci.yml`** on PR + push to `main`: matrix over OS × Python version → ruff,
  mypy, pytest (+coverage). This is the gate.
- **`release.yml`** on tag `v*`: build binaries (matrix), build+push Docker
  (multi-arch), create a GitHub Release with binaries attached and generated
  notes. Release trigger: **release-please** (decided — see #12) — derives the
  version bump and changelog from conventional commits and opens a release PR;
  merging it tags `v*` and fires this workflow. (This implies a
  conventional-commit convention for the repo.)
- All action versions pinned (SHA or exact tag) per repo policy; Renovate keeps
  them current.

## 11. Renovate

- `renovate.json` extending a sensible base; **exact pins** everywhere (deps,
  Actions, Dockerfile `FROM`, `.python-version`).
- **Automerge patch + minor after CI is green; majors get manual review**
  (decided — see #13), across all dep types (runtime, dev, Actions, Docker
  base). Safe because the golden KAT + loopback peer catch a crypto/state-machine
  regression from an `ecdsa`/`scapy` bump deterministically. Residual gap:
  `paramiko` (SSH) isn't fully CI-covered without a router, but SSH is the
  convenience path, so an automerged SSH minor is an acceptable risk.
- Group the automerge-eligible updates and schedule off-hours to cut noise.
- This is why the test suite matters — Renovate is only as safe as CI.

## 12. Licensing

- Tikl ships under **MIT** (decided — see #14). `ecsrp5_curve.py` is adapted
  from `MarginResearch/mikrotik_authentication` (MIT); MIT is the compatible,
  simplest choice, and the upstream copyright/attribution is preserved in the
  curve module.
- MAC-Telnet is implemented **clean-room** — `haakonnessjoen/MAC-Telnet`
  (GPL-2.0) is a protocol reference only, never copied (ADR 0001).

## 13. Open decisions (grill list)

1. API/REST transport in scope for v1? **DECIDED: no** — recovery tool; API/REST
   is daily-driver/automation territory (Terraform's job).
2. SSH library: paramiko vs asyncssh vs system ssh? **DECIDED: paramiko.**
3. How much command-loop logic is shared vs MAC-only? **DECIDED: byte-channel
   seam** — `Transport` = write/read/resize; `session.py` does batch,
   interactive, prompt/ANSI, and SIGWINCH for both. Transport-specific =
   MAC framing/reliability/auth, SSH channel/algorithms.
4. Auto-select transport from target, or require explicit subcommand?
   **DECIDED: auto-select, with explicit `mac`/`ssh` + `--transport` kept.**
5. OS keyring for credentials? **DECIDED: no** — recovery tool; type the
   password (env/prompt). A credential vault is daily-driver ergonomics.
6. Binaries *and* Docker for MAC mode, or scope Docker to SSH? **DECIDED: build
   all; MAC via pip/uv+binary, Docker is the SSH channel** (MAC in Docker only
   on a Linux host with host-net + NET_RAW).
7. EC-SRP5 vectors: real capture vs frozen regression? **DECIDED: capture one
   real successful handshake from the hAP** (via a hidden `--capture` path) as
   the golden KAT; derive per-function vectors from it.
8. Build the in-process loopback peer for CI? **DECIDED: yes** — anchored to the
   KAT via an injectable `client_private`; iterate when it diverges from real
   behaviour.
9. Coverage gate now or later? **DECIDED: report-only in v1**, add a floor once
   the suite settles.
10. macOS binary signing/notarization? **DECIDED: no macOS binary** — no Apple
    Developer ID ($99/yr), and Gatekeeper blocks unsigned binaries. macOS stays
    supported via `pip`/`uv` install and Docker (SSH).
11. Registry: GHCR vs Docker Hub? **DECIDED: GHCR** — same account, pushes with
    `GITHUB_TOKEN`, no extra registry secrets.
12. Release automation: manual tags vs release-please? **DECIDED:
    release-please** (implies conventional commits).
13. Renovate automerge policy? **DECIDED: automerge patch + minor (all dep
    types) after green CI; majors manual.**
14. MIT license confirmed? **DECIDED: yes, MIT.**

## 14. Rough milestones

1. **Package skeleton** ✅ **(hardware-validated)** — `pyproject`/uv, `tikl`
   package, the two scripts moved into `tikl/mac/*` behind the byte-channel
   `Transport`, `tikl mac <mac>` batch works. Injectable `client_private` seam
   and `--capture` in place. Verified live against a real hAP be^3 Media
   (RouterOS 7.24.1): full MAC-Telnet + EC-SRP5 connect + command output, and
   `compute_confirmation` reproduces the confirmation the router accepted.
   NOTE: the seed's `unpack` was correct — MAC-Telnet framing is asymmetric
   (client sends (seskey, clienttype); server replies (clienttype, seskey)),
   pinned by a captured reply fixture.
2. **Cross-platform MAC + discovery** ✅ (mostly) — hardcoded iface dropped;
   MNDP discovery over a plain UDP socket (no root), `tikl discover` table +
   bare-`tikl` picker, validated live against a real hAP be3. **Deferred:**
   per-interface "heard-on" tagging (plain sockets can't do it portably — we
   record the sender IP instead) and true all-interface MAC-Telnet broadcast
   (`--iface` is the workaround for now); revisit when testable with root.
3. **SSH transport + interactive** ✅ — paramiko byte channel (`SshTransport`)
   with host-key AutoAdd + optional `--legacy` algorithms; shared `session.py`
   interactive PTY (POSIX raw mode via `termios`, real `$TERM`/size, `SIGWINCH`;
   Windows `msvcrt` best-effort). Target auto-select (`tikl <MAC>`→MAC,
   `tikl <IP/host>`→SSH) via a custom Click group; `mac`/`ssh`/`--transport`
   override. SSH tested with mocked paramiko (no reachable router IP here);
   needs one live SSH run to confirm against real RouterOS.
4. **Tests** ✅ (KAT slot pending CHR) — in-process **loopback peer** drives the
   real client through START → EC-SRP5 key exchange → shell with no root/hardware
   (via the new `Link` seam); deterministic confirmation with fixed keys guards
   the client crypto path; frozen curve vectors + real MNDP/reply fixtures. CI
   green, no router contacted (43 passed, coverage 82%, reported). The
   real-RouterOS **golden KAT** fixture is generated from a disposable CHR per
   the runbook in `tests/fixtures/README.md` (`test_golden_kat.py` skips until
   present); crypto correctness was already validated live against real hardware.
5. **Distribution** ✅ — PyInstaller one-file binaries (Linux x86_64/arm64,
   Windows x86_64; no macOS per #10) built + attached to releases; multi-arch
   Docker image to GHCR; `release-please` drives version/changelog/tag; Renovate
   (patch/minor automerge, majors manual, `rangeStrategy: pin`). CI also builds
   the wheel + image on every PR. Binary and image were built and run locally
   (the frozen binary discovered the real router; the image runs `tikl`).
6. **Later (post-v1)** — CHR-in-CI live-integration job; legacy pre-6.43 auth if
   ever needed; optional coverage floor.
