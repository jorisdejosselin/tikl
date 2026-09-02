# Tikl

A cross-platform CLI for reaching MikroTik/RouterOS routers over MAC-Telnet
(layer 2, no IP) or SSH.

## Language

**MAC mode**:
Reaching a router over MAC-Telnet at layer 2 with EC-SRP5 auth, requiring no IP
on the target. The differentiating transport.
_Avoid_: MAC-Telnet mode, L2 mode

**SSH mode**:
Reaching a router that has a usable IP over ordinary SSH.
_Avoid_: IP mode, remote mode

**Target**:
What the user names to identify a router — a MAC address, an IP/hostname, or a
named host from config. Its form selects the transport.
_Avoid_: host, device, endpoint (when the specific meaning is "target")

**Named host**:
A config-file entry mapping a friendly name to a MAC and/or IP plus defaults.
_Avoid_: alias, profile

**Transport**:
A connection method (MAC or SSH) behind a shared interface. One `Transport`
implementation per method.
_Avoid_: connection type, backend, driver

**EC-SRP5**:
The password-authenticated key-agreement handshake RouterOS 6.43+ uses over
Curve25519; how MAC mode authenticates without sending the password.
_Avoid_: SRP, the crypto

**Discover**:
Scanning all viable interfaces for MikroTik devices via MNDP (UDP 5678),
tagging each with the interface it was heard on; feeds the interactive picker.
_Avoid_: scan, probe, neighbour lookup

**Capture**:
A one-time, local, manual run (`--capture`) against a disposable CHR VM that
records a real EC-SRP5 handshake as the committed golden test vector.
_Avoid_: record, dump

**Golden KAT**:
The frozen known-answer vector from a captured real handshake; CI replays it to
prove the crypto without any router present.
_Avoid_: fixture, test vector (when this specific one is meant)

**Loopback peer**:
An in-process fake MAC-Telnet peer that exercises the session state machine and
shell loop in CI, anchored to the golden KAT.
_Avoid_: mock, fake server, stub

**Session**:
One connect→run-commands→close lifecycle over a transport, including the
RouterOS-shell command loop and prompt handling.
_Avoid_: connection (when the lifecycle is meant)
