# 3. Golden KAT from disposable CHR; CI never contacts hardware

EC-SRP5 correctness can only be proven against real RouterOS, but CI runs on
public GitHub runners that cannot reach home hardware, and a known-answer vector
must embed a password. We capture one real handshake **locally** against a
throwaway RouterOS CHR VM (via a hidden `--capture` path) and commit it as the
golden KAT — a burner credential on a discarded VM, safe to publish. CI only
replays that KAT and runs the in-process loopback peer, so the pipeline proves
the crypto and state machine with no router present and no network to home. A
live CHR-in-CI job is deferred to a later milestone.
