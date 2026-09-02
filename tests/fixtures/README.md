# Test fixtures

- **`mndp_hap_be3.hex`** — a real MNDP announcement from an hAP be^3 Media
  (RouterOS 7.24.1). Drives `test_mndp.py`.
- **`mt_reply_start_ack.hex`** — a real MAC-Telnet `START` reply from the same
  router. Pins the (asymmetric) header field order in `test_protocol.py`.
- **`golden_kat.json`** — *(not committed yet)* a real EC-SRP5 handshake, the
  golden known-answer test for `test_golden_kat.py`. See below.

## Generating `golden_kat.json` (ADR 0003)

The golden KAT must come from **real RouterOS** but must not leak a real
password, so capture it against a **disposable CHR VM** with a **burner
credential**:

1. Boot a throwaway RouterOS **CHR** VM (free image) reachable at layer 2 on
   some interface `<iface>`. Note its MAC `<chr-mac>`.
2. Set a burner password on it, e.g. `admin` / `tikltest`.
3. Capture one handshake:

   ```bash
   sudo TIKL_PASS=tikltest tikl mac <chr-mac> --iface <iface> \
       --user admin --capture tests/fixtures/golden_kat.json '/system identity print'
   ```

4. Commit `tests/fixtures/golden_kat.json`. It contains only the burner
   credential on a discarded VM, so it is safe to publish. `test_golden_kat.py`
   then proves `compute_confirmation` reproduces a confirmation real RouterOS
   accepted — with no router present in CI.

During development the crypto was already validated live against a real hAP be^3
(the confirmation `compute_confirmation` produced was accepted by the router);
this fixture makes that check reproducible in CI.
