# 01: Report verified connection state accurately

**What to build:** Keep CLI status and the menu-bar app aligned with whether the tunnel has passed all required checks, and reflect session termination without requiring Diagnostics.

**Blocked by:** None (can start immediately).

**Status:** completed

- [x] Authentication and verification remain pending states; a worker PID or allocated interface alone never makes public status or the menu report a verified connection.
- [x] Every required route, DNS, and TCP check must pass before connected status is published. Any failed check prevents success and initiates existing cleanup behavior.
- [x] Tunnel ownership and cleanup bookkeeping remain available while verification is pending or cleanup has failed; disconnected must not silently mean cleanup is complete.
- [x] The app continues observing a connection it started after successful verification and detects termination of adopted sessions without manual refresh.
- [x] Ordinary terminal-state changes appear in the menu within two seconds when status probes are responsive. No automatic reconnect is introduced.
- [x] CLI status output and Swift decoding are updated together; missing, unfamiliar, or incomplete state is never interpreted as verified success.
- [x] Regression tests exercise public CLI status during controlled pending/passing/failing checks using FakeWorker and temporary TunnelStore fixtures, plus VPNController/VPNCLI/ConnectHandle tests for child exit and adopted-session termination.
- [x] Run the full Python suite and macOS tests; run native gates if shared worker protocol or policy changes, plus packaging, public-tree and whitespace gates. Record exact results.

## Notes

This ticket implements the approved Reliable connection lifecycle and clearer menu-bar experience spec. Use existing testing seams and reserved example data. Keep production investigation read-only; live authentication, installation and VPN operations require applicable authorization. Publication of this ticket does not start implementation.


## Comments

### Completed — 2026-09-08

Implemented by Terra/high and reviewed independently by Astra/medium on both standards and spec axes. All review findings were resolved; both final reviews reported zero remaining findings.

Commit: `9c46e55081a200efb6dce43ab979e53e06a26047` — `fix: report verified tunnel lifecycle state`.
Fast-forwarded into local `main` in `/Users/tony/Projects/meraki-openconnect`. No remote push, installation, authentication, or live VPN operations performed.

Validation completed on the implemented commit before the local merge:

- `uv run pytest -q` — 321 passed.
- `make -C native clean test` — passed: strict compilation, smoke, protocol, and policy tests. Native sources were unchanged.
- `xcodebuild -quiet -project macos/MerakiOpenConnect/MerakiOpenConnect.xcodeproj -scheme MerakiOpenConnect -destination 'platform=macOS' -derivedDataPath macos/MerakiOpenConnect/.derivedData test` — 49 passed, zero failures or skips; only the duplicate-destination warning.
- `uv build` — source distribution and wheel built successfully.
- `scripts/check-public-tree.sh` — passed.
- `git diff --check` — passed.
- Spec review independently reran `uv run pytest -q tests/test_tunnel.py tests/test_cli.py` — 56 passed.

The local merge was a fast-forward to the reviewed commit; unrelated checkout changes were preserved. Tickets 02–06 remain outside this completion.
