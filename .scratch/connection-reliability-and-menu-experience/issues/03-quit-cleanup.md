# 03: Complete cleanup before normal Quit

**What to build:** Make normal Quit cancel pending connection attempts and verify session cleanup before exiting, while keeping explicit Force Quit available when cleanup cannot be confirmed.

**Blocked by:** 01: Report verified connection state accurately; 02: Disconnect reliably during browser authentication.

**Status:** completed

- [x] Quit during authentication, verification, or a connected session cancels the owned attempt and awaits its child completion where applicable before approving normal termination.
- [x] A status response that is not verified connected does not by itself authorize termination while an owned connection attempt or unresolved cleanup exists.
- [x] Quit also disconnects an adopted active session and verifies its cleanup without requiring an owned child handle.
- [x] Overlapping connection, disconnect and quit requests do not launch duplicate cleanup or allow a pending connection to become active after quit is approved.
- [x] Cleanup failure or timeout keeps the app open with a useful failure state and explicit Force Quit; Force Quit is never selected automatically.
- [x] Use existing VPNCLI fakes, controlled ConnectHandle and sleeper seams to cover all lifecycle phases, child completion, failure, duplicate requests and explicit force quit. Include the TerminationCoordinator boundary.
- [x] Run macOS tests and applicable Python/native gates for any controller contract changes, plus public-tree and whitespace checks. Record exact results.
- [x] Do not add a new dedicated Cancel button, automatic reconnect or a background daemon.

## Notes

This ticket implements the approved Reliable connection lifecycle and clearer menu-bar experience spec. Use existing testing seams and reserved example data. Keep production investigation read-only; live authentication, installation and VPN operations require applicable authorization. Publication of this ticket does not start implementation.


## Comments

### Completed — 2026-09-08

Implemented by Terra/high on local `main`; reviewed independently by Astra/medium on standards and spec axes against fixed base `99186040b0fb84cdf585d56e23efd1f17b3f6a5f`.

Commit: `fb8928d03fd1b3c9186698178f427d6770027789` — `fix: complete session cleanup before quitting`.

Normal Quit now invalidates pending connection work, shares cleanup with overlapping Disconnect requests, waits for launch and owned-child completion, and verifies a fresh disconnected status before approval. Failure and timeout retain explicit Force Quit. Existing ConnectHandle injection supports deterministic race tests; CLI serialization and VPNCLI contracts are unchanged.

Review results:

- Standards: no documented-standard violations or blocking findings. Optional duplication observations (test gate helpers, cleanup wait branches, short observer status handling) remain deferred.
- Spec: both initial findings fixed and re-reviewed; zero remaining findings or scope creep. The fixes close a stale nil child-result race and add verification, suspended-status, and genuine timeout coverage.

Validation performed:

- Focused `xcodebuild -quiet -project macos/MerakiOpenConnect/MerakiOpenConnect.xcodeproj -scheme MerakiOpenConnect -destination 'platform=macOS' -derivedDataPath macos/MerakiOpenConnect/.derivedData -only-testing:MerakiOpenConnectTests/VPNControllerTests test` — passed. Preflight and child-result regressions were demonstrated failing before their fixes.
- `xcodebuild -quiet -project macos/MerakiOpenConnect/MerakiOpenConnect.xcodeproj -scheme MerakiOpenConnect -destination 'platform=macOS' -derivedDataPath macos/MerakiOpenConnect/.derivedData test` — final run: 58 passed, zero failures or skips; exit 0. Only the duplicate-destination warning. Result summary verified with `xcrun xcresulttool get test-results summary`.
- `uv run pytest -q` — 324 passed in 12.76s. Python sources remained unchanged throughout implementation.
- `make -C native clean test` — passed strict compilation, smoke, protocol, policy and browser-cancellation tests. Native sources remained unchanged.
- `uv build` — source distribution and wheel built successfully.
- `scripts/check-public-tree.sh` — passed.
- `git diff --check` — passed.

Only the four scoped Swift source/test files were committed. Existing unrelated local changes and untracked files were preserved. This completion record remains in the local Markdown tracker. No remote push, installation, authentication, or live VPN operations performed.
