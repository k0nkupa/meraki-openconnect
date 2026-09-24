# Reliable connection lifecycle and clearer menu-bar experience

Status: ready-for-agent

## Problem Statement

Meraki Connect works for the user's current VPN, but its menu-bar status and cleanup behavior are unreliable around authentication, verification, failure, and shutdown. The user confirmed five audit findings: stale connected status after tunnel failure; quitting during authentication without cancelling the connection child; connected status published before required health checks complete; native disconnect stalling during browser authentication; and first-time setup failures leaving no usable recovery command.

The user also wants authentication to open Chrome using Chrome's normal profile selection rather than requiring a Chrome profile directory in configuration, and wants a visibly green menu-bar icon when connected.

## Solution

Make connection status reflect verified readiness throughout the session. Keep authentication and verification distinct from a usable connection, observe unexpected termination, and complete cancellation and cleanup before allowing normal quit. Make interrupted first-time setup recoverable through an explicit supported command.

Open authentication and permission setup using Chrome's normal application-opening behavior without selecting a configured Chrome profile. Preserve the Chrome extension and exact gateway permission requirements. Show green only for a verified connected session, with text and shape cues so color is not the only indicator.

## User Stories

1. As a VPN user, I want the menu to show connecting while authentication is in progress, so that I know the VPN is not ready yet.
2. As a VPN user, I want required health checks to finish before the menu says connected, so that I can trust the displayed status.
3. As a VPN user, I want failed route checks to prevent a successful connection indication, so that unavailable internal routes are not hidden.
4. As a VPN user, I want failed DNS checks to prevent a successful connection indication, so that name-resolution failures are not hidden.
5. As a VPN user, I want failed TCP checks to prevent a successful connection indication, so that required services must be reachable before success is reported.
6. As a VPN user, I want the icon to turn green after successful verification, so that I can recognize an active connection at a glance.
7. As a VPN user, I want a checkmark or equivalent shape alongside the green state, so that connection status does not depend on color alone.
8. As a VPN user, I want the green state to disappear when the tunnel ends, so that an obsolete connection indication cannot mislead me.
9. As a VPN user, I want an unexpected connection-process exit reflected in the menu, so that I do not need to click Diagnostics to discover a failure.
10. As a VPN user, I want an existing verified session to be represented accurately when I open the app, so that starting the app does not imply starting another VPN connection.
11. As a VPN user, I want Quit during authentication to cancel the pending attempt, so that authentication cannot continue unmanaged after the app exits.
12. As a VPN user, I want Quit during verification to cancel the pending attempt and clean up, so that a partly ready tunnel is not left behind.
13. As a VPN user, I want Quit during a connected session to wait for cleanup, so that normal application exit has predictable behavior.
14. As a VPN user, I want cleanup failure to keep the app open with an explicit failure state, so that an unverified shutdown is not presented as successful.
15. As a VPN user, I want Force Quit to remain an explicit escape hatch, so that I can choose to exit when cleanup cannot be confirmed.
16. As a CLI user, I want disconnect to stop a native worker waiting for browser authentication, so that cancellation does not depend on completing login.
17. As a VPN user, I want duplicate connection and shutdown actions handled consistently, so that overlapping operations cannot leave the interface and tunnel disagreeing.
18. As a VPN user, I want Chrome to open without a required profile-directory setting, so that authentication follows the browser behavior I use in other applications.
19. As an existing user, I want my saved configuration to remain usable after the profile-selection change, so that upgrading does not force a complete setup merely to remove that preference.
20. As a VPN user, I want Chrome opening to return control promptly whether Chrome is already running or starts cold, so that authentication handling can continue while the browser is open.
21. As a VPN user, I want clear guidance when authentication cannot reach the extension in the chosen Chrome profile, so that I can resolve the setup problem without a silent indefinite wait.
22. As a VPN user, I want the extension and gateway permission to remain required in the profile Chrome actually opens, so that automatic profile selection does not remove required setup checks.
23. As a new user, I want recovery instructions that work when privileged installation succeeds but local settings fail to save, so that retrying does not lead to contradictory errors.
24. As a new user, I want recovery to work without a complete local profile and settings pair, so that the missing files do not block the recovery command itself.
25. As a VPN user, I want recovery and cleanup confined to this client's installed components, so that unrelated application and network configuration is preserved.

## Implementation Decisions

- Scope is the five confirmed defects plus the two explicit experience changes: Chrome-managed profile selection and a green verified-connected icon. Additional convenience features discussed afterward are not approved requirements.
- Retain the existing Python CLI/controller, native worker, Chrome extension/native messaging bridge, and Swift menu-bar architecture. No daemon, alternate browser-authentication implementation, or broad rewrite is required.
- Separate tunnel ownership and cleanup bookkeeping from verified connection readiness. A worker PID or allocated tunnel interface alone must not imply a verified connected session. Preserve enough state to disconnect during authentication and verification and to report unresolved cleanup.
- Coordinate the CLI status contract and Swift models so the app can distinguish pending work, verified connection, termination, and cleanup failure. The exact serialization change is left to implementation; update consumers together and avoid treating unfamiliar or incomplete state as success.
- Observe the connection child after successful connection and refresh the state of adopted sessions. A later failure must remove the connected indication without user interaction. Proposed acceptance target: ordinary terminal-state changes are reflected within two seconds when status probes are responsive.
- Treat pending connection attempts as resources owned by the app. Normal quit must cancel pending work, await the connection child's completion where applicable, and verify cleanup. Preserve explicit Force Quit behavior and guard against duplicate mutations.
- Make native cancellation wake the browser-authentication wait as well as notifying OpenConnect. Keep signal handling safe; do not call condition-variable operations directly from a signal handler. Prefer adapting the existing cancellation mechanism.
- Remove Chrome profile selection as a required configuration and setup input. Read legacy settings compatibly, but do not use their profile field to force browser selection. New setup must not ask for a profile directory. Align readiness checks and setup documentation with this behavior.
- Delegate profile choice to Chrome through normal macOS application-opening behavior. Do not inspect Chrome's private profile databases, enable debugging, or claim deterministic last-focused-profile selection that the platform does not guarantee.
- Keep the extension identifier, native-host binding, exact gateway permission, and profile receipt checks. Chrome profile selection is separate from the configured organization profile; this remains a one-organization application.
- Browser launch must not block the controller for the lifetime of a newly started Chrome process. Bound extension handoff waits and provide accurate, actionable failure guidance without claiming to detect the precise cause when it cannot be observed.
- Use a green connected icon with a recognizable checkmark or equivalent cue only after required checks succeed. Retain legibility in light and dark menu bars and provide an accessible status label. Other states remain visually distinguishable without relying on green.
- Provide an explicit recovery path for partial first-time installation that does not require the missing local settings. Recovery must respect the installed components and existing operation locking, verify its result, and leave actionable instructions on failure. Do not blindly overwrite unrelated resolver configuration or silently reauthenticate.

## Testing Decisions

- Test externally observable outcomes and failure recovery, not internal call order or a particular refactoring. Prefer existing injectable boundaries rather than introducing a second architecture just for tests.
- Primary test boundary: the Swift VPNController through its existing VPNCLI abstraction and controllable ConnectHandle. Exercise authentication pending, verification pending, verified connection, unexpected child exit, adopted-session changes, quit at every stage, cleanup failure, duplicate actions, and explicit force quit. Existing controller tests and the isolated audit reproduction provide prior art.
- CLI/worker boundary: extend existing Python tunnel tests with FakeWorker, a temporary TunnelStore, controlled health checks, and fake privileged operations. Assert that public status does not report verified connection before checks succeed, that check failure clears success state, and that pending or failed cleanup remains actionable. Use CLI-facing status output where feasible to cover the Python-to-Swift contract.
- Native cancellation boundary: add a bounded unprivileged test that reaches the browser callback's wait, delivers cancellation through the actual signal/cancellation path, and demonstrates completion without a browser token. Existing native protocol/policy fixtures and the isolated audit harness provide prior art. No live tunnel is needed.
- Setup boundary: reuse SetupDependencies to simulate root installation succeeding followed by local persistence failure. Exercise the actual recovery command dispatch with fake privileged execution, then verify that retry or cleanup is possible without missing settings. Cover failures saving either profile or settings and incomplete recovery.
- Chrome boundary: reuse the injected launcher and existing settings, readiness, extension, and native-host test patterns. Verify that no profile-directory selection is supplied, legacy settings remain readable, cold browser opening does not block handoff handling, and unavailable handoff results in bounded useful feedback.
- Icon boundary: extend the existing TunnelStatusIcon tests and visually inspect light/dark menu-bar rendering. Verify state and accessibility labels together; collect screenshots for any eventual visible-change PR.
- Reuse the existing Python, native, JavaScript, macOS, packaging, public-tree, and whitespace gates. Authentication and live network checks are not part of automated fixtures. Use reserved example domains and IP ranges only.
- The user approved these testing boundaries. The cross-language lifecycle cannot be established by a Swift fake alone, so the additional native and Python boundaries are intentional.

## Out of Scope

- Implementing or deploying changes as part of this specification task.
- Automatic reconnect, automatic connection at login, background daemons, and multi-organization support.
- Launch at login, connection duration, disconnect notifications, diagnostics export, and a broad failure-message redesign.
- A new dedicated Cancel button during connection; reliable cancellation through existing Quit and CLI disconnect paths is included. The separate button was suggested but not explicitly accepted.
- A configurable browser/profile picker, support for other browsers, and automatic extension installation into every Chrome profile.
- Broad code cleanup, a new security scan, and changes to certificate trust or gateway authorization policy.
- Assuming Chrome always chooses the previously focused profile; platform behavior must be checked during implementation.

## Further Notes

The user confirmed all five findings and asked to remain in discussion before invoking to-spec. This task records the agreed direction and proposed testing boundaries; it does not authorize product implementation or live VPN operations.

The prior audit reported 307 passing Python tests, 40 passing macOS tests, passing native tests, JavaScript syntax checks, package build, public-tree check, and whitespace check. Those are prior-audit results, not validation of future fixes. Isolated reproductions demonstrated premature and stale status, quit during authentication without child cleanup, native cancellation leaving the browser callback blocked, and contradictory setup retry instructions.

The exact Chrome application-opening behavior and visual icon treatment should be verified during implementation. Missing-extension feedback must remain honest about what the handoff can observe.

## Comments

- User approved the testing boundaries and readiness of this spec. Marked ready-for-agent. No product implementation or live VPN operations performed.
