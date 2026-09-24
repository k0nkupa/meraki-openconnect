# 06: Recover from partially completed setup

**What to build:** Provide a supported recovery command and accurate instructions when privileged installation succeeds but local profile or settings persistence fails.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] A failure saving either the local organization profile or machine settings after privileged installation produces instructions for a recovery path that actually works in that incomplete state.
- [ ] The recovery command is reachable through normal CLI dispatch without requiring the missing profile/settings pair.
- [ ] Recovery operates only on this client's installed components, honors existing operation locking, and does not remove or overwrite unrelated resolver configuration.
- [ ] Recovery verifies its result before reporting success. Partial recovery failure leaves actionable guidance and does not blindly retry live writes.
- [ ] After successful recovery the user can explicitly rerun setup without being trapped by the installed-policy-without-settings guard.
- [ ] Complete existing installations retain normal setup/uninstall behavior. Do not silently reconnect, reauthenticate, or broaden cleanup to unrelated files.
- [ ] Use SetupDependencies to inject failures saving profile and settings separately, and exercise actual recovery CLI dispatch with fake privileged operations. Cover missing settings, missing profile, unsuccessful recovery and successful retry.
- [ ] Run full Python and native gates for privileged installation/policy changes, packaging, public-tree and whitespace checks; add macOS gates if readiness contracts change. Record exact results.

## Notes

This ticket implements the approved Reliable connection lifecycle and clearer menu-bar experience spec. Use existing testing seams and reserved example data. Keep production investigation read-only; live authentication, installation and VPN operations require applicable authorization. Publication of this ticket does not start implementation.
