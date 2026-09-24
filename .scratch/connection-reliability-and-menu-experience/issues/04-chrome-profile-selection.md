# 04: Let Chrome choose its profile

**What to build:** Open Chrome through normal macOS application-opening behavior for setup and authentication, without asking the user to configure a Chrome profile directory.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] New setup and saved configuration do not require a Chrome profile directory; runtime launch does not force a specific Chrome profile.
- [ ] Existing settings containing the legacy profile field remain readable and usable without forcing complete setup solely to remove that field. The legacy value does not control browser selection.
- [ ] Both permission setup and authentication use the revised launch behavior. Cold and already-running Chrome launches return control promptly rather than waiting for Chrome to exit.
- [ ] CLI readiness, Swift readiness decoding and setup guidance no longer require a configured Chrome profile directory, while still checking Chrome availability and applicable extension/native-host receipts.
- [ ] Keep the extension identifier, exact gateway permissions and organization-profile binding. The profile Chrome opens still needs the extension and permission; do not silently relax those requirements.
- [ ] Unavailable extension handoff ends within a bounded wait with useful guidance. Do not assert that a particular profile or missing extension caused the failure unless the application can observe it.
- [ ] Verify normal application-opening behavior for cold and running Chrome where feasible without live authentication. Do not promise deterministic last-focused-profile selection or inspect private browser profile databases.
- [ ] Use existing injected launcher, settings, readiness, extension/native-host and CLI tests to exercise migration, launch arguments, nonblocking launch and handoff failures; update Swift contract tests as needed.
- [ ] Update user-facing setup documentation and examples consistently. Run full Python/macOS gates, extension syntax checks, packaging, public-tree and whitespace checks; run native gates if shared policy or serialization changes. Record exact results.
- [ ] Do not add a browser/profile picker, other-browser support, automatic extension installation, or changes to certificate trust.

## Notes

This ticket implements the approved Reliable connection lifecycle and clearer menu-bar experience spec. Use existing testing seams and reserved example data. Keep production investigation read-only; live authentication, installation and VPN operations require applicable authorization. Publication of this ticket does not start implementation.
