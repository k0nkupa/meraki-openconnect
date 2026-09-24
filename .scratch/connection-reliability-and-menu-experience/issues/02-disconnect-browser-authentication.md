# 02: Disconnect reliably during browser authentication

**What to build:** Make CLI disconnect stop a native worker waiting for browser authentication without requiring the user to finish login or provide a token.

**Blocked by:** None (can start immediately).

**Status:** ready-for-agent

- [ ] Cancellation delivered through the existing privileged disconnect path releases the browser-authentication wait and allows the worker to finish within the existing helper deadline.
- [ ] Cancellation informs both the browser wait and OpenConnect. Signal handlers remain signal-safe; do not invoke condition-variable operations directly from a signal handler.
- [ ] Cancellation remains effective before, during, and immediately after entry to the browser wait. Repeated cancellation does not hang or turn into connection success.
- [ ] Worker termination, controller cleanup and status remain consistent; inability to confirm cleanup remains a failure rather than a successful disconnect.
- [ ] Add a bounded unprivileged native regression test that reaches the real browser callback wait and delivers the actual signal/cancellation path, asserting completion without a token.
- [ ] Exercise CLI/controller disconnect behavior with fake privileged execution and worker fixtures. Tests must not connect to a live VPN or modify installed root components.
- [ ] Run full Python and native gates, packaging, public-tree and whitespace checks; add macOS tests if app-facing contracts change. Record exact results.

## Notes

This ticket implements the approved Reliable connection lifecycle and clearer menu-bar experience spec. Use existing testing seams and reserved example data. Keep production investigation read-only; live authentication, installation and VPN operations require applicable authorization. Publication of this ticket does not start implementation.
