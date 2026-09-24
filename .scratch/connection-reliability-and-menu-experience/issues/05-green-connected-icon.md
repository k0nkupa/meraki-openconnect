# 05: Show green for verified connections

**What to build:** Give the menu-bar app a clear green icon with a recognizable checkmark or equivalent shape only when the VPN is verified connected.

**Blocked by:** 01: Report verified connection state accurately.

**Status:** ready-for-agent

- [ ] The icon becomes green only after required health checks pass; authentication, verification, disconnection and error states never display verified-connected green.
- [ ] Termination or failed verification removes the green state automatically using the lifecycle updates from ticket 01.
- [ ] A checkmark or equivalent shape and an accessible status label convey connection state without relying on color alone.
- [ ] The connected icon renders in color in the actual macOS menu bar and remains legible in light and dark appearances; other states remain distinguishable.
- [ ] Extend existing TunnelStatusIcon tests and controller-to-icon state coverage. Visually inspect light/dark rendering and capture screenshots for an eventual visible-change PR.
- [ ] Run macOS tests, public-tree and whitespace checks; record exact results and any visual verification limitation.
- [ ] Do not introduce a broader visual redesign, connection duration display or notification feature.

## Notes

This ticket implements the approved Reliable connection lifecycle and clearer menu-bar experience spec. Use existing testing seams and reserved example data. Keep production investigation read-only; live authentication, installation and VPN operations require applicable authorization. Publication of this ticket does not start implementation.
