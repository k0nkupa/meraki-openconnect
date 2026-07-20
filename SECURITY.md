# Security Policy

## Reporting a vulnerability

Do not disclose a suspected vulnerability, live organization profile, private
network detail, token-bearing log, cookie, SAML assertion, certificate pin, or
credential in a public issue or discussion.

Use GitHub's private vulnerability reporting flow for this repository. If that
flow is unavailable, contact the maintainer privately through the GitHub account
that owns the repository before sharing sensitive evidence. Include the affected
commit, macOS version, a minimal reproduction using reserved example data, and
the security impact. Redact authentication and organization data even in a
private report unless the maintainer explicitly requests a narrowly scoped
artifact.

## Supported version

The project is pre-release and source-only. Security fixes target the current
default branch; no older release line is currently maintained.

## Security boundary

Meraki Connect is designed around one validated organization policy and one
root-owned policy snapshot. The privileged helper accepts only fixed named
operations. Profiles cannot supply scripts, shell commands, filesystem paths,
OpenConnect arguments, or arbitrary privileged actions.

Passwords, MFA values, cookies, SAML assertions, and VPN tokens must remain
ephemeral. The public repository must never contain a live profile, machine
settings, installed policy, private DNS or routing topology, authentication log,
or generated browser/build state.

A successful browser login or generic tunnel probe is not proof that a private
application is safe or operational. Organizations should define bounded health
checks and independently verify their own application access.

### Browser TLS trust boundary

The saved gateway certificate pin is enforced for Python gateway requests and
the root-owned native VPN tunnel. It is not enforced by Chrome during the visible
SAML exchange. Chrome validates that connection with the macOS system trust
store, while the client constrains the flow to the configured HTTPS origins and
checks the saved pin before and after browser authentication.

Those checks reject ordinary gateway certificate changes. They do not prevent a
network-path attacker with another CA-valid certificate from selectively serving
that certificate only to Chrome while serving the pinned certificate to the
client's Python and native connections. Such an attacker could observe or proxy
the SAML assertion or short-lived VPN token. Version 0.1.0 explicitly accepts
this limitation; deployments that require application-level pinning of the
browser SAML leg should not use this release.
