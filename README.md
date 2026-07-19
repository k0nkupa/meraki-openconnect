# Meraki OpenConnect

Meraki OpenConnect is an unofficial, source-first macOS client for Meraki and
AnyConnect-compatible SSL VPN gateways. It uses OpenConnect for the tunnel and
Google Chrome for visible Microsoft Entra SAML authentication.

This project is not affiliated with, endorsed by, or supported by Cisco or
Meraki. Cisco, Meraki, and AnyConnect are trademarks of their respective
owners.

## Supported scope

- Apple Silicon Mac running macOS 13 or newer.
- One configured organization per Mac.
- Meraki/AnyConnect-compatible HTTPS gateway on port 443.
- Microsoft Entra SAML authentication through Google Chrome.
- Optional split DNS plus required route, DNS, and TCP health checks.
- Foreground CLI controller and a locally built Swift menu-bar application.

Version 1 is deliberately narrow. It has no signed installer, notarized app,
automatic updater, background daemon, automatic reconnect, cross-platform
support, or multi-profile UI.

## Prerequisites

- Xcode
- Google Chrome
- Homebrew
- Python 3.13
- `uv`
- OpenConnect and its development headers

Install the Homebrew prerequisites:

```bash
brew install python@3.13 uv openconnect
```

## Install from source

Clone the repository, enter the checkout, and create the development
environment:

```bash
uv sync --all-groups
uv tool install --editable "$PWD" --force
```

Version 1 is distributed from source only. The wheel contains the native C
worker and Chrome extension sources needed by setup, but it does not contain a
prebuilt privileged binary or signed macOS application.

## Create an organization profile

Copy [the reserved-data example](examples/profile.example.json) to a private
location outside the checkout and replace it with values supplied by your VPN
administrator. Never commit a live profile.

The JSON profile contains non-secret organization policy: display name,
gateway, Entra SAML endpoints, split-DNS rules, and required health checks. It
must not contain passwords, cookies, SAML assertions, tokens, certificate pins,
or credentials. Validate it before setup using an absolute path:

```bash
meraki-openconnect profile validate \
  "$HOME/.config/meraki-openconnect/profile-candidate.json"
```

A Cisco Secure Client XML profile is not a drop-in replacement for this JSON
profile. Its display name and gateway can be useful input, but it normally does
not provide the complete SAML, DNS, and health-check policy required by this
client. Meraki OpenConnect does not currently import Cisco XML.

## Load the Chrome extension

1. Open `chrome://extensions` in the Chrome profile used for VPN login.
2. Enable **Developer mode**.
3. Choose **Load unpacked** and select this checkout's `chrome-extension`
   directory.
4. Copy the 32-character extension ID shown by Chrome.

The extension starts with no gateway access. Setup asks you to grant permission
for the one exact HTTPS gateway in the validated organization profile.

## Run setup

Run setup from a visible Terminal, replacing the candidate path, extension ID,
and Chrome profile directory with your values:

```bash
meraki-openconnect setup \
  "$HOME/.config/meraki-openconnect/profile-candidate.json" \
  --extension-id "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  --chrome-profile-directory "Profile 1"
```

Setup displays the proposed organization policy before changing anything. It
then configures Chrome Native Messaging, requests the exact gateway permission,
captures and verifies the gateway certificate pin before one visible browser
authentication, compiles the native worker, and requests one administrator
authorization to install the fixed helper, worker, root-owned runtime bundle,
policy, and sudoers entry. A changed saved pin requires a separate confirmation
that displays both the previous and newly observed fingerprints.

Certificate pinning in v0.1.0 covers the Python gateway requests and the native
VPN tunnel. Chrome's visible SAML navigation uses Chrome and macOS system CA
validation; the extension cannot apply the saved pin to Chrome's gateway TLS
connection. Exact-origin checks and pin checks before and after browser
authentication detect ordinary certificate changes, but they do not prevent an
attacker with network-path control and another CA-valid gateway certificate from
selectively presenting that certificate only to Chrome. See
[Security Policy](SECURITY.md#browser-tls-trust-boundary) for the complete trust
boundary.

The active profile and machine binding are stored with user-only permissions in
`~/.config/meraki-openconnect/`. The root-owned policy snapshot is installed at
`/Library/PrivilegedHelperTools/io.github.k0nkupa.meraki-openconnect.policy.conf`.
The passwordless helper executes only root-owned runtime files under
`/Library/PrivilegedHelperTools`; it never loads or executes Homebrew files.
Reconfiguring another
organization requires running setup again explicitly; there is no runtime
profile switch.

## Diagnose and connect

These commands are safe, secret-free status probes:

```bash
meraki-openconnect doctor --json
meraki-openconnect status --json
```

Run the tunnel in the foreground:

```bash
meraki-openconnect connect
```

After the tunnel connects, every required route, DNS, and TCP check in the
profile must pass. From another Terminal, disconnect with:

```bash
meraki-openconnect disconnect
```

The client refuses to start if Cisco Secure Client is already connected, the
Chrome gateway receipt differs from the active profile, or the installed policy
digest no longer matches the profile and certificate pin.

If the saved profile and settings are still valid but the fixed root components
were removed, reinstall only those components from a visible Terminal:

```bash
meraki-openconnect privileged install
```

This command rebuilds the worker from packaged source and requests explicit
administrator authorization.
The installed sudoers policy does not authorize OpenConnect directly, the
native worker directly, arbitrary arguments, or a general root shell.

## Build the menu-bar app

Open
`macos/MerakiOpenConnect/MerakiOpenConnect.xcodeproj`, select the
`MerakiOpenConnect` scheme and **My Mac**, then choose **Sign to Run Locally**
when Xcode prompts.

The app calls only `~/.local/bin/meraki-openconnect`, shows the highest-priority
readiness problem, and never invents organization-specific setup commands.
**Quit disconnects** an active tunnel and verifies cleanup before exiting.
Force Quit makes no cleanup guarantee.

## Certificate pin changes

A changed gateway certificate is treated as a security event, not an automatic
update. Independently verify the new certificate with your VPN administrator,
then rerun the complete setup command. Do not edit `settings.json` or the
root-owned policy by hand.

## Uninstall

Disconnect first, then remove the privileged components using the configured
profile:

```bash
meraki-openconnect disconnect
meraki-openconnect privileged uninstall
```

After that succeeds, you may remove the unpacked Chrome extension, the native
host manifest under Chrome's `NativeMessagingHosts` directory, the wrapper in
`~/.local/share/meraki-openconnect/`, the configuration directory
`~/.config/meraki-openconnect/`, and the editable `uv` tool. Review each path
before deleting it; the CLI intentionally does not perform broad recursive
cleanup.

## Development

Run the complete local gates:

```bash
uv run pytest -q
make -C native clean test
xcodebuild -project macos/MerakiOpenConnect/MerakiOpenConnect.xcodeproj \
  -scheme MerakiOpenConnect -destination 'platform=macOS' \
  -derivedDataPath macos/MerakiOpenConnect/.derivedData test
uv build
scripts/check-public-tree.sh
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) before
submitting changes or security reports.

## License

Meraki OpenConnect is licensed under the
[GNU General Public License v3.0 or later](LICENSE).
The bundled `vpnc-script` retains its upstream GPL-2.0-or-later notice and is
distributed under GPL-3.0-or-later as part of this project.
