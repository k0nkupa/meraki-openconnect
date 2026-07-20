# Set up Meraki Connect

You are installing and configuring Meraki Connect from its official public
repository on the user's Mac. Work interactively and evidence-first. Explain
what you found and obtain confirmation before installing packages, changing an
existing installation, opening authentication, or requesting administrator
authorization.

Meraki Connect is an unofficial, source-first client. It supports only an
Apple Silicon Mac running macOS 13 or newer, one configured organization,
Meraki/AnyConnect-compatible SSL VPN on port 443, Microsoft Entra SAML, and
Google Chrome. Stop and report the mismatch if the user's environment is
outside that scope.

## Safety rules

- Read the checked-out `README.md` and `SECURITY.md` completely before making
  changes. Treat them and the current source as the authority if this document
  has drifted.
- Start with read-only discovery. Preserve unrelated files and do not overwrite
  or update a dirty checkout.
- Do not ask the user to paste passwords, MFA values, cookies, SAML assertions,
  VPN tokens, recovery codes, certificate pins, or other credentials into chat.
- Obtain organization policy only from the user or their VPN administrator.
  Never guess missing values.
- Cisco Secure Client XML is not a complete organization profile and must not
  be treated as one.
- Keep the live organization profile outside the repository. Never commit it or
  copy its private network values into logs, issues, or the final report.
- Do not bypass certificate validation, extension permission checks, root-owned
  policy checks, health checks, or repository hooks.
- A changed certificate pin is a security event. Stop and ask the user to
  independently verify the new certificate with their VPN administrator.
- Visible Microsoft Entra login, MFA, consent, Chrome extension approval, and
  macOS administrator authorization belong to the user. Do not simulate,
  suppress, capture, or work around them.
- Do not remove or replace an existing configured installation without showing
  the user what exists and receiving explicit approval.
- Do not connect the VPN automatically. Finish at a verified ready-to-connect
  state unless the user separately asks to connect.

## 1. Verify the supported Mac

Run these read-only checks:

```bash
uname -m
sw_vers -productVersion
command -v git || true
command -v brew || true
xcode-select -p 2>/dev/null || true
test -d "/Applications/Google Chrome.app" && echo "Google Chrome found" || true
command -v uv || true
command -v openconnect || true
command -v meraki-openconnect || true
```

Require `arm64` and macOS major version 13 or newer. Report every missing
prerequisite before changing the machine. Xcode, Google Chrome, Homebrew,
Python 3.13, `uv`, and OpenConnect are required by the project.

If Homebrew, Xcode, or Google Chrome is absent, point the user to the official
provider and pause for them to install it. Do not fetch or execute an unofficial
bootstrap script.

## 2. Resolve the source checkout safely

Ask the user where they want the checkout. If the selected directory does not
exist, show the destination and obtain approval before cloning:

```bash
git clone https://github.com/k0nkupa/meraki-openconnect.git <chosen-directory>
cd <chosen-directory>
```

If it already exists, enter it and inspect it without changing it:

```bash
git remote get-url origin
git status --short --branch
git rev-parse --show-toplevel
```

Require the origin to resolve to `k0nkupa/meraki-openconnect`. If the checkout
has local changes, do not pull, reset, clean, overwrite, or discard them. Ask
the user whether to use the current checkout, choose another directory, or
handle their changes first. If the user requests an update, fetch first and
show the exact branch and divergence before proposing a fast-forward.

Read the repository instructions before continuing:

```bash
sed -n '1,260p' README.md
sed -n '1,240p' SECURITY.md
```

## 3. Install source prerequisites

From the repository root, show the user this Homebrew change and obtain
approval before running it:

```bash
brew install python@3.13 uv openconnect
```

Then create the repository environment and install the editable CLI from this
exact checkout:

```bash
uv sync --all-groups
uv tool install --editable "$PWD" --force
command -v meraki-openconnect
meraki-openconnect --help
```

If any command fails, stop and report the command, exit status, and a sanitized
error summary. Do not substitute an unrelated package or lower a security
setting to continue.

## 4. Create the private organization profile

Review `examples/profile.example.json` with the user. The required values must
come from the user or their VPN administrator:

- organization display name;
- gateway hostname;
- Microsoft Entra identity-provider host, issuer, and destination;
- SAML login and final paths and the VPN token cookie name;
- optional split-DNS domains and nameservers; and
- required route, DNS, and TCP health checks that prove the intended private
  resources are reachable.

Do not ask the user to disclose these private values in chat if the agent's
conversation is externally stored. Help them edit the file locally instead.
Copy the reserved-data example to a private candidate path outside the checkout:

```bash
mkdir -p "$HOME/.config/meraki-openconnect"
cp examples/profile.example.json \
  "$HOME/.config/meraki-openconnect/profile-candidate.json"
chmod 600 "$HOME/.config/meraki-openconnect/profile-candidate.json"
```

Pause while the user replaces every example value locally. Check that the
candidate is outside the Git checkout and validate it without printing its
contents:

```bash
meraki-openconnect profile validate \
  "$HOME/.config/meraki-openconnect/profile-candidate.json"
```

Do not continue until validation succeeds. Do not invent missing health checks
or treat a generic successful tunnel as proof that the user's private service
works.

## 5. Load the Chrome extension

Tell the user to perform these steps in the Google Chrome profile they use for
their Microsoft Entra VPN login:

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Select **Load unpacked** and choose this checkout's `chrome-extension`
   directory.
4. Copy the 32-character extension ID shown by Chrome.
5. Identify the Chrome profile directory, such as `Profile 1`, from
   `chrome://version` under **Profile Path**.

The extension begins without gateway access. The setup flow will ask the user
to approve access to the one exact HTTPS gateway in the validated profile.
Validate only the format of the supplied extension ID and profile-directory
name; never guess either value.

## 6. Run interactive setup

Show the complete command with the user's candidate path, extension ID, and
Chrome profile directory. Run it only in a visible interactive terminal that
can open Chrome and present administrator authorization. If the agent terminal
cannot do that, give the command to the user and wait for its result.

```bash
meraki-openconnect setup \
  "$HOME/.config/meraki-openconnect/profile-candidate.json" \
  --extension-id "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  --chrome-profile-directory "Profile 1"
```

Replace only the two example arguments with the values the user confirmed.
Setup displays the proposed policy, requests an explicit `yes`, configures
Chrome Native Messaging, requests the exact gateway permission, captures and
verifies the gateway certificate pin, opens one visible Entra SAML flow,
builds the native worker, and requests administrator authorization for the
fixed privileged components.

The user must personally handle Chrome permission, Entra sign-in, MFA, consent,
security remediation, certificate-change verification, and the macOS
administrator prompt. Do not request those secrets or approvals through chat.
If setup is cancelled or incomplete, report that state and stop.

## 7. Verify readiness

Run the secret-free probes:

```bash
meraki-openconnect doctor --json
meraki-openconnect status --json
```

`doctor --json` must exit successfully before calling the installation ready.
Do not paste organization values, raw authentication output, or sensitive logs
into the final report. A successful setup message alone is not sufficient.

Do not run `meraki-openconnect connect` as part of installation. Tell the user
that they can explicitly start the foreground tunnel later with:

```bash
meraki-openconnect connect
```

## 8. Offer the optional menu-bar app

Only after core diagnostics pass, ask whether the user wants to build the local
unsigned menu-bar application. If they agree, follow the current README: open
`macos/MerakiOpenConnect/MerakiOpenConnect.xcodeproj`, select the
`MerakiOpenConnect` scheme and **My Mac**, and choose **Sign to Run Locally**
when Xcode prompts. Do not describe the application as signed, notarized, or
automatically updated.

## Final receipt

Report each state separately:

- supported Mac verified;
- prerequisites installed or already present;
- official source checkout and exact branch/commit used;
- CLI installed from that checkout;
- private organization profile validated, without revealing its values;
- Chrome extension and Native Messaging configured;
- privileged components installed;
- visible authentication completed;
- `doctor --json` ready, or the exact remaining blocker;
- VPN left disconnected unless the user separately requested otherwise; and
- optional menu-bar application built or skipped.

Installed, configured, authenticated, and ready to connect are different
states. Report only what the commands actually verified.
