# AI Agent Setup Prompt Design

## Goal

Give prospective users a short prompt they can copy into a capable AI coding
agent to install and configure Meraki OpenConnect from the public repository.
The prompt delegates detailed work to a versioned, reviewable instruction file
in this repository rather than embedding a long setup procedure on another
site.

## User-facing entry point

Add a README section that presents this copyable prompt:

> Set up Meraki OpenConnect by following these instructions:
> https://raw.githubusercontent.com/k0nkupa/meraki-openconnect/main/setup-instructions/setup.md

The linked file will live at `setup-instructions/setup.md`. Keeping the short
prompt and detailed instructions separate makes the setup workflow easy to
copy while allowing corrections to be reviewed and published with the source.

## Agent workflow

The detailed instructions will tell the agent to:

1. Read the repository README and security policy before acting.
2. Confirm that the machine is an Apple Silicon Mac running macOS 13 or newer.
3. Inspect prerequisites and current installation state before changing it.
4. Clone or update the official public repository without overwriting unrelated
   work, then install the documented Homebrew and source dependencies.
5. Help the user create a private organization profile outside the checkout,
   using values supplied by the user or their VPN administrator.
6. Validate the profile, guide the user through loading the unpacked Chrome
   extension, and collect the extension ID and Chrome profile directory.
7. Run the documented setup command from a visible terminal.
8. Run secret-free diagnostics and report the exact final readiness state.
9. Optionally guide the user through building the local menu-bar application
   only after the core CLI setup is ready.

## Human confirmation boundaries

The agent must pause rather than automate or infer:

- missing gateway, Entra SAML, split-DNS, route, DNS, TCP health-check, or Chrome
  profile values;
- Chrome extension loading and gateway permission approval;
- visible Microsoft Entra authentication, MFA, consent, or remediation;
- certificate-pin changes, which require independent verification with the VPN
  administrator;
- macOS administrator authorization for privileged installation; and
- replacement or removal of an existing configured installation.

The agent must not ask the user to paste passwords, cookies, SAML assertions,
VPN tokens, recovery codes, or other credentials into the chat. It must not
treat a Cisco Secure Client XML profile as a complete Meraki OpenConnect
profile or invent missing organization policy.

## Safety and failure handling

The instructions will require read-only discovery before installation and
explicit reporting before every privileged or security-sensitive step. The
agent must preserve unrelated files, avoid destructive cleanup, and follow the
repository's documented commands rather than downloading or executing
unreviewed third-party scripts.

Unsupported hardware, operating systems, identity providers, browsers, or VPN
topologies must be reported as blockers. A failed setup or diagnostic must be
reported with the failed command and a sanitized error summary; the agent must
not weaken certificate, extension, policy, or health checks to make setup pass.

## Completion receipt

The agent may call the installation ready only when
`meraki-openconnect doctor --json` exits successfully. Its final response will
separately report:

- prerequisites installed;
- source checkout and CLI installed;
- private organization profile validated;
- Chrome extension and native messaging configured;
- privileged components installed;
- visible authentication completed;
- diagnostics ready or the exact remaining blocker; and
- whether the optional menu-bar application was built.

Being installed is not equivalent to being configured, authenticated, or ready
to connect.

## Validation

Implementation validation will check that:

- the README prompt contains the correct raw GitHub URL;
- the URL maps to the checked-in instruction file;
- every command and option matches the current README and CLI;
- the instruction file contains no organization-specific values or secrets;
- public-tree and package tests continue to pass; and
- the instructions never claim readiness without successful diagnostics.
