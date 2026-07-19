# Contributing

Contributions should preserve the deliberately narrow version 1 scope: Apple
Silicon macOS, one organization per Mac, Meraki/AnyConnect-compatible HTTPS
gateways, Microsoft Entra SAML through Chrome, and foreground lifecycle
ownership.

Before opening a change:

1. Use reserved domains and addresses from `example.com`, RFC 5737, and RFC
   3849. Never copy a live organization profile or operational log into a test,
   fixture, issue, commit, or pull request.
2. Add or update the closest relevant tests. Security-sensitive behavior should
   be developed test-first and fail closed for missing or unknown input.
3. Run the Python suite, native tests, and public-tree guard. Run the Xcode test
   target for menu application changes and build both Python artifacts for
   packaging changes.
4. Keep organization policy structured and validated. Do not add arbitrary
   scripts, shell commands, OpenConnect arguments, filesystem paths, background
   daemons, automatic authentication retries, or implicit profile switching.

The standard gates are:

```bash
uv run pytest -q
make -C native clean test
xcodebuild -project macos/MerakiOpenConnect/MerakiOpenConnect.xcodeproj \
  -scheme MerakiOpenConnect -destination 'platform=macOS' \
  -derivedDataPath macos/MerakiOpenConnect/.derivedData test
uv build
scripts/check-public-tree.sh
git diff --check
```

Report security concerns using [SECURITY.md](SECURITY.md), not a public issue.
