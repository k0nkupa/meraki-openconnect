# Repository Guidelines

## Project Structure & Module Organization

`src/meraki_openconnect/` contains the Python 3.13 CLI, setup, SAML, profile, readiness, and tunnel logic. Python tests mirror those modules under `tests/` as `test_<module>.py`. The privileged OpenConnect worker and its C tests live in `native/`; Chrome extension sources are in `chrome-extension/`. The Swift menu-bar app and XCTest targets are under `macos/MerakiOpenConnect/`. Use `examples/profile.example.json` only as reserved-data documentation, and keep operational profiles outside the checkout.

## Build, Test, and Development Commands

- `uv sync --all-groups`: create the locked Python development environment.
- `uv run pytest -q`: run the complete Python suite; target one file with `uv run pytest -q tests/test_profile.py`.
- `make -C native clean test`: rebuild the C worker with strict warnings and run protocol, policy, and smoke tests.
- `node --check chrome-extension/background.js`: syntax-check the extension background script.
- `xcodebuild -project macos/MerakiOpenConnect/MerakiOpenConnect.xcodeproj -scheme MerakiOpenConnect -destination 'platform=macOS' -derivedDataPath macos/MerakiOpenConnect/.derivedData test`: run macOS app tests.
- `uv build`: build wheel and source distributions.
- `scripts/check-public-tree.sh && git diff --check`: detect private/generated content and whitespace errors.

## Coding Style & Naming Conventions

Follow nearby code: four-space indentation in Python and Swift, two spaces in JavaScript, and the existing C style. Use `snake_case` for Python functions/modules, `PascalCase` for Python data types and Swift types, and descriptive `test_<behavior>` names. Keep type annotations on Python interfaces and preserve immutable/fail-closed policy models. No formatter or linter is configured; avoid unrelated reformatting and rely on compiler warnings, tests, and `git diff --check`.

## Testing Guidelines

Add or update the closest test for every behavior change. Security-sensitive paths should be developed test-first and reject missing, unknown, or malformed input. Run all Python and native gates for shared policy, serialization, packaging, or privileged-worker changes; add Xcode tests for menu-app behavior. Use only `example.com`, RFC 5737 IPv4, and RFC 3849 IPv6 test data.

## Commit & Pull Request Guidelines

Recent history uses concise Conventional Commit subjects such as `feat:`, `fix:`, `test:`, `ci:`, and `docs:`. Keep commits focused and imperative. Pull requests should explain scope and security impact, list exact validation run, link relevant issues, and include screenshots for visible menu-app changes. Never place live profiles, private topology, tokens, certificate pins, authentication logs, or generated build state in commits or PRs; report vulnerabilities privately as described in `SECURITY.md`.
