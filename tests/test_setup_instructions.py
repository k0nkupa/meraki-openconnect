from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).parents[1]
INSTRUCTIONS = ROOT / "setup-instructions" / "setup.md"
RAW_INSTRUCTIONS_URL = (
    "https://raw.githubusercontent.com/k0nkupa/meraki-openconnect/"
    "main/setup-instructions/setup.md"
)


def test_agent_setup_instructions_cover_commands_and_safety_boundaries() -> None:
    text = INSTRUCTIONS.read_text()

    required_fragments = (
        "uname -m",
        "sw_vers -productVersion",
        "brew install python@3.13 uv openconnect",
        'uv tool install --editable "$PWD" --force',
        "meraki-openconnect profile validate",
        "chrome://extensions",
        "meraki-openconnect setup",
        '--extension-id "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"',
        '--chrome-profile-directory "Profile 1"',
        "meraki-openconnect doctor --json",
        "Do not connect the VPN automatically",
        "Cisco Secure Client XML is not a complete organization profile",
        "Do not ask the user to paste",
        "certificate pin",
        "administrator authorization",
    )
    for fragment in required_fragments:
        assert fragment in text, fragment


def test_agent_setup_instructions_do_not_recommend_unsafe_shortcuts() -> None:
    text = INSTRUCTIONS.read_text()

    forbidden_fragments = (
        "curl | sh",
        "curl -k",
        "--no-check-certificate",
        "sudo -S",
        "git reset --hard",
        "git clean -fd",
        "--no-verify",
    )
    for fragment in forbidden_fragments:
        assert fragment not in text, fragment


def test_readme_exposes_copyable_agent_setup_prompt() -> None:
    readme = (ROOT / "README.md").read_text()

    expected_prompt = (
        "Set up Meraki OpenConnect by following these instructions:\n"
        f"{RAW_INSTRUCTIONS_URL}"
    )
    assert expected_prompt in readme
    assert INSTRUCTIONS.is_file()
