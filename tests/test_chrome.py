import subprocess

import pytest

from meraki_openconnect.chrome import (
    ChromeLaunchError,
    build_extension_start_url,
    build_extension_setup_url,
    chrome_installation_status,
    open_in_chrome_profile,
    open_in_moc_profile,
)


def test_chrome_installation_status_requires_binary_and_profile(tmp_path):
    binary = tmp_path / "Google Chrome"
    profile = tmp_path / "Profile 1"
    binary.write_text("")
    binary.chmod(0o700)
    profile.mkdir()

    assert chrome_installation_status(binary=binary, profile=profile) == (True, True)
    profile.rmdir()
    assert chrome_installation_status(binary=binary, profile=profile) == (True, False)


def test_builds_extension_url_without_callback_capability():
    url = build_extension_start_url("abcdefghijklmnopabcdefghijklmnop")

    assert url == "chrome-extension://abcdefghijklmnopabcdefghijklmnop/start.html"
    assert "127.0.0.1" not in url
    assert "nonce" not in url
    assert build_extension_setup_url(
        "abcdefghijklmnopabcdefghijklmnop"
    ) == "chrome-extension://abcdefghijklmnopabcdefghijklmnop/setup.html"


@pytest.mark.parametrize(
    "extension_id",
    ["wrong", "A" * 32, "abcdefghijklmnopabcdefghijklmnopx"],
)
def test_rejects_invalid_extension_id(extension_id: str):
    with pytest.raises(ChromeLaunchError):
        build_extension_start_url(extension_id)


def test_opens_only_profile_1_without_a_shell():
    calls: list[tuple[list[str], dict[str, object]]] = []

    def runner(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0)

    open_in_moc_profile("chrome-extension://abcdefghijklmnopabcdefghijklmnop/start.html", runner)

    assert calls == [
        (
            [
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                "--profile-directory=Profile 1",
                "chrome-extension://abcdefghijklmnopabcdefghijklmnop/start.html",
            ],
            {"check": True},
        )
    ]


def test_opens_configured_extension_page_in_validated_profile_without_shell():
    calls: list[tuple[list[str], dict[str, object]]] = []

    def runner(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0)

    open_in_chrome_profile(
        "chrome-extension://abcdefghijklmnopabcdefghijklmnop/setup.html",
        "Work Profile",
        runner,
    )

    assert calls == [
        (
            [
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                "--profile-directory=Work Profile",
                "chrome-extension://abcdefghijklmnopabcdefghijklmnop/setup.html",
            ],
            {"check": True},
        )
    ]


@pytest.mark.parametrize(
    ("url", "profile"),
    [
        ("https://vpn.example.com", "Profile 1"),
        ("chrome-extension://abcdefghijklmnopabcdefghijklmnop/other.html", "Profile 1"),
        ("chrome-extension://abcdefghijklmnopabcdefghijklmnop/setup.html?x=1", "Profile 1"),
        ("chrome-extension://abcdefghijklmnopabcdefghijklmnop/setup.html", "../Default"),
    ],
)
def test_profile_driven_launcher_rejects_unsafe_input(url: str, profile: str) -> None:
    with pytest.raises(ChromeLaunchError):
        open_in_chrome_profile(url, profile)
