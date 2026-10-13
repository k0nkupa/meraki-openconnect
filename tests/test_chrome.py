import subprocess

import pytest

from meraki_openconnect.chrome import (
    ChromeLaunchError,
    build_extension_start_url,
    build_extension_setup_url,
    chrome_installation_status,
    open_in_chrome,
)


def test_chrome_installation_status_requires_only_an_executable(tmp_path):
    binary = tmp_path / "Google Chrome"
    assert chrome_installation_status(binary=binary) is False
    binary.write_text("")
    binary.chmod(0o600)
    assert chrome_installation_status(binary=binary) is False
    binary.chmod(0o700)
    assert chrome_installation_status(binary=binary) is True


def test_builds_extension_urls_without_callback_capability():
    extension_id = "abcdefghijklmnopabcdefghijklmnop"
    assert build_extension_start_url(extension_id) == f"chrome-extension://{extension_id}/start.html"
    assert build_extension_setup_url(extension_id) == f"chrome-extension://{extension_id}/setup.html"


@pytest.mark.parametrize("extension_id", ["wrong", "A" * 32, "abcdefghijklmnopabcdefghijklmnopx"])
def test_rejects_invalid_extension_id(extension_id: str):
    with pytest.raises(ChromeLaunchError):
        build_extension_start_url(extension_id)


@pytest.mark.parametrize("page", ["start.html", "setup.html"])
def test_opens_extension_page_through_macos_without_profile_or_browser_exit_wait(page):
    calls = []

    def runner(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0)

    url = f"chrome-extension://abcdefghijklmnopabcdefghijklmnop/{page}"
    open_in_chrome(url, runner)
    assert calls == [
        (["/usr/bin/open", "-a", "/Applications/Google Chrome.app", url],
         {"check": True, "timeout": 10})
    ]


@pytest.mark.parametrize("url", [
    "https://vpn.example.com",
    "chrome-extension://abcdefghijklmnopabcdefghijklmnop/other.html",
    "chrome-extension://abcdefghijklmnopabcdefghijklmnop/setup.html?x=1",
    "chrome-extension://user@abcdefghijklmnopabcdefghijklmnop/start.html",
])
def test_launcher_rejects_unsafe_urls(url: str):
    calls = []
    with pytest.raises(ChromeLaunchError):
        open_in_chrome(url, lambda *args, **kwargs: calls.append(args))
    assert calls == []


@pytest.mark.parametrize("failure", [
    OSError("private path"), subprocess.CalledProcessError(1, ["open"]),
    subprocess.TimeoutExpired(["open"], 10),
])
def test_launch_failure_has_browser_guidance_without_private_details(failure):
    def runner(*args, **kwargs):
        raise failure

    with pytest.raises(ChromeLaunchError, match="Google Chrome could not be opened"):
        open_in_chrome(build_extension_start_url("a" * 32), runner)
