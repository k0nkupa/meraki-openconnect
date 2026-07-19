"""Launch the configured Chrome profile without automation debugging."""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit

from meraki_openconnect.settings import (
    SettingsError,
    validate_chrome_profile_directory,
)


_EXTENSION_ID = re.compile(r"[a-p]{32}\Z")
CHROME_BINARY = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
CHROME_PROFILE = (
    Path.home()
    / "Library"
    / "Application Support"
    / "Google"
    / "Chrome"
    / "Profile 1"
)
CHROME_USER_DATA = CHROME_PROFILE.parent


class ChromeLaunchError(ValueError):
    """The configured Chrome extension start page is not safe to open."""


def chrome_installation_status(
    *,
    binary: Path = CHROME_BINARY,
    profile: Path | None = None,
    profile_directory: str | None = None,
) -> tuple[bool, bool]:
    """Report whether Chrome and the configured profile directory exist."""
    if profile is None:
        if profile_directory is None:
            profile = CHROME_PROFILE
        else:
            try:
                name = validate_chrome_profile_directory(profile_directory)
            except SettingsError:
                return binary.is_file() and os.access(binary, os.X_OK), False
            profile = CHROME_USER_DATA / name
    chrome_available = binary.is_file() and os.access(binary, os.X_OK)
    return chrome_available, chrome_available and profile.is_dir()


def build_extension_start_url(extension_id: str) -> str:
    if not _EXTENSION_ID.fullmatch(extension_id):
        raise ChromeLaunchError("Chrome extension ID must contain 32 letters a-p")
    return f"chrome-extension://{extension_id}/start.html"


def build_extension_setup_url(extension_id: str) -> str:
    if not _EXTENSION_ID.fullmatch(extension_id):
        raise ChromeLaunchError("Chrome extension ID must contain 32 letters a-p")
    return f"chrome-extension://{extension_id}/setup.html"


def open_in_chrome_profile(
    url: str,
    profile_directory: str,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    try:
        profile = validate_chrome_profile_directory(profile_directory)
    except SettingsError as exc:
        raise ChromeLaunchError("Chrome profile directory is invalid") from exc
    parsed = urlsplit(url)
    if (
        parsed.scheme != "chrome-extension"
        or not _EXTENSION_ID.fullmatch(parsed.hostname or "")
        or parsed.path not in {"/start.html", "/setup.html"}
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ChromeLaunchError("only a configured extension page may be opened")
    runner(
        [
            str(CHROME_BINARY),
            f"--profile-directory={profile}",
            url,
        ],
        check=True,
    )


def open_in_moc_profile(
    url: str,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    open_in_chrome_profile(url, "Profile 1", runner)
