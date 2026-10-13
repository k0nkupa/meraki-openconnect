"""Open extension pages through Chrome's normal macOS launch behavior."""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit

_EXTENSION_ID = re.compile(r"[a-p]{32}\Z")
CHROME_BINARY = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")


class ChromeLaunchError(ValueError):
    """The configured Chrome extension start page is not safe to open."""


def chrome_installation_status(
    *,
    binary: Path = CHROME_BINARY,
) -> bool:
    """Report whether Chrome is installed and executable."""
    return binary.is_file() and os.access(binary, os.X_OK)


def build_extension_start_url(extension_id: str) -> str:
    if not _EXTENSION_ID.fullmatch(extension_id):
        raise ChromeLaunchError("Chrome extension ID must contain 32 letters a-p")
    return f"chrome-extension://{extension_id}/start.html"


def build_extension_setup_url(extension_id: str) -> str:
    if not _EXTENSION_ID.fullmatch(extension_id):
        raise ChromeLaunchError("Chrome extension ID must contain 32 letters a-p")
    return f"chrome-extension://{extension_id}/setup.html"


def open_in_chrome(
    url: str,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
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
    try:
        runner(
            ["/usr/bin/open", "-a", "/Applications/Google Chrome.app", url],
            check=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ChromeLaunchError("Google Chrome could not be opened") from exc
