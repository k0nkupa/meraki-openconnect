from __future__ import annotations

import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]


@pytest.fixture(scope="module")
def artifact_names(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[set[str], set[str]]:
    output = tmp_path_factory.mktemp("artifacts")
    subprocess.run(
        ["uv", "build", "--out-dir", str(output)],
        cwd=ROOT,
        check=True,
    )
    source_archive = next(output.glob("*.tar.gz"))
    wheel = next(output.glob("*.whl"))
    with tarfile.open(source_archive, "r:gz") as archive:
        source_names = set(archive.getnames())
    with zipfile.ZipFile(wheel) as archive:
        wheel_names = set(archive.namelist())
    return source_names, wheel_names


def _contains(names: set[str], suffix: str) -> bool:
    return any(name.endswith(suffix) for name in names)


def test_source_artifacts_include_runtime_native_and_extension_sources(
    artifact_names: tuple[set[str], set[str]],
) -> None:
    source_names, wheel_names = artifact_names

    source_required = (
        "/native/Makefile",
        "/native/protocol.c",
        "/native/protocol.h",
        "/native/policy.c",
        "/native/policy.h",
        "/native/worker.c",
        "/native/worker_io.c",
        "/native/worker_io.h",
        "/native/vpnc-script",
        "/chrome-extension/manifest.json",
        "/chrome-extension/background.js",
        "/chrome-extension/setup.html",
        "/chrome-extension/setup.js",
        "/chrome-extension/start.html",
        "/chrome-extension/start.js",
        "/README.md",
        "/SECURITY.md",
        "/CONTRIBUTING.md",
        "/LICENSE",
    )
    wheel_required = tuple(
        f"meraki_openconnect/_resources{suffix}"
        for suffix in source_required[:15]
    )

    for suffix in source_required:
        assert _contains(source_names, suffix), suffix
    for suffix in wheel_required:
        assert _contains(wheel_names, suffix), suffix


def test_source_artifacts_exclude_private_and_generated_state(
    artifact_names: tuple[set[str], set[str]],
) -> None:
    source_names, wheel_names = artifact_names
    all_names = source_names | wheel_names

    forbidden = (
        "profile.json",
        "settings.json",
        "policy.conf",
        "graphify-out",
        ".derivedData",
        "docs/superpowers/plans",
        ".env",
        ".pem",
        ".key",
    )
    for fragment in forbidden:
        assert not any(fragment in name for name in all_names), fragment
