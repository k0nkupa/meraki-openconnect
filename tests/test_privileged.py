from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import meraki_openconnect.privileged as privileged
from meraki_openconnect.profile import OrganizationProfile
from meraki_openconnect.privileged import (
    ALLOWED_OPERATIONS,
    NATIVE_PATH,
    POLICY_PATH,
    PrivilegedError,
    build_install_plan,
    install_privileged,
    installed_policy_digest,
    uninstall_privileged,
)
from meraki_openconnect.root_policy import render_root_policy
from meraki_openconnect.settings import MachineSettings


PROFILE = OrganizationProfile.load(
    Path(__file__).parents[1] / "examples" / "profile.example.json"
)
SETTINGS = MachineSettings(
    schema_version=1,
    chrome_profile_directory="Profile 1",
    extension_id="a" * 32,
    extension_gateway_origin="https://vpn.example.com",
    extension_profile_digest=PROFILE.profile_digest(),
    server_cert_pin="sha1:" + "A" * 40,
    installed_policy_digest="sha256:" + "1" * 64,
)


def _multi_dns_profile(tmp_path: Path) -> OrganizationProfile:
    payload = json.loads(PROFILE.canonical_bytes())
    payload["split_dns"] = [
        {
            "domain": "internal.example.com",
            "nameservers": ["192.0.2.53", "2001:db8::53"],
        },
        {"domain": "corp.example.net", "nameservers": ["198.51.100.53"]},
    ]
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(payload))
    return OrganizationProfile.load(path)


def _shell_function(script: str, name: str) -> str:
    start = script.index(f"{name}() {{")
    return script[start : script.index("\n}", start) + 2]


def test_allowed_operations_are_exact() -> None:
    assert ALLOWED_OPERATIONS == (
        "vpn-connect",
        "vpn-disconnect",
        "dns-connect",
        "dns-disconnect",
        "policy-digest",
    )


def test_privileged_component_requires_root_owned_fixed_executable() -> None:
    def reader(path: str, *, follow_symlinks: bool) -> SimpleNamespace:
        assert follow_symlinks is False
        mode = (
            stat.S_IFREG | 0o755
            if path == privileged.HELPER_PATH
            else stat.S_IFDIR | 0o755
        )
        return SimpleNamespace(st_mode=mode, st_uid=0)

    assert privileged.privileged_component_installed(
        privileged.HELPER_PATH,
        stat_reader=reader,
        acl_checker=lambda _path: True,
    )


@pytest.mark.parametrize(
    ("mode", "uid"),
    [
        (stat.S_IFLNK | 0o755, 0),
        (stat.S_IFREG | 0o755, 501),
        (stat.S_IFREG | 0o775, 0),
        (stat.S_IFREG | 0o644, 0),
        (stat.S_IFREG | 0o055, 0),
    ],
)
def test_privileged_component_rejects_unsafe_metadata(mode: int, uid: int) -> None:
    def reader(path: str, *, follow_symlinks: bool) -> SimpleNamespace:
        assert follow_symlinks is False
        if path == privileged.HELPER_PATH:
            return SimpleNamespace(st_mode=mode, st_uid=uid)
        return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)

    assert not privileged.privileged_component_installed(
        privileged.HELPER_PATH,
        stat_reader=reader,
        acl_checker=lambda _path: True,
    )


@pytest.mark.parametrize(
    "unsafe_ancestor", ["/Library", "/Library/PrivilegedHelperTools"]
)
def test_privileged_component_rejects_user_writable_ancestor(
    unsafe_ancestor: str,
) -> None:
    def reader(path: str, *, follow_symlinks: bool) -> SimpleNamespace:
        assert follow_symlinks is False
        if path == privileged.HELPER_PATH:
            return SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
        mode = stat.S_IFDIR | (0o777 if path == unsafe_ancestor else 0o755)
        return SimpleNamespace(st_mode=mode, st_uid=0)

    assert not privileged.privileged_component_installed(
        privileged.HELPER_PATH,
        stat_reader=reader,
        acl_checker=lambda _path: True,
    )


def test_privileged_component_rejects_extended_acl() -> None:
    def reader(path: str, *, follow_symlinks: bool) -> SimpleNamespace:
        assert follow_symlinks is False
        mode = (
            stat.S_IFREG | 0o755
            if path == privileged.HELPER_PATH
            else stat.S_IFDIR | 0o755
        )
        return SimpleNamespace(st_mode=mode, st_uid=0)

    assert not privileged.privileged_component_installed(
        privileged.HELPER_PATH,
        stat_reader=reader,
        acl_checker=lambda path: path != privileged.HELPER_PATH,
    )


def test_acl_checker_distinguishes_empty_and_extended_acl(tmp_path: Path) -> None:
    candidate = tmp_path / "root-runtime"
    candidate.write_text("runtime")
    subprocess.run(
        ["/usr/bin/xattr", "-w", "io.github.k0nkupa.test", "present", str(candidate)],
        check=True,
    )

    assert privileged._path_has_no_extended_acl(str(candidate))
    subprocess.run(
        ["/bin/chmod", "+a", "everyone deny write", str(candidate)],
        check=True,
    )
    assert not privileged._path_has_no_extended_acl(str(candidate))


def test_plan_contains_exact_policy_digest_and_sudoers_operations(
    tmp_path: Path,
) -> None:
    profile = _multi_dns_profile(tmp_path)
    settings = replace(
        SETTINGS,
        extension_profile_digest=profile.profile_digest(),
        installed_policy_digest="sha256:" + "2" * 64,
    )
    plan = build_install_plan(profile, settings, "tony")
    rendered = render_root_policy(profile, settings.server_cert_pin)

    assert plan.policy_text == rendered.text
    assert plan.digest == rendered.digest
    assert f"POLICY_DIGEST={rendered.digest}" in plan.helper_text
    assert f"{POLICY_PATH}.meraki-openconnect.$$" in plan.install_script
    for operation in ALLOWED_OPERATIONS:
        assert f"{operation})" in plan.helper_text
        assert f"{privileged.HELPER_PATH} {operation}" in plan.sudoers_text
    assert "*" not in plan.sudoers_text


def test_helper_renders_one_fixed_resolver_per_domain_and_every_nameserver(
    tmp_path: Path,
) -> None:
    profile = _multi_dns_profile(tmp_path)
    settings = replace(
        SETTINGS,
        extension_profile_digest=profile.profile_digest(),
    )
    helper = build_install_plan(profile, settings, "tony").helper_text

    for index, domain in enumerate(("internal.example.com", "corp.example.net")):
        assert f"install_dns_rule_{index}()" in helper
        assert f"cleanup_dns_rule_{index}()" in helper
        assert f"/private/etc/resolver/{domain}" in helper
    for server in ("192.0.2.53", "2001:db8::53", "198.51.100.53"):
        assert f"'nameserver {server}'" in helper
    dns_connect = helper.split("dns_connect() {", 1)[1].split("\n}", 1)[0]
    assert dns_connect.index("verify_tunnel_worker") < dns_connect.index(
        "install_dns_resolvers"
    )
    assert '"$(/usr/bin/readlink /etc)" = "private/etc"' in helper
    assert "[ ! -L /private/etc/resolver ]" in helper
    assert "[ ! -L \"$RESOLVER\" ]" in helper
    assert "mv -f \"$TEMP\" \"$RESOLVER\"" in helper
    assert helper.index("rollback_dns_rule_1 ||") < helper.index(
        "rollback_dns_rule_0 ||"
    )
    assert "if rollback_dns_resolvers; then DNS_CONNECT_STATUS=1; else DNS_CONNECT_STATUS=2; fi" in helper
    assert "commit_dns_resolvers" in dns_connect


def test_dns_connect_signal_forces_failure_and_rolls_back(
    tmp_path: Path,
) -> None:
    helper = build_install_plan(PROFILE, SETTINGS, "tony").helper_text
    dns_connect = _shell_function(helper, "dns_connect")
    dns_connect_exit = _shell_function(helper, "dns_connect_exit")
    dns_connect_signal = _shell_function(helper, "dns_connect_signal")
    marker = tmp_path / "rolled-back"
    script = f"""#!/bin/sh
set -eu
verify_tunnel_worker() {{ :; }}
install_dns_resolvers() {{ /bin/kill -TERM $$; }}
commit_dns_resolvers() {{ :; }}
flush_dns() {{ :; }}
rollback_dns_resolvers() {{ : > "$MARKER"; }}
{dns_connect_exit}
{dns_connect_signal}
{dns_connect}
dns_connect
"""

    result = subprocess.run(
        ["/bin/sh"],
        input=script,
        check=False,
        text=True,
        capture_output=True,
        env={**os.environ, "MARKER": str(marker)},
    )

    assert result.returncode == 1
    assert marker.exists()


def test_dns_connect_reports_distinct_status_when_rollback_fails() -> None:
    helper = build_install_plan(PROFILE, SETTINGS, "tony").helper_text
    functions = "\n".join(
        _shell_function(helper, name)
        for name in ("dns_connect_exit", "dns_connect_signal", "dns_connect")
    )
    script = f"""#!/bin/sh
set -eu
verify_tunnel_worker() {{ :; }}
install_dns_resolvers() {{ return 1; }}
commit_dns_resolvers() {{ :; }}
flush_dns() {{ :; }}
rollback_dns_resolvers() {{ return 1; }}
{functions}
dns_connect
"""

    result = subprocess.run(
        ["/bin/sh"], input=script, check=False, text=True, capture_output=True
    )

    assert result.returncode == 2


def test_dns_signal_after_logical_commit_never_rolls_back_committed_rules(
    tmp_path: Path,
) -> None:
    helper = build_install_plan(PROFILE, SETTINGS, "tony").helper_text
    functions = "\n".join(
        _shell_function(helper, name)
        for name in ("dns_connect_exit", "dns_connect_signal", "dns_connect")
    )
    marker = tmp_path / "rolled-back"
    script = f"""#!/bin/sh
set -eu
verify_tunnel_worker() {{ :; }}
install_dns_resolvers() {{ :; }}
commit_dns_resolvers() {{ DNS_COMMITTED=1; /bin/kill -TERM $$; }}
flush_dns() {{ :; }}
rollback_dns_resolvers() {{ : > "$MARKER"; }}
{functions}
dns_connect
"""

    result = subprocess.run(
        ["/bin/sh"],
        input=script,
        check=False,
        text=True,
        capture_output=True,
        env={**os.environ, "MARKER": str(marker)},
    )

    assert result.returncode == 2
    assert marker.exists() is False
    commit = _shell_function(helper, "commit_dns_resolvers")
    assert "DNS_COMMITTED=1" in commit
    assert "/bin/rm" not in commit
    assert "TOUCHED" not in commit


def test_dns_rollback_preserves_an_earlier_rule_failure(
    tmp_path: Path,
) -> None:
    profile = _multi_dns_profile(tmp_path)
    settings = replace(SETTINGS, extension_profile_digest=profile.profile_digest())
    helper = build_install_plan(profile, settings, "tony").helper_text
    resolver_root = tmp_path / "resolver"
    resolver_root.mkdir()
    for domain in ("internal.example.com", "corp.example.net"):
        (resolver_root / domain).write_text("managed\n")
    fake_rm = tmp_path / "rm"
    fake_rm.write_text(
        "#!/bin/sh\n"
        "case \"$*\" in *corp.example.net*) exit 1 ;; esac\n"
        "exec /bin/rm \"$@\"\n"
    )
    fake_rm.chmod(0o700)
    definitions = helper[
        helper.index("DNS_RULE_0_TOUCHED=0") : helper.index(
            "install_dns_resolvers()"
        )
    ]
    rollback = _shell_function(helper, "rollback_dns_resolvers")
    script = f"""#!/bin/sh
set -u
flush_dns() {{ :; }}
resolver_is_managed() {{ :; }}
{definitions}
{rollback}
DNS_RULE_0_TOUCHED=1
DNS_RULE_1_TOUCHED=1
DNS_RULE_0_HAD_PREVIOUS=0
DNS_RULE_1_HAD_PREVIOUS=0
rollback_dns_resolvers
""".replace("/private/etc/resolver", str(resolver_root)).replace(
        "/bin/rm", str(fake_rm)
    )

    result = subprocess.run(
        ["/bin/sh"], input=script, check=False, text=True, capture_output=True
    )

    assert result.returncode != 0


def test_preexisting_resolver_is_preserved_by_connect_disconnect_and_uninstall(
    tmp_path: Path,
) -> None:
    helper = build_install_plan(PROFILE, SETTINGS, "tony").helper_text
    resolver = tmp_path / "resolver" / "internal.example.com"
    resolver.parent.mkdir()
    original = b"# managed by another VPN\nnameserver 192.0.2.99\n"
    resolver.write_bytes(original)
    install_rule = _shell_function(helper, "install_dns_rule_0")
    cleanup_rule = _shell_function(helper, "cleanup_dns_rule_0")
    support = helper[
        helper.index("resolver_is_managed()") : helper.index(
            "DNS_RULE_0_TOUCHED=0"
        )
    ]
    script = f"""#!/bin/sh
set -eu
die() {{ exit 1; }}
verify_root_file() {{ :; }}
{support}
{install_rule}
{cleanup_rule}
""".replace("/private/etc/resolver", str(resolver.parent))

    for operation in ("install_dns_rule_0", "cleanup_dns_rule_0"):
        result = subprocess.run(
            ["/bin/sh"],
            input=f"{script}\n{operation}\n",
            check=False,
            text=True,
            capture_output=True,
        )
        assert result.returncode != 0
        assert resolver.read_bytes() == original

    uninstall = build_install_plan(PROFILE, SETTINGS, "tony").uninstall_script
    uninstall_cleanup = uninstall[
        uninstall.index("resolver_is_managed()") : uninstall.index(
            f"/bin/rm -f {privileged.HELPER_PATH}"
        )
    ].replace("/private/etc/resolver", str(resolver.parent))
    result = subprocess.run(
        ["/bin/sh"],
        input=f"set -eu\n{uninstall_cleanup}",
        check=False,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0
    assert resolver.read_bytes() == original


def test_helper_has_no_profile_controlled_command_surface(tmp_path: Path) -> None:
    profile = _multi_dns_profile(tmp_path)
    settings = replace(
        SETTINGS,
        extension_profile_digest=profile.profile_digest(),
    )
    helper = build_install_plan(profile, settings, "tony").helper_text

    assert f"NATIVE={NATIVE_PATH}" in helper
    assert 'if "$NATIVE"' in helper
    assert profile.gateway.host not in helper
    assert profile.authentication.login_path not in helper
    assert '[ "$#" -eq 1 ]' in helper
    assert "eval " not in helper
    assert "source " not in helper
    assert "experimental-" not in helper
    assert "--cookie" not in helper
    assert "\nopenconnect " not in helper


def test_helper_verifies_every_fixed_runtime_artifact_before_exec() -> None:
    helper = build_install_plan(PROFILE, SETTINGS, "tony").helper_text
    vpn_connect = helper.split("vpn_connect() {", 1)[1].split("\n}", 1)[0]

    assert f"VPNC={privileged.VPNC_SCRIPT_PATH}" in helper
    assert f"LIBRARY_DIR={privileged.RUNTIME_LIBRARY_PATH}" in helper
    assert f"POLICY={privileged.POLICY_PATH}" in helper
    assert 'verify_root_file "$POLICY"' in helper
    assert "verify_runtime" in vpn_connect
    assert vpn_connect.index("verify_runtime") < vpn_connect.index('if "$NATIVE"')
    assert "/usr/bin/stat -f '%u'" in helper
    assert "/usr/bin/stat -f '%Lp'" in helper
    assert "/bin/ls -lde" in helper
    assert "/usr/bin/wc -l" in helper
    assert '"$ACL_LINES" -eq 1' in helper
    assert '"$LIBRARY_DIR/"*.dylib' in helper
    assert "/opt/homebrew" not in helper


def test_policy_digest_operation_is_read_only() -> None:
    helper = build_install_plan(PROFILE, SETTINGS, "tony").helper_text
    section = helper.split("policy_digest() {", 1)[1].split("\n}", 1)[0]

    assert "verify_runtime" in section
    assert "/usr/bin/printf '%s\\n' \"$POLICY_DIGEST\"" in section
    assert "/bin/rm" not in section
    assert "/usr/bin/install" not in section


def test_installed_policy_digest_runs_only_fixed_read_operation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "sha256:" + "a" * 64
    calls: list[tuple[list[str], dict[str, object]]] = []

    def runner(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, digest + "\n", "ignored")

    monkeypatch.setattr(privileged.subprocess, "run", runner)

    assert installed_policy_digest() == digest
    assert calls == [
        (
            [
                "/usr/bin/sudo",
                "-n",
                privileged.HELPER_PATH,
                "policy-digest",
            ],
            {
                "check": False,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.DEVNULL,
                "text": True,
                "timeout": 5,
            },
        )
    ]


@pytest.mark.parametrize(
    ("returncode", "stdout"),
    [
        (1, ""),
        (0, ""),
        (0, "sha256:" + "A" * 64 + "\n"),
        (0, "sha256:" + "a" * 64),
        (0, "sha256:" + "a" * 64 + "\nextra\n"),
    ],
)
def test_installed_policy_digest_rejects_missing_or_malformed_helper_output(
    monkeypatch: pytest.MonkeyPatch, returncode: int, stdout: str
) -> None:
    monkeypatch.setattr(
        privileged.subprocess,
        "run",
        lambda args, **kwargs: subprocess.CompletedProcess(
            args, returncode, stdout, "secret stderr"
        ),
    )

    assert installed_policy_digest() is None


def test_install_script_validates_first_and_installs_atomically() -> None:
    plan = build_install_plan(PROFILE, SETTINGS, "tony")
    script = plan.install_script

    assert script.index("/usr/sbin/visudo -cf") < script.index(
        "/usr/bin/install -d"
    )
    assert '"$PAYLOAD/meraki-openconnect-native" "$NATIVE_TEMP"' in script
    assert '"$PAYLOAD/policy.conf" "$POLICY_TEMP"' in script
    assert f'/bin/mv -f "$NATIVE_TEMP" {NATIVE_PATH}' in script
    assert f'/bin/mv -f "$POLICY_TEMP" {POLICY_PATH}' in script
    assert script.index(f'/bin/mv -f "$POLICY_TEMP" {POLICY_PATH}') < script.index(
        f'/bin/mv -f "$HELPER_TEMP" {privileged.HELPER_PATH}'
    )
    assert '-m 0755 "$PAYLOAD/meraki-openconnect-root"' in script
    assert '-m 0755 "$PAYLOAD/meraki-openconnect-native"' in script
    assert '-m 0755 "$PAYLOAD/meraki-openconnect-vpnc-script"' in script
    assert '-m 0600 "$PAYLOAD/policy.conf"' in script
    assert '-m 0440 "$PAYLOAD/meraki-openconnect.sudoers"' in script
    assert "mktemp -d /var/tmp/meraki-openconnect-install.XXXXXX" in script
    assert "/opt/homebrew" not in script
    assert "meraki-openconnect-libs" in script
    assert "unsafe archive entry" in script
    assert "/usr/bin/codesign --verify --strict" in script
    assert "/bin/chmod -N" in script
    assert "/bin/chmod -RN" in script


def test_generated_privileged_shell_is_syntactically_valid() -> None:
    plan = build_install_plan(PROFILE, SETTINGS, "tony")

    for script in (plan.helper_text, plan.install_script, plan.uninstall_script):
        subprocess.run(
            ["/bin/sh", "-n"],
            input=script,
            check=True,
            text=True,
            capture_output=True,
        )


def test_helper_secures_resolver_directory_and_files_before_predictable_writes(
    tmp_path: Path,
) -> None:
    profile = _multi_dns_profile(tmp_path)
    settings = replace(SETTINGS, extension_profile_digest=profile.profile_digest())
    helper = build_install_plan(profile, settings, "tony").helper_text

    assert "verify_root_directory /private" in helper
    assert "verify_root_directory /private/etc" in helper
    assert "verify_root_directory /private/etc/resolver" in helper
    assert 'resolver_is_managed "$RESOLVER"' in helper
    assert '/bin/chmod -N "$TEMP"' in helper


def test_vpn_disconnect_attempts_worker_stop_before_reporting_dns_cleanup_failure(
    tmp_path: Path,
) -> None:
    helper = build_install_plan(PROFILE, SETTINGS, "tony").helper_text
    vpn_disconnect = _shell_function(helper, "vpn_disconnect")
    marker = tmp_path / "worker-stopped"
    script = f"""#!/bin/sh
set -eu
stop_vpn_worker() {{ : > "$MARKER"; }}
cleanup_dns_resolvers() {{ return 1; }}
{vpn_disconnect}
vpn_disconnect
"""

    result = subprocess.run(
        ["/bin/sh"],
        input=script,
        check=False,
        text=True,
        capture_output=True,
        env={**os.environ, "MARKER": str(marker)},
    )

    assert result.returncode == 1
    assert marker.exists()
    assert vpn_disconnect.index("stop_vpn_worker") < vpn_disconnect.index(
        "cleanup_dns_resolvers"
    )


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS filesystem contract")
def test_helper_accepts_the_canonical_macos_etc_symlink() -> None:
    assert os.path.islink("/etc")
    assert os.readlink("/etc") == "private/etc"
    assert Path("/etc").resolve() == Path("/private/etc")

    helper = build_install_plan(PROFILE, SETTINGS, "tony").helper_text

    assert "verify_root_directory /etc\n" not in helper
    assert '"$(/usr/bin/readlink /etc)" = "private/etc"' in helper


def test_install_transaction_locks_refuses_tunnel_and_rolls_back() -> None:
    plan = build_install_plan(PROFILE, SETTINGS, "tony")
    install = plan.install_script
    helper = plan.helper_text

    assert f"INSTALL_LOCK={privileged.INSTALL_LOCK_PATH}" in install
    assert "/usr/bin/shlock -f \"$INSTALL_LOCK\" -p $$" in install
    assert f"[ ! -e {privileged.TUNNEL_PID_PATH} ]" in install
    assert "rollback_install" in install
    assert "COMMITTED=0" in install
    assert "COMMITTED=1" in install
    assert install.index("rollback_install") < install.index(
        f'/bin/mv -f "$HELPER_TEMP" {privileged.HELPER_PATH}'
    )
    assert install.index(
        f"if [ -e {privileged.HELPER_PATH} ]; then HELPER_BACKED_UP=1; /bin/mv {privileged.HELPER_PATH}"
    ) < install.index(
        '/usr/bin/install -o root -g wheel -m 0755 "$PAYLOAD/meraki-openconnect-root"'
    )
    assert "ROLLED_BACK=0" in install
    assert "set +e" in install
    vpn_connect = helper.split("vpn_connect() {", 1)[1].split("\n}", 1)[0]
    assert "/usr/bin/shlock" in vpn_connect
    assert vpn_connect.index("shlock") < vpn_connect.index('if "$NATIVE"')
    assert "-m 0755 /var/run/meraki-openconnect" in install
    assert "openconnect.pid" not in install
    assert "experimental.pid" not in install


@pytest.mark.parametrize("failed_move", range(1, 7))
def test_install_backup_failure_restores_every_original_component(
    tmp_path: Path,
    failed_move: int,
) -> None:
    install = build_install_plan(PROFILE, SETTINGS, "tony").install_script
    fragment = install[
        install.index("HELPER_TEMP=") : install.index(
            '/usr/bin/install -o root -g wheel -m 0755 "$PAYLOAD/meraki-openconnect-root"'
        )
    ]
    case_root = tmp_path / f"failure-{failed_move}"
    case_root.mkdir()
    replacements = {
        privileged.HELPER_PATH: case_root / "helper",
        privileged.NATIVE_PATH: case_root / "native",
        privileged.VPNC_SCRIPT_PATH: case_root / "vpnc-script",
        privileged.RUNTIME_LIBRARY_PATH: case_root / "libraries",
        privileged.POLICY_PATH: case_root / "policy",
        privileged.SUDOERS_PATH: case_root / "sudoers",
        privileged.TUNNEL_PID_PATH: case_root / "tunnel.pid",
    }
    for original, replacement in replacements.items():
        fragment = fragment.replace(original, str(replacement))
    originals: dict[Path, bytes] = {}
    for replacement in replacements.values():
        if replacement.name == "tunnel.pid":
            continue
        if replacement.name == "libraries":
            replacement.mkdir()
            marker = replacement / "original.dylib"
            marker.write_bytes(b"original-library")
            originals[marker] = b"original-library"
        else:
            replacement.write_bytes(f"original-{replacement.name}".encode())
            originals[replacement] = replacement.read_bytes()
    fake_mv = case_root / "mv"
    fake_mv.write_text(
        "#!/bin/sh\n"
        "COUNT=0\n"
        "[ ! -f \"$COUNT_FILE\" ] || COUNT=$(/bin/cat \"$COUNT_FILE\")\n"
        "COUNT=$((COUNT + 1))\n"
        "/usr/bin/printf '%s\\n' \"$COUNT\" > \"$COUNT_FILE\"\n"
        "[ \"$COUNT\" -ne \"$FAIL_MOVE\" ] || exit 1\n"
        "exec /bin/mv \"$@\"\n"
    )
    fake_mv.chmod(0o700)
    fragment = fragment.replace("/bin/mv", str(fake_mv))
    payload = case_root / "payload"
    payload.mkdir()
    script = f"""#!/bin/sh
set -eu
PAYLOAD={payload}
INSTALL_LOCK={case_root / "operation.lock"}
{fragment}
"""

    result = subprocess.run(
        ["/bin/sh"],
        input=script,
        check=False,
        text=True,
        capture_output=True,
        env={
            **os.environ,
            "COUNT_FILE": str(case_root / "count"),
            "FAIL_MOVE": str(failed_move),
        },
    )

    assert result.returncode != 0
    for original, content in originals.items():
        assert original.read_bytes() == content


def test_install_command_streams_one_immutable_payload_to_sudo_stdin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[tuple[list[str], dict[str, object]]] = []

    def runner(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append((args, kwargs))
        if args[0] == "/usr/bin/clang":
            Path(args[-1]).write_bytes(b"test-native-binary")
        if args[0] == "/usr/bin/otool":
            target = Path(args[-1])
            return subprocess.CompletedProcess(
                args,
                0,
                f"{target}:\n\t/usr/lib/libSystem.B.dylib "
                "(compatibility version 1.0.0, current version 1.0.0)\n",
                "",
            )
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(privileged.subprocess, "run", runner)

    def bundle(worker: Path, runtime: Path) -> None:
        runtime.mkdir()
        (runtime / "libopenconnect.5.dylib").write_bytes(b"test-library")
        subprocess.run(
            ["/usr/bin/codesign", "--force", "--sign", "-", str(worker)],
            check=True,
        )

    monkeypatch.setattr(privileged, "_bundle_native_runtime", bundle)

    install_privileged(PROFILE, SETTINGS, username="tony")

    assert commands[-1][0] == ["/usr/bin/sudo", "/bin/sh"]
    assert commands[-1][1]["check"] is True
    assert commands[-1][1]["input"].startswith(b"#!/bin/sh\n")
    assert b"policy.conf" in commands[-1][1]["input"]
    assert not any(
        "meraki-openconnect-install-" in argument
        for argument in commands[-1][0]
    )
    assert commands[0][0][0] == "/usr/bin/clang"
    assert any(path.endswith("/worker_io.c") for path in commands[0][0])
    assert any(command[0][0] == "/usr/bin/codesign" for command in commands)
    assert any(command[0][-1] == "--smoke" for command in commands)


def test_runtime_bundle_rewrites_every_homebrew_dependency(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    homebrew = tmp_path / "homebrew"
    source_library = homebrew / "opt" / "openconnect" / "lib" / "libopenconnect.5.dylib"
    transitive_library = homebrew / "opt" / "gnutls" / "lib" / "libgnutls.30.dylib"
    source_library.parent.mkdir(parents=True)
    transitive_library.parent.mkdir(parents=True)
    source_library.write_bytes(b"openconnect")
    transitive_library.write_bytes(b"gnutls")
    worker = tmp_path / "meraki-openconnect-native"
    worker.write_bytes(b"worker")
    commands: list[list[str]] = []
    rewritten: set[Path] = set()

    def runner(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(args)
        if args[0] == "/usr/bin/install_name_tool":
            rewritten.add(Path(args[-1]))
        if args[:2] == ["/usr/bin/otool", "-l"]:
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[:2] == ["/usr/bin/otool", "-L"]:
            target = Path(args[-1])
            if target in rewritten:
                dependency = (
                    f"@executable_path/{privileged.RUNTIME_LIBRARY_DIRECTORY_NAME}/"
                    f"{source_library.name}"
                    if target == worker
                    else f"@loader_path/{target.name}"
                )
                output = f"{target}:\n\t{dependency} (compatibility version 1.0.0, current version 1.0.0)\n"
            elif target == worker:
                output = (
                    f"{target}:\n\t{source_library} "
                    "(compatibility version 1.0.0, current version 1.0.0)\n"
                )
            elif target.name == source_library.name:
                output = (
                    f"{target}:\n\t{source_library} "
                    "(compatibility version 1.0.0, current version 1.0.0)\n"
                    f"\t{transitive_library} "
                    "(compatibility version 1.0.0, current version 1.0.0)\n"
                )
            else:
                output = (
                    f"{target}:\n\t{transitive_library} "
                    "(compatibility version 1.0.0, current version 1.0.0)\n"
                    "\t/usr/lib/libSystem.B.dylib "
                    "(compatibility version 1.0.0, current version 1.0.0)\n"
                )
            return subprocess.CompletedProcess(args, 0, output, "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(privileged, "HOMEBREW_PREFIX", homebrew)
    monkeypatch.setattr(privileged.subprocess, "run", runner)

    runtime = tmp_path / "runtime"
    privileged._bundle_native_runtime(worker, runtime)

    assert sorted(path.name for path in runtime.iterdir()) == [
        "libgnutls.30.dylib",
        "libopenconnect.5.dylib",
    ]
    rendered = [" ".join(command) for command in commands]
    worker_rewrite = (
        f"-change {source_library} "
        f"@executable_path/{privileged.RUNTIME_LIBRARY_DIRECTORY_NAME}/"
        f"{source_library.name}"
    )
    assert any(
        worker_rewrite in command
        for command in rendered
    )
    assert any(
        f"-change {transitive_library} @loader_path/{transitive_library.name}" in command
        for command in rendered
    )
    assert all(
        str(homebrew) not in dependency
        for dependency in privileged._otool_dependencies(worker)
    )


@pytest.mark.parametrize(
    ("dependency", "rpaths"),
    [
        ("@rpath/libopenconnect.5.dylib", ()),
        ("@loader_path/../outside.dylib", ()),
        ("@loader_path/missing.dylib", ()),
        ("/tmp/user-library.dylib", ()),
        ("@loader_path/libopenconnect.5.dylib", ("/tmp/user-libs",)),
    ],
)
def test_runtime_bundle_rejects_unapproved_dynamic_loader_paths(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    dependency: str,
    rpaths: tuple[str, ...],
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    binary = runtime / "libopenconnect.5.dylib"
    binary.write_bytes(b"library")
    monkeypatch.setattr(
        privileged,
        "_otool_dependencies",
        lambda _binary: (dependency,),
    )
    monkeypatch.setattr(privileged, "_otool_rpaths", lambda _binary: rpaths)

    with pytest.raises(PrivilegedError, match="runtime"):
        privileged._validate_bundled_dependencies(binary, runtime, worker=False)


def test_real_bundled_smoke_loads_no_homebrew_runtime(
    tmp_path: Path,
) -> None:
    worker = tmp_path / "meraki-openconnect-native"
    privileged._build_native_worker(worker)
    environment = dict(os.environ)
    environment["DYLD_PRINT_LIBRARIES"] = "1"

    result = subprocess.run(
        [str(worker), "--smoke"],
        check=True,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    loaded = result.stdout + result.stderr
    assert "/opt/homebrew" not in loaded
    assert str(tmp_path) in loaded
    early_signal = subprocess.run(
        [str(worker), "--smoke-early-signal"],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    assert early_signal.returncode == 128 + 15


def test_native_worker_publishes_pid_and_starts_cancel_dispatch_before_auth() -> None:
    with privileged._native_source_directory() as native:
        source = (native / "worker.c").read_text()
    live = source.split("static int run_live(void)", 1)[1]

    assert live.index("write_pid_file(getpid())") < live.index(
        "initialize_openconnect(&context)"
    )
    assert live.index("pthread_create(&watcher") < live.index(
        "openconnect_obtain_cookie(context.vpninfo)"
    )
    assert "webview_result" in source
    assert "pthread_cond_wait" in source


def test_native_worker_early_signal_unlinks_pid_and_exits() -> None:
    with privileged._native_source_directory() as native:
        source = (native / "worker.c").read_text()
    handler = source.split("static void cancel_signal", 1)[1].split("\n}", 1)[0]

    assert "unlink(MOC_PID_PATH)" in handler
    assert "_exit(128 + signal_number)" in handler


def test_native_source_directory_falls_back_to_packaged_resources(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    package_root = tmp_path / "package"
    packaged_native = package_root / "_resources" / "native"
    packaged_native.mkdir(parents=True)
    fake_module = tmp_path / "installed" / "meraki_openconnect" / "privileged.py"

    monkeypatch.setattr(privileged, "__file__", str(fake_module))
    monkeypatch.setattr(privileged.resources, "files", lambda _name: package_root)

    with privileged._native_source_directory() as source:
        assert source == packaged_native


def test_uninstall_plan_removes_only_installed_profile_artifacts(
    tmp_path: Path,
) -> None:
    profile = _multi_dns_profile(tmp_path)
    settings = replace(
        SETTINGS,
        extension_profile_digest=profile.profile_digest(),
    )
    script = build_install_plan(profile, settings, "tony").uninstall_script

    for path in (
        privileged.HELPER_PATH,
        privileged.NATIVE_PATH,
        privileged.POLICY_PATH,
        "/private/etc/resolver/internal.example.com",
        "/private/etc/resolver/corp.example.net",
    ):
        assert path in script
    assert "/etc/hosts" not in script
    assert "/private/etc/resolver/unrelated.example" not in script
    assert "openconnect.pid" not in script
    assert "experimental.pid" not in script


def test_uninstall_command_streams_profile_derived_script_to_sudo_stdin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[tuple[list[str], dict[str, object]]] = []

    def runner(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append((args, kwargs))
        assert privileged.POLICY_PATH.encode() in kwargs["input"]
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(privileged.subprocess, "run", runner)

    uninstall_privileged(PROFILE, SETTINGS, username="tony")

    assert commands == [
        (
            ["/usr/bin/sudo", "/bin/sh"],
            {"check": True, "input": commands[0][1]["input"]},
        )
    ]


def test_invalid_username_and_mismatched_receipt_are_rejected() -> None:
    with pytest.raises(PrivilegedError, match="username"):
        build_install_plan(PROFILE, SETTINGS, "tony ALL=(ALL) ALL")
    mismatched = replace(
        SETTINGS,
        extension_gateway_origin="https://other.example.com",
    )
    with pytest.raises(PrivilegedError, match="configured gateway"):
        build_install_plan(PROFILE, mismatched, "tony")
