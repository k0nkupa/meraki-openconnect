"""Generate and install a fixed-purpose privileged VPN policy."""

from __future__ import annotations

import getpass
import base64
import ctypes
import errno
import hashlib
import io
import os
import re
import shlex
import shutil
import stat
import subprocess
import tarfile
import tempfile
from collections.abc import Callable, Iterable
from contextlib import contextmanager
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Iterator

from meraki_openconnect.profile import OrganizationProfile
from meraki_openconnect.root_policy import render_root_policy
from meraki_openconnect.settings import MachineSettings


PRIVILEGED_ROOT = "/Library/PrivilegedHelperTools"
HELPER_PATH = f"{PRIVILEGED_ROOT}/io.github.k0nkupa.meraki-openconnect.root"
NATIVE_PATH = f"{PRIVILEGED_ROOT}/io.github.k0nkupa.meraki-openconnect.native"
VPNC_SCRIPT_PATH = (
    f"{PRIVILEGED_ROOT}/io.github.k0nkupa.meraki-openconnect.vpnc-script"
)
RUNTIME_LIBRARY_DIRECTORY_NAME = "io.github.k0nkupa.meraki-openconnect-libs"
RUNTIME_LIBRARY_PATH = f"{PRIVILEGED_ROOT}/{RUNTIME_LIBRARY_DIRECTORY_NAME}"
POLICY_PATH = f"{PRIVILEGED_ROOT}/io.github.k0nkupa.meraki-openconnect.policy.conf"
SUDOERS_PATH = "/etc/sudoers.d/meraki-openconnect"
RUNTIME_PATH = "/var/run/meraki-openconnect"
TUNNEL_PID_PATH = f"{RUNTIME_PATH}/tunnel.pid"
INSTALL_LOCK_PATH = f"{RUNTIME_PATH}/privileged-operation.lock"
ALLOWED_OPERATIONS = (
    "vpn-connect",
    "vpn-disconnect",
    "dns-connect",
    "dns-disconnect",
    "policy-digest",
)
_USERNAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
_POLICY_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\n\Z")
HOMEBREW_PREFIX = Path("/opt/homebrew")
_SYSTEM_LIBRARY_PREFIXES = ("/usr/lib/", "/System/Library/")
_PAYLOAD_MARKER = "__MERAKI_OPENCONNECT_PAYLOAD_BASE64__"
_RESOLVER_MARKER = "# meraki-openconnect managed resolver"


class PrivilegedError(RuntimeError):
    """The fixed privileged helper could not be safely configured."""


def _path_has_no_extended_acl(path: str) -> bool:
    libc = ctypes.CDLL(None, use_errno=True)
    acl_get_file = libc.acl_get_file
    acl_get_file.argtypes = (ctypes.c_char_p, ctypes.c_int)
    acl_get_file.restype = ctypes.c_void_p
    acl_free = libc.acl_free
    acl_free.argtypes = (ctypes.c_void_p,)
    acl_free.restype = ctypes.c_int

    acl = acl_get_file(os.fsencode(path), 0x00000100)
    if not acl:
        return ctypes.get_errno() == errno.ENOENT
    acl_free(acl)
    return False


@dataclass(frozen=True)
class PrivilegedInstallPlan:
    helper_text: str
    policy_text: str
    sudoers_text: str
    install_script: str
    uninstall_script: str
    digest: str


def privileged_component_installed(
    path: str,
    *,
    stat_reader: Callable[..., os.stat_result] = os.stat,
    acl_checker: Callable[[str], bool] = _path_has_no_extended_acl,
) -> bool:
    """Return whether a fixed privileged executable is safely installed."""
    candidate = Path(path)
    if not candidate.is_absolute():
        return False
    try:
        metadata = stat_reader(str(candidate), follow_symlinks=False)
        ancestors = [
            stat_reader(str(parent), follow_symlinks=False)
            for parent in candidate.parents
        ]
    except OSError:
        return False
    target_is_safe = (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == 0
        and metadata.st_mode & stat.S_IXUSR != 0
        and metadata.st_mode & 0o022 == 0
    )
    ancestors_are_safe = all(
        stat.S_ISDIR(ancestor.st_mode)
        and ancestor.st_uid == 0
        and ancestor.st_mode & 0o022 == 0
        for ancestor in ancestors
    )
    acl_paths_are_safe = all(
        acl_checker(str(item)) for item in (candidate, *candidate.parents)
    )
    return target_is_safe and ancestors_are_safe and acl_paths_are_safe


def _shell_literal(value: str) -> str:
    if not value or any(
        ord(character) < 0x20 or ord(character) > 0x7E
        for character in value
    ):
        raise PrivilegedError("profile contains an unsafe privileged-policy value")
    return shlex.quote(value)


def _resolver_content(nameservers: Iterable[str]) -> bytes:
    lines = [_RESOLVER_MARKER]
    lines.extend(f"nameserver {nameserver}" for nameserver in nameservers)
    return ("\n".join(lines) + "\n").encode("ascii")


def _resolver_functions(profile: OrganizationProfile) -> tuple[str, ...]:
    installers: list[str] = []
    cleaners: list[str] = []
    rollbackers: list[str] = []
    install_calls: list[str] = []
    cleanup_calls: list[str] = []
    rollback_calls: list[str] = []
    for index, rule in enumerate(profile.split_dns):
        resolver = _shell_literal(f"/private/etc/resolver/{rule.domain}")
        content_lines = " ".join(
            _shell_literal(line)
            for line in _resolver_content(rule.nameservers)
            .decode("ascii")
            .splitlines()
        )
        content_digest = hashlib.sha256(_resolver_content(rule.nameservers)).hexdigest()
        installers.append(
            f"""DNS_RULE_{index}_TOUCHED=0

install_dns_rule_{index}() {{
  RESOLVER={resolver}
  [ ! -L "$RESOLVER" ] || die "DNS resolver path is unsafe"
  [ ! -e "$RESOLVER" ] || die "DNS resolver path already exists"
  TEMP="${{RESOLVER}}.meraki-openconnect.$$"
  [ ! -e "$TEMP" ] || die "DNS resolver temporary path already exists"
  DNS_RULE_{index}_TOUCHED=1
  /usr/bin/printf '%s\\n' {content_lines} > "$TEMP"
  /usr/sbin/chown root:wheel "$TEMP"
  /bin/chmod 0644 "$TEMP"
  /bin/chmod -N "$TEMP"
  /bin/mv -f "$TEMP" "$RESOLVER"
}}"""
        )
        cleaners.append(
            f"""cleanup_dns_rule_{index}() {{
  RESOLVER={resolver}
  [ ! -L "$RESOLVER" ] || die "DNS resolver path is unsafe"
  [ -e "$RESOLVER" ] || return 0
  resolver_is_managed "$RESOLVER" {content_digest} || die "DNS resolver path is not managed by this client"
  /bin/rm -f "$RESOLVER"
}}"""
        )
        rollbackers.append(
            f"""rollback_dns_rule_{index}() {{
  [ "$DNS_RULE_{index}_TOUCHED" -eq 1 ] || return 0
  RESOLVER={resolver}
  TEMP="${{RESOLVER}}.meraki-openconnect.$$"
  RULE_ROLLBACK_STATUS=0
  /bin/rm -f "$TEMP" || RULE_ROLLBACK_STATUS=1
  [ ! -L "$RESOLVER" ] || RULE_ROLLBACK_STATUS=1
  if [ "$RULE_ROLLBACK_STATUS" -eq 0 ] && [ -e "$RESOLVER" ]; then
    resolver_is_managed "$RESOLVER" {content_digest} || RULE_ROLLBACK_STATUS=1
    [ "$RULE_ROLLBACK_STATUS" -ne 0 ] || /bin/rm -f "$RESOLVER" || RULE_ROLLBACK_STATUS=1
  fi
  DNS_RULE_{index}_TOUCHED=0
  return "$RULE_ROLLBACK_STATUS"
}}"""
        )
        install_calls.append(f"  install_dns_rule_{index}")
        cleanup_calls.append(f"  cleanup_dns_rule_{index}")
        rollback_calls.insert(
            0, f"  rollback_dns_rule_{index} || ROLLBACK_STATUS=1"
        )
    return (
        "\n\n".join(installers),
        "\n\n".join(cleaners),
        "\n\n".join(rollbackers),
        "\n".join(install_calls) or "  :",
        "\n".join(cleanup_calls) or "  :",
        "\n".join(rollback_calls) or "  :",
    )


def _helper_text(profile: OrganizationProfile, digest: str) -> str:
    (
        installers,
        cleaners,
        rollbackers,
        install_calls,
        cleanup_calls,
        rollback_calls,
    ) = _resolver_functions(profile)
    resolver_functions = "\n\n".join(
        part for part in (installers, cleaners, rollbackers) if part
    )
    return f"""#!/bin/sh
set -eu
umask 077
PATH=/usr/bin:/bin:/usr/sbin:/sbin

NATIVE={NATIVE_PATH}
VPNC={VPNC_SCRIPT_PATH}
LIBRARY_DIR={RUNTIME_LIBRARY_PATH}
POLICY={POLICY_PATH}
TUNNEL_PID_PATH={TUNNEL_PID_PATH}
INSTALL_LOCK={INSTALL_LOCK_PATH}
POLICY_DIGEST={_shell_literal(digest)}

die() {{
  /usr/bin/printf '%s\\n' "meraki-openconnect-root: $1" >&2
  exit 1
}}

verify_root_file() {{
  ITEM=$1
  [ -f "$ITEM" ] || die "privileged runtime file is missing"
  [ ! -L "$ITEM" ] || die "privileged runtime file is unsafe"
  OWNER=$(/usr/bin/stat -f '%u' "$ITEM")
  MODE=$(/usr/bin/stat -f '%Lp' "$ITEM")
  [ "$OWNER" = "0" ] || die "privileged runtime file is not root-owned"
  [ $((0$MODE & 022)) -eq 0 ] || die "privileged runtime file is writable"
  ACL_LINES=$(/bin/ls -lde "$ITEM" | /usr/bin/wc -l | /usr/bin/xargs)
  [ "$ACL_LINES" -eq 1 ] || die "privileged runtime file has an extended ACL"
}}

verify_root_directory() {{
  ITEM=$1
  [ -d "$ITEM" ] || die "privileged runtime directory is missing"
  [ ! -L "$ITEM" ] || die "privileged runtime directory is unsafe"
  OWNER=$(/usr/bin/stat -f '%u' "$ITEM")
  MODE=$(/usr/bin/stat -f '%Lp' "$ITEM")
  [ "$OWNER" = "0" ] || die "privileged runtime directory is not root-owned"
  [ $((0$MODE & 022)) -eq 0 ] || die "privileged runtime directory is writable"
  ACL_LINES=$(/bin/ls -lde "$ITEM" | /usr/bin/wc -l | /usr/bin/xargs)
  [ "$ACL_LINES" -eq 1 ] || die "privileged runtime directory has an extended ACL"
}}

verify_runtime() {{
  verify_root_directory /Library
  verify_root_directory {PRIVILEGED_ROOT}
  verify_root_directory {RUNTIME_PATH}
  verify_root_directory "$LIBRARY_DIR"
  verify_root_file "$NATIVE"
  verify_root_file "$VPNC"
  verify_root_file "$POLICY"
  FOUND_LIBRARY=0
  for LIBRARY in "$LIBRARY_DIR/"*.dylib; do
    [ -e "$LIBRARY" ] || continue
    FOUND_LIBRARY=1
    verify_root_file "$LIBRARY"
  done
  [ "$FOUND_LIBRARY" -eq 1 ] || die "privileged runtime libraries are missing"
}}

read_tunnel_pid() {{
  [ -f "$TUNNEL_PID_PATH" ] || die "tunnel PID is missing"
  TUNNEL_PID=$(/bin/cat "$TUNNEL_PID_PATH")
  case "$TUNNEL_PID" in
    ''|*[!0-9]*) die "tunnel PID is invalid" ;;
  esac
}}

verify_tunnel_worker() {{
  read_tunnel_pid
  OWNER=$(/bin/ps -p "$TUNNEL_PID" -o uid= 2>/dev/null | /usr/bin/xargs || true)
  COMMAND=$(/bin/ps -p "$TUNNEL_PID" -o comm= 2>/dev/null | /usr/bin/xargs || true)
  [ "$OWNER" = "0" ] || die "tunnel worker is not root-owned"
  [ "$COMMAND" = "$NATIVE" ] || die "tunnel PID is not the fixed worker"
}}

vpn_connect() {{
  verify_runtime
  [ -x "$NATIVE" ] || die "native worker is missing"
  /usr/bin/shlock -f "$INSTALL_LOCK" -p $$ || die "privileged operation is already active"
  trap '/bin/rm -f "$INSTALL_LOCK"' EXIT HUP INT TERM
  if [ -f "$TUNNEL_PID_PATH" ]; then
    read_tunnel_pid
    if /bin/kill -0 "$TUNNEL_PID" 2>/dev/null; then
      verify_tunnel_worker
      die "Meraki OpenConnect tunnel is already running"
    fi
    /bin/rm -f "$TUNNEL_PID_PATH"
  fi
  if "$NATIVE"; then
    STATUS=0
  else
    STATUS=$?
  fi
  /bin/rm -f "$INSTALL_LOCK"
  trap - EXIT HUP INT TERM
  exit "$STATUS"
}}

flush_dns() {{
  /usr/bin/dscacheutil -flushcache >/dev/null 2>&1 || true
  /usr/bin/killall -HUP mDNSResponder >/dev/null 2>&1 || true
}}

resolver_is_managed() {{
  RESOLVER_FILE=$1
  EXPECTED_DIGEST=$2
  [ -f "$RESOLVER_FILE" ] && [ ! -L "$RESOLVER_FILE" ] || return 1
  [ "$(/usr/bin/sed -n '1p' "$RESOLVER_FILE")" = {_shell_literal(_RESOLVER_MARKER)} ] || return 1
  ACTUAL_DIGEST=$(/usr/bin/shasum -a 256 "$RESOLVER_FILE" | /usr/bin/awk '{{print $1}}') || return 1
  [ "$ACTUAL_DIGEST" = "$EXPECTED_DIGEST" ]
}}

{resolver_functions}

install_dns_resolvers() {{
  [ "$(/usr/bin/readlink /etc)" = "private/etc" ] || die "system resolver path is unsafe"
  verify_root_directory /private
  verify_root_directory /private/etc
  [ ! -L /private/etc/resolver ] || die "resolver directory is unsafe"
  if [ ! -d /private/etc/resolver ]; then
    /usr/bin/install -d -o root -g wheel -m 0755 /private/etc/resolver
    /bin/chmod -N /private/etc/resolver
  fi
  verify_root_directory /private/etc/resolver
{install_calls}
}}

commit_dns_resolvers() {{
  DNS_COMMITTED=1
}}

rollback_dns_resolvers() {{
  ROLLBACK_STATUS=0
{rollback_calls}
  flush_dns
  [ "$ROLLBACK_STATUS" -eq 0 ] || /usr/bin/printf '%s\\n' "DNS resolver rollback failed" >&2
  return "$ROLLBACK_STATUS"
}}

dns_connect_exit() {{
  DNS_CONNECT_STATUS=$1
  trap - EXIT HUP INT TERM
  if [ "$DNS_CONNECT_STATUS" -ne 0 ]; then
    if [ "$DNS_COMMITTED" -eq 0 ]; then
      if rollback_dns_resolvers; then DNS_CONNECT_STATUS=1; else DNS_CONNECT_STATUS=2; fi
    else
      DNS_CONNECT_STATUS=2
    fi
  fi
  exit "$DNS_CONNECT_STATUS"
}}

dns_connect_signal() {{
  trap - EXIT HUP INT TERM
  DNS_CONNECT_STATUS=2
  if [ "$DNS_COMMITTED" -eq 0 ]; then
    if rollback_dns_resolvers; then DNS_CONNECT_STATUS=1; else DNS_CONNECT_STATUS=2; fi
  fi
  exit "$DNS_CONNECT_STATUS"
}}

cleanup_dns_resolvers() {{
  [ "$(/usr/bin/readlink /etc)" = "private/etc" ] || die "system resolver path is unsafe"
  verify_root_directory /private
  verify_root_directory /private/etc
  [ ! -L /private/etc/resolver ] || die "resolver directory is unsafe"
  [ ! -e /private/etc/resolver ] || verify_root_directory /private/etc/resolver
{cleanup_calls}
  flush_dns
}}

dns_connect() {{
  verify_tunnel_worker
  DNS_COMMITTED=0
  trap 'dns_connect_exit "$?"' EXIT
  trap dns_connect_signal HUP INT TERM
  install_dns_resolvers
  commit_dns_resolvers
  trap - EXIT HUP INT TERM
  flush_dns
}}

dns_disconnect() {{
  cleanup_dns_resolvers
}}

stop_vpn_worker() {{
  [ -f "$TUNNEL_PID_PATH" ] || exit 0
  read_tunnel_pid
  if ! /bin/kill -0 "$TUNNEL_PID" 2>/dev/null; then
    /bin/rm -f "$TUNNEL_PID_PATH"
    exit 0
  fi
  verify_tunnel_worker
  /bin/kill -TERM "$TUNNEL_PID"
  COUNT=0
  while /bin/kill -0 "$TUNNEL_PID" 2>/dev/null; do
    COUNT=$((COUNT + 1))
    [ "$COUNT" -lt 100 ] || die "tunnel worker did not stop"
    /bin/sleep 0.1
  done
  /bin/rm -f "$TUNNEL_PID_PATH"
}}

vpn_disconnect() {{
  DISCONNECT_STATUS=0
  if (stop_vpn_worker); then :; else DISCONNECT_STATUS=1; fi
  if (cleanup_dns_resolvers); then :; else DISCONNECT_STATUS=1; fi
  return "$DISCONNECT_STATUS"
}}

policy_digest() {{
  verify_runtime
  /usr/bin/printf '%s\\n' "$POLICY_DIGEST"
}}

[ "$#" -eq 1 ] || die "expected exactly one operation"
case "$1" in
  vpn-connect) vpn_connect ;;
  vpn-disconnect) vpn_disconnect ;;
  dns-connect) dns_connect ;;
  dns-disconnect) dns_disconnect ;;
  policy-digest) policy_digest ;;
  *) die "unsupported operation" ;;
esac
"""


def _sudoers_text(username: str) -> str:
    operations = ", ".join(
        f"{HELPER_PATH} {operation}" for operation in ALLOWED_OPERATIONS
    )
    return f"{username} ALL=(root) NOPASSWD: {operations}\n"


def _install_script() -> str:
    return f"""#!/bin/sh
set -eu
umask 077
PAYLOAD=$(/usr/bin/mktemp -d /var/tmp/meraki-openconnect-install.XXXXXX)
ARCHIVE="$PAYLOAD/payload.tar.gz"
trap '/bin/rm -rf "$PAYLOAD"' EXIT HUP INT TERM
/usr/bin/base64 -D > "$ARCHIVE" <<'MERAKI_OPENCONNECT_PAYLOAD'
{_PAYLOAD_MARKER}
MERAKI_OPENCONNECT_PAYLOAD
/usr/bin/tar -tzf "$ARCHIVE" | while IFS= read -r ENTRY; do
  case "$ENTRY" in
    meraki-openconnect-root|meraki-openconnect-native|meraki-openconnect-vpnc-script|policy.conf|meraki-openconnect.sudoers|{RUNTIME_LIBRARY_DIRECTORY_NAME}|{RUNTIME_LIBRARY_DIRECTORY_NAME}/|{RUNTIME_LIBRARY_DIRECTORY_NAME}/*.dylib) ;;
    *) /usr/bin/printf '%s\\n' "unsafe archive entry" >&2; exit 1 ;;
  esac
done
/usr/bin/tar -xzf "$ARCHIVE" -C "$PAYLOAD"
/bin/rm -f "$ARCHIVE"
[ -z "$(/usr/bin/find "$PAYLOAD" -type l -print -quit)" ] || exit 1
[ -f "$PAYLOAD/meraki-openconnect-root" ] || exit 1
[ -f "$PAYLOAD/meraki-openconnect-native" ] || exit 1
[ -f "$PAYLOAD/meraki-openconnect-vpnc-script" ] || exit 1
[ -f "$PAYLOAD/policy.conf" ] || exit 1
[ -f "$PAYLOAD/meraki-openconnect.sudoers" ] || exit 1
[ -d "$PAYLOAD/{RUNTIME_LIBRARY_DIRECTORY_NAME}" ] || exit 1
/usr/sbin/visudo -cf "$PAYLOAD/meraki-openconnect.sudoers"
/usr/bin/codesign --verify --strict "$PAYLOAD/meraki-openconnect-native"
for LIBRARY in "$PAYLOAD/{RUNTIME_LIBRARY_DIRECTORY_NAME}/"*.dylib; do
  [ -f "$LIBRARY" ] || exit 1
  /usr/bin/codesign --verify --strict "$LIBRARY"
done
[ ! -L {PRIVILEGED_ROOT} ] || exit 1
[ ! -L {RUNTIME_PATH} ] || exit 1
verify_install_directory() {{
  DIRECTORY=$1
  [ -d "$DIRECTORY" ] && [ ! -L "$DIRECTORY" ] || exit 1
  [ "$(/usr/bin/stat -f '%u' "$DIRECTORY")" = "0" ] || exit 1
  DIRECTORY_MODE=$(/usr/bin/stat -f '%Lp' "$DIRECTORY")
  [ $((0$DIRECTORY_MODE & 022)) -eq 0 ] || exit 1
  ACL_LINES=$(/bin/ls -lde "$DIRECTORY" | /usr/bin/wc -l | /usr/bin/xargs)
  [ "$ACL_LINES" -eq 1 ] || {{ /usr/bin/printf '%s\\n' "unsafe privileged ancestor ACL" >&2; exit 1; }}
}}
verify_install_directory /Library
if [ ! -d {PRIVILEGED_ROOT} ]; then
  /usr/bin/install -d -o root -g wheel -m 0755 {PRIVILEGED_ROOT}
  /bin/chmod -N {PRIVILEGED_ROOT}
fi
verify_install_directory {PRIVILEGED_ROOT}
/usr/bin/install -d -o root -g wheel -m 0755 {RUNTIME_PATH}
/bin/chmod -N {RUNTIME_PATH}
INSTALL_LOCK={INSTALL_LOCK_PATH}
/usr/bin/shlock -f "$INSTALL_LOCK" -p $$ || exit 1
trap '/bin/rm -rf "$PAYLOAD"; /bin/rm -f "$INSTALL_LOCK"' EXIT HUP INT TERM
[ ! -e {TUNNEL_PID_PATH} ] || exit 1
HELPER_TEMP={HELPER_PATH}.meraki-openconnect.$$
NATIVE_TEMP={NATIVE_PATH}.meraki-openconnect.$$
VPNC_TEMP={VPNC_SCRIPT_PATH}.meraki-openconnect.$$
LIBRARY_TEMP={RUNTIME_LIBRARY_PATH}.meraki-openconnect.$$
POLICY_TEMP={POLICY_PATH}.meraki-openconnect.$$
SUDOERS_TEMP={SUDOERS_PATH}.meraki-openconnect.$$
HELPER_BACKUP={HELPER_PATH}.previous.$$
NATIVE_BACKUP={NATIVE_PATH}.previous.$$
VPNC_BACKUP={VPNC_SCRIPT_PATH}.previous.$$
LIBRARY_BACKUP={RUNTIME_LIBRARY_PATH}.previous.$$
POLICY_BACKUP={POLICY_PATH}.previous.$$
SUDOERS_BACKUP={SUDOERS_PATH}.previous.$$
COMMITTED=0
ROLLED_BACK=0
HELPER_BACKED_UP=0
NATIVE_BACKED_UP=0
VPNC_BACKED_UP=0
LIBRARY_BACKED_UP=0
POLICY_BACKED_UP=0
SUDOERS_BACKED_UP=0
HELPER_ACTIVATED=0
NATIVE_ACTIVATED=0
VPNC_ACTIVATED=0
LIBRARY_ACTIVATED=0
POLICY_ACTIVATED=0
SUDOERS_ACTIVATED=0
rollback_install() {{
  set +e
  if [ "$COMMITTED" -eq 0 ] && [ "$ROLLED_BACK" -eq 0 ]; then
    ROLLED_BACK=1
    [ "$HELPER_ACTIVATED" -eq 0 ] || /bin/rm -f {HELPER_PATH}
    [ "$LIBRARY_ACTIVATED" -eq 0 ] || /bin/rm -rf {RUNTIME_LIBRARY_PATH}
    [ "$VPNC_ACTIVATED" -eq 0 ] || /bin/rm -f {VPNC_SCRIPT_PATH}
    [ "$NATIVE_ACTIVATED" -eq 0 ] || /bin/rm -f {NATIVE_PATH}
    [ "$POLICY_ACTIVATED" -eq 0 ] || /bin/rm -f {POLICY_PATH}
    [ "$SUDOERS_ACTIVATED" -eq 0 ] || /bin/rm -f {SUDOERS_PATH}
    [ "$LIBRARY_BACKED_UP" -eq 0 ] || [ ! -e "$LIBRARY_BACKUP" ] || /bin/mv "$LIBRARY_BACKUP" {RUNTIME_LIBRARY_PATH}
    [ "$VPNC_BACKED_UP" -eq 0 ] || [ ! -e "$VPNC_BACKUP" ] || /bin/mv "$VPNC_BACKUP" {VPNC_SCRIPT_PATH}
    [ "$NATIVE_BACKED_UP" -eq 0 ] || [ ! -e "$NATIVE_BACKUP" ] || /bin/mv "$NATIVE_BACKUP" {NATIVE_PATH}
    [ "$POLICY_BACKED_UP" -eq 0 ] || [ ! -e "$POLICY_BACKUP" ] || /bin/mv "$POLICY_BACKUP" {POLICY_PATH}
    [ "$SUDOERS_BACKED_UP" -eq 0 ] || [ ! -e "$SUDOERS_BACKUP" ] || /bin/mv "$SUDOERS_BACKUP" {SUDOERS_PATH}
    [ "$HELPER_BACKED_UP" -eq 0 ] || [ ! -e "$HELPER_BACKUP" ] || /bin/mv "$HELPER_BACKUP" {HELPER_PATH}
  elif [ "$COMMITTED" -eq 1 ]; then
    /bin/rm -f "$HELPER_BACKUP" "$NATIVE_BACKUP" "$VPNC_BACKUP" "$POLICY_BACKUP" "$SUDOERS_BACKUP"
    /bin/rm -rf "$LIBRARY_BACKUP"
  fi
  /bin/rm -rf "$PAYLOAD" "$LIBRARY_TEMP"
  /bin/rm -f "$HELPER_TEMP" "$NATIVE_TEMP" "$VPNC_TEMP" "$POLICY_TEMP" "$SUDOERS_TEMP" "$INSTALL_LOCK"
}}
trap rollback_install EXIT
trap 'rollback_install; exit 1' HUP INT TERM
/bin/rm -f "$HELPER_BACKUP" "$NATIVE_BACKUP" "$VPNC_BACKUP" "$POLICY_BACKUP" "$SUDOERS_BACKUP"
/bin/rm -rf "$LIBRARY_BACKUP"
for CURRENT in {HELPER_PATH} {NATIVE_PATH} {VPNC_SCRIPT_PATH} {RUNTIME_LIBRARY_PATH} {POLICY_PATH} {SUDOERS_PATH}; do
  [ ! -L "$CURRENT" ] || exit 1
done
if [ -e {HELPER_PATH} ]; then HELPER_BACKED_UP=1; /bin/mv {HELPER_PATH} "$HELPER_BACKUP"; fi
if [ -e {RUNTIME_LIBRARY_PATH} ]; then LIBRARY_BACKED_UP=1; /bin/mv {RUNTIME_LIBRARY_PATH} "$LIBRARY_BACKUP"; fi
if [ -e {VPNC_SCRIPT_PATH} ]; then VPNC_BACKED_UP=1; /bin/mv {VPNC_SCRIPT_PATH} "$VPNC_BACKUP"; fi
if [ -e {NATIVE_PATH} ]; then NATIVE_BACKED_UP=1; /bin/mv {NATIVE_PATH} "$NATIVE_BACKUP"; fi
if [ -e {POLICY_PATH} ]; then POLICY_BACKED_UP=1; /bin/mv {POLICY_PATH} "$POLICY_BACKUP"; fi
if [ -e {SUDOERS_PATH} ]; then SUDOERS_BACKED_UP=1; /bin/mv {SUDOERS_PATH} "$SUDOERS_BACKUP"; fi
[ ! -e {TUNNEL_PID_PATH} ] || exit 1
/usr/bin/install -o root -g wheel -m 0755 "$PAYLOAD/meraki-openconnect-root" "$HELPER_TEMP"
/usr/bin/install -o root -g wheel -m 0755 "$PAYLOAD/meraki-openconnect-native" "$NATIVE_TEMP"
/usr/bin/install -o root -g wheel -m 0755 "$PAYLOAD/meraki-openconnect-vpnc-script" "$VPNC_TEMP"
/usr/bin/install -d -o root -g wheel -m 0755 "$LIBRARY_TEMP"
for LIBRARY in "$PAYLOAD/{RUNTIME_LIBRARY_DIRECTORY_NAME}/"*.dylib; do
  [ -f "$LIBRARY" ] || exit 1
  /usr/bin/install -o root -g wheel -m 0555 "$LIBRARY" "$LIBRARY_TEMP/$(/usr/bin/basename "$LIBRARY")"
done
/usr/bin/install -o root -g wheel -m 0600 "$PAYLOAD/policy.conf" "$POLICY_TEMP"
/usr/bin/install -o root -g wheel -m 0440 "$PAYLOAD/meraki-openconnect.sudoers" "$SUDOERS_TEMP"
/bin/chmod -N "$HELPER_TEMP" "$NATIVE_TEMP" "$VPNC_TEMP" "$POLICY_TEMP" "$SUDOERS_TEMP"
/bin/chmod -RN "$LIBRARY_TEMP"
LIBRARY_ACTIVATED=1
/bin/mv "$LIBRARY_TEMP" {RUNTIME_LIBRARY_PATH}
VPNC_ACTIVATED=1
/bin/mv -f "$VPNC_TEMP" {VPNC_SCRIPT_PATH}
NATIVE_ACTIVATED=1
/bin/mv -f "$NATIVE_TEMP" {NATIVE_PATH}
POLICY_ACTIVATED=1
/bin/mv -f "$POLICY_TEMP" {POLICY_PATH}
SUDOERS_ACTIVATED=1
/bin/mv -f "$SUDOERS_TEMP" {SUDOERS_PATH}
HELPER_ACTIVATED=1
/bin/mv -f "$HELPER_TEMP" {HELPER_PATH}
COMMITTED=1
/bin/rm -f "$HELPER_BACKUP" "$NATIVE_BACKUP" "$VPNC_BACKUP" "$POLICY_BACKUP" "$SUDOERS_BACKUP"
/bin/rm -rf "$LIBRARY_BACKUP"
/bin/rm -f /usr/local/libexec/meraki-openconnect-root /usr/local/libexec/meraki-openconnect-native /usr/local/etc/meraki-openconnect/policy.conf
trap - EXIT HUP INT TERM
/bin/rm -rf "$PAYLOAD"
/bin/rm -f "$INSTALL_LOCK"
"""


def _uninstall_script(
    resolver_rules: Iterable[tuple[str, tuple[str, ...]]],
) -> str:
    resolver_cleaners: list[str] = []
    for domain, nameservers in resolver_rules:
        resolver = _shell_literal(f"/private/etc/resolver/{domain}")
        digest = hashlib.sha256(_resolver_content(nameservers)).hexdigest()
        resolver_cleaners.append(
            f"""RESOLVER={resolver}
if [ -e "$RESOLVER" ] && resolver_is_managed "$RESOLVER" {digest}; then
  /bin/rm -f "$RESOLVER"
fi"""
        )
    resolver_cleanup = "\n".join(resolver_cleaners)
    return f"""#!/bin/sh
set -eu
if [ -x {HELPER_PATH} ]; then
  {HELPER_PATH} vpn-disconnect || true
fi
[ ! -L {RUNTIME_PATH} ] || exit 1
/usr/bin/install -d -o root -g wheel -m 0755 {RUNTIME_PATH}
/bin/chmod -N {RUNTIME_PATH}
INSTALL_LOCK={INSTALL_LOCK_PATH}
/usr/bin/shlock -f "$INSTALL_LOCK" -p $$ || exit 1
trap '/bin/rm -f "$INSTALL_LOCK"' EXIT HUP INT TERM
[ ! -e {TUNNEL_PID_PATH} ] || exit 1
[ "$(/usr/bin/readlink /etc)" = "private/etc" ] || exit 1
[ ! -L /private/etc/resolver ] || exit 1
resolver_is_managed() {{
  RESOLVER_FILE=$1
  EXPECTED_DIGEST=$2
  [ -f "$RESOLVER_FILE" ] && [ ! -L "$RESOLVER_FILE" ] || return 1
  [ "$(/usr/bin/sed -n '1p' "$RESOLVER_FILE")" = {_shell_literal(_RESOLVER_MARKER)} ] || return 1
  ACTUAL_DIGEST=$(/usr/bin/shasum -a 256 "$RESOLVER_FILE" | /usr/bin/awk '{{print $1}}') || return 1
  [ "$ACTUAL_DIGEST" = "$EXPECTED_DIGEST" ]
}}
{resolver_cleanup}
/bin/rm -f {HELPER_PATH} {NATIVE_PATH} {VPNC_SCRIPT_PATH} {POLICY_PATH} {SUDOERS_PATH} {TUNNEL_PID_PATH}
/bin/rm -rf {RUNTIME_LIBRARY_PATH}
/bin/rm -f /usr/local/libexec/meraki-openconnect-root /usr/local/libexec/meraki-openconnect-native /usr/local/etc/meraki-openconnect/policy.conf
/usr/bin/dscacheutil -flushcache >/dev/null 2>&1 || true
/usr/bin/killall -HUP mDNSResponder >/dev/null 2>&1 || true
/bin/rm -f "$INSTALL_LOCK"
trap - EXIT HUP INT TERM
/bin/rmdir {RUNTIME_PATH} 2>/dev/null || true
"""


def build_install_plan(
    profile: OrganizationProfile,
    settings: MachineSettings,
    username: str,
) -> PrivilegedInstallPlan:
    """Render immutable root payloads for one validated organization profile."""
    if settings.extension_gateway_origin != f"https://{profile.gateway.host}":
        raise PrivilegedError(
            "authenticate against the configured gateway before privileged installation"
        )
    if settings.extension_profile_digest != profile.profile_digest():
        raise PrivilegedError(
            "authenticate the configured profile before privileged installation"
        )
    if not _USERNAME.fullmatch(username):
        raise PrivilegedError("username is invalid for a sudoers entry")
    rendered = render_root_policy(profile, settings.server_cert_pin)
    return PrivilegedInstallPlan(
        helper_text=_helper_text(profile, rendered.digest),
        policy_text=rendered.text,
        sudoers_text=_sudoers_text(username),
        install_script=_install_script(),
        uninstall_script=_uninstall_script(
            (rule.domain, rule.nameservers) for rule in profile.split_dns
        ),
        digest=rendered.digest,
    )


def installed_policy_digest() -> str | None:
    """Read the fixed helper's public policy receipt without prompting for sudo."""
    try:
        result = subprocess.run(
            ["/usr/bin/sudo", "-n", HELPER_PATH, "policy-digest"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0 or not _POLICY_DIGEST.fullmatch(result.stdout):
        return None
    return result.stdout[:-1]


def _archive_payload(directory: Path, plan: PrivilegedInstallPlan) -> bytes:
    payloads = {
        "meraki-openconnect-root": plan.helper_text.encode(),
        "policy.conf": plan.policy_text.encode(),
        "meraki-openconnect.sudoers": plan.sudoers_text.encode(),
    }
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w:gz") as tar:
        for name, contents in payloads.items():
            info = tarfile.TarInfo(name)
            info.size = len(contents)
            info.mode = 0o600
            tar.addfile(info, io.BytesIO(contents))
        for name in ("meraki-openconnect-native", "meraki-openconnect-vpnc-script"):
            tar.add(directory / name, arcname=name, recursive=False)
        tar.add(
            directory / RUNTIME_LIBRARY_DIRECTORY_NAME,
            arcname=RUNTIME_LIBRARY_DIRECTORY_NAME,
            recursive=True,
        )
    return archive.getvalue()


def _installation_input(directory: Path, plan: PrivilegedInstallPlan) -> bytes:
    encoded = base64.b64encode(_archive_payload(directory, plan)).decode("ascii")
    wrapped = "\n".join(
        encoded[index : index + 76] for index in range(0, len(encoded), 76)
    )
    if plan.install_script.count(_PAYLOAD_MARKER) != 1:
        raise PrivilegedError("privileged installer payload marker is invalid")
    return plan.install_script.replace(_PAYLOAD_MARKER, wrapped).encode("ascii")


@contextmanager
def _native_source_directory() -> Iterator[Path]:
    checkout = Path(__file__).resolve().parents[2] / "native"
    if checkout.exists():
        if not checkout.is_dir() or checkout.is_symlink():
            raise PrivilegedError("native worker source directory is unsafe")
        yield checkout
        return
    packaged = resources.files("meraki_openconnect").joinpath(
        "_resources", "native"
    )
    try:
        with resources.as_file(packaged) as extracted:
            if not extracted.is_dir() or extracted.is_symlink():
                raise PrivilegedError("packaged native worker sources are unsafe")
            yield extracted
    except (FileNotFoundError, ModuleNotFoundError, TypeError) as exc:
        raise PrivilegedError("native worker sources are missing") from exc


def _compile_native_worker(native: Path, output: Path) -> None:
    sources = [
        native / name
        for name in ("protocol.c", "policy.c", "worker_io.c", "worker.c")
    ]
    headers = [
        native / name for name in ("protocol.h", "policy.h", "worker_io.h")
    ]
    if any(
        not path.is_file() or path.is_symlink() for path in [*sources, *headers]
    ):
        raise PrivilegedError("native worker sources are missing or unsafe")
    command = [
        "/usr/bin/clang",
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        "-Werror",
        "-I/opt/homebrew/include",
        "-L/opt/homebrew/lib",
        "-Wl,-headerpad_max_install_names",
        *(str(path) for path in sources),
        "-lopenconnect",
        "-lgnutls",
        "-lpthread",
        "-o",
        str(output),
    ]
    try:
        subprocess.run(command, check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise PrivilegedError("native worker compilation failed") from exc
    if not output.is_file() or output.is_symlink():
        raise PrivilegedError("native worker build did not create a safe binary")
    output.chmod(0o700)


def _otool_dependencies(binary: Path) -> tuple[str, ...]:
    try:
        result = subprocess.run(
            ["/usr/bin/otool", "-L", str(binary)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise PrivilegedError("native runtime dependency inspection failed") from exc
    dependencies: list[str] = []
    for line in result.stdout.splitlines()[1:]:
        stripped = line.strip()
        if not stripped:
            continue
        dependency = stripped.split(" (", 1)[0]
        if dependency:
            dependencies.append(dependency)
    return tuple(dependencies)


def _otool_rpaths(binary: Path) -> tuple[str, ...]:
    try:
        result = subprocess.run(
            ["/usr/bin/otool", "-l", str(binary)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise PrivilegedError("native runtime load-command inspection failed") from exc
    rpaths: list[str] = []
    reading_rpath = False
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("Load command "):
            if reading_rpath:
                raise PrivilegedError("native runtime contains a malformed rpath")
            continue
        if stripped == "cmd LC_RPATH":
            reading_rpath = True
            continue
        if reading_rpath and stripped.startswith("path "):
            rpath = stripped[5:].split(" (offset ", 1)[0]
            if not rpath:
                raise PrivilegedError("native runtime contains a malformed rpath")
            rpaths.append(rpath)
            reading_rpath = False
    if reading_rpath:
        raise PrivilegedError("native runtime contains a malformed rpath")
    return tuple(rpaths)


def _is_system_dependency(dependency: str) -> bool:
    return dependency.startswith(_SYSTEM_LIBRARY_PREFIXES)


def _is_homebrew_dependency(dependency: str) -> bool:
    try:
        Path(dependency).relative_to(HOMEBREW_PREFIX)
    except ValueError:
        return False
    return True


def _validate_bundled_dependencies(
    binary: Path,
    runtime: Path,
    *,
    worker: bool,
) -> None:
    if _otool_rpaths(binary):
        raise PrivilegedError("native runtime contains an unsupported rpath")
    allowed_names = {
        candidate.name
        for candidate in runtime.iterdir()
        if candidate.is_file() and not candidate.is_symlink()
    }
    if not allowed_names:
        raise PrivilegedError("native runtime libraries are missing")
    prefix = (
        f"@executable_path/{RUNTIME_LIBRARY_DIRECTORY_NAME}/"
        if worker
        else "@loader_path/"
    )
    for dependency in _otool_dependencies(binary):
        if _is_system_dependency(dependency):
            continue
        if not dependency.startswith(prefix):
            raise PrivilegedError("native runtime has an unsupported dependency")
        library_name = dependency[len(prefix) :]
        if (
            not library_name
            or "/" in library_name
            or library_name not in allowed_names
        ):
            raise PrivilegedError("native runtime has an unsupported dependency")


def _bundle_native_runtime(worker: Path, runtime: Path) -> None:
    runtime.mkdir(mode=0o700)
    if _otool_rpaths(worker):
        raise PrivilegedError("native worker contains an unsupported rpath")
    worker_dependencies = _otool_dependencies(worker)
    if any(
        not _is_homebrew_dependency(dependency)
        and not _is_system_dependency(dependency)
        for dependency in worker_dependencies
    ):
        raise PrivilegedError("native worker has an unsupported dependency")
    sources_by_name: dict[str, Path] = {}
    pending = [
        dependency
        for dependency in worker_dependencies
        if _is_homebrew_dependency(dependency)
    ]
    while pending:
        dependency = pending.pop()
        source = Path(dependency)
        try:
            resolved = source.resolve(strict=True)
        except OSError as exc:
            raise PrivilegedError("native runtime dependency is missing") from exc
        existing = sources_by_name.get(source.name)
        if existing is not None:
            if existing != resolved:
                raise PrivilegedError("native runtime dependency names collide")
            continue
        sources_by_name[source.name] = resolved
        destination = runtime / source.name
        shutil.copy2(source, destination, follow_symlinks=True)
        if _otool_rpaths(destination):
            raise PrivilegedError("native runtime contains an unsupported rpath")
        for child in _otool_dependencies(destination):
            if _is_homebrew_dependency(child):
                pending.append(child)
            elif not _is_system_dependency(child):
                raise PrivilegedError("native runtime has an unsupported dependency")

    if not sources_by_name:
        raise PrivilegedError("native worker is not linked to the expected runtime")

    for destination in runtime.iterdir():
        arguments = [
            "/usr/bin/install_name_tool",
            "-id",
            f"@loader_path/{destination.name}",
        ]
        for dependency in _otool_dependencies(destination):
            if _is_homebrew_dependency(dependency):
                arguments.extend(
                    ["-change", dependency, f"@loader_path/{Path(dependency).name}"]
                )
        arguments.append(str(destination))
        try:
            subprocess.run(arguments, check=True)
            subprocess.run(
                ["/usr/bin/codesign", "--force", "--sign", "-", str(destination)],
                check=True,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            raise PrivilegedError("native runtime dependency rewrite failed") from exc

    worker_arguments = ["/usr/bin/install_name_tool"]
    for dependency in _otool_dependencies(worker):
        if _is_homebrew_dependency(dependency):
            worker_arguments.extend(
                [
                    "-change",
                    dependency,
                    f"@executable_path/{RUNTIME_LIBRARY_DIRECTORY_NAME}/{Path(dependency).name}",
                ]
            )
        elif not _is_system_dependency(dependency) and not dependency.startswith("@"):
            raise PrivilegedError("native worker has an unsupported dependency")
    worker_arguments.append(str(worker))
    try:
        subprocess.run(worker_arguments, check=True)
        subprocess.run(
            ["/usr/bin/codesign", "--force", "--sign", "-", str(worker)],
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise PrivilegedError("native worker dependency rewrite failed") from exc

    _validate_bundled_dependencies(worker, runtime, worker=True)
    for binary in runtime.iterdir():
        _validate_bundled_dependencies(binary, runtime, worker=False)


def _build_native_worker(output: Path) -> None:
    with _native_source_directory() as native:
        _compile_native_worker(native, output)
        vpnc_script = native / "vpnc-script"
        if not vpnc_script.is_file() or vpnc_script.is_symlink():
            raise PrivilegedError("bundled vpnc script is missing or unsafe")
        shutil.copy2(vpnc_script, output.parent / "meraki-openconnect-vpnc-script")
    _bundle_native_runtime(
        output, output.parent / RUNTIME_LIBRARY_DIRECTORY_NAME
    )
    try:
        subprocess.run([str(output), "--smoke"], check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise PrivilegedError("native worker smoke test failed") from exc


def install_privileged(
    profile: OrganizationProfile,
    settings: MachineSettings,
    *,
    username: str | None = None,
) -> None:
    """Install the fixed helper through one interactive, user-invoked sudo command."""
    plan = build_install_plan(profile, settings, username or getpass.getuser())
    with tempfile.TemporaryDirectory(
        prefix="meraki-openconnect-install-"
    ) as temporary:
        directory = Path(temporary)
        directory.chmod(0o700)
        _build_native_worker(directory / "meraki-openconnect-native")
        installer = _installation_input(directory, plan)
        subprocess.run(
            ["/usr/bin/sudo", "/bin/sh"], check=True, input=installer
        )


def uninstall_privileged(
    profile: OrganizationProfile | None = None,
    settings: MachineSettings | None = None,
    *,
    username: str | None = None,
) -> None:
    """Remove only the named artifacts for the installed organization profile."""
    if (profile is None) != (settings is None):
        raise PrivilegedError("profile and settings are both required for uninstall")
    if profile is None or settings is None:
        script_text = _uninstall_script(())
    else:
        script_text = build_install_plan(
            profile, settings, username or getpass.getuser()
        ).uninstall_script
    subprocess.run(
        ["/usr/bin/sudo", "/bin/sh"], check=True, input=script_text.encode("ascii")
    )
