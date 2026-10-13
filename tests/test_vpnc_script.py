from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


SERVICE = "00000000-0000-0000-0000-000000000001"
OTHER_SERVICE = "00000000-0000-0000-0000-000000000002"
VPN_DNS = "192.0.2.53"


@pytest.fixture
def script_host(tmp_path: Path):
    commands = tmp_path / "commands"
    commands.mkdir()
    state_file = tmp_path / "host.json"
    state_file.write_text(json.dumps({
        "primary": SERVICE,
        "services": {
            SERVICE: {"name": "Example Wi-Fi", "interface": "en0", "dns": [],
                      "dhcp": [VPN_DNS, "198.51.100.53"]},
            OTHER_SERVICE: {"name": "Example Ethernet", "interface": "en1", "dns": [],
                            "dhcp": ["203.0.113.53"]},
        },
        "writes": [], "keys": {}, "fail_write": False,
    }))
    mock = commands / "mock"
    mock.write_text(f"#!{sys.executable}\n" + r'''
import json, os, sys
from pathlib import Path
state_file = Path(os.environ["HOST_STATE"])
state = json.loads(state_file.read_text())
command = Path(sys.argv[0]).name
args = sys.argv[1:]
if command == "uname":
    print(os.environ.get("HOST_OS", "Darwin") if args == ["-s"] else "25.0.0")
elif command == "id":
    print("0")
elif command == "stat":
    print("0" if args[1] == "%u" else oct(Path(args[-1]).stat().st_mode & 0o777)[2:])
elif command == "ls":
    print("root-owned fixture without ACL")
elif command == "scutil":
    lines = sys.stdin.read().splitlines()
    for line in lines:
        parts = line.strip().split()
        if not parts:
            continue
        if parts[0] == "show":
            key = parts[1]
            if key == "State:/Network/Global/IPv4":
                print("<dictionary> {\n  PrimaryService : " + state["primary"] + "\n}")
            elif key.startswith("Setup:/Network/Service/"):
                service = state["services"].get(key.split("/")[3])
                if service:
                    prop = "DeviceName" if key.endswith("/Interface") else "UserDefinedName"
                    value = service["interface"] if prop == "DeviceName" else service["name"]
                    print("<dictionary> {\n  " + prop + " : " + value + "\n}")
                else:
                    print("No such key")
        elif parts[0] in {"set", "remove"}:
            state["writes"].append(line.strip())
            if parts[0] == "set":
                state["keys"][parts[1]] = True
            else:
                state["keys"].pop(parts[1], None)
elif command == "networksetup":
    service = next((v for v in state["services"].values() if v["name"] == args[1]), None)
    if service is None:
        sys.exit(1)
    if args[0] == "-getdnsservers":
        print("\n".join(service["dns"]) if service["dns"] else
              "There aren't any DNS Servers set on " + args[1] + ".")
    else:
        state["writes"].append(args)
        if state["fail_write"]:
            sys.exit(1)
        service["dns"] = [] if args[2:] == ["Empty"] else args[2:]
elif command == "route":
    if "get" in args:
        print("   interface: en0\n   gateway: 192.0.2.1")
elif command == "netstat":
    print("Destination Gateway Flags Netif")
state_file.write_text(json.dumps(state))
''')
    mock.chmod(0o755)
    for command in ("uname", "id", "stat", "ls", "scutil", "networksetup", "route", "ifconfig", "netstat"):
        (commands / command).symlink_to(mock)
    for command in ("grep", "awk", "sed", "xargs", "mkdir", "rm", "rmdir", "cat", "wc", "basename", "head", "cut", "tr", "expr", "cp", "readlink"):
        (commands / command).symlink_to(shutil.which(command))
    source = Path(__file__).parents[1] / "native" / "vpnc-script"
    script = tmp_path / "vpnc-script"
    script.write_text(source.read_text()
                      .replace("PATH=/sbin:/usr/sbin:$PATH", 'PATH="$FAKE_COMMANDS"')
                      .replace("/var/run", str(tmp_path / "run"))
                      .replace("/etc/", str(tmp_path / "etc") + "/")
                      .replace("/usr/sbin/", str(commands) + "/")
                      .replace("/usr/bin/", str(commands) + "/")
                      .replace("/sbin/", str(commands) + "/"))
    runtime = tmp_path / "run" / "meraki-openconnect"
    runtime.mkdir(parents=True, mode=0o700)
    resolv = tmp_path / "etc" / "resolv.conf"
    resolv.parent.mkdir()
    resolv.write_text("nameserver 198.51.100.53\n")

    class Host:
        def read(self):
            return json.loads(state_file.read_text())

        def update(self, state):
            state_file.write_text(json.dumps(state))

        def run(self, reason, **overrides):
            env = {**os.environ, "FAKE_COMMANDS": str(commands), "HOST_STATE": str(state_file),
                   "reason": reason, "VPNPID": "1234", "TUNDEV": "utun9",
                   "VPNGATEWAY": "192.0.2.1", "INTERNAL_IP4_ADDRESS": "192.0.2.10",
                   "INTERNAL_IP4_DNS": VPN_DNS, "CISCO_SPLIT_INC": "0", **overrides}
            return subprocess.run(["/bin/sh", str(script)], env=env, text=True,
                                  capture_output=True, check=False)

        recovery = runtime / "dns.1234"
        resolv_conf = resolv

    return Host()


@pytest.mark.parametrize("original", [[], [VPN_DNS], [VPN_DNS, "2001:db8::53", "198.51.100.53"]])
def test_connect_disconnect_preserves_existing_dns(script_host, original):
    state = script_host.read()
    state["services"][SERVICE]["dns"] = original
    script_host.update(state)
    assert script_host.run("connect").returncode == 0
    assert script_host.run("disconnect").returncode == 0
    state = script_host.read()
    assert state["services"][SERVICE]["dns"] == original
    assert state["services"][SERVICE]["dhcp"] == [VPN_DNS, "198.51.100.53"]
    assert not any(isinstance(w, str) and SERVICE in w for w in state["writes"])
    assert not script_host.recovery.exists()
    assert script_host.resolv_conf.read_text() == "nameserver 198.51.100.53\n"
    assert not state["keys"]


def test_disconnect_uses_original_service_and_current_dhcp(script_host):
    assert script_host.run("connect").returncode == 0
    state = script_host.read()
    state["primary"] = OTHER_SERVICE
    state["services"][SERVICE]["name"] = "Renamed Wi-Fi"
    state["services"][SERVICE]["dhcp"] = ["203.0.113.54"]
    script_host.update(state)
    assert script_host.run("disconnect").returncode == 0
    state = script_host.read()
    assert state["services"][SERVICE]["dns"] == []
    assert state["services"][SERVICE]["dhcp"] == ["203.0.113.54"]
    assert not any(isinstance(w, list) and w[1] == "Example Ethernet" for w in state["writes"])


def test_disconnect_preserves_later_manual_change_and_is_repeatable(script_host):
    assert script_host.run("connect").returncode == 0
    state = script_host.read()
    state["services"][SERVICE]["dns"] = ["203.0.113.53"]
    script_host.update(state)
    assert script_host.run("disconnect").returncode == 0
    assert script_host.run("disconnect").returncode == 0
    assert script_host.read()["services"][SERVICE]["dns"] == ["203.0.113.53"]
    assert not script_host.recovery.exists()


@pytest.mark.parametrize("failure", ["write", "missing_service", "changed_interface"])
def test_failed_restoration_retains_recovery_state(script_host, failure):
    assert script_host.run("connect").returncode == 0
    state = script_host.read()
    if failure == "write":
        state["fail_write"] = True
    elif failure == "missing_service":
        del state["services"][SERVICE]
    else:
        state["services"][SERVICE]["interface"] = "en2"
    script_host.update(state)
    assert script_host.run("disconnect").returncode != 0
    assert script_host.recovery.exists()
    assert not script_host.read()["keys"]


def test_missing_dns_environment_does_not_skip_owned_cleanup(script_host):
    assert script_host.run("connect").returncode == 0
    assert script_host.run("disconnect", INTERNAL_IP4_DNS="").returncode == 0
    assert script_host.read()["services"][SERVICE]["dns"] == []
    assert not script_host.recovery.exists()


def test_reconnect_does_not_replace_original_record(script_host):
    assert script_host.run("connect").returncode == 0
    original = (script_host.recovery / "record").read_bytes()
    assert script_host.run("attempt-reconnect").returncode == 0
    assert script_host.run("reconnect").returncode == 0
    assert (script_host.recovery / "record").read_bytes() == original
    assert script_host.run("disconnect").returncode == 0


def test_symlinked_recovery_state_is_not_followed(script_host, tmp_path):
    target = tmp_path / "unrelated"
    target.mkdir()
    script_host.recovery.symlink_to(target)
    assert script_host.run("connect").returncode != 0
    assert script_host.run("disconnect").returncode != 0
    assert list(target.iterdir()) == []
    assert not any(isinstance(w, list) for w in script_host.read()["writes"])


@pytest.mark.parametrize("damage", ["missing_record", "symlink_record", "writable_record", "invalid_dns", "extra_data"])
def test_invalid_recovery_record_is_preserved_without_dns_writes(script_host, damage):
    assert script_host.run("connect").returncode == 0
    record = script_host.recovery / "record"
    if damage == "missing_record":
        record.unlink()
    elif damage == "symlink_record":
        target = record.with_name("unrelated")
        record.rename(target)
        record.symlink_to(target)
    elif damage == "writable_record":
        record.chmod(0o666)
    elif damage == "invalid_dns":
        record.write_text(f"{SERVICE}\nen0\n$(touch marker)\n{VPN_DNS}\n")
    else:
        with record.open("a") as stream:
            stream.write("unexpected unterminated data")
    writes_before = [w for w in script_host.read()["writes"] if isinstance(w, list)]
    assert script_host.run("disconnect").returncode != 0
    assert script_host.recovery.exists()
    assert [w for w in script_host.read()["writes"] if isinstance(w, list)] == writes_before


@pytest.mark.parametrize("invalid", ["192.0.2.999", "2001:::53", "-setdnsservers", "192.0.2.53;echo"])
def test_invalid_vpn_dns_is_rejected_before_override(script_host, invalid):
    assert script_host.run("connect", INTERNAL_IP4_DNS=invalid).returncode != 0
    assert not any(isinstance(w, list) for w in script_host.read()["writes"])
    assert not script_host.recovery.exists()


def test_failed_dns_write_keeps_original_for_later_cleanup(script_host):
    state = script_host.read()
    state["fail_write"] = True
    script_host.update(state)
    assert script_host.run("connect").returncode != 0
    assert script_host.recovery.exists()
    state = script_host.read()
    state["fail_write"] = False
    script_host.update(state)
    assert script_host.run("disconnect").returncode == 0
    assert script_host.read()["services"][SERVICE]["dns"] == []
    assert not script_host.recovery.exists()


@pytest.mark.parametrize("split_count", ["", "1"])
def test_full_and_split_routes_use_the_same_dns_restoration(script_host, split_count):
    env = {"CISCO_SPLIT_INC": split_count, "CISCO_SPLIT_INC_0_ADDR": "198.51.100.0",
           "CISCO_SPLIT_INC_0_MASK": "255.255.255.0", "CISCO_SPLIT_INC_0_MASKLEN": "24"}
    assert script_host.run("connect", **env).returncode == 0
    assert script_host.run("disconnect", **env).returncode == 0
    assert script_host.read()["services"][SERVICE]["dns"] == []
    assert not script_host.recovery.exists()


def test_non_macos_retains_resolv_conf_backup_restoration(script_host):
    original = script_host.resolv_conf.read_text()
    assert script_host.run("connect", HOST_OS="NetBSD").returncode == 0
    assert f"nameserver {VPN_DNS}" in script_host.resolv_conf.read_text()
    assert script_host.run("disconnect", HOST_OS="NetBSD").returncode == 0
    assert script_host.resolv_conf.read_text() == original
    assert not any(isinstance(w, list) for w in script_host.read()["writes"])
