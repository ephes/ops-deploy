"""Real DNS installation, convergence, staged includes, rollback and DDNS in owned VM."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import traceback
import urllib.request
from dataclasses import asdict
from importlib import import_module
from pathlib import Path
from typing import Any
from unittest.mock import patch

EVIDENCE = Path(sys.argv[1])
ROOT = Path("/opt/dns-routine-fixture")
TSIG_MATERIAL = base64.b64encode(b"owned-fixture-only-tsig-material!").decode()
BASIC_AUTH_VALUE = "owned-fixture-only-password"


def command(*args: str) -> str:
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout.strip()


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def unit(name: str, text: str) -> None:
    write(Path("/etc/systemd/system") / name, text)
    command("systemctl", "daemon-reload")
    command("systemctl", "start", name)


def snapshot() -> dict[str, Any]:
    result: dict[str, Any] = {}
    for base in ("/etc/unbound", "/etc/ddns", "/etc/ddns-status-endpoint"):
        if Path(base).exists():
            for p in sorted(Path(base).rglob("*")):
                if p.is_file():
                    st = p.stat()
                    result[str(p)] = [
                        hashlib.sha256(p.read_bytes()).hexdigest(),
                        st.st_mode,
                        st.st_uid,
                        st.st_gid,
                        st.st_mtime_ns,
                    ]
    for p in list(Path("/etc/systemd/system").glob("*ddns*")) + list(
        Path("/etc/systemd/system").glob("unbound-blocklist.*")
    ):
        if p.is_file():
            st = p.stat()
            result[str(p)] = [hashlib.sha256(p.read_bytes()).hexdigest(), st.st_mtime_ns]
    for path in [
        "/etc/resolv.conf",
        "/etc/default/unbound",
        "/etc/iptables/rules.v4",
        "/etc/iptables/rules.v6",
        "/var/lib/unbound/blocklist.conf",
        "/var/lib/unbound/allowlist.conf",
        "/usr/local/bin/ddns-update",
        "/usr/local/bin/ddns_status_httpd.py",
        "/usr/local/bin/update-blocklists.sh",
    ]:
        p = Path(path)
        if p.exists():
            st = p.stat()
            result[path] = [
                hashlib.sha256(p.read_bytes()).hexdigest(),
                st.st_mode,
                st.st_uid,
                st.st_gid,
                st.st_mtime_ns,
            ]
    return result


def assert_trace(text: str) -> None:
    mutations = []
    for line in text.splitlines():
        if not re.search(
            r"^(?:[0-9]+\s+)?(?:open|openat|openat2|creat)\(.*(?:O_WRONLY|O_RDWR|O_CREAT|O_TRUNC)|"
            r"^(?:[0-9]+\s+)?(?:mkdir|mkdirat|unlink|unlinkat|rename|renameat|renameat2|chmod|fchmod|fchmodat|chown|lchown|fchown|fchownat|utime|utimes|utimensat|symlink|symlinkat|link|linkat|truncate|ftruncate)\(",
            line,
        ):
            continue
        if '"/dev/null"' in line:
            continue
        if re.search(
            r'openat\(AT_FDCWD, "/dev/tty", O_RDWR\|O_NONBLOCK\) = -1 ENXIO \(No such device or address\)$', line
        ):
            continue
        mutations.append(line)
    assert not mutations, mutations


def deploy(cfg: Any, label: str, *, failure: bool = False) -> dict[str, Any]:
    from pyinfra.api import Config, Inventory, State
    from pyinfra.api.command import QuoteString, StringCommand
    from pyinfra.api.connect import connect_all, disconnect_all
    from pyinfra.api.deploy import add_deploy
    from pyinfra.api.operations import run_ops
    from pyinfra.connectors.local import LocalConnector

    from ops_deploy.core.secrets import SecretRef, SecretValues

    deploy_dns = import_module("ops_deploy.services.dns").deploy_dns
    from ops_deploy.testing.harness import collect_ops

    before = snapshot()
    pids_before = command("systemctl", "show", "unbound", "ddns-status-endpoint", "-p", "MainPID", "--value")
    original_command = LocalConnector.run_shell_command
    counter = 0

    def traced(self: Any, command: Any, **kwargs: Any) -> Any:
        nonlocal counter
        counter += 1
        trace = EVIDENCE / f"{label}-{counter}.strace"
        wrapped = StringCommand(
            "strace",
            "-f",
            "-s",
            "1000000",
            "-e",
            "trace=file,process,fchmod,fchown,ftruncate",
            "-o",
            str(trace),
            "sh",
            "-c",
            QuoteString(command.get_raw_value()),
        )
        result = original_command(self, wrapped, **kwargs)
        assert_trace(trace.read_text())
        return result

    def no_upload(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("repeat attempted helper/file upload")

    patches = []
    if label.endswith("repeat") or label == "role-seeded-first":
        patches = [
            patch.object(LocalConnector, "run_shell_command", traced),
            patch.object(LocalConnector, "put_file", no_upload),
        ]
    for active_patch in patches:
        active_patch.start()
    state = State(Inventory(([("@local", {})], {})), Config())
    error = None
    error_traceback = None
    try:
        connect_all(state)
        add_deploy(
            state,
            deploy_dns,
            cfg=cfg,
            secrets=SecretValues(
                SecretRef("fixture.yml"), {"tsig_secret": TSIG_MATERIAL, "endpoint_password": BASIC_AUTH_VALUE}
            ),
        )
        run_ops(state)
    except Exception as exc:
        error = type(exc).__name__
        error_traceback = traceback.format_exc()
    finally:
        ops = collect_ops(state, "@local")
        disconnect_all(state)
        for active_patch in reversed(patches):
            active_patch.stop()
    record = {
        "error": error,
        "error_traceback": error_traceback,
        "operations": [asdict(x) for x in ops],
        "mutations": [x.name for x in ops if x.changed and not x.read_only],
        "files_unchanged": snapshot() == before,
        "pids_unchanged": command("systemctl", "show", "unbound", "ddns-status-endpoint", "-p", "MainPID", "--value")
        == pids_before,
    }
    (EVIDENCE / (label + ".json")).write_text(json.dumps(record, indent=2))
    if failure:
        assert error is not None, record
    else:
        assert error is None, record
        assert all(x.succeeded for x in ops), record
    if label.endswith("repeat") or label == "role-seeded-first":
        assert not record["mutations"], record
        assert record["files_unchanged"], record
        assert record["pids_unchanged"], record
    return record


def fixtures() -> None:
    ROOT.mkdir(mode=0o755)
    command("ip", "address", "add", "192.0.2.1/32", "dev", "lo")
    command("ip", "address", "add", "100.64.0.1/32", "dev", "lo")
    command("ip", "netns", "add", "dns-routine-fixture")
    command("ip", "link", "add", "dns-host", "type", "veth", "peer", "name", "dns-peer")
    command("ip", "link", "set", "dns-peer", "netns", "dns-routine-fixture")
    command("ip", "address", "add", "10.203.0.1/24", "dev", "dns-host")
    command("ip", "link", "set", "dns-host", "up")
    command("ip", "-n", "dns-routine-fixture", "address", "add", "10.203.0.2/24", "dev", "dns-peer")
    command("ip", "-n", "dns-routine-fixture", "link", "set", "dns-peer", "up")
    command("ip", "-n", "dns-routine-fixture", "link", "set", "lo", "up")
    bindroot = Path("/var/lib/bind/dns-routine-fixture")
    bindroot.mkdir()
    write(
        bindroot / "zone",
        "$TTL 300\n@ IN SOA ns.fixture.example. hostmaster.fixture.example. (1 60 60 3600 60)\n"
        "@ IN NS ns.fixture.example.\nns IN A 10.203.0.2\n",
    )
    write(
        Path("/etc/bind/dns-fixture.conf"),
        f'''options {{ directory "{bindroot}"; listen-on {{10.203.0.2;}}; listen-on-v6 {{none;}};
recursion no; pid-file "/run/named/dns-fixture.pid"; session-keyfile "{bindroot}/session.key"; }};
key "fixture" {{ algorithm hmac-sha256; secret "{TSIG_MATERIAL}"; }};
zone "fixture.example" {{ type primary; file "zone";
update-policy {{ grant fixture name home.fixture.example. A AAAA;
grant fixture name *.home.fixture.example. A AAAA; }}; }};
''',
    )
    command("chown", "-R", "bind:bind", str(bindroot))
    command("install", "-d", "-o", "bind", "-g", "bind", "/run/named")
    unit(
        "dns-fixture-primary.service",
        "[Service]\nExecStart=/usr/sbin/ip netns exec dns-routine-fixture "
        "/usr/sbin/named -g -u bind -c /etc/bind/dns-fixture.conf\n",
    )
    for name, text in [
        ("ipv4", "1.1.1.1\n"),
        ("ipv6", "2606:4700:4700::1111\n"),
        ("hosts", "0.0.0.0 blocked.fixture.example\n"),
    ]:
        write(ROOT / name, text)
    unit(
        "dns-fixture-http.service",
        f"[Service]\nExecStart=/usr/bin/python3 -m http.server 18090 --bind 127.0.0.1 --directory {ROOT}\n",
    )
    time.sleep(1)


def role_seed(cfg: Any) -> None:
    """Render the immutable upstream role with Ansible, not the production renderer."""
    import yaml

    role_vars = import_module("ops_deploy.services.dns.render").role_vars

    source = Path(os.environ["ROLE_SOURCE"]) / "roles/dns_deploy"
    variables = role_vars(cfg, "192.0.2.1", "100.64.0.1", 2)
    variables["dns_ddns_rfc2136_key_secret"] = TSIG_MATERIAL
    mapping = {
        "unbound-base-full.conf.j2": ("/etc/unbound/unbound.conf.d/00-base.conf", "root", "root", "0644"),
        "unbound-split-dns.conf.j2": ("/etc/unbound/unbound.conf.d/10-split-dns.conf", "root", "root", "0644"),
        "unbound-allowlist.conf.j2": ("/var/lib/unbound/allowlist.conf", "unbound", "unbound", "0644"),
        "resolv.conf.j2": ("/etc/resolv.conf", "root", "root", "0644"),
        "update-blocklists.sh.j2": ("/usr/local/bin/update-blocklists.sh", "root", "root", "0755"),
        "ddns-config.json.j2": ("/etc/ddns/config.json", "root", "ddns", "0644"),
        "ddns.env.j2": ("/etc/ddns/credentials.env", "ddns", "ddns", "0600"),
    }
    for name in [
        "unbound-blocklist.service",
        "unbound-blocklist.timer",
        "ddns-update.service",
        "ddns-update.timer",
        "ddns-status-endpoint.service",
    ]:
        mapping[name + ".j2"] = ("/etc/systemd/system/" + name, "root", "root", "0644")
    tasks = [
        {
            "name": "Seed upstream role " + name,
            "ansible.builtin.template": {
                "src": str(source / "templates" / name),
                "dest": dest,
                "owner": user,
                "group": group,
                "mode": mode,
            },
        }
        for name, (dest, user, group, mode) in mapping.items()
    ]
    for name, dest in [
        ("ddns_update.py", "/usr/local/bin/ddns-update"),
        ("ddns_status_httpd.py", "/usr/local/bin/ddns_status_httpd.py"),
    ]:
        tasks.append(
            {
                "name": "Seed upstream role " + name,
                "ansible.builtin.copy": {
                    "src": str(source / "files" / name),
                    "dest": dest,
                    "owner": "root",
                    "group": "root",
                    "mode": "0755",
                },
            }
        )
    play = [{"hosts": "localhost", "gather_facts": False, "vars": variables, "tasks": tasks}]
    path = ROOT / "role-seed.yml"
    path.write_text(yaml.safe_dump(play, allow_unicode=True))
    output = command(os.environ["ANSIBLE_PLAYBOOK"], "-c", "local", "-i", "localhost,", str(path))
    (EVIDENCE / "role-seed.log").write_text(output)
    # Independent bcrypt material proves existing-role credentials are verified,
    # not compared against a hash generated by the new deployment.
    hashed = subprocess.run(
        ["htpasswd", "-niB", "fixture"], input=BASIC_AUTH_VALUE + "\n", text=True, capture_output=True, check=True
    ).stdout
    Path("/etc/ddns-status-endpoint/htpasswd").write_text(hashed)
    command("systemctl", "daemon-reload")
    command("systemctl", "restart", "unbound", "ddns-status-endpoint")


def legacy_fixture(cfg: Any) -> None:
    """Seed exact historical rules in the owned VM; preserve unrelated NAT rules."""
    module = import_module("ops_deploy.services.dns.files.legacy_host")
    expected = {}
    for family, tool, source, destination in (
        (4, "iptables", "100.64.0.0/10", "127.0.0.1:5335"),
        (6, "ip6tables", "fd7a:115c:a1e0::/48", "[::1]:5335"),
    ):
        command(tool, "-t", "nat", "-N", "DNS_FIXTURE_UNRELATED")
        command(tool, "-t", "nat", "-A", "DNS_FIXTURE_UNRELATED", "-j", "RETURN")
        command(tool, "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", "19535", "-j", "DNS_FIXTURE_UNRELATED")
        for proto in ("tcp", "udp"):
            sources = (source, None) if family == 4 else (source,)
            for network in sources:
                args = [tool, "-t", "nat", "-A", "PREROUTING"]
                if network:
                    args += ["-s", network]
                command(*args, "-p", proto, "--dport", "53", "-j", "DNAT", "--to-destination", destination)
        original = command(tool + "-save", "-t", "nat") + "\n"
        filtered, removed = module.filter_rules(original, family)
        assert len(removed) == (4 if family == 4 else 2)
        persistent = Path("/etc/iptables/rules.v" + str(family))
        assert not persistent.exists(), "fixture must not overwrite existing persistent rules"
        write(persistent, original)
        persistent.chmod(0o640)
        expected[family] = filtered
    LocalRecord = import_module("ops_deploy.services.dns.config").LocalRecord
    invalid = cfg.model_copy(
        update={"local_records": (LocalRecord(name="invalid.example", type="A", value="not-an-address"),)}
    )
    before_rules = {tool: command(tool, "-t", "nat", "-S") for tool in ("iptables", "ip6tables")}
    refused = deploy(invalid, "legacy-invalid-candidate", failure=True)
    assert refused["files_unchanged"]
    assert refused["pids_unchanged"]
    assert before_rules == {tool: command(tool, "-t", "nat", "-S") for tool in before_rules}
    deploy(cfg, "legacy-cleanup")
    for family, tool in ((4, "iptables"), (6, "ip6tables")):
        persistent = Path("/etc/iptables/rules.v" + str(family))
        assert persistent.read_text() == expected[family]
        assert persistent.stat().st_mode & 0o777 == 0o640
        assert persistent.stat().st_uid == persistent.stat().st_gid == 0
        actual = command(tool + "-save", "-t", "nat")
        assert not module.filter_rules(actual, family)[1]

        # iptables-save timestamps are not rules and naturally differ.
        def rules(text: str) -> list[str]:
            return [line for line in text.splitlines() if not line.startswith("#")]

        assert rules(actual) == rules(expected[family])
    deploy(cfg, "legacy-repeat")


def main() -> None:
    from ops_deploy.core.secrets import SecretRef

    DdnsEndpointConfig = import_module("ops_deploy.services.dns").DdnsEndpointConfig
    DnsConfig = import_module("ops_deploy.services.dns").DnsConfig
    LocalRecord = import_module("ops_deploy.services.dns.config").LocalRecord

    marker = json.loads(Path("/var/tmp/dns-routine-owned-vm.json").read_text())
    assert marker["run"] == os.environ["GITHUB_RUN_ID"]
    assert marker["machine"] == Path("/etc/machine-id").read_text().strip()
    fixtures()
    cfg = DnsConfig(
        local_domain="home.fixtüre.example",
        local_domain_punycode="home.fixture.example",
        split_lan_ip="192.0.2.1",
        split_tailscale_ip="100.64.0.1",
        processor_vcpus=2,
        split_lan_network="192.0.2.0/24",
        blocklists=("http://127.0.0.1:18090/hosts",),
        update_resolv_conf=True,
    )
    # Exercise the actual Ubuntu stub-resolver symlink replacement path.
    resolver = Path("/etc/resolv.conf")
    write(ROOT / "resolver-stub.conf", resolver.read_text())
    resolver.unlink()
    resolver.symlink_to(ROOT / "resolver-stub.conf")
    deploy(cfg, "fresh-install")
    assert not Path("/etc/resolv.conf").is_symlink()
    deploy(cfg, "fresh-repeat")
    legacy_fixture(cfg)
    # Includes outside the glob but inside the complete configuration tree must be staged too.
    write(Path("/etc/unbound/operator/extra.inc"), 'server:\n local-zone: "unrelated.example" static\n')
    write(Path("/etc/unbound/unbound.conf.d/operator.conf"), 'include: "/etc/unbound/operator/*.inc"\n')
    command("systemctl", "restart", "unbound")
    preserved = snapshot()
    changed = cfg.model_copy(update={"unbound_prefetch": True})
    deploy(changed, "config-update")
    deploy(changed, "config-repeat")
    for p in [
        "/etc/unbound/operator/extra.inc",
        "/etc/unbound/unbound.conf.d/operator.conf",
        "/etc/resolv.conf",
        "/etc/default/unbound",
        "/var/lib/unbound/blocklist.conf",
    ]:
        assert snapshot()[p] == preserved[p]
    pid = command("systemctl", "show", "unbound", "-p", "MainPID", "--value")
    invalid = changed.model_copy(
        update={"local_records": (LocalRecord(name="invalid.example", type="A", value="not-an-address"),)}
    )
    invalid_result = deploy(invalid, "invalid-config", failure=True)
    assert invalid_result["files_unchanged"]
    assert command("systemctl", "show", "unbound", "-p", "MainPID", "--value") == pid
    # A real one-shot restart failure, with a recoverable original unit.
    write(
        Path("/etc/systemd/system/unbound.service.d/fixture-fault.conf"),
        f'[Service]\nRestart=no\nExecStartPre=/bin/sh -c "if test -e {ROOT}/fail-once; '
        f'then rm {ROOT}/fail-once; exit 1; fi"\n',
    )
    command("systemctl", "daemon-reload")
    write(ROOT / "fail-once", "fixture\n")
    before = snapshot()
    deploy(cfg, "restart-failure", failure=True)
    after = snapshot()
    # Restoration is byte/mode/ownership exact; replacement naturally changes mtime.
    assert {p: v[:4] for p, v in before.items()} == {p: v[:4] for p, v in after.items()}
    assert command("systemctl", "is-active", "unbound") == "active"
    deploy(changed, "recovered-repeat")
    ddns = changed.model_copy(
        update={
            "ddns_enabled": True,
            "ddns_domain": "fixture.example",
            "ddns_interval": "1h",
            "ddns_rfc2136_server": "10.203.0.2",
            "ddns_rfc2136_key_name": "fixture",
            "ddns_rfc2136_update_zone": "fixture.example",
            "ddns_verify_nameservers": ("10.203.0.2",),
            "ddns_ipv4_source_url": "http://127.0.0.1:18090/ipv4",
            "ddns_ipv6_source_url": "http://127.0.0.1:18090/ipv6",
            "endpoint": DdnsEndpointConfig(secrets=SecretRef("fixture.yml"), auth_user="fixture"),
        }
    )
    deploy(ddns, "ddns-install")
    status = json.loads(Path("/var/lib/ddns/status.json").read_text())
    assert status["summary"]["run_ok"], status["summary"]
    assert status["summary"]["public_ok"], status["summary"]
    auth = base64.b64encode(("fixture:" + BASIC_AUTH_VALUE).encode()).decode()
    request = urllib.request.Request(
        "http://100.64.0.1:9112/.well-known/ddns", headers={"Authorization": "Basic " + auth}
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        assert json.load(response)["summary"]["run_ok"]
    last = command("systemctl", "show", "ddns-update", "-p", "ExecMainStartTimestampMonotonic", "--value")
    deploy(ddns, "ddns-repeat")
    role_seed(ddns)
    deploy(ddns, "role-seeded-first")
    deploy(ddns, "role-seeded-repeat")
    assert command("systemctl", "show", "ddns-update", "-p", "ExecMainStartTimestampMonotonic", "--value") == last
    # Exercise the shared current pinned Rust implementation and return to Python.
    assert ddns.endpoint is not None
    rust_endpoint = ddns.endpoint.model_copy(
        update={
            "httpd_impl": "rust",
            "httpd_rust_version": "0.1.0",
            "httpd_rust_sha256": "7befbd0f4151d6eb11009d7a93a7e7defbd4559cb0c2086915fa598c6d85fc27",
        }
    )
    rust_cfg = ddns.model_copy(update={"endpoint": rust_endpoint})
    deploy(rust_cfg, "rust-switch")
    deploy(rust_cfg, "rust-repeat")
    deploy(ddns, "python-return")
    deploy(ddns, "python-return-repeat")
    (EVIDENCE / "summary.json").write_text(
        json.dumps(
            {
                "implementation": os.environ["IMPLEMENTATION_SHA"],
                "harness": os.environ["HARNESS_SHA"],
                "phases": 18,
                "status": "passed",
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
