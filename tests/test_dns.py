from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core.config import ConfigValidationError
from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.dns.config import DnsConfig
from ops_deploy.services.dns.deploy import configuration_command, validate_secrets
from ops_deploy.services.dns.render import configuration, render, role_vars


def test_root_forwarder_and_record_validation() -> None:
    cfg = DnsConfig(forward_zones=({"name": ".", "forward_addrs": ["1.1.1.1"]},))
    assert cfg.forward_zones[0].name == "."
    with pytest.raises(ConfigValidationError):
        DnsConfig(local_records=({"name": "host.example.com", "type": "A", "value": "1.2.3.4\nserver:"},))
    with pytest.raises(ConfigValidationError):
        DnsConfig(blocklists=("https://example.com/$(touch /tmp/x)",))


def test_role_render_preserves_actual_allowlist_contract() -> None:
    cfg = DnsConfig()
    variables = role_vars(cfg, "192.0.2.1", "100.64.0.1", 4)
    result = configuration(cfg, variables)
    assert result["/etc/unbound/unbound.conf.d/05-forward-zones.conf"] is None
    assert "access-control: 0.0.0.0/0 refuse" in str(result["/etc/unbound/unbound.conf.d/00-base.conf"])
    assert "num-threads: 4" in str(result["/etc/unbound/unbound.conf.d/00-base.conf"])
    assert 'local-zone: "github.com" transparent' in render("unbound-allowlist.conf.j2", variables)
    assert render("resolv.conf.j2", variables).endswith("options edns0 trust-ad\n")


def test_ddns_rfc2136_config_has_no_secret() -> None:
    cfg = DnsConfig(ddns_enabled=True, ddns_gandi_auth_scheme="apikey")
    data = json.loads(render("ddns-config.json.j2", role_vars(cfg, "192.0.2.1", "100.64.0.1", 2)))
    assert data["providers"] == ["rfc2136"]
    assert data["gandi"]["auth_scheme"] == "apikey"
    assert "key_secret" not in data["rfc2136"]
    with pytest.raises(Exception, match="key material"):
        validate_secrets(cfg, SecretValues(SecretRef("fixture.yml"), {"tsig_secret": "invalid\nsecret"}))


def host_module() -> Any:
    path = Path(__file__).parents[1] / "src/ops_deploy/services/dns/files/config_host.py"
    spec = importlib.util.spec_from_file_location("dns_config_host", path)
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_converged_config_never_stages_or_starts(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    module = host_module()
    wanted = {p: "server:\n" for p in module.OWNED}
    monkeypatch.setattr(module.pwd, "getpwnam", lambda _: type("User", (), {"pw_uid": 10, "pw_gid": 10})())
    monkeypatch.setattr(
        module, "state", lambda p: (b"server:\n", 0o644, *((10, 10) if p.startswith("/var/") else (0, 0)))
    )
    monkeypatch.setattr(module.tempfile, "TemporaryDirectory", lambda **_: pytest.fail("no-op created staging"))
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: pytest.fail("no-op called systemd"))
    module.main({"files": wanted, "apply": True})
    assert capsys.readouterr().out == "changed=false\n"


def test_changed_check_never_stages(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    module = host_module()
    monkeypatch.setattr(module, "state", lambda p: None)
    monkeypatch.setattr(module.tempfile, "TemporaryDirectory", lambda **_: pytest.fail("check staged files"))
    module.main({"files": {p: "server:\n" for p in module.OWNED}})
    assert capsys.readouterr().out == "changed=true\n"


def test_reject_unknown_path_before_read(monkeypatch: pytest.MonkeyPatch) -> None:
    module = host_module()
    monkeypatch.setattr(module, "state", lambda p: pytest.fail("read before admission"))
    with pytest.raises(ValueError, match="unexpected DNS"):
        module.main({"files": {"/etc/shadow": "x"}})


def test_transport_argv_is_source_only() -> None:
    command = configuration_command()
    assert "python3 -I -B -c" in command
    assert "DDNS_TSIG_SECRET=" not in command
    assert "json.load(sys.stdin)" in command


def test_candidate_include_rewrite_and_failed_restart_restores_owned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = host_module()
    owned = "/etc/unbound/unbound.conf.d/00-base.conf"
    originals: dict[str, Any] = {p: None for p in module.OWNED}
    originals[owned] = (b"server:\n  verbosity: 1\n", 0o640, 27, 28)
    writes: list[tuple[str, Any]] = []
    staged = tmp_path / "candidate"
    staged.mkdir()

    class Stage:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def __enter__(self) -> str:
            return str(staged)

        def __exit__(self, *args: Any) -> None:
            pass

    def copy(source: str, target: Path, **kwargs: Any) -> None:
        target.mkdir(parents=True)
        if source == "/etc/unbound":
            (target / "unbound.conf.d").mkdir()
            (target / "unbound.conf").write_text('include-toplevel: "/etc/unbound/unbound.conf.d/*.conf"\n')
            (target / "unbound.conf.d/unrelated.conf").write_text('server:\n  local-zone: "unrelated.example" static\n')
        else:
            (target / "blocklist.conf").write_text('server:\n  local-zone: "blocked.example" always_nxdomain\n')

    calls: list[list[str]] = []

    def run(args: list[str]) -> str:
        calls.append(args)
        if args[0] == "unbound-checkconf":
            top = Path(args[1]).read_text()
            assert str(staged / "etc/unbound/unbound.conf.d") in top
            assert (staged / "etc/unbound/unbound.conf.d/unrelated.conf").exists()
            candidate = (staged / owned.lstrip("/")).read_text()
            assert str(staged / "var/lib/unbound/blocklist.conf") in candidate
        elif len([x for x in calls if x[0] == "systemctl"]) == 1:
            raise RuntimeError("simulated restart failure")
        return ""

    monkeypatch.setattr(module, "state", lambda p: originals[p])
    monkeypatch.setattr(module.pwd, "getpwnam", lambda _: type("User", (), {"pw_uid": 10, "pw_gid": 10})())
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: type("Result", (), {"returncode": 0})())
    monkeypatch.setattr(module.tempfile, "TemporaryDirectory", Stage)
    monkeypatch.setattr(module.shutil, "copytree", copy)
    monkeypatch.setattr(module, "run", run)
    monkeypatch.setattr(module, "replace", lambda p, v: writes.append((p, v)))
    desired: dict[str, Any] = {p: None for p in module.OWNED}
    desired[owned] = 'server:\n  include: "/var/lib/unbound/blocklist.conf"\n'
    with pytest.raises(RuntimeError, match="restart failure"):
        module.main({"files": desired, "apply": True, "probes": []})
    assert writes[-1] == (owned, originals[owned])
    assert {p for p, _ in writes} == {owned}
    assert calls[-1] == ["systemctl", "restart", "unbound"]


def test_invalid_candidate_never_changes_files_or_service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = host_module()
    monkeypatch.setattr(module, "state", lambda p: None)
    monkeypatch.setattr(module.pwd, "getpwnam", lambda _: type("User", (), {"pw_uid": 10, "pw_gid": 10})())
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **k: type("Result", (), {"returncode": 0})())

    def copy(source: str, target: Path, **kwargs: Any) -> None:
        target.mkdir(parents=True)
        if source == "/etc/unbound":
            (target / "unbound.conf.d").mkdir()
            (target / "unbound.conf").write_text('include: "/etc/unbound/unbound.conf.d/*.conf"\n')

    monkeypatch.setattr(module.shutil, "copytree", copy)
    monkeypatch.setattr(module, "replace", lambda *a: pytest.fail("invalid candidate changed live file"))

    def reject(args: list[str]) -> str:
        assert args[0] == "unbound-checkconf"
        raise RuntimeError("validator rejected")

    monkeypatch.setattr(module, "run", reject)
    with pytest.raises(RuntimeError, match="validator rejected"):
        module.main({"files": {p: "invalid syntax\n" for p in module.OWNED}, "apply": True})


@pytest.mark.parametrize(
    "override", [{"user": "other"}, {"group": "other"}, {"bind": "127.0.0.1"}, {"path": "/ok\nUser=root"}]
)
def test_endpoint_admission_matches_unit(override: dict[str, str]) -> None:
    from ops_deploy.services.dns.config import DdnsEndpointConfig

    with pytest.raises(ConfigValidationError):
        DdnsEndpointConfig(secrets=SecretRef("fixture.yml"), auth_user="fixture", **override)


def test_include_graph_copies_external_and_nonconf_dependencies(tmp_path: Path) -> None:
    module = host_module()
    root = tmp_path / "stage"
    external = tmp_path / "external.inc"
    external.write_text('server:\n include: "/var/lib/unbound/nested.data"\n')
    top = root / "etc/unbound/unbound.conf"
    top.parent.mkdir(parents=True)
    top.write_text('include: "' + str(external) + '"\n')
    nested = root / "var/lib/unbound/nested.data"
    nested.parent.mkdir(parents=True)
    nested.write_text('server:\n local-zone: "blocked.fixture.example" static\n')
    module.stage_includes(root)
    assert str(root / str(external).lstrip("/")) in top.read_text()
    copied = root / str(external).lstrip("/")
    assert str(nested) in copied.read_text()
    assert external.read_text() == 'server:\n include: "/var/lib/unbound/nested.data"\n'


def test_shipped_role_resource_bytes_match_recorded_digests() -> None:
    # Portable default-suite coverage, plus upstream drift checks with OPS_LIBRARY_PATH.
    manifest = json.loads((Path(__file__).parent / "parity/dns_resources.json").read_text())
    package = Path(__file__).parents[1] / "src/ops_deploy/services/dns"
    import hashlib

    for name, digest in manifest.items():
        assert hashlib.sha256((package / name).read_bytes()).hexdigest() == digest


def test_native_trace_detects_ephemeral_writes_without_matching_source_argv(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    monkeypatch.setattr(sys, "argv", ["harness.py", "/tmp/not-used-dns-evidence"])
    path = Path(__file__).parent / "integration/dns/harness.py"
    spec = importlib.util.spec_from_file_location("dns_native_harness", path)
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.assert_trace('123 execve("python3", ["python3", "-c", "os.fchmod(fd, 384)"], []) = 0')
    module.assert_trace('123 openat(AT_FDCWD, "/etc/unbound/unbound.conf", O_RDONLY) = 3')
    from pyinfra.api.command import StringCommand

    assert module.raw_command("uname -s") == "uname -s"
    assert module.raw_command(StringCommand("uname", "-s")) == "uname -s"
    dig = '11212 execve("/usr/bin/dig", ["dig"], []) = 0\n'
    module.assert_trace(dig + '11212 openat(AT_FDCWD, "/proc/self/task/11214/comm", O_RDWR) = 11')
    for changed in [
        '11213 openat(AT_FDCWD, "/proc/self/task/11214/comm", O_RDWR) = 11',
        '11212 openat(AT_FDCWD, "/proc/sys/kernel/hostname", O_RDWR) = 11',
        '11212 openat(AT_FDCWD, "/proc/self/task/11214/comm", O_RDWR|O_CREAT) = 11',
        '11212 openat(AT_FDCWD, "/tmp/write", O_WRONLY|O_CREAT, 0600) = 11',
    ]:
        with pytest.raises(AssertionError):
            module.assert_trace(dig + changed)
    with pytest.raises(AssertionError):
        module.assert_trace('123 openat(AT_FDCWD, "/tmp/hidden-stage", O_WRONLY|O_CREAT, 0600) = 3')
    with pytest.raises(AssertionError):
        module.assert_trace('123 unlink("/tmp/hidden-stage") = 0')


def dns_helper(name: str) -> Any:
    path = Path(__file__).parents[1] / "src/ops_deploy/services/dns/files" / (name + ".py")
    spec = importlib.util.spec_from_file_location("dns_" + name, path)
    assert spec
    assert spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("idle_job", ["", "0"])
def test_periodic_wait_observes_queued_running_then_success(monkeypatch: pytest.MonkeyPatch, idle_job: str) -> None:
    from types import SimpleNamespace

    module = dns_helper("wait_job")
    states = iter(
        [
            "Job=21\nActiveState=inactive\nResult=success",
            "Job=21\nActiveState=activating\nResult=success",
            f"Job={idle_job}\nActiveState=inactive\nResult=success",
        ]
    )
    calls = []

    def run(args: list[str], **kwargs: Any) -> Any:
        calls.append(args)
        return SimpleNamespace(stdout=next(states))

    monkeypatch.setattr(module.subprocess, "run", run)
    monkeypatch.setattr(module.time, "sleep", lambda _: None)
    module.wait("ddns-update.service")
    assert len(calls) == 3
    assert all(args[:2] == ["systemctl", "show"] for args in calls)


@pytest.mark.parametrize(
    ("state", "message"),
    [
        ("Job=\nActiveState=failed\nResult=exit-code", "job failed"),
        ("ActiveState=inactive\nResult=success", "did not complete"),
        ("Job=42\nActiveState=activating\nResult=success", "did not complete"),
    ],
)
def test_periodic_wait_fails_bounded(monkeypatch: pytest.MonkeyPatch, state: str, message: str) -> None:
    from types import SimpleNamespace

    module = dns_helper("wait_job")
    clock = iter([0, 0, 1, 2])
    monkeypatch.setattr(module.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(module.time, "sleep", lambda _: None)
    monkeypatch.setattr(module.subprocess, "run", lambda *a, **kw: SimpleNamespace(stdout=state))
    with pytest.raises(RuntimeError, match=message):
        module.wait("unbound-blocklist.service", timeout=2)


@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize("proto", ["tcp", "udp"])
def test_legacy_selector_preserves_unrelated_rules_and_tables(family: int, proto: str) -> None:
    module = dns_helper("legacy_host")
    target = "127.0.0.1:5335" if family == 4 else "[::1]:5335"
    source = "100.64.0.0/10" if family == 4 else "fd7a:115c:a1e0::/48"
    rule = f"-A PREROUTING -s {source} -p {proto} -m {proto} --dport 53 -j DNAT --to-destination {target}\n"
    unrelated = "-A PREROUTING -p tcp -m tcp --dport 5335 -j RETURN\n"
    original = "*nat\n:PREROUTING ACCEPT [0:0]\n" + unrelated + rule + "COMMIT\n*filter\n" + rule + "COMMIT\n"
    filtered, removed = module.filter_rules(original, family)
    assert len(removed) == 1
    assert filtered == original.replace(unrelated + rule, unrelated, 1)
    assert not module.owned((rule.strip() + " -i eth0").split(), family)
    assert not module.owned(rule.replace("--dport 53", "--dport 54").split(), family)


def test_legacy_known_absence_is_distinct_from_unknown_read_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    from types import SimpleNamespace

    module = dns_helper("legacy_host")
    monkeypatch.setattr(module.shutil, "which", lambda _: None)
    assert module.runtime(4)[2] == "tools-absent"
    monkeypatch.setattr(module.shutil, "which", lambda name: "/sbin/" + name)
    monkeypatch.setattr(
        module.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=1, stderr="Permission denied")
    )
    with pytest.raises(ValueError, match="cannot read"):
        module.runtime(4)
    monkeypatch.setattr(
        module.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=1, stderr="Table does not exist")
    )
    assert module.runtime(6)[2] == "nat-table-absent"
    monkeypatch.setattr(module.shutil, "which", lambda name: None if name.endswith("-save") else "/sbin/" + name)
    with pytest.raises(ValueError, match="incomplete"):
        module.runtime(4)


def test_invalid_candidate_retains_legacy_forwarding(monkeypatch: pytest.MonkeyPatch) -> None:
    from importlib import import_module
    from types import SimpleNamespace

    module = import_module("ops_deploy.services.dns.deploy")
    calls = []
    for name in ("require_linux", "require_systemd"):
        monkeypatch.setattr(module, name, lambda *a: None)
    monkeypatch.setattr(module, "target_inputs", lambda _: ("192.0.2.1", "100.64.0.1", 2))
    monkeypatch.setattr(module, "legacy_admission", lambda: ("legacy-cleanup", True))
    monkeypatch.setattr(module, "probe", lambda *a, **kw: "not-found")
    monkeypatch.setattr(module, "host", SimpleNamespace(get_fact=lambda *a, **kw: {"size": 1}))
    monkeypatch.setattr(module.apt, "packages", lambda **kw: None)
    monkeypatch.setattr(module.systemd, "service", lambda **kw: None)
    for name in ("line", "link", "directory"):
        monkeypatch.setattr(module.files, name, lambda **kw: None)
    monkeypatch.setattr(module, "secret_stdin", lambda **kw: calls.append(kw))

    def reject(*args: Any) -> None:
        raise RuntimeError("invalid candidate")

    monkeypatch.setattr(module, "apply_configuration", reject)
    with pytest.raises(RuntimeError, match="invalid candidate"):
        module.deploy_dns.__wrapped__(DnsConfig(), SecretValues(SecretRef("fixture.yml"), {}))
    assert calls == []


def test_legacy_apply_deletes_rules_individually_without_restore(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = dns_helper("legacy_host")
    rule4 = "-A PREROUTING -p tcp --dport 53 -j DNAT --to-destination 127.0.0.1:5335"
    rule6 = "-A PREROUTING -s fd7a:115c:a1e0::/48 -p udp --dport 53 -j DNAT --to-destination [::1]:5335"
    for family, rule in ((4, rule4), (6, rule6)):
        (tmp_path / f"rules.v{family}").write_text("*nat\n:PREROUTING ACCEPT [7:560]\n" + rule + "\nCOMMIT\n")
    monkeypatch.setattr(
        module, "Path", lambda p: tmp_path / Path(p).name if str(p).startswith("/etc/iptables/") else Path(p)
    )
    monkeypatch.setattr(
        module,
        "runtime",
        lambda family: (
            "iptables" if family == 4 else "ip6tables",
            [(rule4 if family == 4 else rule6).split()],
            "present",
        ),
    )
    calls = []
    monkeypatch.setattr(module.subprocess, "run", lambda args, **kwargs: calls.append(args))
    module.main(apply=True)
    assert calls == [
        ["iptables", "-t", "nat", "-D", *rule4.split()[1:]],
        ["ip6tables", "-t", "nat", "-D", *rule6.split()[1:]],
    ]
    for family in (4, 6):
        assert (tmp_path / f"rules.v{family}").read_text() == "*nat\n:PREROUTING ACCEPT [7:560]\nCOMMIT\n"
