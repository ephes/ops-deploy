"""``deploy_bind`` against the fake connector, plus its config.

The host script's answers are scripted here; ``tests/test_infra_bind_docker.py``
runs the script and the deploy against a real named.
"""

from __future__ import annotations

import base64
import shlex
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr, ValidationError

from ops_deploy.infra.bind import BindConfig, BindZone, TsigKey, deploy_bind, render_named_conf
from ops_deploy.infra.bind.deploy import HOST_SCRIPT, check_secrets, entries, host_command, payload, read_probe
from ops_deploy.infra.bind.render import builtin_zones_file, render_keys, ships_root_hints
from ops_deploy.testing import FakeRun, run_deploy_fake
from ops_deploy.testing.harness import fish_unsafe
from tests import fakehost
from tests.fakehost import UBUNTU

P = "BIND authoritative | "
PROBE = "bind-config probe "
APPLY = "bind-config apply "
SECRETS = {
    "xfer": SecretStr("Zml4dHVyZS14ZmVyLWtleS0wMQ=="),
    "acme": SecretStr("Zml4dHVyZS1hY21lLWtleS0wMg=="),
}
INSTALL = P + "Install the BIND configuration (validated first)"
RELOAD = P + "Reload named"
DISTRIBUTION = 'printf "%s %s" "$ID"'
UFW = "command -v ufw"
PRESENT = "for name in named.conf.default-zones named.conf.root-hints; do"
DEFAULT_ZONES = 'include "/etc/bind/named.conf.default-zones";\n'
ROOT_HINTS = 'include "/etc/bind/named.conf.root-hints";\n'


@pytest.fixture
def zones_dir(tmp_path: Path) -> Path:
    (tmp_path / "db.example.org").write_text("$TTL 300\n@ IN SOA ns1 h 2026102101 1 1 1 1\n@ IN NS ns1\n")
    (tmp_path / "db.home.example.org").write_text("$TTL 60\n@ IN SOA ns1 h 1 1 1 1 1\n@ IN NS ns1\n")
    return tmp_path


def config(zones_dir: Path, **changes: Any) -> BindConfig:
    base: dict[str, Any] = {
        "zone_files_dir": str(zones_dir),
        "zones": [
            {"name": "example.org", "file": "db.example.org", "type": "master", "allow_transfer": ('key "xfer"',)},
            {
                "name": "home.example.org",
                "file": "db.home.example.org",
                "type": "master",
                "dynamic": True,
                "update_policy": ('grant "acme" name _acme-challenge.home.example.org. TXT',),
            },
        ],
        "tsig_keys": [{"name": "xfer"}, {"name": "acme"}],
    }
    return BindConfig.model_validate({**base, **changes})


def host(
    cfg: BindConfig, probe: list[str] | None = None, installed: bool = True, extra: dict[str, Any] | None = None
) -> dict[str, Any]:
    packages = "\n".join(f"ii |{name}|" for name in cfg.packages) if installed else ""
    return {
        PROBE: probe if probe is not None else [],
        DISTRIBUTION: ["ubuntu 24.04"],
        UFW: [],
        **(extra or {}),
        **UBUNTU,
        "dpkg-query -W": packages.splitlines(),
        f"stat -c %a {cfg.config_dir}": ["755"],
        f"stat -c %a {cfg.dynamic_zone_dir}": ["775"],
        f"stat -c %a {cfg.working_dir}": ["775"],
        **fakehost.stat(cfg.config_dir, group="bind", mode="drwxr-xr-x"),
        **fakehost.stat(cfg.dynamic_zone_dir, user="bind", group="bind", mode="drwxrwxr-x"),
        **fakehost.stat(cfg.working_dir, user="bind", group="bind", mode="drwxrwxr-x"),
        **fakehost.service("named.service"),
    }


def run(cfg: BindConfig, responses: dict[str, Any], secrets: dict[str, SecretStr] | None = None) -> FakeRun:
    result = run_deploy_fake(deploy_bind, cfg, SECRETS if secrets is None else secrets, responses=responses)
    assert result.succeeded, result.error
    return result


def failed(cfg: BindConfig, responses: dict[str, Any], secrets: dict[str, SecretStr] | None = None) -> FakeRun:
    result = run_deploy_fake(deploy_bind, cfg, SECRETS if secrets is None else secrets, responses=responses)
    assert not result.succeeded
    return result


def secret_values() -> list[str]:
    return [secret.get_secret_value() for secret in SECRETS.values()]


def arguments(command: str) -> list[str]:
    """The host script's arguments after ``bind-config`` (the script itself is argv[2])."""

    words = shlex.split(command[command.index("bash -c ") :])
    return words[words.index("bind-config") + 1 :]


def apply_stdin(result: FakeRun) -> str:
    [stdin] = [text for command, text in result.stdin if APPLY in command]
    return stdin


# -- converged, fresh and changed hosts ---------------------------------------------------


def test_converged_host_plans_only_read_only_checks(zones_dir: Path) -> None:
    cfg = config(zones_dir)

    result = run(cfg, host(cfg))

    assert result.mutating_changed_ops == []
    assert result.changed_ops == [
        P + "Verify authoritative answers for example.org",
        P + "Verify authoritative answers for home.example.org",
    ]
    assert not any(APPLY in command for command in result.executed_commands)
    assert not any("systemctl reload" in command for command in result.executed_commands)
    # The probe got the key file on stdin; nothing else carries a secret.
    assert [command for command, _ in result.stdin if PROBE in command]
    assert not [command for command, _ in result.stdin if PROBE not in command]
    for value in secret_values():
        assert value not in result.all_text()


def test_fresh_host_installs_packages_then_the_validated_configuration(zones_dir: Path) -> None:
    cfg = config(zones_dir)
    sources = {"example.org": b"", "home.example.org": b""}
    changes = [f"change {item.path}" for item in entries(cfg, "/x", SECRETS, sources)]
    responses = host(cfg, changes, installed=False)
    responses.update(fakehost.service("named.service", running=False, enabled=False))

    result = run(cfg, responses)

    assert result.mutating_changed_ops == [
        P + "Install BIND packages",
        INSTALL,
        P + "Ensure named is enabled and running",
        RELOAD,
    ]
    commands = result.executed_commands
    assert any("bind9 bind9-utils dnsutils" in command for command in commands)
    apply = next(c for c in commands if APPLY in c)
    reload = next(c for c in commands if c.startswith("flock -w 120 /etc/bind systemctl reload named"))
    assert commands.index(apply) < commands.index(reload)
    args = arguments(apply)
    assert args[:5] == ["apply", "/etc/bind", "/var/cache/bind", "named", "/etc/bind/named.conf.keys"]
    rows = [args[i : i + 7] for i in range(5, len(args), 7)]
    keys = render_keys(cfg, SECRETS).reveal()
    assert [row[:6] for row in rows] == [
        ["keys", "/etc/bind/named.conf.keys", "-", "root", "bind", "0640"],
        ["config", "/etc/bind/named.conf.options", "-", "root", "bind", "0644"],
        ["config", "/etc/bind/named.conf.local", "-", "root", "bind", "0644"],
        ["zone", "/etc/bind/db.example.org", "example.org", "root", "bind", "0644"],
        ["seed", "/var/lib/bind/db.home.example.org", "home.example.org", "bind", "bind", "0644"],
        ["config", "/etc/bind/named.conf", "-", "root", "bind", "0644"],
    ]
    assert rows[0][6] == str(len(keys))
    lines = apply_stdin(result).splitlines()
    assert len(lines) == len(rows)
    assert base64.b64decode(lines[0]) == keys
    assert base64.b64decode(lines[3]) == (zones_dir / "db.example.org").read_bytes()
    # Key material only ever on stdin (probe and apply), never on a command line.
    for value in secret_values():
        assert value not in result.all_text()
        assert value not in apply


def test_a_changed_file_reinstalls_and_reloads(zones_dir: Path) -> None:
    cfg = config(zones_dir)

    result = run(cfg, host(cfg, ["change /etc/bind/named.conf.keys"]))

    assert result.mutating_changed_ops == [INSTALL, RELOAD]


def test_a_refusal_stops_the_deploy_before_any_operation(zones_dir: Path) -> None:
    cfg = config(zones_dir)
    probe = [
        "change /etc/bind/db.example.org",
        "refuse zone example.org: the new file keeps serial 1, which is not greater than the installed 2",
        "refuse named-checkconf rejects the new configuration:",
        "refuse   /etc/bind/named.conf.options:3: unknown option 'x'",
    ]

    result = failed(cfg, host(cfg, probe, installed=False))

    assert "bind: refusing to change anything:" in str(result.error)
    assert "which is not greater than the installed 2" in str(result.error)
    assert "/etc/bind/named.conf.options:3: unknown option 'x'" in str(result.error)
    assert result.executed_commands == []


def test_a_reload_a_run_never_reached_is_made(zones_dir: Path) -> None:
    cfg = config(zones_dir)

    result = run(cfg, host(cfg, ["reload-pending"]))

    assert result.mutating_changed_ops == [RELOAD]
    # Under the host script's lock, so named never loads a tree another run is renaming.
    assert "flock -w 120 /etc/bind systemctl reload named" in result.executed_commands


def test_leftover_staged_files_are_cleaned_up_without_a_reload(zones_dir: Path) -> None:
    cfg = config(zones_dir)

    result = run(cfg, host(cfg, ["leftover /etc/bind/.ops-deploy-new.named.conf"]))

    assert result.mutating_changed_ops == [INSTALL]


def test_a_failed_probe_stops_the_deploy(zones_dir: Path) -> None:
    cfg = config(zones_dir)

    result = failed(cfg, host(cfg, ["partial", "", "ops-deploy-probe-failed"]))

    assert "probe failed; nothing was changed" in str(result.error)
    assert result.executed_commands == []


def test_unexpected_probe_output_stops_the_deploy(zones_dir: Path) -> None:
    cfg = config(zones_dir)

    result = failed(cfg, host(cfg, ["something else"]))

    assert "printed something unexpected" in str(result.error)
    assert result.executed_commands == []


def test_read_probe() -> None:
    plan = read_probe("change /a\nleftover /b\nreload-pending\n")

    assert (plan.changes, plan.leftovers, plan.reload_pending) == (("/a",), ("/b",), True)
    assert read_probe("").changes == ()


def test_without_keys_the_keys_file_is_removed_and_not_included(zones_dir: Path) -> None:
    cfg = config(zones_dir, tsig_keys=[], zones=[{"name": "example.org", "file": "db.example.org"}])

    assert run(cfg, host(cfg), secrets={}).mutating_changed_ops == []
    result = run(cfg, host(cfg, ["change /etc/bind/named.conf.keys"]), secrets={})

    assert result.mutating_changed_ops == [INSTALL, RELOAD]
    args = arguments(next(c for c in result.executed_commands if APPLY in c))
    assert args[-7:] == ["absent", "/etc/bind/named.conf.keys", "-", "-", "-", "-", "-"]
    lines = apply_stdin(result).splitlines()
    assert len(lines) == 4  # options, local, zone, named.conf: nothing for the removal
    assert "named.conf.keys" not in base64.b64decode(lines[-1]).decode()


def test_a_secondary_ensures_its_working_dir_and_installs_no_zone_file(zones_dir: Path) -> None:
    cfg = config(
        zones_dir,
        recursion=False,
        tsig_keys=[{"name": "xfer"}],
        zones=[{"name": "example.org", "file": "db.example.org", "type": "secondary", "primaries": ("192.0.2.1",)}],
    )
    responses = host(cfg)
    responses[f"stat -c %a {cfg.working_dir}"] = ["2775"]

    result = run(cfg, responses, secrets={"xfer": SECRETS["xfer"]})

    assert result.mutating_changed_ops == [P + "Clear special mode bits on /var/cache/bind"]
    files = entries(cfg, "/etc/bind/named.conf.default-zones", {"xfer": SECRETS["xfer"]}, {})
    assert [item.kind for item in files] == ["keys", "config", "config", "config"]


def test_the_disabled_role_is_a_no_op(zones_dir: Path) -> None:
    cfg = config(zones_dir, enabled=False)

    result = run(cfg, {})

    assert result.ops == []
    assert result.events == []


def test_verify_asks_for_an_authoritative_answer_per_zone(zones_dir: Path) -> None:
    cfg = config(
        zones_dir,
        verify_retries=3,
        verify_delay=2,
        zones=[
            {"name": "example.org", "file": "db.example.org"},
            {"name": ".", "file": "db.root", "type": "hint"},
            {"name": "sec.example.org", "file": "db.sec", "type": "slave", "primaries": "192.0.2.1"},
        ],
        tsig_keys=[],
    )
    (zones_dir / "db.root").write_text(". 1 IN NS a.\n")

    result = run(cfg, host(cfg), secrets={})

    verify = [c for c in result.executed_commands if "dig " in c]
    assert len(verify) == 2
    assert "dig @127.0.0.1 example.org SOA +comments +norecurse" in verify[0]
    assert "dig @127.0.0.1 sec.example.org SOA +comments +norecurse" in verify[1]
    assert "grep -q 'status: NOERROR'" in verify[0]
    assert "grep -Eq 'flags:[^;]* aa[ ;]'" in verify[0]
    assert "-lt 3" in verify[0]
    assert "sleep 2" in verify[0]


def test_verify_can_be_turned_off(zones_dir: Path) -> None:
    cfg = config(zones_dir, verify_enabled=False)

    assert run(cfg, host(cfg)).changed_ops == []


def test_ufw_warnings(zones_dir: Path, caplog: pytest.LogCaptureFixture) -> None:
    cfg = config(zones_dir)
    run(cfg, host(cfg, extra={UFW: ["Status: active", "22/tcp ALLOW IN Anywhere"]}))
    assert "UFW is active but no explicit TCP/UDP 53 rule was found" in caplog.text
    caplog.clear()
    run(cfg, host(cfg, extra={UFW: ["Status: inactive"]}))
    assert "UFW is inactive" in caplog.text
    caplog.clear()
    run(cfg, host(cfg, extra={UFW: ["Status: active", "53/udp ALLOW IN Anywhere"]}))
    assert "UFW" not in caplog.text


def test_debian_13_includes_the_root_hints(zones_dir: Path) -> None:
    cfg = config(zones_dir)
    responses = host(cfg, ["change /etc/bind/named.conf"])
    responses[DISTRIBUTION] = ["debian 13"]

    result = run(cfg, responses)

    text = base64.b64decode(apply_stdin(result).splitlines()[-1]).decode()
    assert text.endswith('include "/etc/bind/named.conf.root-hints";\n')


def probe_named_conf(result: FakeRun) -> str:
    """``named.conf`` as the probe compared it (the last file on its stdin, with keys configured)."""

    [stdin] = [text for command, text in result.stdin if PROBE in command]
    return base64.b64decode(stdin.splitlines()[-1]).decode()


def _role_rule(distribution: str, major: int | None) -> str:
    """The include before Ubuntu 26.04 support: the role's rule, unchanged since the port."""

    debian13 = distribution == "Debian" and major is not None and major >= 13
    return f"/etc/bind/{'named.conf.root-hints' if debian13 else 'named.conf.default-zones'}"


@pytest.mark.parametrize("distribution", ["Debian", "Ubuntu", "ubuntu", "Linuxmint", "debian", ""])
@pytest.mark.parametrize("major", [None, 10, 11, 12, 13, 14, 20, 22, 24, 25, 26, 27, 30])
def test_the_include_is_the_roles_except_on_ubuntu_26_04_and_later(
    zones_dir: Path, distribution: str, major: int | None
) -> None:
    cfg = config(zones_dir)
    ubuntu26 = distribution in ("Ubuntu", "ubuntu") and major is not None and major >= 26

    by_release = builtin_zones_file(cfg, distribution, major)

    assert ships_root_hints(distribution, major) == by_release.endswith("root-hints")
    if ubuntu26:
        assert by_release == "/etc/bind/named.conf.root-hints"
    else:
        assert by_release == _role_rule(distribution, major)
    # The release's file present (alone or with the other one), or neither file: the release decides.
    own = by_release.rsplit("/", 1)[1]
    for present in (set(), {own}, {"named.conf.default-zones", "named.conf.root-hints"}, {"zones.rfc1918"}):
        assert builtin_zones_file(cfg, distribution, major, present) == by_release
    # Only the other file present: that one.
    [other] = {"named.conf.default-zones", "named.conf.root-hints"} - {own}
    assert builtin_zones_file(cfg, distribution, major, {other}) == f"/etc/bind/{other}"
    # A configured file always wins.
    assert builtin_zones_file(config(zones_dir, builtin_zones_file="/x/y"), distribution, major, {other}) == "/x/y"


@pytest.mark.parametrize(
    ("release", "present", "include"),
    [
        # Ubuntu 24.04: the package's default-zones (alone, with a stray root-hints, or before bind9 is installed).
        ("ubuntu 24.04", ["named.conf.default-zones"], DEFAULT_ZONES),
        ("ubuntu 24.04", ["named.conf.default-zones", "named.conf.root-hints"], DEFAULT_ZONES),
        ("ubuntu 24.04", [], DEFAULT_ZONES),
        # Debian 13: root-hints (alone, or with a default-zones a release upgrade left); Debian 12 as before.
        ("debian 13", ["named.conf.root-hints"], ROOT_HINTS),
        ("debian 13", ["named.conf.default-zones", "named.conf.root-hints"], ROOT_HINTS),
        ("debian 12", ["named.conf.default-zones"], DEFAULT_ZONES),
        # Ubuntu 26.04 (BIND 9.20): root-hints, also before bind9 is installed and next to a leftover.
        ("ubuntu 26.04", ["named.conf.root-hints"], ROOT_HINTS),
        ("ubuntu 26.04", [], ROOT_HINTS),
        ("ubuntu 26.04", ["named.conf.default-zones", "named.conf.root-hints"], ROOT_HINTS),
        ("ubuntu 26.10", ["named.conf.root-hints"], ROOT_HINTS),
    ],
)
def test_the_include_follows_the_release(zones_dir: Path, release: str, present: list[str], include: str) -> None:
    cfg = config(zones_dir)
    responses = host(cfg, extra={DISTRIBUTION: [release], PRESENT: present})

    result = run(cfg, responses)

    assert probe_named_conf(result).endswith(include)
    assert result.mutating_changed_ops == []


@pytest.mark.parametrize(
    ("release", "distribution", "major", "own"),
    [
        ("ubuntu 24.04", "ubuntu", 24, "named.conf.default-zones"),
        ("debian 13", "Debian", 13, "named.conf.root-hints"),
        ("debian 12", "Debian", 12, "named.conf.default-zones"),
    ],
)
def test_existing_releases_probe_the_same_named_conf_as_before(
    zones_dir: Path, release: str, distribution: str, major: int, own: str
) -> None:
    """Existing releases (Ubuntu 24.04, Debian 12 and 13): the bytes of the role's rule, whatever else is there."""

    cfg = config(zones_dir)
    before = render_named_conf(cfg, _role_rule(distribution, major))

    for present in ([own], [], ["named.conf.default-zones", "named.conf.root-hints"]):
        result = run(cfg, host(cfg, extra={DISTRIBUTION: [release], PRESENT: present}))
        assert probe_named_conf(result) == before


def test_a_missing_release_file_falls_back_to_the_one_present(
    zones_dir: Path, caplog: pytest.LogCaptureFixture
) -> None:
    cfg = config(zones_dir)
    responses = host(cfg, extra={DISTRIBUTION: ["ubuntu 25.10"], PRESENT: ["named.conf.root-hints"]})

    result = run(cfg, responses)

    assert probe_named_conf(result).endswith(ROOT_HINTS)
    assert "named.conf.default-zones (the choice for ubuntu 25) is missing" in caplog.text
    # The release's own file present: no fallback, no warning.
    caplog.clear()
    run(cfg, host(cfg, extra={DISTRIBUTION: ["ubuntu 24.04"], PRESENT: ["named.conf.default-zones"]}))
    assert "is missing" not in caplog.text


@pytest.mark.parametrize(
    ("statuses", "installs"),
    [
        # A release upgrade left bind9 half-configured (or only unpacked): no apt run before the repair.
        (["iF |bind9|", "ii |bind9-utils|", "ii |bind9-dnsutils|dnsutils"], None),
        (["iU |bind9|", "iU |bind9-utils|", "iU |bind9-dnsutils|dnsutils"], None),
        (["iW |bind9|", "it |bind9-utils|", "ii |dnsutils|"], None),
        # As before: removed (config files left), half-installed or unknown packages are installed.
        (["rc |bind9|", "ii |bind9-utils|", "ii |dnsutils|"], "bind9"),
        (["iH |bind9|", "ii |bind9-utils|", "ii |dnsutils|"], "bind9"),
        (["ri |bind9|", "ii |bind9-utils|", "ii |dnsutils|"], "bind9"),
        (["ii |bind9|", "ii |bind9-utils|"], "dnsutils"),
        ([], "bind9 bind9-utils dnsutils"),
    ],
)
def test_unpacked_packages_are_not_reinstalled_before_the_configuration(
    zones_dir: Path, statuses: list[str], installs: str | None
) -> None:
    cfg = config(zones_dir)
    responses = host(cfg, ["change /etc/bind/named.conf"], extra={DISTRIBUTION: ["ubuntu 26.04"]})
    responses["dpkg-query -W"] = statuses

    result = run(cfg, responses)

    ops = result.mutating_changed_ops
    if installs is None:
        assert P + "Install BIND packages" not in ops
    else:
        assert ops.index(P + "Install BIND packages") < ops.index(INSTALL)
        assert any(f"install {installs}" in command for command in result.executed_commands)
    assert INSTALL in ops


def test_the_presence_probe_is_read_only_and_fish_safe(zones_dir: Path) -> None:
    cfg = config(zones_dir)

    result = run(cfg, host(cfg))

    [command] = [command for command in result.fact_commands if PRESENT in command]
    assert not [command for command in result.executed_commands if PRESENT in command]
    assert not fish_unsafe(command)
    assert not result.fish_unsafe_commands
    assert "/etc/bind/" in command
    assert 'if [ -f /etc/bind/"$name" ]; then echo "$name"; fi; done 2>/dev/null || true' in command
    assert not any(word in command for word in (" rm ", " mv ", " cp ", " > ", "install ", "touch "))


def test_the_command_lines_are_fish_safe_and_carry_no_content(zones_dir: Path) -> None:
    cfg = config(zones_dir)
    files = entries(cfg, "/x", SECRETS, {"example.org": b"zone\\'data", "home.example.org": b""})

    for mode in ("probe", "apply"):
        command = host_command(cfg, mode, files)
        assert not fish_unsafe(command)
        assert "zone\\'data" not in command
    assert "\\\\" not in HOST_SCRIPT
    assert "\\'" not in HOST_SCRIPT
    assert payload(files).count("\n") == len(files)


# -- secrets and controller files ---------------------------------------------------------


@pytest.mark.parametrize(
    ("secrets", "message"),
    [
        ({"xfer": SECRETS["xfer"]}, "missing: ['acme']"),
        ({**SECRETS, "other": SecretStr("b3RoZXI=")}, "unexpected: ['other']"),
        ({**SECRETS, "acme": SecretStr("CHANGEME")}, "TSIG key acme"),
        ({**SECRETS, "acme": SecretStr("")}, "TSIG key acme"),
        ({**SECRETS, "acme": SecretStr('abc"; } ; key "x')}, "TSIG key acme"),
        ({**SECRETS, "acme": SecretStr("abc")}, "TSIG key acme"),
    ],
    ids=["missing", "extra", "placeholder", "empty", "injection", "padding"],
)
def test_secrets_are_checked_without_printing_them(
    zones_dir: Path, secrets: dict[str, SecretStr], message: str
) -> None:
    cfg = config(zones_dir)

    result = failed(cfg, host(cfg), secrets=secrets)

    assert message in str(result.error)
    for secret in secrets.values():
        if secret.get_secret_value():
            assert secret.get_secret_value() not in str(result.error)
    assert result.executed_commands == []


def test_check_secrets_accepts_exactly_the_keys(zones_dir: Path) -> None:
    assert check_secrets(config(zones_dir), SECRETS) == SECRETS
    assert check_secrets(config(zones_dir, tsig_keys=[]), None) == {}


def test_missing_zone_files_are_named(zones_dir: Path) -> None:
    (zones_dir / "db.example.org").unlink()
    cfg = config(zones_dir)

    result = failed(cfg, host(cfg))

    assert "Missing zone files: db.example.org" in str(result.error)


def test_a_missing_zone_directory_is_refused(tmp_path: Path) -> None:
    cfg = config(tmp_path / "nowhere")

    result = failed(cfg, host(cfg))

    assert "bind_zone_files_dir not found" in str(result.error)


# -- config validation (the role's validate.yml, and what is stricter) ----------------------


def test_defaults_are_the_roles(zones_dir: Path) -> None:
    cfg = BindConfig(zone_files_dir=str(zones_dir), zones=[BindZone(name="example.org", file="db.example.org")])

    assert cfg.packages == ("bind9", "bind9-utils", "dnsutils")
    assert cfg.keys_file == "/etc/bind/named.conf.keys"
    assert cfg.query_cache_acl == ("localhost", "localnets")
    assert cfg.zone_path(cfg.zones[0]) == "/etc/bind/db.example.org"
    assert TsigKey(name="k").algorithm == "hmac-sha256"


@pytest.mark.parametrize(
    ("zones", "message"),
    [
        ([], "at least 1"),
        ([{"name": "a.org", "file": "db.a", "type": "secondary"}], "non-empty primaries"),
        ([{"name": "a.org", "file": "db.a", "type": "slave", "primaries": ()}], "non-empty primaries"),
        ([{"name": "a.org", "file": "db.a", "dynamic": True}], "non-empty update_policy"),
        (
            [
                {
                    "name": "a.org",
                    "file": "db.a",
                    "dynamic": True,
                    "type": "hint",
                    "update_policy": "grant x zonesub ANY",
                }
            ],
            "must be type master/primary",
        ),
        ([{"name": "a.org", "file": "../db.a"}], "one file name"),
        ([{"name": "a.org", "file": "/etc/bind/db.a"}], "only supported for transfer-backed"),
        ([{"name": "a.org", "file": "db.a"}, {"name": "a.org", "file": "db.b"}], "each zone name may appear once"),
        ([{"name": 'a"org', "file": "db.a"}], "not a zone name"),
        ([{"name": "a.org", "file": "db.a", "extra_config": ("x;\ny;",)}], "control characters"),
        ([{"name": "a.org", "file": "db.a", "type": "bogus"}], "Input should be"),
        ([{"name": "a.org", "file": "/var/cache/bind/../x", "type": "slave", "primaries": "1"}], "transfer-backed"),
    ],
)
def test_invalid_zones_are_refused(zones_dir: Path, zones: list[dict[str, Any]], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        config(zones_dir, zones=zones)


# -- what the deploy writes into: the role's default paths, db.* zone files of their own ---


@pytest.mark.parametrize(
    ("changes", "moved"),
    [
        ({"config_dir": "/srv/bind"}, "config_dir"),
        ({"config_dir": "/etc/bind/"}, "config_dir"),
        ({"dynamic_zone_dir": "/etc/bind"}, "dynamic_zone_dir"),
        ({"working_dir": "/var//cache/bind"}, "working_dir"),
        # Another name for the dynamic zone through a symlinked directory, a staged
        # file's name, a journal: never a place for the key file.
        ({"tsig_keys_file": "/etc/bind/keys/db.home.example.org"}, "tsig_keys_file"),
        ({"tsig_keys_file": "/etc/bind/.ops-deploy-new.named.conf"}, "tsig_keys_file"),
        ({"tsig_keys_file": "/var/lib/bind/db.home.example.org.jnl"}, "tsig_keys_file"),
        ({"builtin_zones_file": "/etc/bind/named.conf.default-zones"}, "builtin_zones_file"),
    ],
)
def test_only_the_roles_default_paths_are_deployed(zones_dir: Path, changes: dict[str, str], moved: str) -> None:
    cfg = config(zones_dir, **changes)

    result = failed(cfg, host(cfg))

    message = f"bind: only the role's default paths are supported, refusing the changed {moved} ("
    assert str(result.error).startswith(message)
    assert result.events == []


@pytest.mark.parametrize(
    "zones",
    [
        # Never a zone file: the builtin zones file, a named.conf file, rndc.key, a package zone file.
        [{"name": "a.org", "file": "named.conf.default-zones"}],
        [{"name": "a.org", "file": "named.conf.local"}],
        [{"name": "a.org", "file": "rndc.key"}],
        [{"name": "localhost", "file": "db.local"}],
        [{"name": "a.org", "file": "a.org.zone"}],
        # Another zone's journal, and one file for two zones, also across directories.
        [{"name": "a.org", "file": "db.a"}, {"name": "b.org", "file": "db.a.jnl"}],
        [{"name": "a.org", "file": "db.a"}, {"name": "b.org", "file": "db.a"}],
        [
            {"name": "a.org", "file": "db.a"},
            {"name": "b.org", "file": "db.a", "dynamic": True, "update_policy": "grant k zonesub ANY"},
        ],
        [{"name": "a.org", "file": "db.a"}, {"name": "b.org", "file": "db.a", "type": "slave", "primaries": "1"}],
        # An absolute file, which the role allows for a transfer-backed zone.
        [{"name": "a.org", "file": "/var/cache/bind/db.a", "type": "slave", "primaries": "192.0.2.1"}],
    ],
)
def test_zone_files_are_db_names_of_their_own(zones_dir: Path, zones: list[dict[str, Any]]) -> None:
    cfg = config(zones_dir, zones=zones, tsig_keys=[])

    result = failed(cfg, host(cfg), secrets={})

    assert "each zone needs a db.* file name of its own" in str(result.error)
    assert result.events == []


def test_the_default_key_file_may_be_spelled_out(zones_dir: Path) -> None:
    cfg = config(zones_dir, tsig_keys_file="/etc/bind/named.conf.keys")

    assert run(cfg, host(cfg)).mutating_changed_ops == []


def test_other_settings_are_validated(zones_dir: Path) -> None:
    with pytest.raises(ValidationError, match="at least one ACL entry"):
        config(zones_dir, allow_transfer=())
    with pytest.raises(ValidationError, match="each key name may appear once"):
        config(zones_dir, tsig_keys=[{"name": "k"}, {"name": "k"}])
    with pytest.raises(ValidationError, match="not a TSIG key name"):
        config(zones_dir, tsig_keys=[{"name": 'k" ; x'}])
    with pytest.raises(ValidationError, match="Input should be"):
        config(zones_dir, tsig_keys=[{"name": "k", "algorithm": "sha1"}])
    with pytest.raises(ValidationError, match="control characters"):
        config(zones_dir, extra_options=("a;\nb;",))
    with pytest.raises(ValidationError):
        config(zones_dir, secret="x")
