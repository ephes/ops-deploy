"""``deploy_certbot_dns`` against the fake connector, plus its pieces.

The role templates are vendored under ``tests/parity/ansible`` (checked
against ops-library by ``test_traefik_parity.test_vendored_templates_match_ops_library``)
and rendered the way Ansible's ``template`` module does. No test contacts an
ACME server: ``certbot`` never runs here.
"""

from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Any

import jinja2
import pytest
from pydantic import SecretStr, ValidationError

from ops_deploy.infra import CertbotDnsConfig, deploy_certbot_dns
from ops_deploy.infra.certbot_dns import (
    Lineage,
    certonly_argv,
    reconfigure_argv,
    render_credentials,
    render_hook,
    renewal_due,
)
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost
from tests.fakehost import UBUNTU

VENDORED = Path(__file__).parent / "parity" / "ansible"
DOMAIN = "home.example.org"
SECRET = SecretStr("dHNpZy1maXh0dXJlLXNlY3JldA==")
CFG = CertbotDnsConfig(
    provider="rfc2136",
    domain=DOMAIN,
    email="admin@example.org",
    rfc2136_server="192.0.2.53",
    rfc2136_key_name="acme-key",
    renewal_hooks=("systemctl restart traefik", "systemctl reload postfix@-", "systemctl reload dovecot"),
)
GANDI = "/etc/letsencrypt/dns-credentials.ini"
RFC2136 = "/etc/letsencrypt/dns-rfc2136-credentials.ini"
HOOK = "/etc/letsencrypt/renewal-hooks/deploy/reload-services.sh"
NOW = 1_800_000_000
PROBE = "' probe /etc/letsencrypt "
GUARD = "env 'CERTBOT_STRAY_INPUT="
P = "certbot DNS | "
CERTONLY = P + "Request or renew the certificate"
READ_ONLY = [P + "Check the renewal hook"]


def render_ansible(template: str, variables: dict[str, Any]) -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(VENDORED),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["upper"] = str.upper
    return env.get_template(template).render(**variables)


def lineage(
    *,
    authenticator: str = "dns-rfc2136",
    settings: tuple[str, ...] = ("rfc2136",),
    days_left: int = 60,
    names: tuple[str, ...] = (DOMAIN, f"*.{DOMAIN}"),
    version: int = 3,
    inactive: dict[str, Any] | None = None,
    stray: dict[str, bool] | None = None,
    **values: str,
) -> dict[str, Any]:
    """Probe output for an issued lineage on its ``version`` (90-day certificate)."""

    base = "/etc/letsencrypt"
    return {
        "config_dir": base,
        "now": NOW,
        "conf": {
            "malformed": False,
            "authenticator": authenticator,
            "settings": list(settings),
            "values": {
                "archive_dir": f"{base}/archive/{DOMAIN}",
                **{kind: f"{base}/live/{DOMAIN}/{kind}.pem" for kind in ("cert", "chain", "fullchain", "privkey")},
                **values,
            },
            "autorenew": None,
        },
        "cert": {
            "not_before": NOW + days_left * 86400 - 90 * 86400,
            "not_after": NOW + days_left * 86400,
            "names": names,
            "key_type": "ECDSA",
        },
        "links": {
            kind: {"target": f"../../archive/{DOMAIN}/{kind}{version}.pem", "exists": True}
            for kind in ("cert", "chain", "fullchain", "privkey")
        },
        "archive": sorted(f"{kind}{n}.pem" for kind in ("cert", "chain", "fullchain", "privkey") for n in (1, 2, 3)),
        "inactive": inactive if inactive is not None else {GANDI: {"kind": "missing", "rc": None}},
        "stray": stray or {},
    }


def fresh_probe(cfg: CertbotDnsConfig = CFG) -> dict[str, Any]:
    return {
        "config_dir": "/etc/letsencrypt",
        "now": NOW,
        "conf": None,
        "cert": None,
        "links": {},
        "archive": [],
        "inactive": {path: {"kind": "missing", "rc": None} for path in cfg.inactive_credentials_files},
        "stray": {path: False for path in cfg.stray_config_dirs},
    }


def converged(cfg: CertbotDnsConfig = CFG, state: dict[str, Any] | None = None, **extra: Any) -> dict[str, Any]:
    credentials = cfg.active_credentials_file
    return {
        PROBE: [json.dumps(state if state is not None else lineage())],
        **extra,
        **UBUNTU,
        **fakehost.deb_installed("certbot", "python3-certbot-dns-rfc2136", "python3-certbot-dns-gandi"),
        "stat -c %a ": ["755"],
        **fakehost.directory("/etc/letsencrypt"),
        **fakehost.directory("/etc/letsencrypt/renewal-hooks/deploy"),
        **{k: v for k, v in fakehost.file(credentials, render_credentials(cfg, SECRET)).items() if "test -e" not in k},
        **fakehost.stat(credentials, mode="-rw-------"),
        **fakehost.file(HOOK, render_hook(cfg), mode="-rwxr-xr-x"),
        **fakehost.service("certbot.timer"),
    }


def run(responses: dict[str, Any], cfg: CertbotDnsConfig = CFG, secret: SecretStr = SECRET) -> FakeRun:
    result = run_deploy_fake(deploy_certbot_dns, cfg, secret, responses=responses)
    assert result.succeeded, result.error
    return result


def cfg(**changes: Any) -> CertbotDnsConfig:
    return CertbotDnsConfig.model_validate({**CFG.model_dump(), **changes})


# Rendering against the role ------------------------------------------------------------------


@pytest.mark.parametrize(
    "config",
    [
        CFG,
        cfg(rfc2136_key_algorithm="hmac-sha512", rfc2136_port=5353, rfc2136_server="2001:db8::53"),
        cfg(provider="gandi"),
    ],
    ids=["rfc2136", "rfc2136-overrides", "gandi"],
)
def test_credentials_match_the_role(config: CertbotDnsConfig) -> None:
    variables = {
        "certbot_dns_provider": config.provider,
        "certbot_dns_gandi_api_token": SECRET.get_secret_value(),
        "certbot_dns_rfc2136_server": config.rfc2136_server,
        "certbot_dns_rfc2136_port": config.rfc2136_port,
        "certbot_dns_rfc2136_key_name": config.rfc2136_key_name,
        "certbot_dns_rfc2136_key_secret": SECRET.get_secret_value(),
        "certbot_dns_rfc2136_key_algorithm": config.rfc2136_key_algorithm.lower(),
    }

    expected = render_ansible("certbot_dns_deploy__dns-credentials.ini.j2", variables)
    assert render_credentials(config, SECRET) == expected


@pytest.mark.parametrize(
    "hooks",
    [(), CFG.renewal_hooks, ("one", "two\nthree", 'printf "%s\\n" x\n')],
    ids=["none", "consumers", "multi-line"],
)
def test_hook_matches_the_role(hooks: tuple[str, ...]) -> None:
    expected = render_ansible("certbot_dns_deploy__renewal-hooks.sh.j2", {"certbot_dns_renewal_hooks": list(hooks)})

    assert render_hook(cfg(renewal_hooks=hooks)) == expected


def test_certonly_argv_is_the_roles() -> None:
    config = cfg(additional_domains=("www.example.org", DOMAIN), staging=True, propagation_seconds=30)

    assert certonly_argv(config) == [
        "certbot",
        "certonly",
        "--non-interactive",
        "--agree-tos",
        "--email",
        "admin@example.org",
        "--authenticator",
        "dns-rfc2136",
        "--dns-rfc2136-credentials",
        RFC2136,
        "--dns-rfc2136-propagation-seconds",
        "30",
        "--cert-name",
        DOMAIN,
        "--key-type",
        "ecdsa",
        "--keep-until-expiring",
        "--expand",
        "--staging",
        # The role's map('regex_replace', '^(.*)$', '-d \\1'): one word each.
        f"-d {DOMAIN}",
        f"-d *.{DOMAIN}",
        "-d www.example.org",
    ]
    assert reconfigure_argv(cfg(provider="gandi")) == [
        "certbot",
        "reconfigure",
        "--non-interactive",
        "--cert-name",
        DOMAIN,
        "--authenticator",
        "dns-gandi",
        "--dns-gandi-credentials",
        GANDI,
        "--dns-gandi-propagation-seconds",
        "120",
    ]


def test_domains_and_credentials_files() -> None:
    assert cfg(wildcard=False).domains == (DOMAIN,)
    assert cfg(include_base=False).domains == (f"*.{DOMAIN}",)
    assert CFG.active_credentials_file == RFC2136
    assert CFG.inactive_credentials_files == (GANDI,)
    assert cfg(provider="gandi").inactive_credentials_files == (RFC2136,)
    assert cfg(rfc2136_credentials_file=GANDI).inactive_credentials_files == ()
    assert CFG.protected_dirs == ("/etc/letsencrypt", "/var/lib/letsencrypt", "/var/log/letsencrypt")


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"rfc2136_server": None}, "set rfc2136_server"),
        ({"rfc2136_server": "ns1.example.org"}, "must be an IP address"),
        ({"rfc2136_server": "999.1.1.1"}, "must be an IP address"),
        ({"rfc2136_key_name": "CHANGEME"}, "TSIG key name"),
        ({"rfc2136_key_algorithm": "HMAC-MD5"}, "rfc2136_key_algorithm"),
        ({"wildcard": False, "include_base": False}, "No domains requested"),
        ({"domain": "*.example.org"}, "not a lowercase DNS name"),
        ({"domain": "Home.Example.org"}, "not a lowercase DNS name"),
        ({"additional_domains": ("a b.example.org",)}, "not a lowercase DNS name"),
        ({"email": "two@x@y"}, "single address"),
        ({"email": "admin@example.org\n"}, "single address"),
        ({"key_type": "dsa"}, "key_type"),
        ({"propagation_seconds": -1}, "propagation_seconds"),
        ({"config_dir": "/srv/letsencrypt"}, "config_dir"),
        ({"config_dir": "/etc/letsencrypt/"}, "config_dir"),
        ({"renewal_hooks": ("a\x00b",)}, "NUL"),
        ({"consumer_units": ("-x",)}, "systemd unit name"),
        ({"stray_config_dirs": ("letsencrypt",)}, "Refusing stray certbot dir"),
        ({"stray_config_dirs": ("/old/../etc",)}, "Refusing stray certbot dir"),
        ({"stray_config_dirs": ("/old/",)}, "Refusing stray certbot dir"),
        ({"stray_config_dirs": ("/old//x",)}, "Refusing stray certbot dir"),
        ({"stray_config_dirs": ("/old dir",)}, "Refusing stray certbot dir"),
        ({"stray_config_dirs": ("/etc",)}, "overlaps a live certbot dir"),
        ({"stray_config_dirs": ("/var/lib/letsencrypt/x",)}, "overlaps a live certbot dir"),
        ({"package_state": "absent"}, "package_state"),
    ],
)
def test_invalid_config_is_refused(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        cfg(**changes)


def test_gandi_needs_no_rfc2136_settings() -> None:
    config = CertbotDnsConfig(domain=DOMAIN, email="a@example.org")

    assert config.provider == "gandi"
    assert config.rfc2136_key_algorithm == "HMAC-SHA256"
    assert cfg(rfc2136_key_algorithm="hmac-sha384").rfc2136_key_algorithm == "HMAC-SHA384"


# Renewal decision ---------------------------------------------------------------------------


def due(state: dict[str, Any] | None, config: CertbotDnsConfig = CFG) -> str | None:
    return renewal_due(config, Lineage.parse(None if state is None else json.dumps(state)))


def test_not_due_with_two_months_left() -> None:
    assert due(lineage()) is None
    assert due(lineage(days_left=31)) is None


@pytest.mark.parametrize(
    ("state", "reason"),
    [
        (None, "the lineage probe failed"),
        ({**lineage(), "conf": None}, "no lineage yet"),
        (lineage(days_left=29), "inside its renewal window"),
        (lineage(days_left=-1), "inside its renewal window"),
        (lineage(names=(DOMAIN,)), "names differ"),
        (lineage(names=(DOMAIN, f"*.{DOMAIN}", "www.example.org")), "names differ"),
        (lineage(version=2), "live links are not on the latest"),
        (lineage(cert="/srv/cert.pem"), "standard paths"),
        (lineage(renew_before_expiry="1 month"), "renew_before_expiry is not understood"),
        (lineage(renew_before_expiry="45 days", days_left=40), "inside its renewal window"),
        ({**lineage(), "cert": None}, "live certificate is missing"),
        ({**lineage(), "conf": {**lineage()["conf"], "malformed": True}}, "not plain configobj"),
        ({**lineage(), "conf": {k: v for k, v in lineage()["conf"].items() if k != "malformed"}}, "configobj"),
    ],
)
def test_due(state: dict[str, Any] | None, reason: str) -> None:
    assert reason in (due(state) or "")


def test_window_follows_the_lineage_setting() -> None:
    assert due(lineage(renew_before_expiry="2 weeks", days_left=20)) is None
    assert due(lineage(renew_before_expiry="2 weeks", days_left=13)) is not None
    assert due(lineage(renew_before_expiry="10d", days_left=11)) is None
    assert due(lineage(renew_before_expiry="10", days_left=11)) is None
    assert due(lineage(renew_before_expiry="10", days_left=9)) is not None


def test_key_type_change_is_due() -> None:
    assert "key type changes" in (due(lineage(), cfg(key_type="rsa")) or "")
    state = lineage()
    state["cert"]["key_type"] = "RSA"
    assert due(state, cfg(key_type="rsa")) is None


def test_names_compare_as_sets_ignoring_case() -> None:
    assert due(lineage(names=(f"*.{DOMAIN}", DOMAIN.upper()))) is None


def test_link_on_another_kind_or_broken_is_due() -> None:
    state = lineage()
    state["links"]["chain"] = {"target": f"../../archive/{DOMAIN}/cert3.pem", "exists": True}
    assert due(state) is not None
    state = lineage()
    state["links"]["privkey"] = {"target": f"../../archive/{DOMAIN}/privkey3.pem", "exists": False}
    assert due(state) is not None


def test_latest_version_needs_all_four_files() -> None:
    state = lineage(version=3)
    state["archive"] = [*state["archive"], "cert4.pem", "chain4.pem", "fullchain4.pem"]
    assert due(state) is None
    state["archive"].append("privkey4.pem")
    assert due(state) is not None


def test_autorenew_off_is_never_due_unless_names_change() -> None:
    state = lineage(days_left=1)
    state["conf"]["autorenew"] = "False"
    assert due(state) is None
    state["conf"]["autorenew"] = "maybe"
    assert due(state) is not None
    state["conf"]["autorenew"] = "True"
    assert due(state) is not None


def test_short_lifetime_uses_the_longer_window() -> None:
    # A third of a 160-day lifetime (53 days) is longer than certbot 2's 30 days.
    state = lineage(days_left=50)
    state["cert"]["not_before"] = state["cert"]["not_after"] - 160 * 86400
    assert due(state) is not None


def test_malformed_probe_output_parses_to_none() -> None:
    assert Lineage.parse("not json") is None
    assert Lineage.parse(json.dumps({"now": 1})) is None


# Fake host runs ------------------------------------------------------------------------------


def test_converged_host_runs_no_certbot_and_changes_nothing() -> None:
    result = run(converged())

    assert result.mutating_changed_ops == []
    assert result.changed_ops == READ_ONLY
    assert not any("certbot " in command and "python3" not in command for command in result.executed_commands)
    assert result.stdin == []
    assert SECRET.get_secret_value() not in result.all_text()


def test_fresh_host_installs_writes_requests_and_hooks() -> None:
    result = run({PROBE: [json.dumps(fresh_probe())], **UBUNTU})

    assert result.mutating_changed_ops == [
        P + "Install certbot and the DNS plugin",
        P + "Ensure /etc/letsencrypt",
        P + "Clear special mode bits on /etc/letsencrypt",
        P + f"Write {RFC2136}",
        CERTONLY,
        P + "Ensure /etc/letsencrypt/renewal-hooks/deploy",
        P + "Clear special mode bits on /etc/letsencrypt/renewal-hooks/deploy",
        P + f"Write {HOOK}",
        P + "Ensure certbot.timer",
    ]
    commands = result.executed_commands
    assert "certbot python3-certbot-dns-rfc2136" in "\n".join(commands)
    assert shlex.join(certonly_argv(CFG)) in commands
    # The credentials reach the host on stdin only, never in a command or upload.
    assert len(result.stdin) == 1
    assert SECRET.get_secret_value() not in result.all_text()
    assert result.uploaded_paths == [HOOK]
    assert result.upload(HOOK).decode() == render_hook(CFG)
    assert "systemctl start certbot.timer" in commands
    assert "systemctl enable certbot.timer" in commands


def test_due_certificate_is_requested_with_the_roles_argv() -> None:
    result = run(converged(state=lineage(days_left=10)))

    assert result.mutating_changed_ops == [CERTONLY]
    assert shlex.join(certonly_argv(CFG)) in result.executed_commands


def test_changed_credentials_are_rewritten_without_certbot() -> None:
    responses = converged()
    responses.update({k: v for k, v in fakehost.file(RFC2136, "old\n").items() if "test -e" not in k})

    result = run(responses)

    assert result.mutating_changed_ops == [P + f"Write {RFC2136}"]
    assert len(result.stdin) == 1


def test_provider_switch_reconfigures_drops_settings_and_removes_the_old_file() -> None:
    state = lineage(
        authenticator="dns-gandi",
        settings=("gandi",),
        inactive={GANDI: {"kind": "file", "rc": 0}},
    )

    result = run(converged(state=state))

    assert result.mutating_changed_ops == [
        P + "Switch the lineage to dns-rfc2136",
        P + "Drop the other providers' settings from the lineage",
        P + f"Remove {GANDI} once no lineage uses it",
    ]
    switch, drop, remove = (
        c for c in result.executed_commands if any(word in c for word in ("reconfigure", "drop-settings", "rm -f"))
    )
    assert shlex.join(reconfigure_argv(CFG)) in switch
    assert 'if [ -n "$cur" ] && [ "$cur" != dns-rfc2136 ]' in switch
    assert drop.endswith(f"drop-settings /etc/letsencrypt/renewal/{DOMAIN}.conf rfc2136")
    assert remove == (
        'sh -c \'exec grep -l -F -e "$1" -- "$2"/*.conf\' sh /etc/letsencrypt/dns-credentials.ini '
        "/etc/letsencrypt/renewal >/dev/null 2>&1; rc=$?; "
        "case $rc in 1) rm -f -- /etc/letsencrypt/dns-credentials.ini ;; 0|2) ;; *) exit $rc ;; esac"
    )


def test_reconfigure_can_be_turned_off() -> None:
    state = lineage(authenticator="dns-gandi", settings=("gandi",), inactive={GANDI: {"kind": "file", "rc": 0}})

    config = cfg(reconfigure_on_provider_change=False)

    result = run(converged(config, state=state), config)

    # Nothing would change what uses the old file, so nothing is planned.
    assert result.mutating_changed_ops == []


def test_leftover_settings_after_an_earlier_switch_are_dropped() -> None:
    result = run(converged(state=lineage(settings=("rfc2136", "gandi"))))

    assert result.mutating_changed_ops == [P + "Drop the other providers' settings from the lineage"]


@pytest.mark.parametrize(("rc", "planned"), [(1, True), (0, False), (2, False), (3, True)])
def test_unused_old_file_follows_the_scan(rc: int, planned: bool) -> None:
    state = lineage(inactive={GANDI: {"kind": "file", "rc": rc}})

    result = run(converged(state=state))

    assert result.mutating_changed_ops == ([P + f"Remove {GANDI} once no lineage uses it"] if planned else [])


def test_old_file_kept_when_cleanup_is_off() -> None:
    config = cfg(remove_unused_credentials=False)
    state = lineage(settings=("rfc2136", "gandi"), inactive={})

    result = run(converged(config, state=state), config)

    assert result.mutating_changed_ops == []
    assert "'[]'" in next(c for c in result.fact_commands if PROBE in c)


def test_old_credentials_path_that_is_a_directory_is_refused() -> None:
    state = lineage(inactive={GANDI: {"kind": "other", "rc": 2}})

    result = run_deploy_fake(deploy_certbot_dns, CFG, SECRET, responses=converged(state=state))

    assert not result.succeeded
    assert "not a regular file or symlink" in str(result.error)
    assert result.executed_commands == []


def test_failed_probe_runs_every_gated_step_and_probes_again() -> None:
    responses = converged()
    del responses[PROBE]
    responses["ops-deploy-probe-failed"] = ["ops-deploy-probe-failed"]
    responses[PROBE] = ["", "ops-deploy-probe-failed"]

    result = run(responses)

    assert result.mutating_changed_ops == [
        CERTONLY,
        P + "Switch the lineage to dns-rfc2136",
        P + "Drop the other providers' settings from the lineage",
        P + f"Remove {GANDI} once no lineage uses it",
    ]
    assert P + "Probe again: certbot lineage" in result.changed_ops


def test_secret_placeholder_and_newline_are_refused() -> None:
    for secret in ("", "CHANGEME", "abc\ndns_rfc2136_server = 10.0.0.1"):
        result = run_deploy_fake(deploy_certbot_dns, CFG, SecretStr(secret), responses=converged())
        assert not result.succeeded
        assert result.executed_commands == []
        assert "10.0.0.1" not in str(result.error)


def test_non_debian_and_non_systemd_hosts_are_refused() -> None:
    for responses in (
        {**UBUNTU, "command -v apt-get": []},
        {**UBUNTU, "cat /proc/1/comm": ["init"]},
    ):
        result = run_deploy_fake(deploy_certbot_dns, CFG, SECRET, responses=responses)
        assert not result.succeeded


# Stray dirs -----------------------------------------------------------------------------------

STRAY = cfg(stray_config_dirs=("/letsencrypt",))


def guard(remove: list[str], skipped: list[str], refused: list[Any] | None = None) -> list[str]:
    return [json.dumps({"remove": remove, "skipped": skipped, "refused": refused or []})]


def test_listed_stray_dir_is_removed_after_the_guard() -> None:
    responses = converged(STRAY, state=lineage(stray={"/letsencrypt": True}), **{GUARD: guard(["/letsencrypt"], [])})

    result = run(responses, STRAY)

    assert result.mutating_changed_ops == [P + "Remove listed stray certbot dirs"]
    (command,) = (c for c in result.executed_commands if "remove-stray" in c)
    assert command.startswith("out=$(env 'CERTBOT_STRAY_INPUT=")
    guard_input = json.loads(shlex.split(command.split("$(", 1)[1])[1].split("=", 1)[1])
    assert guard_input == {
        "stray": ["/letsencrypt"],
        "protected": ["/etc/letsencrypt", "/var/lib/letsencrypt", "/var/log/letsencrypt"],
        "config_dir": "/etc/letsencrypt",
    }
    assert command.endswith(" remove-stray")


def test_removed_stray_dir_is_converged() -> None:
    responses = converged(STRAY, state=lineage(stray={"/letsencrypt": False}), **{GUARD: guard([], ["/letsencrypt"])})

    result = run(responses, STRAY)

    assert result.mutating_changed_ops == []
    assert any(GUARD in c for c in result.fact_commands)


def test_refused_stray_dir_fails_before_any_change() -> None:
    refused = [{"path": "/letsencrypt", "reasons": ["unexpected symlink /etc/letsencrypt/x in a live certbot dir"]}]
    responses = converged(STRAY, state=lineage(stray={"/letsencrypt": True}), **{GUARD: guard([], [], refused)})

    result = run_deploy_fake(deploy_certbot_dns, STRAY, SECRET, responses=responses)

    assert not result.succeeded
    assert "Refusing stray certbot dirs, nothing removed" in str(result.error)
    assert "unexpected symlink" in str(result.error)
    assert result.executed_commands == []


def test_stray_dir_on_a_first_run_is_left_to_the_removal_step() -> None:
    state = fresh_probe(STRAY)
    state["stray"] = {"/letsencrypt": True}

    result = run({PROBE: [json.dumps(state)], **UBUNTU}, STRAY)

    assert P + "Remove listed stray certbot dirs" in result.mutating_changed_ops
    assert not any(GUARD in c for c in result.fact_commands)
    order = result.mutating_changed_ops
    assert order.index(CERTONLY) < order.index(P + "Remove listed stray certbot dirs")


# Final checks ---------------------------------------------------------------------------------


def test_lineage_and_consumer_checks_are_read_only() -> None:
    config = cfg(single_lineage=True, consumer_units=("traefik", "postfix@-"))

    result = run(converged(config), config)

    assert result.mutating_changed_ops == []
    assert result.changed_ops == [
        *READ_ONLY,
        P + "Check the lineage is the only one",
        P + "Check traefik is loaded and active",
        P + "Check postfix@- is loaded and active",
    ]
    commands = result.executed_commands
    # Every entry certbot's glob finds, symlinks included (no -type f).
    assert any(
        "find /etc/letsencrypt/renewal -mindepth 1 -maxdepth 1 -name '*.conf' ! -name '.*'" in c
        and f'[ "$found" = /etc/letsencrypt/renewal/{DOMAIN}.conf ]' in c
        for c in commands
    )
    assert any(
        "systemctl show --property=LoadState --property=ActiveState postfix@-" in c
        and "grep -qxF ActiveState=active" in c
        for c in commands
    )
