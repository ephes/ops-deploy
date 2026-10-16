"""``deploy_traefik`` against the fake connector, and parity with the role's templates."""

from pathlib import Path
from typing import Any

import jinja2
import pytest
import yaml
from pydantic import ValidationError

from ops_deploy.infra import FileCertificate, TraefikDeployConfig, deploy_traefik, traefik_deploy
from ops_deploy.infra.traefik_deploy import (
    render_certificates,
    render_logrotate,
    render_static,
    render_unit,
)
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost
from tests.fakehost import LINUX

CHECKSUM = "sha256:" + "a" * 64
CFG = TraefikDeployConfig(checksum=CHECKSUM, letsencrypt_email="ops@example.org")
STATIC = "/etc/traefik/traefik.toml"
UNIT = "/etc/systemd/system/traefik.service"
LOGROTATE = "/etc/logrotate.d/traefik"
CERTS = "/etc/traefik/dynamic/certificates.yml"
RESTART = "Traefik | Restart Traefik for the new configuration"
CHECKS = ["Traefik | Wait for Traefik on port 80", "Traefik | Check Traefik is active"]
WEB = ("nginx.service", "apache2.service", "caddy.service", "lighttpd.service")
CERT = FileCertificate(
    cert_file="/etc/letsencrypt/live/x/fullchain.pem", key_file="/etc/letsencrypt/live/x/privkey.pem"
)


def web_units(**states: dict[str, str]) -> dict[str, Any]:
    lines: list[str] = []
    for unit in WEB:
        state = {"LoadState": "not-found", "ActiveState": "inactive", "UnitFileState": "", **states.get(unit, {})}
        lines += [f"Id={unit}", *(f"{key}={value}" for key, value in state.items()), "---"]
    return {"for unit in nginx.service": lines}


def converged(cfg: TraefikDeployConfig = CFG, /, **extra: Any) -> dict[str, Any]:
    responses = {
        **LINUX,
        "cat /proc/1/comm": ["systemd"],
        "/usr/local/bin/traefik version": ["Version:      3.7.13", "Codename:     x"],
        "command -v ufw": ["/usr/sbin/ufw"],
        "command -v apt-get": ["/usr/bin/apt-get"],
        "ufw show added": [
            "Added user rules (see 'ufw status' for running firewall):",
            "ufw allow 80/tcp",
            "ufw allow 443/tcp",
        ],
        **web_units(),
        **fakehost.file(STATIC, render_static(cfg)),
        **fakehost.file(UNIT, render_unit(cfg)),
        **fakehost.file(LOGROTATE, render_logrotate(cfg)),
        **fakehost.stat("/etc/traefik/acme/acme.json", mode="-rw-------"),
        **fakehost.directory("/etc/traefik/acme", mode="drwx------"),
        **fakehost.directory("/etc/traefik/dynamic"),
        **fakehost.directory("/etc/traefik"),
        **fakehost.directory("/var/log/traefik"),
        **fakehost.directory("/etc/systemd/system"),
        **fakehost.directory("/etc/logrotate.d"),
        "stat -c %a ": ["755"],
        **fakehost.service("traefik.service"),
    }
    responses.update(extra)
    return responses


def run(responses: dict[str, Any], cfg: TraefikDeployConfig = CFG) -> FakeRun:
    return run_deploy_fake(deploy_traefik, cfg, responses=responses)


def ok(responses: dict[str, Any], cfg: TraefikDeployConfig = CFG) -> FakeRun:
    result = run(responses, cfg)
    assert result.succeeded, result.error
    return result


def test_converged_host_changes_nothing() -> None:
    result = ok(converged())

    assert result.mutating_changed_ops == []
    assert result.changed_ops == CHECKS
    assert not any("restart" in command for command in result.executed_commands)


def test_changed_static_config_is_written_then_traefik_restarts() -> None:
    result = ok(converged(**fakehost.file(STATIC, "# old\n")))

    assert result.mutating_changed_ops == ["Traefik | Write the Traefik static config", RESTART]
    assert result.upload(STATIC).decode() == render_static(CFG)
    assert "systemctl restart traefik.service" in result.executed_commands


def test_changed_unit_reloads_systemd_and_restarts() -> None:
    result = ok(converged(**fakehost.file(UNIT, "[Unit]\n")))

    assert result.mutating_changed_ops == [
        "Traefik | Write the Traefik unit",
        "Traefik | Reload systemd for the Traefik unit",
        RESTART,
    ]


def test_invalid_static_config_never_reaches_the_host(monkeypatch: pytest.MonkeyPatch) -> None:
    # Whatever produces it, a static config that does not parse stops the
    # deploy while planning: nothing is written and Traefik is not restarted.
    monkeypatch.setattr(traefik_deploy, "render_static", lambda cfg: '[entryPoints\n  address = ":80"\n')

    result = run(converged(**fakehost.file(STATIC, "# old\n")))

    assert not result.succeeded
    assert "not valid TOML" in str(result.error)
    assert result.executed_commands == []
    assert result.uploaded_paths == []


def test_static_config_without_entrypoints_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(traefik_deploy, "render_static", lambda cfg: "[global]\n")

    result = run(converged())

    assert "has no [entryPoints]" in str(result.error)
    assert result.executed_commands == []


def test_invalid_certificate_list_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = CFG.model_copy(update={"file_certificates": (CERT,)})
    monkeypatch.setattr(traefik_deploy, "render_certificates", lambda cfg: "tls:\n  certificates: {certFile: x}\n")

    result = run(converged(cfg), cfg)

    assert "malformed" in str(result.error)
    assert result.executed_commands == []


def test_missing_certificate_file_is_refused() -> None:
    cfg = CFG.model_copy(update={"file_certificates": (CERT,)})

    result = run(converged(cfg, **{f"test -f {CERT.cert_file}": ["present"]}), cfg)

    assert f"{CERT.key_file} is missing" in str(result.error)
    assert result.uploaded_paths == []


def test_certificates_are_written_when_configured() -> None:
    cfg = CFG.model_copy(update={"file_certificates": (CERT,)})
    present = {f"test -f {path}": ["present"] for path in (CERT.cert_file, CERT.key_file)}

    result = ok(converged(cfg, **present), cfg)

    assert result.mutating_changed_ops == ["Traefik | Write the file-provider certificates", RESTART]
    assert yaml.safe_load(result.upload(CERTS)) == {
        "tls": {"certificates": [{"certFile": CERT.cert_file, "keyFile": CERT.key_file}]}
    }


@pytest.mark.parametrize(
    "responses",
    [{"test -e /var/lib/traefik-transactions": ["enrolled"]}, {}],
    ids=["enrolled host", "transaction_required"],
)
def test_transaction_managed_hosts_are_refused(responses: dict[str, Any]) -> None:
    cfg = CFG if responses else CFG.model_copy(update={"transaction_required": True})

    result = run(converged(**responses, **fakehost.file(STATIC, "# old\n")), cfg)

    assert "guarded Traefik transaction workflow" in str(result.error)
    assert result.executed_commands == []
    assert result.uploaded_paths == []


def test_new_version_is_verified_before_the_restart() -> None:
    cfg = CFG.model_copy(update={"version": "3.7.14"})

    result = ok(converged(cfg, **{"uname -m": ["x86_64"]}), cfg)

    assert result.mutating_changed_ops == [
        "Traefik | Install Traefik 3.7.14",
        "Traefik | Check the installed Traefik is 3.7.14",
        RESTART,
    ]
    install, check, restart = result.executed_commands[:3]
    assert "traefik_v3.7.14_linux_amd64.tar.gz" in install
    assert "a" * 64 in install
    assert "sha256sum -c" in install
    assert check == "/usr/local/bin/traefik version | grep -Eq 'Version:[[:space:]]+v?3\\.7\\.14$'"
    assert restart == "systemctl restart traefik.service"


def test_failed_version_check_stops_before_the_restart() -> None:
    cfg = CFG.model_copy(update={"version": "3.7.14"})
    responses = {"version | grep -Eq": {"success": False}, **converged(cfg, **{"uname -m": ["x86_64"]})}

    result = run(responses, cfg)

    assert not result.succeeded
    assert "systemctl restart traefik.service" not in result.executed_commands


def test_fresh_host_installs_and_starts_without_restart() -> None:
    responses = {
        **LINUX,
        "cat /proc/1/comm": ["systemd"],
        "uname -m": ["aarch64"],
        **web_units(),
        **fakehost.service("traefik.service", running=False, enabled=False),
    }

    result = ok(responses)

    changed = result.mutating_changed_ops
    for path in ("/etc/traefik", "/etc/traefik/dynamic", "/etc/traefik/acme", "/var/log/traefik"):
        assert f"Traefik | Ensure {path}" in changed
    assert changed.index("Traefik | Install Traefik 3.7.13") < changed.index(
        "Traefik | Write the Traefik static config"
    )
    assert any("traefik_v3.7.13_linux_arm64.tar.gz" in command for command in result.executed_commands)
    assert "Traefik | Ensure Traefik" in result.mutating_changed_ops
    assert "systemctl start traefik.service" in result.executed_commands
    # Not running before: the start picks up the new files, no restart.
    assert "systemctl restart traefik.service" not in result.executed_commands


def test_unknown_architecture_is_refused() -> None:
    responses = converged(**{"/usr/local/bin/traefik version": [], "uname -m": ["riscv64"]})

    assert "unknown host architecture" in str(run(responses).error)


def test_force_update_reinstalls_the_same_version() -> None:
    cfg = CFG.model_copy(update={"force_update": True, "arch": "amd64"})

    result = ok(converged(cfg), cfg)

    assert result.mutating_changed_ops[0] == "Traefik | Install Traefik 3.7.13"


def test_conflicting_web_servers_are_disarmed() -> None:
    responses = converged(
        **web_units(
            **{
                "nginx.service": {"LoadState": "loaded", "ActiveState": "active", "UnitFileState": "enabled"},
                "lighttpd.service": {"LoadState": "masked", "ActiveState": "failed", "UnitFileState": "masked"},
                "caddy.service": {"LoadState": "masked", "ActiveState": "inactive", "UnitFileState": "masked"},
            }
        )
    )

    result = ok(responses)

    assert result.mutating_changed_ops == ["Traefik | Disarm nginx.service", "Traefik | Disarm lighttpd.service"]
    assert result.executed_commands[:4] == [
        "systemctl stop nginx.service",
        "systemctl disable nginx.service",
        "systemctl mask nginx.service",
        "systemctl reset-failed lighttpd.service",
    ]


def test_web_servers_are_left_alone_when_masking_is_off() -> None:
    cfg = CFG.model_copy(update={"mask_conflicting_web_services": False})
    nginx = {"LoadState": "loaded", "ActiveState": "active", "UnitFileState": "enabled"}

    result = ok(converged(cfg, **web_units(**{"nginx.service": nginx})), cfg)

    assert result.mutating_changed_ops == []


def test_missing_firewall_rules_are_added() -> None:
    cfg = CFG.model_copy(update={"dashboard_firewall_open": True})

    result = ok(converged(cfg, **{"ufw show added": ["ufw allow 80/tcp"]}), cfg)

    assert [c for c in result.executed_commands if c.startswith("ufw")] == ["ufw allow 443/tcp", "ufw allow 8090/tcp"]


def test_firewall_is_left_alone_without_ufw_or_when_off() -> None:
    no_ufw = converged(**{"command -v ufw": [], "ufw show added": []})
    off = CFG.model_copy(update={"configure_firewall": False})

    assert ok(no_ufw).mutating_changed_ops == []
    assert ok(converged(off, **{"ufw show added": []}), off).mutating_changed_ops == []


@pytest.mark.parametrize(
    "update",
    [
        {"https_port": 80},
        {"dashboard_port": 443},
        {"dashboard_enabled": False, "metrics_port": 80},
        {"dashboard_enabled": False, "metrics_bind_address": "::1"},
    ],
)
def test_listeners_traefik_cannot_bind_are_refused(update: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        TraefikDeployConfig(checksum=CHECKSUM, letsencrypt_email="a@example.org", **update)


def test_bracketed_ipv6_metrics_bind_is_accepted() -> None:
    cfg = TraefikDeployConfig(
        checksum=CHECKSUM, letsencrypt_email="a@example.org", dashboard_enabled=False, metrics_bind_address="[::1]"
    )
    assert 'address = "[::1]:8080"' in render_static(cfg)


def test_config_validation() -> None:
    with pytest.raises(ValidationError):
        TraefikDeployConfig(letsencrypt_email="ops@example.org")  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        TraefikDeployConfig(checksum="", letsencrypt_email="ops@example.org")
    with pytest.raises(ValidationError):
        TraefikDeployConfig(checksum=CHECKSUM, letsencrypt_email='a"b@example.org')
    with pytest.raises(ValidationError, match="cover exactly"):
        TraefikDeployConfig(checksum=CHECKSUM, letsencrypt_email="a@example.org", alias_policy={"web": "delete"})
    with pytest.raises(ValidationError, match=r"3\.7\.12"):
        TraefikDeployConfig(
            checksum=CHECKSUM,
            letsencrypt_email="a@example.org",
            version="3.7.11",
            alias_policy={"web": "delete", "web-secure": "delete", "traefik": "delete"},
        )
    without_traefik = TraefikDeployConfig(
        checksum=CHECKSUM,
        letsencrypt_email="a@example.org",
        dashboard_enabled=False,
        metrics_enabled=False,
        alias_policy={"web": "delete", "web-secure": "delete"},
    )
    assert "traefik" not in without_traefik.alias_policy


# -- parity with the role -----------------------------------------------------

VENDORED = Path(__file__).parent / "parity" / "ansible"
ALL_ALIASES = {"web": "delete", "web-secure": "delete", "traefik": "delete"}
PARITY = {
    "defaults": CFG,
    "macmini-like": CFG.model_copy(
        update={"version": "3.7.14", "alias_policy": ALL_ALIASES, "file_certificates": (CERT, CERT)}
    ),
    "metrics only, no redirect": CFG.model_copy(
        update={"dashboard_enabled": False, "http_redirect_to_https": False, "alias_policy": ALL_ALIASES}
    ),
    "thirty days of logs": CFG.model_copy(update={"logrotate_days": 30, "log_dir": "/var/log/t"}),
    "nothing on the traefik entrypoint": CFG.model_copy(
        update={
            "dashboard_enabled": False,
            "metrics_enabled": False,
            "log_level": "DEBUG",
            "log_format": "common",
            "config_dir": "/srv/traefik",
            "log_dir": "/srv/log",
            "binary_path": "/usr/bin/traefik",
            "http_port": 8000,
            "https_port": 8443,
        }
    ),
}


def role_vars(cfg: TraefikDeployConfig) -> dict[str, Any]:
    return {
        "traefik_dashboard_enabled": cfg.dashboard_enabled,
        "traefik_log_level": cfg.log_level,
        "traefik_log_format": cfg.log_format,
        "traefik_log_dir": cfg.log_dir,
        "traefik_logrotate_days": cfg.logrotate_days,
        "traefik_dynamic_dir": cfg.dynamic_path,
        "traefik_alias_policy": dict(cfg.alias_policy),
        "traefik_http_port": cfg.http_port,
        "traefik_https_port": cfg.https_port,
        "traefik_http_redirect_to_https": cfg.http_redirect_to_https,
        "traefik_dashboard_port": cfg.dashboard_port,
        "traefik_metrics_enabled": cfg.metrics_enabled,
        "traefik_metrics_bind_address": cfg.metrics_bind_address,
        "traefik_metrics_port": cfg.metrics_port,
        "traefik_letsencrypt_email": cfg.letsencrypt_email,
        "traefik_acme_storage": cfg.acme_storage_path,
        "traefik_binary_path": cfg.binary_path,
        "traefik_static_config": cfg.static_path,
        "traefik_config_dir": cfg.config_dir,
        "traefik_file_certificates": [cert.model_dump() for cert in cfg.file_certificates],
    }


def render_ansible(template: str, cfg: TraefikDeployConfig) -> str:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(VENDORED),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    return env.get_template(template).render(**role_vars(cfg))


@pytest.mark.parametrize("cfg", PARITY.values(), ids=PARITY.keys())
def test_static_config_matches_the_role(cfg: TraefikDeployConfig) -> None:
    assert render_static(cfg) == render_ansible("traefik_deploy__traefik.toml.j2", cfg)


@pytest.mark.parametrize("cfg", PARITY.values(), ids=PARITY.keys())
def test_unit_matches_the_role(cfg: TraefikDeployConfig) -> None:
    assert render_unit(cfg) == render_ansible("traefik_deploy__traefik.service.j2", cfg)


def test_certificates_match_the_role() -> None:
    cfg = PARITY["macmini-like"]
    assert render_certificates(cfg) == render_ansible("traefik_deploy__dynamic__certificates.yml.j2", cfg)


@pytest.mark.parametrize("cfg", PARITY.values(), ids=PARITY.keys())
def test_logrotate_matches_the_role(cfg: TraefikDeployConfig) -> None:
    assert render_logrotate(cfg) == render_ansible("traefik_deploy__traefik.logrotate.j2", cfg)
