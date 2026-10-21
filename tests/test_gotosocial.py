"""Deploy-level scenarios for gotosocial against the fake connector."""

import base64
import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr, ValidationError

from ops_deploy.helpers.probes import FAILED
from ops_deploy.services.gotosocial import (
    GotosocialConfig,
    deploy_gotosocial,
    render_admin_wrapper,
    render_config,
    render_route,
    render_unit,
)
from ops_deploy.services.gotosocial.deploy import INSTALLER, RESTART_PROBE, install_command
from ops_deploy.services.gotosocial.deploy import READINESS as READY_SCRIPT
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost

P = "Deploy GoToSocial | "
DATA = "/var/lib/gotosocial"
MARKER = f"{DATA}/.ops-domain-layout"
CONFIG = "/etc/gotosocial/config.yaml"
UNIT = "/etc/systemd/system/gotosocial.service"
WRAPPER = "/usr/local/sbin/gotosocial-admin"
ROUTE = "/etc/traefik/dynamic/gotosocial.yml"
RELEASE = "/opt/gotosocial/releases/0.22.2"
CURRENT = "/opt/gotosocial/current"
LAYOUT = "fedi.example.org example.org"
PASSWORD = "gotosocial-fixture-smtp-password-0123"
# Probe commands (substrings of the fact commands).
LAYOUT_PROBE = f"if [ -L {MARKER} ]"
RELEASE_PROBE = f"[ -e {RELEASE}/gotosocial ]"
RESTART = "ActiveEnterTimestamp"
DPKG = "dpkg-query -W"
RELOAD = "NeedDaemonReload"
READINESS = f"{P}Wait for GoToSocial readiness"


@pytest.fixture
def cfg() -> GotosocialConfig:
    return GotosocialConfig(host="fedi.example.org", account_domain="example.org", traefik_cert_resolver="letsencrypt")


def marker_answer(content: str) -> list[str]:
    return ["file " + base64.b64encode(content.encode()).decode()]


def file_with_group(path: str, content: str, *, user: str, group: str, mode: str) -> dict[str, Any]:
    return {
        f"sha1sum {path} ": [f"{hashlib.sha1(content.encode()).hexdigest()}  {path}"],
        f"sha256sum {path} ": [f"{hashlib.sha256(content.encode()).hexdigest()}  {path}"],
        **fakehost.stat(path, user=user, group=group, mode=mode),
    }


def base_host(**overrides: Any) -> dict[str, Any]:
    """A Linux/systemd amd64 host with the packages installed and nothing else."""

    return {
        LAYOUT_PROBE: ["absent"],
        RELEASE_PROBE: ["absent"],
        RESTART: ["inactive"],
        RELOAD: ["no"],
        DPKG: [f"ii |{name}|" for name in ("ca-certificates", "sqlite3", "tar")],
        **fakehost.UBUNTU,
        **overrides,
    }


def converged(cfg: GotosocialConfig, *drift: dict[str, Any], password: SecretStr | None = None) -> dict[str, Any]:
    """Facts of a host the role (or this deploy) fully deployed with ``cfg``."""

    responses = base_host(
        **{
            LAYOUT_PROBE: marker_answer(cfg.domain_layout + "\n"),
            RELEASE_PROBE: ["present"],
            RESTART: ["current"],
        }
    )
    responses.update(fakehost.accounts({"gotosocial": DATA}))
    for path in ("/opt/gotosocial", "/opt/gotosocial/releases", "/etc/traefik/dynamic", "/etc/systemd/system"):
        responses.update(fakehost.directory(path))
    responses.update(fakehost.stat("/etc/gotosocial", user="root", group="gotosocial", mode="drwxr-x---"))
    for path in (DATA, f"{DATA}/storage", f"{DATA}/.cache"):
        responses.update(fakehost.directory(path, user="gotosocial", mode="drwx------"))
    responses.update(fakehost.symlink(CURRENT, RELEASE))
    responses.update(fakehost.file(WRAPPER, render_admin_wrapper(cfg), mode="-rwxr-x---"))
    config = render_config(cfg, password).reveal().decode()
    responses.update(file_with_group(CONFIG, config, user="root", group="gotosocial", mode="-rw-r-----"))
    responses.update(fakehost.file(UNIT, render_unit(cfg)))
    responses.update(fakehost.file(MARKER, cfg.domain_layout + "\n"))
    responses.update(fakehost.file(ROUTE, render_route(cfg)))
    responses.update(fakehost.service("gotosocial.service"))
    for overrides in drift:
        responses.update(overrides)
    return responses


def deploy(cfg: GotosocialConfig, responses: dict[str, Any], password: SecretStr | None = None) -> FakeRun:
    run = run_deploy_fake(deploy_gotosocial, cfg, password, responses=responses)
    assert run.succeeded, run.error
    return run


def refused(cfg: GotosocialConfig, responses: dict[str, Any]) -> FakeRun:
    run = run_deploy_fake(deploy_gotosocial, cfg, responses=responses)
    assert not run.succeeded
    assert run.executed_commands == []
    assert run.uploads == []
    return run


def changed(*names: str) -> list[str]:
    return [f"{P}{name}" for name in names]


# -- first deploy ------------------------------------------------------------------------


def test_first_run_installs_everything_in_the_roles_order(cfg: GotosocialConfig) -> None:
    run = deploy(cfg, base_host(**{DPKG: ["ii |tar|"]}))

    assert run.mutating_changed_ops == changed(
        "Install GoToSocial packages",
        "Ensure group gotosocial",
        "Ensure user gotosocial",
        "Ensure /opt/gotosocial",
        "Ensure /opt/gotosocial/releases",
        "Ensure /etc/gotosocial",
        f"Ensure {DATA}",
        f"Ensure {DATA}/storage",
        f"Ensure {DATA}/.cache",
        "Install GoToSocial 0.22.2",
        f"Point {CURRENT} at 0.22.2",
        "Install admin wrapper",
        f"Write {CONFIG}",
        "Install systemd unit gotosocial.service",
        "Reload systemd",
        "Enable gotosocial.service",
        "Start gotosocial.service",
        "Record the domain layout",
        "Ensure /etc/traefik/dynamic",
        "Write Traefik route gotosocial",
    )
    commands = run.executed_commands
    # Only the missing packages, with the role's cache refresh.
    assert "apt-get update" in commands
    assert any(c.endswith("install ca-certificates sqlite3") for c in commands)
    assert "groupadd -r gotosocial" in commands
    assert "useradd -d /var/lib/gotosocial -s /usr/sbin/nologin -g gotosocial -r -M gotosocial" in commands
    assert f"ln -s {RELEASE} {CURRENT}" in commands
    assert "chmod 750 /etc/gotosocial" in commands
    assert "chown root:gotosocial /etc/gotosocial" in commands
    assert "chmod 700 /var/lib/gotosocial" in commands
    # Started once: no restart right after the start (the role restarts from a handler too).
    assert "systemctl start gotosocial.service" in commands
    assert "systemctl restart gotosocial.service" not in commands
    assert not any("traefik" in c and "systemctl" in c for c in commands)
    # The data directory keeps its owner: the marker upload never chowns its parent.
    assert f"chown root:root {DATA}" not in commands
    assert run.upload(MARKER) == (LAYOUT + "\n").encode()
    assert run.upload(ROUTE).decode() == render_route(cfg)
    assert run.upload(UNIT).decode() == render_unit(cfg)
    assert run.upload(WRAPPER).decode() == render_admin_wrapper(cfg)
    assert READINESS in run.changed_ops
    assert any("http://127.0.0.1:10070/readyz" in c for c in commands)


def test_first_run_with_every_package_present_skips_apt(cfg: GotosocialConfig) -> None:
    run = deploy(cfg, base_host())

    assert f"{P}Install GoToSocial packages" not in [op.name for op in run.ops]
    assert not any("apt-get" in c for c in run.executed_commands)


def test_release_install_command_carries_url_checksum_and_release_dir(cfg: GotosocialConfig) -> None:
    run = deploy(cfg, base_host())

    install = next(c for c in run.executed_commands if c.startswith("python3 -I -c") and "gotosocial_0.22.2" in c)
    payload = {
        "release_dir": RELEASE,
        "sha256": "b8e7406c7eae73a50b7990affb5b1151fe81cfdb1c12951630bb08b0d77f7337",
        "url": "https://codeberg.org/superseriousbusiness/gotosocial/releases/download/v0.22.2/"
        "gotosocial_0.22.2_linux_amd64.tar.gz",
    }
    assert json.dumps(payload, sort_keys=True) in install
    assert install == install_command(cfg, "amd64")


def test_arm64_host_gets_the_arm64_archive(cfg: GotosocialConfig) -> None:
    run = deploy(cfg, base_host(**{"uname -m": ["aarch64"]}))

    install = next(c for c in run.executed_commands if "gotosocial_0.22.2" in c)
    assert "linux_arm64.tar.gz" in install
    assert "274ddb425444ea06f9f02bbd5abbce0bddc6f0a0d7c359ba8d8f0936ab8f3da5" in install


def test_unsupported_architecture_fails_before_any_change(cfg: GotosocialConfig) -> None:
    run = refused(cfg, base_host(**{"uname -m": ["riscv64"]}))

    assert "riscv64" in str(run.error)


def test_architecture_without_a_checksum_fails(cfg: GotosocialConfig) -> None:
    amd64_only = cfg.model_copy(update={"release_checksums": {"amd64": cfg.release_checksums["amd64"]}})

    refused(amd64_only, base_host(**{"uname -m": ["aarch64"]}))


def test_non_linux_or_non_systemd_hosts_are_refused(cfg: GotosocialConfig) -> None:
    refused(cfg, base_host(**{"cat /proc/1/comm": ["init"]}))


# -- converged host ----------------------------------------------------------------------


def test_converged_host_gets_no_mutating_operation(cfg: GotosocialConfig) -> None:
    run = deploy(cfg, converged(cfg))

    assert run.mutating_changed_ops == []
    assert run.changed_ops == [READINESS]
    assert run.uploads == []
    assert run.stdin == []


def test_converged_with_smtp_password_is_idempotent() -> None:
    cfg = GotosocialConfig(host="example.org", smtp_host="smtp.example.org", smtp_from="gts@example.org")
    password = SecretStr(PASSWORD)

    run = deploy(cfg, converged(cfg, password=password), password)

    assert run.mutating_changed_ops == []


def test_second_run_after_the_first_changes_nothing(cfg: GotosocialConfig) -> None:
    first = deploy(cfg, base_host())
    second = deploy(cfg, converged(cfg))

    assert first.mutating_changed_ops
    assert second.mutating_changed_ops == []


# -- restarts ------------------------------------------------------------------------------


def test_config_drift_rewrites_and_restarts_once(cfg: GotosocialConfig) -> None:
    drift = file_with_group(CONFIG, "log-level: debug\n", user="root", group="gotosocial", mode="-rw-r-----")
    run = deploy(cfg, converged(cfg, drift))

    assert run.mutating_changed_ops == changed(f"Write {CONFIG}", "Restart gotosocial.service")
    assert run.executed_commands.count("systemctl restart gotosocial.service") == 1


def test_unit_drift_reloads_and_restarts(cfg: GotosocialConfig) -> None:
    run = deploy(cfg, converged(cfg, fakehost.file(UNIT, "[Unit]\n")))

    assert run.mutating_changed_ops == changed(
        "Install systemd unit gotosocial.service", "Reload systemd", "Restart gotosocial.service"
    )


def test_wrapper_or_route_drift_does_not_restart(cfg: GotosocialConfig) -> None:
    drift = {**fakehost.file(WRAPPER, "#!/bin/sh\n", mode="-rwxr-x---"), **fakehost.file(ROUTE, "http: {}\n")}
    run = deploy(cfg, converged(cfg, drift))

    assert run.mutating_changed_ops == changed("Install admin wrapper", "Write Traefik route gotosocial")


def test_new_version_installs_relinks_and_restarts(cfg: GotosocialConfig) -> None:
    newer = cfg.model_copy(update={"version": "0.23.0"})
    responses = converged(newer, {RELEASE_PROBE: ["present"], "[ -e /opt/gotosocial/releases/0.23.0": ["absent"]})
    responses.update(fakehost.symlink(CURRENT, RELEASE))
    run = deploy(newer, responses)

    # config.yaml names the ``current`` link, not the version: only the link changes it.
    assert run.mutating_changed_ops == changed(
        "Install GoToSocial 0.23.0", f"Point {CURRENT} at 0.23.0", "Restart gotosocial.service"
    )
    assert any(f"ln -s /opt/gotosocial/releases/0.23.0 {CURRENT}" in c for c in run.executed_commands)


def test_lost_restart_from_an_earlier_run_is_made_up(cfg: GotosocialConfig) -> None:
    run = deploy(cfg, converged(cfg, {RESTART: ["owed"]}))

    assert run.mutating_changed_ops == changed("Restart gotosocial.service")


def test_owed_daemon_reload_runs_without_a_unit_change(cfg: GotosocialConfig) -> None:
    run = deploy(cfg, converged(cfg, {RELOAD: ["yes"]}))

    assert run.mutating_changed_ops == changed("Reload systemd")


def test_stopped_service_is_started_not_restarted(cfg: GotosocialConfig) -> None:
    drift = {**fakehost.service("gotosocial.service", running=False), RESTART: ["inactive"]}
    drift.update(file_with_group(CONFIG, "x: 1\n", user="root", group="gotosocial", mode="-rw-r-----"))
    run = deploy(cfg, converged(cfg, drift))

    assert run.mutating_changed_ops == changed(f"Write {CONFIG}", "Start gotosocial.service")


def test_failing_restart_probe_fails_the_deploy(cfg: GotosocialConfig) -> None:
    refused(cfg, converged(cfg, {RESTART: ["", FAILED]}))


def test_state_stopped_stops_and_skips_restart_and_health(cfg: GotosocialConfig) -> None:
    stopped = cfg.model_copy(update={"service_state": "stopped"})
    run = deploy(stopped, converged(stopped))

    assert run.mutating_changed_ops == changed("Stop gotosocial.service")
    assert READINESS not in run.changed_ops
    assert not any(RESTART in c for c in run.fact_commands)


def test_disabled_service_is_disabled(cfg: GotosocialConfig) -> None:
    disabled = cfg.model_copy(update={"service_enabled": False})
    run = deploy(disabled, converged(disabled))

    assert run.mutating_changed_ops == changed("Disable gotosocial.service")
    assert "systemctl disable gotosocial.service" in run.executed_commands


def test_health_check_can_be_disabled(cfg: GotosocialConfig) -> None:
    quiet = cfg.model_copy(update={"healthcheck_enabled": False})
    run = deploy(quiet, converged(quiet))

    assert run.changed_ops == []


def test_ipv6_listener_is_checked_in_brackets() -> None:
    cfg = GotosocialConfig(host="example.org", bind_address="::1", port=18080)
    run = deploy(cfg, converged(cfg))

    assert any("http://[::1]:18080/readyz" in c for c in run.executed_commands)


# -- the domain layout guard -------------------------------------------------------------


def test_changed_layout_is_refused_before_anything_changes(cfg: GotosocialConfig) -> None:
    run = refused(cfg, converged(cfg, {LAYOUT_PROBE: marker_answer("social.example.org social.example.org\n")}))

    message = str(run.error)
    assert '"social.example.org social.example.org"' in message
    assert f'"{LAYOUT}"' in message
    assert "allow_domain_layout_change" in message
    assert run.ops == []


def test_changed_account_domain_alone_is_refused() -> None:
    cfg = GotosocialConfig(host="fedi.example.org")
    refused(cfg, converged(cfg, {LAYOUT_PROBE: marker_answer(LAYOUT + "\n")}))


def test_override_allows_and_records_the_new_layout(cfg: GotosocialConfig) -> None:
    allowed = cfg.model_copy(update={"allow_domain_layout_change": True})
    old = "social.example.org social.example.org\n"
    responses = converged(allowed, {LAYOUT_PROBE: marker_answer(old), **fakehost.file(MARKER, old)})
    run = deploy(allowed, responses)

    assert run.mutating_changed_ops == changed("Record the domain layout")
    assert run.upload(MARKER) == (LAYOUT + "\n").encode()


@pytest.mark.parametrize("recorded", [LAYOUT, f"  {LAYOUT}  \n\n", f"{LAYOUT}\r\n"])
def test_recorded_layout_is_compared_trimmed(cfg: GotosocialConfig, recorded: str) -> None:
    # slurp | b64decode | trim on both sides, as layout.yml compares them.
    run = deploy(cfg, converged(cfg, {LAYOUT_PROBE: marker_answer(recorded), **fakehost.file(MARKER, recorded)}))

    assert run.mutating_changed_ops == changed("Record the domain layout")


@pytest.mark.parametrize("recorded", ["", "\n", f"{LAYOUT} extra\n", LAYOUT.replace(" ", "  ")])
def test_any_other_recorded_content_is_refused(cfg: GotosocialConfig, recorded: str) -> None:
    refused(cfg, converged(cfg, {LAYOUT_PROBE: marker_answer(recorded)}))


def test_missing_marker_on_an_existing_instance_is_recorded(cfg: GotosocialConfig) -> None:
    # An instance deployed before the guard existed: the pair is recorded, nothing else changes.
    responses = converged(cfg, {LAYOUT_PROBE: ["absent"]})
    del responses[f"test -e {MARKER} ||"]
    run = deploy(cfg, responses)

    assert run.mutating_changed_ops == changed("Record the domain layout")


def test_marker_that_is_not_a_regular_file_is_refused(cfg: GotosocialConfig) -> None:
    run = refused(cfg, converged(cfg, {LAYOUT_PROBE: ["other"]}))

    assert "not a regular file" in str(run.error)


def test_override_does_not_accept_a_non_regular_marker(cfg: GotosocialConfig) -> None:
    allowed = cfg.model_copy(update={"allow_domain_layout_change": True})
    refused(allowed, converged(allowed, {LAYOUT_PROBE: ["other"]}))


@pytest.mark.parametrize("answer", [["", FAILED], ["file !!!"], ["something"]])
def test_failed_or_garbled_layout_probe_is_refused(cfg: GotosocialConfig, answer: list[str]) -> None:
    refused(cfg, converged(cfg, {LAYOUT_PROBE: answer}))


def test_layout_probe_reads_raw_bytes_like_slurp(cfg: GotosocialConfig) -> None:
    run = deploy(cfg, converged(cfg))

    probe = next(c for c in run.fact_commands if LAYOUT_PROBE in c)
    assert f"base64 -w0 < {MARKER}" in probe
    assert f"[ -f {MARKER} ]" in probe


# -- release probe ---------------------------------------------------------------------------


def test_present_release_is_never_downloaded_again(cfg: GotosocialConfig) -> None:
    run = deploy(cfg, converged(cfg))

    assert not any("gotosocial_0.22.2" in c for c in run.executed_commands)


def test_failing_release_probe_fails_the_deploy(cfg: GotosocialConfig) -> None:
    refused(cfg, converged(cfg, {RELEASE_PROBE: ["", FAILED]}))


# -- Traefik ---------------------------------------------------------------------------------


def test_disabled_routing_removes_the_route(cfg: GotosocialConfig) -> None:
    unrouted = cfg.model_copy(update={"traefik_enabled": False})
    run = deploy(unrouted, converged(unrouted))

    assert run.mutating_changed_ops == changed("Remove Traefik route gotosocial")
    assert f"rm -f {ROUTE}" in run.executed_commands
    assert not any("systemctl" in c and "traefik" in c for c in run.executed_commands)


def test_disabled_routing_without_a_route_changes_nothing(cfg: GotosocialConfig) -> None:
    unrouted = cfg.model_copy(update={"traefik_enabled": False})
    responses = converged(unrouted)
    del responses[f"test -e {ROUTE} ||"]
    run = deploy(unrouted, responses)

    assert run.mutating_changed_ops == []


# -- secrets ---------------------------------------------------------------------------------


def test_smtp_password_travels_only_on_stdin() -> None:
    cfg = GotosocialConfig(host="example.org", smtp_host="smtp.example.org", smtp_from="gts@example.org")
    run = deploy(cfg, base_host(), SecretStr(PASSWORD))

    assert PASSWORD not in run.all_text()
    assert base64.b64encode(PASSWORD.encode()).decode() not in run.all_text()
    assert CONFIG not in run.uploaded_paths
    [(command, stdin)] = [(c, s) for c, s in run.stdin if "config.yaml" in c]
    assert PASSWORD not in command
    assert PASSWORD in base64.b64decode(stdin).decode()
    assert "smtp-password:" in base64.b64decode(stdin).decode()


def test_config_without_password_has_an_empty_smtp_password(cfg: GotosocialConfig) -> None:
    run = deploy(cfg, base_host())

    [(_, stdin)] = [(c, s) for c, s in run.stdin if "config.yaml" in c]
    assert "smtp-password: ''" in base64.b64decode(stdin).decode()


# -- users -----------------------------------------------------------------------------------


def test_existing_user_gets_the_roles_shell_and_home(cfg: GotosocialConfig) -> None:
    # ansible.builtin.user enforces shell and home on an existing account.
    responses = converged(cfg, fakehost.accounts({"gotosocial": "/home/gotosocial"}, shell="/bin/bash"))
    run = deploy(cfg, responses)

    assert run.mutating_changed_ops == changed("Ensure user gotosocial")
    assert "usermod -d /var/lib/gotosocial -s /usr/sbin/nologin gotosocial" in run.executed_commands


# -- config validation (validate.yml) ----------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"host": "CHANGEME"},
        {"host": ""},
        {"host": "Fedi.example.org"},
        {"host": "fedi.example.org."},
        {"host": "fedi.example.org", "account_domain": "other.org"},
        {"host": "example.org", "account_domain": "fedi.example.org"},
        {"host": "badexample.org", "account_domain": "example.org"},
        {"host": "example.org", "account_domain": "Example.org"},
        {"host": "example.org", "version": "0.22"},
        {"host": "example.org", "version": "v0.22.2"},
        {"host": "example.org", "release_checksums": {"amd64": "b8e7"}},
        {"host": "example.org", "bind_address": "0.0.0.0"},
        {"host": "example.org", "port": 1024},
        {"host": "example.org", "port": 65536},
        {"host": "example.org", "service_state": "restarted"},
        {"host": "example.org", "extra_config": {"smtp-password": "x"}},
        {"host": "example.org", "extra_config": {"oidc-client-secret": "x"}},
        {"host": "example.org", "extra_config": {"tls-key": "x"}},
        {"host": "example.org", "extra_config": {"host": "other.org"}},
        {"host": "example.org", "extra_config": {"db-address": "/tmp/x.db"}},
        {"host": "example.org", "extra_config": {"accounts-registration-open": True}},
        {"host": "example.org", "smtp_host": "smtp.example.org"},
        {"host": "example.org", "download_base_url": "ftp://example.org/x"},
        {"host": "example.org", "download_base_url": "https://user:pw@example.org/x"},
        {"host": "example.org", "install_root": "/opt/go to"},
        {"host": "example.org", "install_root": "/opt/../etc"},
        {"host": "example.org", "trusted_proxies": ("not-a-network",)},
        {"host": "example.org", "traefik_entrypoints": ()},
        {"host": "example.org", "systemd_memory_max": "1G\nExecStartPre=/bin/sh"},
        {"host": "example.org", "application_name": "line\nbreak"},
    ],
)
def test_role_assertions_fail_on_the_controller(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        GotosocialConfig(**overrides)


def test_subdomain_and_equal_account_domains_pass() -> None:
    assert GotosocialConfig(host="fedi.example.org", account_domain="example.org").domain_layout == LAYOUT
    assert GotosocialConfig(host="example.org", account_domain="example.org").domain_layout == "example.org example.org"
    assert GotosocialConfig(host="example.org").domain_layout == "example.org example.org"


def test_validation_errors_do_not_echo_the_extra_config_value() -> None:
    with pytest.raises(ValidationError) as caught:
        GotosocialConfig(host="example.org", extra_config={"smtp-password": "leaky-value-123"})

    assert "leaky-value-123" not in str(caught.value)


# -- the host-side release installer -------------------------------------------------------------


def _installer() -> Any:
    spec = importlib.util.spec_from_loader("gotosocial_release_host", loader=None)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    exec(compile(INSTALLER, "release_host.py", "exec"), module.__dict__)
    return module


def _archive(tmp_path: Path, members: dict[str, bytes]) -> tuple[str, str]:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755 if name == "gotosocial" else 0o644
            info.uid = info.gid = 1234
            tar.addfile(info, io.BytesIO(data))
    path = tmp_path / "release.tar.gz"
    path.write_bytes(buffer.getvalue())
    return path.as_uri(), hashlib.sha256(buffer.getvalue()).hexdigest()


@pytest.fixture
def releases(tmp_path: Path) -> Path:
    path = tmp_path / "opt" / "releases"
    path.mkdir(parents=True)
    path.chmod(0o755)
    return path


def test_installer_unpacks_into_place(tmp_path: Path, releases: Path) -> None:
    url, digest = _archive(tmp_path, {"gotosocial": b"#!/bin/sh\n", "web/assets/a.css": b"a{}"})
    release = releases / "0.22.2"

    _installer().main({"url": url, "sha256": digest, "release_dir": str(release)})

    assert (release / "gotosocial").read_bytes() == b"#!/bin/sh\n"
    assert (release / "web/assets/a.css").read_bytes() == b"a{}"
    assert oct(release.stat().st_mode & 0o777) == "0o755"
    assert [p.name for p in releases.iterdir()] == ["0.22.2"]


def test_installer_refuses_a_bad_checksum_and_leaves_nothing(tmp_path: Path, releases: Path) -> None:
    url, _ = _archive(tmp_path, {"gotosocial": b"x"})
    module = _installer()

    with pytest.raises(module.InstallError, match="checksum"):
        module.main({"url": url, "sha256": "0" * 64, "release_dir": str(releases / "0.22.2")})
    assert list(releases.iterdir()) == []


def test_installer_refuses_an_archive_without_the_binary(tmp_path: Path, releases: Path) -> None:
    url, digest = _archive(tmp_path, {"README.md": b"x"})
    module = _installer()

    with pytest.raises(module.InstallError, match="no gotosocial binary"):
        module.main({"url": url, "sha256": digest, "release_dir": str(releases / "0.22.2")})
    assert list(releases.iterdir()) == []


def test_installer_never_overwrites_a_partial_release_dir(tmp_path: Path, releases: Path) -> None:
    url, digest = _archive(tmp_path, {"gotosocial": b"x"})
    partial = releases / "0.22.2"
    (partial / "web").mkdir(parents=True)
    module = _installer()

    with pytest.raises(module.InstallError, match="review it"):
        module.main({"url": url, "sha256": digest, "release_dir": str(partial)})
    assert [p.name for p in partial.iterdir()] == ["web"]


def test_installer_fills_an_empty_release_dir_and_skips_an_installed_one(tmp_path: Path, releases: Path) -> None:
    url, digest = _archive(tmp_path, {"gotosocial": b"new"})
    release = releases / "0.22.2"
    release.mkdir()
    module = _installer()

    module.main({"url": url, "sha256": digest, "release_dir": str(release)})
    assert (release / "gotosocial").read_bytes() == b"new"
    (release / "gotosocial").write_bytes(b"kept")
    module.main({"url": "file:///nonexistent", "sha256": digest, "release_dir": str(release)})
    assert (release / "gotosocial").read_bytes() == b"kept"


def test_installer_refuses_a_group_writable_releases_dir(tmp_path: Path, releases: Path) -> None:
    url, digest = _archive(tmp_path, {"gotosocial": b"x"})
    releases.chmod(0o775)
    module = _installer()

    with pytest.raises(module.InstallError, match="not writable by others"):
        module.main({"url": url, "sha256": digest, "release_dir": str(releases / "0.22.2")})


def test_installer_failure_prints_a_fixed_message(tmp_path: Path, releases: Path) -> None:
    payload = json.dumps(
        {"url": "file:///nonexistent/secret-path", "sha256": "0" * 64, "release_dir": str(releases / "v")}
    )
    result = subprocess.run([sys.executable, "-I", "-c", INSTALLER, payload], capture_output=True, text=True)

    assert result.returncode == 1
    assert result.stdout == ""
    assert "secret-path" not in result.stderr
    assert result.stderr.startswith("release install failed")


# -- host-side probes ------------------------------------------------------------------------


def _script(source: str, name: str) -> Any:
    spec = importlib.util.spec_from_loader(name, loader=None)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    exec(compile(source, f"{name}.py", "exec"), module.__dict__)
    return module


def test_marker_probe_fails_when_the_read_fails(cfg: GotosocialConfig) -> None:
    run = deploy(cfg, converged(cfg))

    probe = next(c for c in run.fact_commands if LAYOUT_PROBE in c)
    assert f"c=$(base64 -w0 < {MARKER}) || exit 1" in probe


@pytest.mark.parametrize(
    ("active", "mtimes", "answer"),
    [
        ("inactive", [], "inactive"),
        ("failed", [], "inactive"),
        # Started 05:00:00.500000 UTC; a file written 0.1 s later in the same second is newer.
        ("active", [1_792_558_800_400_000_000], "current"),
        ("active", [1_792_558_800_500_000_000], "current"),
        ("active", [1_792_558_800_600_000_000], "owed"),
        ("active", [1_792_558_800_400_000_000, 1_792_558_801_000_000_000], "owed"),
        ("active", [], "current"),
    ],
)
def test_restart_probe_compares_with_sub_second_precision(active: str, mtimes: list[int], answer: str) -> None:
    probe = _script(RESTART_PROBE, "restart_host")

    assert probe.decide(active, "Wed 2026-10-21 05:00:00.500000 UTC", mtimes) == answer


@pytest.mark.parametrize("text", ["", "n/a", "Wed 2026-10-21 05:00:00 UTC", "Wed 2026-10-21 05:00:00.5 CEST"])
def test_restart_probe_refuses_an_unreadable_timestamp(text: str) -> None:
    probe = _script(RESTART_PROBE, "restart_host")

    with pytest.raises(ValueError):  # noqa: PT011 - strptime's own messages differ per input
        probe.decide("active", text, [0])


def test_restart_probe_is_strict(cfg: GotosocialConfig) -> None:
    run = deploy(cfg, converged(cfg))

    probe = next(c for c in run.fact_commands if RESTART in c)
    assert "python3 -I -c" in probe
    assert '"paths": ["/etc/gotosocial/config.yaml", "/etc/systemd/system/gotosocial.service", ' in probe


def test_readiness_check_needs_no_curl(cfg: GotosocialConfig) -> None:
    run = deploy(cfg, base_host(**{"command -v curl": []}))

    check = next(c for c in run.executed_commands if "/readyz" in c)
    assert check.startswith("python3 -I -c")
    assert "curl -" not in check
    assert not any(c.startswith(("curl", "sh -c")) for c in run.executed_commands)
    assert '"retries": 30' in check
    assert '"delay": 2' in check


def test_readiness_script_waits_for_200(tmp_path: Path) -> None:
    import http.server
    import threading

    answers = [503, 200]

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(answers.pop(0) if answers else 200)
            self.end_headers()

        def log_message(self, *args: Any) -> None:
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/readyz"
        ready = _script(READY_SCRIPT, "ready_host")
        assert ready.main({"url": url, "retries": 3, "delay": 0, "timeout": 5}) == 0
        answers[:] = [500, 500]
        payload = json.dumps({"url": url, "retries": 2, "delay": 0, "timeout": 5})
        result = subprocess.run([sys.executable, "-I", "-c", READY_SCRIPT, payload], capture_output=True, text=True)
        assert result.returncode == 1
        assert result.stderr.strip() == f"{url} answered 500, expected 200"
    finally:
        server.shutdown()
