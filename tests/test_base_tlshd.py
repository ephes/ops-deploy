"""tlshd for NFS over TLS: config validation, rendered files, fake-host rollout, secrets kept out of the plan."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import SecretStr, ValidationError

from ops_deploy.base import TlshdConfig, deploy_tlshd
from ops_deploy.base.tlshd import (
    CA_PATH,
    CONFIG_PATH,
    DROPIN_DIR,
    DROPIN_PATH,
    SERVICE,
    pem,
    render_config,
    render_dropin,
)
from ops_deploy.testing import run_deploy_fake
from tests import fakehost
from tests.nfs_fixtures import CA, CLIENT_CERT, KEY, KEY_MARKER, SERVER_CERT, block, tls

UNITS_BEFORE = "for unit in zfs-share.service remote-fs-pre.target"


def keep_units(zfs_share: str = "enabled") -> dict[str, Any]:
    states = []
    for state in (zfs_share, "static"):
        states += ["LoadState=loaded", "ActiveState=active", f"UnitFileState={state}", "---"]
    return {UNITS_BEFORE: states}


def converged(cfg: TlshdConfig) -> dict[str, Any]:
    return {
        **fakehost.UBUNTU,
        **fakehost.deb_installed("ktls-utils"),
        **fakehost.directory("/etc"),
        **fakehost.directory("/etc/tlshd"),
        **fakehost.directory(DROPIN_DIR),
        **fakehost.file(CA_PATH, pem(CA)),
        **fakehost.file(cfg.certificate_path, pem(cfg.certificate), mode="-rw-------"),
        **fakehost.file(cfg.key_path, pem(KEY), mode="-rw-------"),
        **fakehost.file(CONFIG_PATH, render_config(cfg)),
        **fakehost.file(DROPIN_PATH, render_dropin()),
        **fakehost.service(SERVICE),
    }


def fresh() -> dict[str, Any]:
    return {**fakehost.UBUNTU, **keep_units()}


def test_config_names_only_this_sides_files() -> None:
    assert render_config(tls("server")) == (
        "# Managed by ops-deploy base.tlshd; local changes are overwritten.\n"
        "[authenticate.server]\n"
        "x509.certificate=/etc/tlshd/server.pem\n"
        "x509.private_key=/etc/tlshd/server.key\n"
    )
    client = render_config(tls("client"))
    assert client.endswith(
        "[authenticate.client]\nx509.certificate=/etc/tlshd/client.pem\nx509.private_key=/etc/tlshd/client.key\n"
    )
    assert "debug" not in client


def test_dropin_binds_the_private_ca_over_the_system_bundle() -> None:
    assert render_dropin().endswith(
        "[Service]\nBindReadOnlyPaths=/etc/tlshd/nfs-ca.pem:/etc/ssl/certs/ca-certificates.crt\n"
    )


@pytest.mark.parametrize(
    "fields",
    [
        {"role": "peer"},
        {"ca_certificate": ""},
        {"ca_certificate": CA + CA},
        {"ca_certificate": KEY},
        {"certificate": "not a certificate"},
        {"certificate": CA},
        {"certificate": SERVER_CERT.replace("MII", "MI I", 1)},
        {"private_key": SecretStr(SERVER_CERT)},
        {"private_key": SecretStr(KEY + KEY)},
        {"private_key": SecretStr(block("ENCRYPTED PRIVATE KEY", "Benc"))},
        {"private_key": SecretStr(KEY.replace("-----END PRIVATE KEY-----", "-----END EC PRIVATE KEY-----"))},
        {"extra": 1},
    ],
)
def test_invalid_configs_are_refused_without_echoing_the_key(fields: dict[str, Any]) -> None:
    data = {"role": "server", "ca_certificate": CA, "certificate": SERVER_CERT, "private_key": SecretStr(KEY), **fields}
    with pytest.raises(ValidationError) as error:
        TlshdConfig.model_validate(data)
    assert KEY_MARKER not in str(error.value)


def test_ec_and_rsa_keys_are_accepted() -> None:
    for label in ("EC PRIVATE KEY", "RSA PRIVATE KEY"):
        key = SecretStr(block(label, "Bk"))
        cfg = TlshdConfig(role="client", ca_certificate=CA, certificate=CLIENT_CERT, private_key=key)
        assert cfg.key_path == "/etc/tlshd/client.key"


def test_key_never_appears_in_repr_or_dump() -> None:
    cfg = tls()
    assert KEY_MARKER not in repr(cfg)
    assert KEY_MARKER not in str(cfg.model_dump())


def test_fresh_host_installs_writes_and_restarts_after_the_files() -> None:
    cfg = tls("server")
    run = run_deploy_fake(deploy_tlshd, cfg, responses=fresh())

    assert run.succeeded, run.error
    commands = run.executed_commands
    install = commands.index(
        "env NEEDRESTART_SUSPEND=1 NEEDRESTART_MODE=l DEBIAN_FRONTEND=noninteractive "
        "apt-get install -y -q --no-install-recommends ktls-utils"
    )
    assert commands[install + 1] == "systemctl enable -- zfs-share.service"
    reload = commands.index("systemctl daemon-reload")
    restart = commands.index(f"systemctl restart {SERVICE}")
    assert install < reload < restart
    secrets = dict(run.secret_files)
    assert secrets[CA_PATH] == pem(CA).encode()
    assert secrets["/etc/tlshd/server.pem"] == pem(SERVER_CERT).encode()
    assert secrets["/etc/tlshd/server.key"] == pem(KEY).encode()
    assert run.written(CONFIG_PATH) == render_config(cfg).encode()
    assert run.written(DROPIN_PATH) == render_dropin().encode()
    # The package started tlshd before the files existed: it is restarted although "Start" also ran.
    assert f"systemctl enable {SERVICE}" in commands
    assert "nsenter" in commands[-1]
    assert KEY_MARKER not in run.all_text()


def test_secret_installs_keep_their_modes() -> None:
    run = run_deploy_fake(deploy_tlshd, tls("client"), responses=fresh())

    installs = [command for command in run.executed_commands if command.startswith("python3 -I -c")]
    assert len(installs) == 3
    assert installs[0].endswith(" 0644 root root")
    assert all(command.endswith(" 0600 root root") for command in installs[1:])


def test_converged_host_changes_nothing() -> None:
    cfg = tls("client")
    run = run_deploy_fake(deploy_tlshd, cfg, responses=converged(cfg))

    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    assert all("restart" not in command for command in run.executed_commands)
    assert all("apt-get" not in command for command in run.executed_commands)


def test_new_key_restarts_without_reload() -> None:
    cfg = tls("client")
    responses = converged(cfg)
    responses.update(fakehost.file(cfg.key_path, "old\n", mode="-rw-------"))
    run = run_deploy_fake(deploy_tlshd, cfg, responses=responses)

    assert run.succeeded, run.error
    assert [path for path, _ in run.secret_files] == [cfg.key_path]
    commands = run.executed_commands
    assert "systemctl daemon-reload" not in commands
    assert f"systemctl restart {SERVICE}" in commands
    assert KEY_MARKER not in run.all_text()


def test_changed_dropin_reloads_then_restarts() -> None:
    cfg = tls("client")
    responses = converged(cfg)
    responses.update(fakehost.file(DROPIN_PATH, "[Service]\n"))
    run = run_deploy_fake(deploy_tlshd, cfg, responses=responses)

    commands = run.executed_commands
    assert commands.index("systemctl daemon-reload") < commands.index(f"systemctl restart {SERVICE}")


def test_symlinked_key_is_refused() -> None:
    cfg = tls("client")
    responses = converged(cfg)
    responses.update(fakehost.symlink(cfg.key_path, "/root/client.key"))
    run = run_deploy_fake(deploy_tlshd, cfg, responses=responses)

    assert not run.succeeded
    assert "not a regular file" in str(run.error)


def test_needs_apt() -> None:
    run = run_deploy_fake(deploy_tlshd, tls(), responses={**fakehost.UBUNTU, "command -v apt-get": []})

    assert not run.succeeded
    assert "apt" in str(run.error)
