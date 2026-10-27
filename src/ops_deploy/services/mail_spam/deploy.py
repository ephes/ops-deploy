"""Native Rspamd role, preserving classifier/Redis/DNS and Postfix intent."""

from __future__ import annotations

import json
import re
import shlex
from collections.abc import Generator
from io import StringIO
from pathlib import Path, PurePosixPath

from pydantic import SecretStr
from pyinfra import host
from pyinfra.api import DeployError, StringCommand, deploy, operation
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.deb import DebPackages
from pyinfra.facts.files import File
from pyinfra.facts.server import LinuxDistribution
from pyinfra.operations import apt, files, server, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers.checks import mark_read_only, wait_port
from ops_deploy.helpers.probes import StdinLines, probe
from ops_deploy.helpers.systemd import service_rollout, systemd_unit
from ops_deploy.ops import secret_file
from ops_deploy.services._mail_config import finish_restart, postfix_group_access, prepare_configs, validate_native
from ops_deploy.services._mail_postfix import verify_master
from ops_deploy.services.mail_spam.config import MailSpamConfig
from ops_deploy.services.mail_spam.render import render_role

CONTROLLER = (Path(__file__).parent / "files" / "mail_spam_controller.py").read_text()
PASSWORD_MARKER = "__OPS_DEPLOY_STABLE_CONTROLLER_PASSWORD__"


def controller_command(mode: str) -> str:
    if mode not in {"check", "apply"}:
        raise ValueError("invalid Rspamd controller action")
    return shlex.join(["python3", "-I", "-c", CONTROLLER, mode])


def controller_state(raw: str) -> str:
    state = probe(controller_command("check"), name="Native Rspamd controller credential", stdin=raw)
    if state not in {"current", "pending"}:
        raise DeployError("Rspamd controller credential state is unknown; no credential mutation attempted")
    return state


@operation()
def _controller_preflight(payload: SecretStr) -> Generator[StringCommand, None, None]:
    controller_state(payload.get_secret_value())
    host.noop("Rspamd controller credential state is qualified")
    yield from ()


@operation()
def _controller(payload: SecretStr) -> Generator[StringCommand, None, None]:
    raw = payload.get_secret_value()
    if controller_state(raw) == "current":
        host.noop("Rspamd controller configuration and credential are current")
        return
    yield StringCommand(controller_command("apply"), _stdin=StdinLines(raw), _get_pty=False, _shell_executable="sh")


def resolver_check(cfg: MailSpamConfig) -> OperationMeta:
    script = (
        "import subprocess,sys; p=subprocess.run(['dig','+short','+time=3','+tries=3','-p',sys.argv[2],"
        "'@'+sys.argv[1],'2.0.0.127.zen.spamhaus.org','A'],capture_output=True,text=True,timeout=15); "
        "sys.exit(0 if p.returncode==0 and '127.0.0.2' in p.stdout.splitlines() else 1)"
    )
    return mark_read_only(
        server.shell(
            name="Verify private Rspamd resolver DNSBL test point",
            commands=[shlex.join(["python3", "-I", "-c", script, cfg.resolver_listen, str(cfg.resolver_port)])],
            _retries=5,
            _retry_delay=3,
        )
    )


@deploy("Deploy native mail spam filtering")
def deploy_mail_spam(cfg: MailSpamConfig, secrets: SecretValues) -> None:
    web_password = secrets.get("web_password", "")
    if cfg.web_enabled and (not web_password or any(char in web_password for char in "\r\n\0")):
        raise ValueError("enabled Rspamd controller requires its configured credential without CR/LF/NUL")
    redis_password = secrets.get("redis_password", "")
    if any(char in redis_password for char in "\r\n\0"):
        raise ValueError("Rspamd Redis credential must not contain CR/LF/NUL")
    distribution = host.get_fact(LinuxDistribution)
    release = distribution.get("release_meta", {}).get("VERSION_CODENAME", "")
    if not re.fullmatch(r"[a-z][a-z0-9-]*", release):
        raise ValueError("Rspamd package repository requires the host distribution codename")
    apt.packages(name="Ensure Rspamd repository transport dependencies", packages=["ca-certificates", "gnupg"])
    files.directory(
        name="Ensure Rspamd scoped keyring directory",
        path=str(PurePosixPath(cfg.rspamd_repo_keyring).parent),
        user="root",
        group="root",
        mode="0755",
    )
    repository_key = files.download(
        name="Install missing Rspamd repository key",
        src=cfg.rspamd_repo_key_url,
        dest=cfg.rspamd_repo_keyring,
        user="root",
        group="root",
        mode="0644",
    )
    if cfg.rspamd_legacy_repo_url != cfg.rspamd_repo_url:
        files.line(
            name="Remove original unscoped Rspamd repository line",
            path="/etc/apt/sources.list.d/rspamd.list",
            line=r"^deb[[:space:]]+"
            + re.escape(cfg.rspamd_legacy_repo_url)
            + r"[[:space:]]+"
            + release
            + r"[[:space:]]+main$",
            present=False,
            extended_regex=True,
        )
    repository = apt.repo(
        name="Ensure scoped Rspamd package repository",
        src=f"deb [signed-by={cfg.rspamd_repo_keyring}] {cfg.rspamd_repo_url} {release} main",
        filename="rspamd",
    )
    if cfg.rspamd_cleanup_legacy_key:
        command = (
            'out=$(apt-key list --keyid-format=long 2>/dev/null) || exit 1; case "$out" in *'
            + shlex.quote(cfg.rspamd_repo_legacy_key_id)
            + "*) echo present ;; *) echo absent ;; esac"
        )
        legacy = probe(command, name="Legacy Rspamd apt key")
        if legacy not in {"present", "absent"}:
            raise DeployError("Rspamd legacy key state could not be established")
        if legacy == "present":
            server.shell(
                name="Remove original unscoped Rspamd apt key",
                commands=[shlex.join(["apt-key", "del", cfg.rspamd_repo_legacy_key_id]) + " >/dev/null"],
            )
    packages = [*cfg.packages]
    if cfg.install_redis:
        packages.append("redis-server")
    if cfg.resolver_enabled and cfg.resolver_install_packages:
        packages += ["unbound", "unbound-anchor", "bind9-dnsutils"]
    installed = host.get_fact(DebPackages)
    missing = any(package.partition("=")[0] not in installed for package in packages)
    apt.update(name="Refresh changed Rspamd package repository", _if=any_changed(repository_key, repository))
    apt.packages(name="Install mail spam packages", packages=packages, update=missing, cache_time=3600)
    controller_payload = SecretStr(
        json.dumps(
            {
                "path": cfg.local_config_path + "/worker-controller.inc",
                "password": web_password,
                "content": render_role(
                    "local.d/worker-controller.inc.j2", cfg, secrets, web_password_hash=PASSWORD_MARKER
                ),
                "restart_marker": "/var/lib/ops-deploy/mail-core/rspamd.restart",
            }
        )
    )
    if cfg.web_enabled:
        _controller_preflight(name="Qualify existing Rspamd controller credential", payload=controller_payload)
    current_milters = probe("postconf -h smtpd_milters", name="Current Postfix milter chain")
    if current_milters is None:
        raise DeployError("Postfix milter state could not be established; existing chain retained")
    socket = cfg.milter_socket_postfix or "rspamd/" + cfg.milter_socket_name
    milters = [
        value.strip()
        for value in current_milters.split(",")
        if value.strip() not in {"", "unix:/var/lib/rspamd/milter.sock", "unix:" + socket}
    ]
    milters.append("unix:" + socket)
    rspamd_inputs: list[OperationMeta] = []
    postfix_inputs: list[OperationMeta] = []
    postfix_reload_inputs: list[OperationMeta] = []
    rspamd = prepare_configs("rspamd", rspamd_inputs)
    postfix = prepare_configs("postfix", postfix_inputs)
    postfix_reload = prepare_configs("postfix", postfix_reload_inputs, action="reload")
    postfix_inputs.append(postfix_group_access("_rspamd"))
    for path in (cfg.local_config_path, cfg.override_config_path):
        files.directory(
            name="Ensure mail spam config directory", path=path, user="_rspamd", group="_rspamd", mode="0755"
        )
    files.directory(
        name="Ensure Postfix chroot Rspamd socket directory",
        path=cfg.milter_socket_dir,
        user="_rspamd",
        group="postfix",
        mode="0750",
    )

    def put(template: str, destination: str, *, secret: bool = False, mode: str = "0644") -> OperationMeta:
        body = render_role(template, cfg, secrets)
        if secret:
            return secret_file(
                name="Install protected spam configuration",
                path=destination,
                content=SecretContent(body),
                user="_rspamd",
                group="_rspamd",
                mode=mode,
            )
        return files.put(
            name="Install spam configuration",
            src=StringIO(body),
            dest=destination,
            user="_rspamd",
            group="_rspamd",
            mode=mode,
        )

    for name in (
        "options.inc",
        "external_relay.conf",
        "settings.conf",
        "worker-normal.inc",
        "worker-proxy.inc",
        "actions.conf",
        "greylist.conf",
        "milter_headers.conf",
    ):
        rspamd_inputs.append(
            put("local.d/" + name + ".j2", cfg.local_config_path + "/" + name, secret=name == "settings.conf")
        )
    if cfg.redis_enabled:
        rspamd_inputs += [
            put("local.d/redis.conf.j2", cfg.local_config_path + "/redis.conf", secret=True, mode="0640"),
            put("local.d/classifier-bayes.conf.j2", cfg.local_config_path + "/classifier-bayes.conf"),
        ]
    controller = (
        _controller(name="Reconcile stable native Rspamd controller credential", payload=controller_payload)
        if cfg.web_enabled
        else None
    )
    if cfg.web_enabled:
        rspamd_inputs.append(
            files.file(
                name="Retain Rspamd controller config permissions",
                path=cfg.local_config_path + "/worker-controller.inc",
                user="_rspamd",
                group="_rspamd",
                mode="0644",
            )
        )
    for key, value in (
        ("smtpd_milters", ", ".join(milters)),
        ("non_smtpd_milters", "$smtpd_milters"),
        ("milter_default_action", "accept"),
        ("milter_protocol", "6"),
    ):
        postfix_reload_inputs.append(
            files.line(
                name="Retain Postfix spam milter integration",
                path="/etc/postfix/main.cf",
                line=r"^" + key + r"[[:space:]]*=.*",
                replace=key + " = " + value,
                extended_regex=True,
            )
        )
    resolver_inputs: list[OperationMeta] = []
    resolver = prepare_configs(cfg.resolver_service, resolver_inputs)
    resolver_units: list[OperationMeta] = []
    if cfg.resolver_enabled:
        validate_native(["test", "-x", "/usr/sbin/unbound"], "Require private resolver binary")
        files.directory(
            name="Ensure private spam resolver state directory",
            path=cfg.resolver_state_dir,
            user="unbound",
            group="unbound",
            mode="0755",
        )
        anchor = cfg.resolver_state_dir + "/root.key"
        if host.get_fact(File, path=anchor) is None:
            command = shlex.join(["runuser", "-u", "unbound", "--", "/usr/sbin/unbound-anchor", "-a", anchor])
            resolver_inputs.append(
                server.shell(
                    name="Bootstrap missing private resolver trust anchor",
                    commands=[command + " >/dev/null 2>&1; rc=$?; test $rc -eq 0 -o $rc -eq 1"],
                )
            )
        resolver_inputs.append(
            files.put(
                name="Install private spam resolver configuration",
                src=StringIO(render_role("unbound-rspamd.conf.j2", cfg, secrets)),
                dest=cfg.resolver_config,
                user="root",
                group="root",
                mode="0644",
            )
        )
        resolver_units.append(
            systemd_unit(cfg.resolver_service, render_role("unbound-rspamd.service.j2", cfg, secrets))
        )
        resolver_inputs += resolver_units
        validate_native(["unbound-checkconf", cfg.resolver_config], "Validate private spam resolver configuration")
        service_rollout(
            cfg.resolver_service,
            units=resolver_units,
            restart_when=[*resolver_inputs, resolver.operation],
            always_restart=resolver.owed,
        )
        resolver_check(cfg)
    else:
        if host.get_fact(File, path=f"/etc/systemd/system/{cfg.resolver_service}.service") is not None:
            systemd.service(
                name="Stop disabled private spam resolver", service=cfg.resolver_service, running=False, enabled=False
            )
        resolver_inputs += [
            files.file(name="Remove disabled private spam resolver resource", path=path, present=False)
            for path in (f"/etc/systemd/system/{cfg.resolver_service}.service", cfg.resolver_config)
        ]
        systemd.daemon_reload(
            name="Reload removed private spam resolver unit", _if=lambda: any(op.did_change() for op in resolver_inputs)
        )
    validate_native(["rspamadm", "configtest"], "Validate native Rspamd configuration", stdout_marker="syntax OK")
    validate_native(["postconf", "-n"], "Validate Postfix spam milter configuration")
    restart_when = [*rspamd_inputs, rspamd.operation]
    if controller is not None:
        restart_when.append(controller)
    service_rollout("rspamd", restart_when=restart_when, always_restart=rspamd.owed or "rspamd" not in installed)
    postfix_rollout = service_rollout(
        "postfix", restart_when=[*postfix_inputs, postfix.operation], always_restart=postfix.owed
    )
    systemd.service(
        name="Reload Postfix spam milter integration",
        service="postfix",
        running=None,
        reloaded=True,
        _if=lambda: (
            not postfix_rollout.start.did_change()
            and not postfix_rollout.restart.did_change()
            and (postfix_reload.owed or any(op.did_change() for op in postfix_reload_inputs))
        ),
    )
    if cfg.web_enabled:
        wait_port(cfg.web_port, host=cfg.web_bind, name="Verify authenticated Rspamd controller listener")
    verify_master()
    mark_read_only(server.shell(name="Verify Rspamd daemon active", commands=["systemctl is-active --quiet rspamd"]))
    finish_restart(rspamd, changes=(controller,) if controller is not None else ())
    finish_restart(postfix)
    finish_restart(postfix_reload)
    finish_restart(resolver)
