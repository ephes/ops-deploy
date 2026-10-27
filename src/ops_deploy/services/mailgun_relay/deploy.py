"""Role-compatible service and ingress; Python preservation is the default."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from functools import cache
from io import StringIO
from pathlib import Path
from typing import Any

import jinja2
from pyinfra import host
from pyinfra.api import deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import Directory, FileContents
from pyinfra.facts.server import Command
from pyinfra.operations import files, git, server, systemd

from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers import mark_read_only, service_rollout, system_user, systemd_unit, wait_port
from ops_deploy.helpers.probes import stdin_arguments
from ops_deploy.helpers.python import uv_sync
from ops_deploy.helpers.rust_release import HOST_SCRIPT, Install, install_release
from ops_deploy.ops import secret_file, sync_tree
from ops_deploy.services._traefik_routes import route_put
from ops_deploy.services.mailgun_relay.config import MailgunRelayConfig

SCRIPT = (Path(__file__).parent / "files/mailgun_release_host.py").read_text()
HTTP_SCRIPT = (Path(__file__).parent / "files/mailgun_http_archive_host.py").read_text()


@cache
def environment() -> jinja2.Environment:
    return jinja2.Environment(
        loader=jinja2.PackageLoader("ops_deploy.services.mailgun_relay", "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )


def validate_secrets(secrets: SecretValues) -> dict[str, Any]:
    secrets.require(MailgunRelayConfig.required_secret_keys)
    for key in ("smtp_username", "smtp_password", "envelope_sender"):
        value = secrets[key]
        # The authoritative template uses double-quoted YAML scalars. Refuse
        # syntax-changing inputs rather than altering existing credential bytes.
        if (
            not value.strip()
            or value in {"CHANGEME", "changeme", "replace-me"}
            or re.search(r'[\x00-\x1f\x7f"\\]', value)
        ):
            raise ValueError("SMTP credentials/envelope sender contain an unsupported value")
    if not re.fullmatch(r"[^@\s<>\"\\]+@[^@\s<>\"\\]+", secrets["envelope_sender"]):
        raise ValueError("envelope_sender must be one address without whitespace")
    try:
        tokens = json.loads(secrets["tokens"])
        if not isinstance(tokens, list) or not tokens:
            raise ValueError
        for token in tokens:
            if not isinstance(token, dict):
                raise ValueError
            if not re.fullmatch(r"[0-9a-fA-F]{64}", token.get("token_sha256", "")):
                raise ValueError
            if not isinstance(token.get("label"), str) or not token["label"].strip():
                raise ValueError
            for field in ("mailgun_domains", "allowed_from_domains", "allowed_from_addresses"):
                values = token.get(field, [])
                if not isinstance(values, list) or (field != "allowed_from_addresses" and not values):
                    raise ValueError
                if any(not isinstance(value, str) or not value.strip() for value in values):
                    raise ValueError
            for value in [
                token["label"],
                *token["mailgun_domains"],
                *token["allowed_from_domains"],
                *token.get("allowed_from_addresses", []),
            ]:
                if re.search(r'[\x00-\x1f\x7f"\\]', value) or value == "CHANGEME":
                    raise ValueError
    except (ValueError, TypeError, KeyError):
        raise ValueError("tokens must be a nonempty JSON list of valid relay policies (values withheld)") from None
    return {**dict(secrets), "tokens": tokens}


def role_vars(cfg: MailgunRelayConfig, secret_values: dict[str, Any] | None = None) -> dict[str, Any]:
    values = cfg.model_dump(mode="json", exclude={"secrets"})
    values.update(
        venv_bin=str(cfg.venv / "bin"),
        env_path=str(cfg.environment_path),
        secrets_path=str(cfg.policy_path),
        rust_binary=str(cfg.binary),
        smtp_max_concurrency=cfg.smtp_max_concurrency or "",
    )
    if secret_values is not None:
        values.update(secret_values)
    return {"mailgun_relay_" + key: value for key, value in values.items()}


def render_role(template: str, cfg: MailgunRelayConfig, values: dict[str, Any] | None = None) -> str:
    return environment().get_template(template).render(**role_vars(cfg, values))


def lifecycle(
    cfg: MailgunRelayConfig,
    mode: str,
    sha256: str = "",
    fresh: bool = False,
    archive_refused: bool = False,
) -> str:
    data = {
        "root": str(cfg.rust_install_root),
        "version": cfg.rust_version,
        "sha256": sha256,
        "url": cfg.rust_release_url.replace("{version}", cfg.rust_version),
        "fresh": fresh,
        "archive_refused": archive_refused,
        "user": cfg.user,
        "group": cfg.group,
        "env": str(cfg.environment_path),
        "unit": cfg.service_name + ".service",
        "impl": cfg.impl,
        "keep": cfg.rust_keep_versions,
        "python": str(cfg.venv / "bin/python"),
        "dropin": str(cfg.dropin),
    }
    return shlex.join(["python3", "-I", "-c", SCRIPT, mode, json.dumps(data)])


def _install(cfg: MailgunRelayConfig, checksum: str) -> Install:
    url = cfg.rust_release_url.replace("{version}", cfg.rust_version)
    if cfg.rust_local_archive is None and url.startswith("http://"):
        # The original role permits a checksum-pinned HTTP mirror. Download to
        # a root-owned temporary upload, then use the SAME shared installer for
        # checksum, members, atomic publication, validation and failure cleanup.
        upload = str(cfg.rust_install_root / f".upload-{cfg.rust_version}.tar.gz")
        options = [
            "/usr/bin/python3",
            "-I",
            "-c",
            HTTP_SCRIPT,
            upload,
            url,
            cfg.impl,
            "install",
            "--name",
            "mailgun-relay",
            "--root",
            str(cfg.rust_install_root),
            "--version",
            cfg.rust_version,
            "--sha256",
            checksum,
            "--upload",
            upload,
            "--url",
            "https://unused.invalid/fixture",
            "--validate-user",
            cfg.user,
        ]
        if cfg.impl == "python":
            options.append("--soft")
        operation = server.shell(
            name="Install relay from a checksum-pinned HTTP mirror",
            commands=[shlex.join(options)],
            **stdin_arguments(HOST_SCRIPT),
        )
        return Install(operation, str(cfg.binary))
    return install_release(
        "mailgun-relay",
        cfg.rust_version,
        sha256=cfg.rust_sha256,
        install_root=str(cfg.rust_install_root),
        release_url=url,
        local_archive=cfg.rust_local_archive,
        validate_user=cfg.user,
        fail_hard=cfg.impl == "rust",
    )


def fact(command: str) -> str:
    """An empty or failed probe is never mistaken for a converged state."""
    wrapper = "result=$( " + command + ' ) || exit $?; printf "%s\\n__mailgun_ok__\\n" "$result"'
    value = str(host.get_fact(Command, command=shlex.join(["sh", "-c", wrapper])) or "")
    if not value.endswith("__mailgun_ok__"):
        raise ValueError("mailgun-relay read-only preflight failed")
    return value.removesuffix("__mailgun_ok__").strip()


def _python(cfg: MailgunRelayConfig) -> list[OperationMeta]:
    if cfg.python_deploy == "preserve":
        return []
    if cfg.python_deploy == "rsync":
        assert cfg.source_path is not None
        source = sync_tree(
            name="Sync explicitly selected mailgun-relay Python source",
            src=cfg.source_path,
            dest=cfg.site_path,
            user=cfg.user,
            group=cfg.group,
            excludes=cfg.rsync_excludes,
        )
    else:
        source = git.repo(
            name="Update explicitly selected mailgun-relay Python Git source",
            src=cfg.git_repo,
            dest=str(cfg.site_path),
            branch=cfg.git_version,
            user=cfg.user,
        )
    result = [source]
    missing = fact(f"if test -x {shlex.quote(str(cfg.venv / 'bin/python'))}; then echo present; else echo missing; fi")
    if source.will_change or missing == "missing":
        result.append(
            uv_sync(
                cfg.site_path,
                user=cfg.user,
                home=cfg.home,
                venv=cfg.venv,
                python=cfg.python_version,
                args=cfg.uv_sync_args,
            )
        )
    return result


def _ingress(cfg: MailgunRelayConfig, text: str | None) -> None:
    if text is not None:
        route_put(
            name="Write relay Traefik ingress",
            src=text,
            dest=str(cfg.ingress_traefik_config_path),
            mode="0644",
        )


@deploy("Deploy Mailgun relay")
def deploy_mailgun_relay(cfg: MailgunRelayConfig, secrets: SecretValues) -> None:
    values = validate_secrets(secrets)
    env_text = render_role("mailgun-relay.env.j2", cfg, values)
    if cfg.smtp_ca_file is not None:
        env_text += f"MAILGUN_RELAY_SMTP_CA_FILE={cfg.smtp_ca_file}\n"
    policy = render_role("secrets.yml.j2", cfg, values)
    unit_text = render_role("mailgun-relay.service.j2", cfg)
    dropin_text = render_role("impl.conf.j2", cfg)
    route_text = render_role("traefik-mailgun-relay.yml.j2", cfg) if cfg.ingress_enabled else None
    checksum = cfg.rust_sha256
    archive_refused = False
    if cfg.rust_local_archive is not None:
        try:
            actual = hashlib.sha256(cfg.rust_local_archive.read_bytes()).hexdigest()
            archive_refused = bool(checksum and actual != checksum)
            checksum = checksum or actual
        except OSError:
            archive_refused = True
        if archive_refused and cfg.impl == "rust":
            raise ValueError("controller archive is unreadable or differs from the pinned checksum")
    if fact("uname -s") != "Linux" or fact("cat /proc/1/comm") != "systemd":
        raise ValueError("mailgun-relay requires Linux with systemd")
    if cfg.python_deploy == "preserve":
        required = [cfg.site_path / "pyproject.toml", cfg.site_path / "uv.lock"]
        checks = " && ".join("test -e " + shlex.quote(str(path)) for path in required)
        checks += " && test -x " + shlex.quote(str(cfg.venv / "bin/python"))
        if fact(f"if {checks}; then echo present; else echo absent; fi") != "present":
            raise ValueError("Python rollback is absent; explicitly choose a Python installation method")
    before = "\n".join(host.get_fact(FileContents, path=str(cfg.dropin)) or [])
    match = re.search(rf"(?m)^ExecStart={re.escape(str(cfg.rust_install_root))}/([^/ ]+)/mailgun-relay(?: |$)", before)
    old = match[1] if match else ""
    prior = old and old != (cfg.rust_version if cfg.impl == "rust" else "")
    existing = bool(cfg.rust_version and host.get_fact(Directory, path=str(cfg.binary.parent)) is not None)
    if existing:
        marker = "\n".join(host.get_fact(FileContents, path=str(cfg.binary.parent / ".archive-sha256")) or []).strip()
        # With Python this is a warning at execution, allowing rollback.
        if marker != checksum and cfg.impl == "rust":
            raise ValueError("installed version has a different archive; replacing it is refused")
    state = shlex.quote(str(cfg.state_dir))
    restart_left = fact(f"if test -e {state}/restart; then echo pending; else echo clear; fi") == "pending"
    inputs: list[OperationMeta] = []
    # Registered before input writes, with the complete list populated below.
    # A failed candidate cannot lose a restart owed by an earlier config write.
    server.shell(
        name="Remember mailgun-relay restart owed",
        commands=[f"install -d -o root -g root -m 0700 {state} && touch {state}/restart"],
        _if=lambda: not restart_left and any(op.will_change for op in inputs),
    )
    system_user(cfg.user, home=cfg.home, group=cfg.group, shell="/usr/sbin/nologin", directories=[cfg.site_path])
    files.directory(
        name="Ensure relay config directory", path=str(cfg.env_dir), user="root", group=cfg.group, mode="0750"
    )
    inputs += _python(cfg)
    inputs.append(
        secret_file(
            name="Write relay runtime environment",
            path=cfg.environment_path,
            content=SecretContent(env_text),
            user="root",
            group=cfg.group,
            mode="0640",
        )
    )
    inputs.append(
        secret_file(
            name="Write relay secret policies",
            path=cfg.policy_path,
            content=SecretContent(policy),
            user="root",
            group=cfg.group,
            mode="0640",
        )
    )
    units: list[OperationMeta] = []
    if cfg.impl == "python":
        selection = files.file(name="Select preserved Python relay", path=str(cfg.dropin), present=False)
        inputs.append(selection)
        units.append(selection)
    if cfg.rust_version:
        files.directory(
            name="Ensure relay Rust install root",
            path=str(cfg.rust_install_root),
            user="root",
            group="root",
            mode="0755",
        )
        files.directory(
            name="Remove interrupted relay staging", path=str(cfg.rust_install_root / ".staging"), present=False
        )
        installed = None if existing else _install(cfg, checksum)
        candidate = server.shell(
            name="Validate relay candidate configuration",
            commands=[lifecycle(cfg, "candidate", checksum, not existing, archive_refused)],
            _if=lambda: installed is None or not installed.failed(),
        )
        if existing:
            mark_read_only(candidate)
    if cfg.impl == "rust":
        files.directory(
            name="Ensure relay selection directory", path=str(cfg.dropin.parent), user="root", group="root", mode="0755"
        )
        selection = files.put(
            name="Select pinned Rust relay",
            src=StringIO(dropin_text),
            dest=str(cfg.dropin),
            user="root",
            group="root",
            mode="0644",
        )
        inputs.append(selection)
        units.append(selection)
    if prior and host.get_fact(Directory, path=str(cfg.rust_install_root / old)) is not None:
        files.put(
            name="Remember previous relay release",
            src=StringIO(old + "\n"),
            dest=str(cfg.rust_install_root / ".previous-version"),
            user="root",
            group="root",
            mode="0644",
        )
    base_unit = systemd_unit(cfg.service_name, unit_text)
    units.append(base_unit)
    inputs.append(base_unit)
    reload_needed = (
        fact(f"systemctl show -p NeedDaemonReload --value {shlex.quote(cfg.service_name)} 2>/dev/null || true") == "yes"
    )
    if restart_left or reload_needed:
        systemd.daemon_reload(name="Resume relay systemd reload")
    rollout = service_rollout(cfg.service_name, units=units, restart_when=inputs)
    systemd.service(
        name="Resume relay restart",
        service=cfg.service_name,
        running=None,
        restarted=True,
        _if=lambda: restart_left and not rollout.start.did_change() and not rollout.restart.did_change(),
    )
    if cfg.healthcheck_enabled:
        wait_port(
            cfg.bind_port, host=cfg.bind_host, retries=cfg.healthcheck_retries, delay=cfg.healthcheck_delay_seconds
        )
        url = cfg.healthcheck_url or f"http://{cfg.bind_host}:{cfg.bind_port}/health"
        parse = "import json,sys; d=json.load(sys.stdin); assert d.get('status')=='ok' and 'version' not in d"
        check = (
            f"curl --fail --silent --max-time {cfg.healthcheck_timeout_seconds} {shlex.quote(url)} "
            f"| python3 -c {shlex.quote(parse)}"
        )
        command = (
            f"for i in $(seq 1 {cfg.healthcheck_retries}); do {check} && exit 0; "
            f"sleep {cfg.healthcheck_delay_seconds}; done; exit 1"
        )
        mark_read_only(
            server.shell(
                name="Verify relay health payload", commands=[shlex.join(["bash", "-o", "pipefail", "-c", command])]
            )
        )
    verify = lifecycle(cfg, "live")
    verify_wait = f"for i in $(seq 1 10); do {verify} && exit 0; sleep 3; done; exit 1"
    mark_read_only(server.shell(name="Verify selected relay process", commands=[shlex.join(["sh", "-c", verify_wait])]))
    if cfg.rust_version:
        prunable = json.loads(fact(lifecycle(cfg, "prune-plan")))
        if prunable:
            server.shell(
                name="Prune old relay releases after verification",
                commands=[lifecycle(cfg, "prune")],
                _if=lambda: (
                    (installed is None or not installed.failed())
                    and not any(line.startswith("failed ") for line in candidate.stdout_lines)
                ),
            )
    _ingress(cfg, route_text)
    server.shell(
        name="Clear completed relay restart",
        commands=[f"rm -f {state}/restart"],
        _if=lambda: restart_left or any(op.did_change() for op in inputs),
    )
