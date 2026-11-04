"""OpenClaw: the ``openclaw_deploy`` role's steps, in the role's order (``tasks/main.yml``).

Files are the role's bytes, owners and modes (:mod:`.layout`). The
bind-mounted data tree belongs to the container's numeric uid/gid 1000,
which may have another name (or none) on the host, so those files and
directories are compared and set by number (:func:`owned_file`,
:func:`owned_directory`).

The role's handlers become change-gated operations where the role flushes
them: ``restart openclaw`` before the health check, before the weeknotes cron
registration and with the metrics units; the metrics handlers before the
collector's first run. The ``reload traefik`` handler (a Traefik restart) is
not ported: Traefik reads the route file through its file provider, and the
pyinfra deploys never restart Traefik.

The steps that depend on what the host holds at run time (the existing
``openclaw.json``, the gateway's image, the Codex plugin, legacy workspace
state, the audio SecretRef plan, the reminder cron job) run the role's logic
in ``files/openclaw_host.py``; its ``check`` mode decides while planning, so a
converged host gets no mutating operation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shlex
from collections.abc import Callable, Generator, Mapping, Sequence
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import Any

from pyinfra import host, logger
from pyinfra.api import StringCommand, deploy, operation
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import FileContents
from pyinfra.facts.server import Command
from pyinfra.operations import apt, files, server, systemd

from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers import mark_read_only, systemd_unit, wait_port
from ops_deploy.helpers.probes import probe, stdin_arguments, verify_probe
from ops_deploy.helpers.traefik import hash_password
from ops_deploy.infra import docker_steps
from ops_deploy.ops import secret_file, secret_stdin
from ops_deploy.ops.secret_file import encode_payload, install_command
from ops_deploy.services import _metrics_httpd as metrics_httpd
from ops_deploy.services.logyard.core import NYXMON_CHECKS, nyxmon_checks_current
from ops_deploy.services.openclaw import layout
from ops_deploy.services.openclaw import render as r
from ops_deploy.services.openclaw.config import OpenClawConfig, OpenClawNyxmonChecks, OpenClawSecrets
from ops_deploy.services.openclaw.layout import DirSpec, FileSpec
from ops_deploy.services.openclaw.validate import host_checks
from ops_deploy.services.openclaw.variables import ansible_bool as bool_
from ops_deploy.services.openclaw.variables import version_at_least
from ops_deploy.services.thermal_monitoring.deploy import credentials_verify

HOST_SCRIPT = (Path(__file__).parent / "files" / "openclaw_host.py").read_bytes()
SYSTEMD = PurePosixPath("/etc/systemd/system")

Vars = Mapping[str, Any]
Meta = OperationMeta | None


# -- host steps ------------------------------------------------------------------------------


def host_command(step: str, mode: str) -> str:
    """``files/openclaw_host.py STEP MODE`` as root, isolated from the host's Python setup."""

    source = base64.b64encode(HOST_SCRIPT).decode()
    script = (
        f"import base64;exec(compile(base64.b64decode('{source}'),'<openclaw-host>','exec'),{{'__name__':'__main__'}})"
    )
    return shlex.join(["/usr/bin/python3", "-I", "-B", "-c", script, step, mode])


def pending(step: str, request: Mapping[str, Any]) -> bool:
    """The step's ``check`` answer while planning: anything but ``current`` (or a failed probe) runs it."""

    answer = probe(host_command(step, "check"), name=f"openclaw {step}", stdin=json.dumps(request))
    return answer is None or answer.strip().splitlines()[-1:] != ["current"]


def host_step(name: str, step: str, request: Mapping[str, Any], when: Callable[[], bool]) -> OperationMeta:
    return server.shell(
        name=name, commands=[host_command(step, "apply")], _if=when, **stdin_arguments(json.dumps(request))
    )


# -- files -----------------------------------------------------------------------------------


def stat_command(path: str) -> str:
    """Probe printing ``<uid> <gid> <mode>`` and the sha256 of a regular file, else ``absent``."""

    quoted = shlex.quote(path)
    return (
        f"if test -f {quoted} && ! test -L {quoted}; then stat -c '%u %g %a' {quoted}; "
        f"sha256sum {quoted} | cut -d' ' -f1; else echo absent; fi"
    )


def stat_answer(spec: FileSpec) -> str:
    return f"{spec.owner} {spec.group} {int(spec.mode, 8):o}\n{hashlib.sha256(spec.content).hexdigest()}"


@operation()
def owned_file(spec: FileSpec) -> Generator[Any, None, None]:
    """``spec`` with a numeric owner; rewritten only when bytes, owner or mode differ.

    The bytes travel like ``secret_file``'s (stdin, staged install, no
    symlink followed); the owner is set by number right after the rename.
    """

    if (host.get_fact(Command, command=stat_command(spec.path)) or "").strip() == stat_answer(spec):
        host.noop(f"{spec.path} is up to date")
        return
    content = SecretContent(spec.content)
    yield StringCommand(
        install_command(PurePosixPath(spec.path), len(content), mode=spec.mode),
        _stdin=encode_payload(content),
        _get_pty=False,
        _shell_executable="sh",
    )
    yield f"chown -h {spec.owner}:{spec.group} {shlex.quote(spec.path)}"


def write(spec: FileSpec) -> Meta:
    """Write ``spec`` the way its owner needs; a ``create_only`` file only while it is missing."""

    if spec.create_only and present(spec.path):
        return None
    name = f"Write {spec.path}"
    if spec.owner.isdigit():
        return owned_file(name=name, spec=spec)
    if spec.secret:
        content = SecretContent(spec.content)
        return secret_file(
            name=name, path=spec.path, content=content, user=spec.owner, group=spec.group, mode=spec.mode
        )
    return files.put(
        name=name,
        src=StringIO(spec.content.decode()),
        dest=spec.path,
        user=spec.owner,
        group=spec.group,
        mode=spec.mode,
    )


def directory(spec: DirSpec) -> Meta:
    if not spec.owner.isdigit():
        return files.directory(
            name=f"Ensure {spec.path}", path=spec.path, user=spec.owner, group=spec.group, mode=spec.mode
        )
    # Numeric ids, compared with stat (files.directory compares names), like the compose apps' directories.
    quoted = shlex.quote(spec.path)
    wanted = f"{spec.owner} {spec.group} {int(spec.mode, 8):o}"
    current = probe(f"if test -d {quoted}; then stat -c '%u %g %a' {quoted}; else echo absent; fi", name=spec.path)
    if (current or "").strip() == wanted:
        return None
    return server.shell(
        name=f"Ensure {spec.path}",
        commands=[f"mkdir -p {quoted} && chown {spec.owner}:{spec.group} {quoted} && chmod {spec.mode} {quoted}"],
    )


def present(path: str) -> bool:
    quoted = shlex.quote(path)
    return (
        probe(f"if test -e {quoted}; then echo present; else echo absent; fi", name=path) or ""
    ).strip() == "present"


def changed(*metas: Meta) -> Callable[[], bool]:
    return lambda: any(meta is not None and meta.did_change() for meta in metas)


def restart_openclaw(v: Vars, label: str, triggers: Sequence[Meta]) -> OperationMeta:
    """The role's ``restart openclaw`` handler where it is flushed (a stopped unit is started too)."""

    return systemd.service(
        name=f"Restart openclaw ({label})",
        service=f"{v['openclaw_service_name']}.service",
        command="restart",
        enabled=True,
        daemon_reload=True,
        _if=changed(*triggers),
    )


# -- requests of the host steps ---------------------------------------------------------------


def base_request(v: Vars) -> dict[str, Any]:
    return {
        "container": v["openclaw_container_name"],
        "image": r.image(v),
        "site_dir": v["openclaw_site_dir"],
        "data_dir": v["openclaw_data_dir"],
        "service": v["openclaw_service_name"],
        "workspace_dir": v["openclaw_agent_workspace_dir"],
    }


def config_request(v: Vars) -> dict[str, Any]:
    return {
        "path": f"{v['openclaw_data_dir']}/openclaw.json",
        "mode": str(v["openclaw_gateway_config_mode"]),
        "force": bool_(v["openclaw_force_config"]),
        "migrate_v2026_9_1": version_at_least(v["openclaw_version"], "2026.9.1"),
        "runtime": r.runtime_inputs(v),
    }


def health_request(v: Vars) -> dict[str, Any]:
    gateway = v["openclaw_gateway_config"]
    telegram = (
        bool_(gateway.get("channels", {}).get("telegram", {}).get("enabled", False))
        if len(gateway) > 0
        else bool_(v["openclaw_telegram_enabled"])
    )
    return {
        "container": v["openclaw_container_name"],
        "bind_host": v["openclaw_bind_host"],
        "port": int(v["openclaw_host_port"]),
        "startup_timeout": int(v["openclaw_startup_timeout"]),
        "retries": int(v["openclaw_healthcheck_retries"]),
        "delay": int(v["openclaw_healthcheck_delay"]),
        "telegram": telegram,
    }


# -- tasks/*.yml -----------------------------------------------------------------------------


def _account(v: Vars) -> None:
    server.group(name="Ensure OpenClaw group exists", group=v["openclaw_group"], system=True)
    server.user(
        name="Ensure OpenClaw user exists",
        user=v["openclaw_user"],
        group=v["openclaw_group"],
        system=True,
        home=v["openclaw_home"],
        create_home=True,
        shell="/usr/sbin/nologin",
    )


def source_state(v: Vars) -> str:
    """Probe of the build checkout: ``absent``, ``dirty``, or whether HEAD is the remote tag's commit."""

    build = shlex.quote(v["openclaw_build_dir"])
    tag = "refs/tags/" + v["openclaw_version"]
    patterns = shlex.join([tag, tag + "^{}"])
    git = "git -C " + build
    # The peeled line (``<tag>^{}``) names an annotated tag's commit; a lightweight tag has none.
    pick = "awk '/\\^\\{\\}$/ { peeled = $1 } NR == 1 { first = $1 } END { print (peeled != \"\" ? peeled : first) }'"
    return (
        f"if ! test -d {build}/.git; then echo absent; exit 0; fi; "
        f"if ! {git} diff --quiet HEAD; then echo dirty; exit 0; fi; "
        f"head=$({git} rev-parse HEAD) || exit 1; "
        f"remote=$({git} ls-remote origin {patterns}) || exit 1; "
        f'want=$(printf "%s\\n" "$remote" | {pick}); '
        'if [ -n "$want" ] && [ "$head" = "$want" ]; then echo current; else echo pending; fi'
    )


def source_command(v: Vars) -> str:
    """source.yml's ``git`` task: the release tag, shallow, local changes discarded (``force``)."""

    build = shlex.quote(v["openclaw_build_dir"])
    repo, version = shlex.quote(v["openclaw_repo_url"]), shlex.quote(v["openclaw_version"])
    depth = int(v["openclaw_git_depth"])
    single = "--single-branch" if bool_(v["openclaw_git_single_branch"]) else "--no-single-branch"
    tag = shlex.quote(f"+refs/tags/{v['openclaw_version']}:refs/tags/{v['openclaw_version']}")
    return (
        f"if test -d {build}/.git; then git -C {build} fetch --depth {depth} --force origin {tag} "
        f"&& git -C {build} checkout --force {version}; "
        f"else git clone --depth {depth} {single} --branch {version} {repo} {build}; fi"
    )


def _source_and_image(v: Vars) -> OperationMeta:
    """source.yml and build.yml: the image is built when missing, forced or the checkout moved."""

    state = (probe(source_state(v), name="OpenClaw source checkout") or "").strip()
    source = server.shell(
        name="Clone OpenClaw repository", commands=[source_command(v)], _if=lambda: state != "current"
    )
    image = r.image(v)
    found = probe(
        f"if docker image inspect {shlex.quote(image)} >/dev/null 2>&1; then echo present; else echo absent; fi",
        name=image,
    )
    missing = (found or "").strip() != "present"
    force = bool_(v["openclaw_force_rebuild"])
    return server.shell(
        name="Build OpenClaw Docker image",
        commands=[
            f"cd {shlex.quote(v['openclaw_build_dir'])} && docker build --network host -t {shlex.quote(image)} ."
        ],
        _if=lambda: force or missing or source.did_change(),
    )


def _config(v: Vars) -> list[Meta]:
    """config.yml: the seed when there is no config (or ``force``), else the host's patch steps."""

    force = bool_(v["openclaw_force_config"])
    seed = layout.seed_file(v)
    written = write(seed) if force or not present(seed.path) else None
    metas: list[Meta] = [written]
    # A seeded file is neither migrated nor patched (the role's stat came first); with
    # ``force`` the host step only normalizes the Telegram aliases of the new seed.
    if written is None or force:
        request = config_request(v)
        state = force or pending("config", request)
        metas.append(host_step("Reconcile the existing OpenClaw gateway config", "config", request, lambda: state))
    metas += [write(spec) for spec in layout.workspace_prompts(v)]
    return metas


def _runtime(v: Vars) -> list[Meta]:
    """doctor_activation.yml, plugins.yml, upgrade_migrations.yml and audio_transcription.yml."""

    base = base_request(v)
    metas: list[Meta] = []
    if bool_(v["openclaw_doctor_activation_enabled"]) and version_at_least(v["openclaw_version"], "2026.9.7"):
        doctor = pending("doctor", base)
        metas.append(host_step("Activate the new image through Doctor", "doctor", base, lambda: doctor))
    if bool_(v["openclaw_codex_plugin_enabled"]):
        names = ("plugin_id", "plugin_package", "plugin_version")
        request = {**base, **{name: str(v[f"openclaw_codex_{name}"]) for name in names}}
        plugin = pending("plugins", request)
        metas.append(host_step("Install the official Codex runtime plugin", "plugins", request, lambda: plugin))
    if bool_(v["openclaw_upgrade_migrations_enabled"]) and version_at_least(v["openclaw_version"], "2026.9.1"):
        request = {**base, "config": config_request(v)}
        legacy = pending("migrations", request)
        metas.append(host_step("Run guarded upstream upgrade migrations", "migrations", request, lambda: legacy))
    if bool_(v["openclaw_audio_transcription_enabled"]):
        plan = layout.audio_plan(v)
        written = write(plan)
        request = {
            **base,
            "plan_path": "/home/node/.openclaw/managed-audio-secrets-plan.json",
            "plan_host_path": plan.path,
        }
        audio = pending("audio", request)
        plan_changed = changed(written)
        apply = host_step("Apply the dedicated audio auth profile", "audio", request, lambda: audio or plan_changed())
        metas += [written, apply]
    return metas


def _route(v: Vars) -> Meta:
    if not bool_(v["openclaw_traefik_enabled"]):
        return None
    route = layout.route_file(v)
    parent = str(PurePosixPath(route.path).parent)
    files.directory(
        name="Ensure Traefik dynamic config directory exists", path=parent, user="root", group="root", mode="0755"
    )
    return write(route)


def _cron(v: Vars) -> OperationMeta:
    port = int(v["openclaw_host_port"])
    wait_port(port, host=v["openclaw_bind_host"], retries=30, name="Wait for gateway to accept commands")
    request = {
        "site_dir": v["openclaw_site_dir"],
        "cron": v["openclaw_weeknotes_reminder_cron"],
        "command": v["openclaw_weeknotes_reminder_command"],
    }
    state = pending("cron", request)
    return host_step("Register the weeknotes reminder cron job", "cron", request, lambda: state)


def _features(v: Vars) -> list[Meta]:
    """imap.yml to opsgate.yml (with the legacy /ha directory removal) and workspace_skills.yml."""

    metas: list[Meta] = []
    if bool_(v["openclaw_homeassistant_enabled"]) and v["openclaw_homeassistant_command_skill_name"] != "ha":
        legacy = f"{v['openclaw_homeassistant_skills_dir']}/ha"
        if present(legacy):
            metas.append(
                server.shell(
                    name="Remove legacy /ha command skill directory", commands=[f"rm -rf -- {shlex.quote(legacy)}"]
                )
            )
    metas += [write(spec) for spec in layout.feature_files(v)]
    return metas


def _workspace_skills(v: Vars) -> list[Meta]:
    if len(v["openclaw_workspace_skills"]) == 0:
        return []
    for spec in layout.workspace_directories(v):
        directory(spec)
    return [write(spec) for spec in layout.workspace_skill_files(v)]


# -- metrics.yml -----------------------------------------------------------------------------


def httpd_endpoint(v: Vars) -> metrics_httpd.Endpoint:
    """The role's ``metrics_httpd_switch`` inputs (the vars of metrics.yml's deploy block)."""

    m = "openclaw_metrics_endpoint_"
    return metrics_httpd.Endpoint(
        service_name=v[m + "service_name"],
        argv=(
            *("json-file", "--bind", v[m + "bind"], "--port", str(v[m + "port"]), "--path", v[m + "path"]),
            *("--json-path", v[m + "json_path"], "--htpasswd-file", v[m + "htpasswd_path"]),
            *("--realm", "openclaw-metrics", "--server-name", "openclaw-metrics-httpd/0.1"),
            *("--missing-message", "Metrics file not found - collector timer may not have run yet"),
        ),
        user=v[m + "user"],
        group=v[m + "group"],
        sandbox=(
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "PrivateTmp=yes",
            f"ReadOnlyPaths={v[m + 'data_dir']}",
        ),
        python_script=v[m + "server_path"],
        probe_bind=v[m + "bind"],
        probe_port=int(v[m + "port"]),
        probe_path=v[m + "path"],
        probe_realm="openclaw-metrics",
        ip_address_allow=("localhost", "100.64.0.0/10"),
    )


def _metrics_disabled(v: Vars) -> None:
    m = "openclaw_metrics_endpoint_"
    service, timer = v[m + "service_name"], v[m + "timer_name"]
    for unit in (f"{service}.service", f"{timer}.timer"):
        if present(str(SYSTEMD / unit)):
            systemd.service(
                name=f"Stop and disable {unit}", service=unit, running=False, enabled=False, daemon_reload=True
            )
    for path in (
        f"{SYSTEMD}/{service}.service",
        f"{SYSTEMD}/{service}.service.d/metrics-httpd-impl.conf",
        f"{SYSTEMD}/{timer}.service",
        f"{SYSTEMD}/{timer}.timer",
        v[m + "server_path"],
        v[m + "collector_path"],
        v[m + "synthetic_canary_state_path"],
        v[m + "htpasswd_path"],
    ):
        files.file(name=f"Remove {path}", path=path, present=False)
    files.directory(name=f"Remove {v[m + 'htpasswd_dir']}", path=v[m + "htpasswd_dir"], present=False)
    if bool_(v[m + "remove_data_on_disable"]):
        files.directory(name=f"Remove {v[m + 'data_dir']}", path=v[m + "data_dir"], present=False)
    systemd.daemon_reload(name="Reload systemd after unit removal")


def _htpasswd(v: Vars) -> list[OperationMeta]:
    """The role's verify-then-regenerate htpasswd (``htpasswd -v``, then ``-n`` on failure)."""

    m = "openclaw_metrics_endpoint_"
    path, user, password = v[m + "htpasswd_path"], v[m + "auth_user"], v[m + "auth_password"]
    if credentials_verify(host.get_fact(FileContents, path=path), user, password):
        return []
    content = SecretContent(f"{user}:{hash_password(password)}\n")
    return [
        secret_file(name=f"Write {path}", path=path, content=content, user="root", group=v[m + "group"], mode="0640")
    ]


def _metrics(v: Vars, cfg: OpenClawConfig, skill_changes: Sequence[Meta]) -> None:
    """metrics.yml, with its two handler flushes."""

    m = "openclaw_metrics_endpoint_"
    if not bool_(v[m + "enabled"]):
        _metrics_disabled(v)
        restart_openclaw(v, "skills", skill_changes)
        return
    user, group = v[m + "user"], v[m + "group"]
    apt.packages(name="Install metrics dependencies", packages=list(v[m + "packages"]))
    server.group(name="Create metrics system group", group=group, system=True)
    server.user(
        name="Create metrics system user",
        user=user,
        group=group,
        shell="/usr/sbin/nologin",
        create_home=False,
        ensure_home=False,
        system=True,
    )
    for path in (v[m + "data_dir"], v[m + "htpasswd_dir"]):
        files.directory(name=f"Ensure {path}", path=path, user="root", group=group, mode="0750")
    specs = layout.metrics_files(v)
    collector, httpd = write(specs["collector"]), write(specs["httpd"])
    credentials = _htpasswd(v)
    timer, service = v[m + "timer_name"], v[m + "service_name"]
    collector_unit = systemd_unit(f"{timer}.service", specs["collector_unit"].content.decode())
    timer_unit = systemd_unit(f"{timer}.timer", specs["timer_unit"].content.decode())
    endpoint_unit = systemd_unit(service, specs["endpoint_unit"].content.decode())
    selection = metrics_httpd.select(httpd_endpoint(v), cfg.httpd)
    # The role's flush before the first collector run, in handler order.
    systemd.daemon_reload(
        name="Reload systemd for the OpenClaw metrics units",
        _if=changed(collector_unit, timer_unit, endpoint_unit, selection.dropin),
    )
    restart_openclaw(v, "skills", skill_changes)
    endpoint_changes = changed(httpd, *credentials, endpoint_unit, selection.dropin)
    systemd.service(name=f"Restart {service}", service=f"{service}.service", command="restart", _if=endpoint_changes)
    systemd.service(
        name=f"Restart {timer}.timer", service=f"{timer}.timer", command="restart", _if=changed(collector, timer_unit)
    )
    # The role starts the oneshot collector on every run (changed_when: false).
    run_once = shlex.join(["systemctl", "start", f"{timer}.service"])
    mark_read_only(server.shell(name="Run collector once for initial metrics file", commands=[run_once]))
    systemd.service(name=f"Enable and start {timer}.timer", service=f"{timer}.timer", running=True, enabled=True)
    systemd.service(name=f"Enable and start {service}", service=f"{service}.service", running=True, enabled=True)
    metrics_httpd.verify(selection)


def _session_state(v: Vars, workspace_files: Sequence[Meta]) -> None:
    manifest = write(layout.manifest_file(v))
    request = {"path": v["openclaw_session_state_path"]}
    name = "Reset session bindings when managed skills changed"
    host_step(name, "session", request, changed(manifest, *workspace_files))


@deploy("Deploy OpenClaw")
def deploy_openclaw(cfg: OpenClawConfig, secrets: OpenClawSecrets) -> None:
    v = cfg.role_variables(secrets)
    # Everything is rendered before the first operation: a template or payload error changes nothing.
    for render_step in (
        layout.feature_files,
        layout.weeknotes_files,
        layout.metrics_files,
        layout.workspace_skill_files,
    ):
        render_step(v)
    for task, test in host_checks(v):
        failure = f"{test} || {{ echo {shlex.quote(task + ' failed')} >&2; exit 1; }}"
        mark_read_only(server.shell(name=task, commands=[failure]))
    if bool_(v["openclaw_install_docker"]):
        docker_steps(cfg.docker)
        mark_read_only(server.shell(name="Verify Docker Compose v2 is available", commands=["docker compose version"]))
    if bool_(v["openclaw_manage_user"]):
        _account(v)
    for spec in layout.directories(v):
        directory(spec)
    image = _source_and_image(v)
    env = write(layout.env_file(v))
    config = _config(v)
    runtime = _runtime(v)
    compose = write(layout.compose_file(v))
    unit = systemd_unit(v["openclaw_service_name"], layout.unit_file(v).content.decode())
    systemd.daemon_reload(name="Reload systemd for openclaw", _if=changed(unit))
    service = f"{v['openclaw_service_name']}.service"
    systemd.service(
        name="Ensure OpenClaw systemd service is enabled and started", service=service, running=True, enabled=True
    )
    _route(v)
    write(layout.logrotate_file(v))
    restart_openclaw(v, "deploy", [image, env, *config, *runtime, compose, unit])
    if bool_(v["openclaw_healthcheck_enabled"]):
        mark_read_only(host_step("Run OpenClaw health check", "health", health_request(v), lambda: True))
    if bool_(v["openclaw_weeknotes_enabled"]):
        weeknotes = [write(spec) for spec in layout.weeknotes_files(v)]
        restart_openclaw(v, "weeknotes", weeknotes)
        _cron(v)
    skills = _features(v)
    workspace = _workspace_skills(v)
    _metrics(v, cfg, [*skills, *workspace])
    _session_state(v, workspace)


# -- the playbook's post task ----------------------------------------------------------------


def nyxmon_command(checks: OpenClawNyxmonChecks, mode: str) -> str:
    env = [f"NYXMON_DB_PATH={checks.db_path}", f"NYXMON_SERVICE_NAME={checks.service_name}"]
    return shlex.join(["runuser", "-u", checks.user, "--", "env", *env, "python3", "-I", "-c", NYXMON_CHECKS, mode])


@deploy("OpenClaw Nyxmon checks")
def deploy_openclaw_nyxmon_checks(checks: OpenClawNyxmonChecks) -> None:
    """The playbook's post task: upsert its json-metrics checks into the local Nyxmon database.

    Its upsert script is the one of ``deploy-logyard-core.yml``
    (``services/logyard/files/nyxmon_checks.py``); the digest probe needs no
    secret, so a converged database gets no operation. Without a Nyxmon
    database the step is skipped, as the playbook skips it.
    """

    db = shlex.quote(str(checks.db_path))
    if (
        probe(f"if test -f {db}; then echo present; else echo absent; fi", name="Nyxmon database") or ""
    ).strip() != "present":
        logger.info(
            f"{host.name}: Nyxmon DB not found at {checks.db_path}, skipping OpenClaw Nyxmon check provisioning."
        )
        return
    command = nyxmon_command(checks, "probe")
    stored = probe(command, name="Nyxmon OpenClaw checks")
    rows = checks.revealed()
    current = stored is not None and nyxmon_checks_current(stored, rows)
    secret_stdin(
        name="Upsert Nyxmon OpenClaw json-metrics checks",
        command=nyxmon_command(checks, "apply") + " >/dev/null",
        content=SecretContent(json.dumps(rows)),
        _if=lambda: not current,
    )
    if stored is None:
        verify_probe(command, name="Nyxmon OpenClaw checks")
