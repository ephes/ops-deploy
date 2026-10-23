"""The step sequence every Django/Wagtail site shares.

A step runs when its input changed or a read-only probe says it is owed, so a
converged deploy changes nothing. Markers in ``/var/lib/ops-deploy/<service>/``,
written before the changes they stand for and removed when a run completed,
make the next run finish what a failed one left undone:

- ``.ops-deploy-pending``: the source or the dependencies changed; the steps
  they gate (migrations, static files, triggered step groups) and the restart
  are owed.
- ``.ops-deploy-restart-<unit>``: something the unit reads changed (``.env``,
  the launcher, the unit file, the user's primary group, the frontend's
  build); the restart is owed.

The directory is root's (``0700``, created by the first marker): no sync of
either tool touches it, so the markers survive a deploy that synced with
``--delete`` and then failed, and the service user cannot plant a symlink
that a root ``touch`` or write would follow.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Callable
from io import StringIO
from pathlib import PurePosixPath
from typing import cast

from pydantic import SecretStr
from pyinfra import host
from pyinfra.api import deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import Directory, FileContents
from pyinfra.operations import apt, files, server

from ops_deploy.core.config import UNIX_USER_PATTERN
from ops_deploy.core.rsync import RsyncRunner, subprocess_rsync_runner
from ops_deploy.core.secrets import SecretValues
from ops_deploy.helpers import (
    TraefikRoute,
    http_check,
    record_source,
    service_rollout,
    system_user,
    systemd_unit,
    traefik_route,
    wait_port,
)
from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.postgres import postgres_database
from ops_deploy.helpers.probes import probe, verify_probe
from ops_deploy.helpers.python_security import require_lock_floors, verify_trust
from ops_deploy.helpers.traefik import DYNAMIC_DIR
from ops_deploy.ops import secret_file, secret_stdin, sync_tree
from ops_deploy.services._echoport import upsert_target
from ops_deploy.services._traefik_routes import route_put
from ops_deploy.services.django_site import frontend
from ops_deploy.services.django_site.config import (
    DjangoSiteConfig,
    EnsureSuperuser,
    NextStandalone,
    PostgresDb,
    StepGroup,
)
from ops_deploy.services.django_site.django import (
    bootstrap_superuser,
    deps_probe,
    ensure_superuser,
    fact,
    manage,
    manage_script,
    migrations_probe,
    site_shell,
    static_collected,
    stdin_env,
    uv_command,
)
from ops_deploy.services.django_site.public import public_checks
from ops_deploy.services.django_site.render import render, render_env, resolve

PENDING = ".ops-deploy-pending"
RESTART = ".ops-deploy-restart-{unit}"
# The old primary group while its files still move (see _primary_group).
REGROUP = ".ops-deploy-regroup"
# Root's directory for the markers, one per site.
STATE_ROOT = PurePosixPath("/var/lib/ops-deploy")


class SiteRoute(TraefikRoute):
    """The route file is ``<unit>.traefik.yml``, not the helper's ``<name>.yml``."""

    @property
    def path(self) -> PurePosixPath:
        return DYNAMIC_DIR / f"{self.name}.traefik.yml"


def state_dir(cfg: DjangoSiteConfig) -> PurePosixPath:
    return STATE_ROOT / cfg.service_name


def _marker(cfg: DjangoSiteConfig, name: str) -> str:
    return shlex.quote(str(state_dir(cfg) / name))


def _touch(cfg: DjangoSiteConfig, name: str) -> str:
    """Create the root-only state directory if needed, then the marker ``name`` in it."""

    return f"install -d -o root -g root -m 0700 {shlex.quote(str(state_dir(cfg)))} && touch {_marker(cfg, name)}"


def markers_command(cfg: DjangoSiteConfig) -> str:
    """Lists the markers an earlier run left because it stopped before its end."""

    state = shlex.quote(str(state_dir(cfg)))
    return f"ls -1A {state} 2>/dev/null | grep -x -e {PENDING} -e '.ops-deploy-restart-.*' || true"


def _no_site_markers(cfg: DjangoSiteConfig) -> None:
    """Stops before any change when the site holds markers of an older deploy that kept them there.

    That deploy (the split-site module before django_site) stopped before its
    end; its work is not one django_site can tell from its own markers.
    """

    site = shlex.quote(str(cfg.site_path))
    found = fact(
        f"ls -1A {site} 2>/dev/null | grep -x -e .ops-deploy-collectstatic -e {PENDING} -e '.ops-deploy-restart-.*' "
        "|| true"
    ).split()
    if found:
        raise ValueError(
            f"{cfg.site_path} holds {', '.join(found)} from an older deploy that stopped early: finish it first"
        )


def _mark(cfg: DjangoSiteConfig, name: str, marker: str, *, when: Callable[[], bool]) -> OperationMeta:
    """Write ``marker`` when ``when()`` says so (evaluated while executing, so it may read later ops)."""

    return server.shell(name=name, commands=[_touch(cfg, marker)], _if=when)


def _site_owned(cfg: DjangoSiteConfig) -> OperationMeta:
    """A recursive ``chown`` of the site, only when something in it has another owner."""

    site = shlex.quote(str(cfg.site_path))
    wrong = f"find {site} \\( ! -user {cfg.user} -o ! -group {cfg.group_name} \\) -print -quit"
    pending = fact(f"{wrong} 2>/dev/null || true")
    return server.shell(
        name="Set ownership of the site tree",
        commands=[f"chown -hR {cfg.user}:{cfg.group_name} {site}"],
        _if=lambda: bool(pending),
    )


def _primary_group(cfg: DjangoSiteConfig) -> list[OperationMeta]:
    """Make the service group the user's primary group, and move the user's files to it.

    ``system_user`` leaves an existing user alone; a user an older deploy
    created with another primary group (the Ansible roles' ``users``) writes
    its uploads, cache and bytecode with that group, and every run repairs
    them again. ``usermod -g`` changes the group and, like every Linux
    ``usermod``, also moves the files in the home that carry the old group,
    whoever owns them and across mount points. So it runs only when every
    such file belongs to the user and nothing is mounted below the home;
    otherwise the deploy stops before any change. Then the user's own files
    with the old group in the site (when it is outside the home) and the home
    get the service group (``find -xdev``, symlinks themselves).

    ``.ops-deploy-regroup`` in the state directory holds the old group from before ``usermod``
    until the move succeeded, so a run that stopped in between finishes the
    move. The running processes keep the old group until the unit restarts:
    both operations count as something the unit reads.
    """

    user, group = cfg.user, cfg.group_name
    marker = _marker(cfg, REGROUP)
    # Group name, then the home passwd records (usermod works on that one).
    account = fact(f"id -gn {shlex.quote(user)} 2>/dev/null && getent passwd {shlex.quote(user)} | cut -d: -f6 || true")
    current, _, passwd_home = account.partition("\n")
    owed = fact(f"cat {marker} 2>/dev/null || true")
    old = current if current and current != group else owed
    if not old:
        return []
    if not re.fullmatch(UNIX_USER_PATTERN, old):
        raise ValueError(f"{user}'s old primary group has an unexpected name")
    roots = " ".join(
        shlex.quote(str(root))
        for root in (cfg.home, *([] if cfg.site_path.is_relative_to(cfg.home) else [cfg.site_path]))
    )
    ops = []
    if old == current:
        if passwd_home.strip() != str(cfg.home):
            raise ValueError(f"{user}'s home in passwd is not {cfg.home}: fix the primary group by hand")
        home = shlex.quote(f"{cfg.home}/")
        foreign = fact(
            f"find {shlex.quote(str(cfg.home))} -group {old} ! -user {user} -print -quit 2>/dev/null || true"
        )
        mounts = fact(f"awk -v h={home} 'index($2, h) == 1 {{print $2}}' /proc/mounts")
        if foreign or mounts:
            raise ValueError(
                f"{user}'s primary group is {old}, not {group}, and usermod would also move "
                f"{'files of other owners' if foreign else 'files on other mounts'} in {cfg.home}: "
                "fix the group by hand"
            )
        ops.append(
            server.shell(
                name=f"Make {group} the primary group of {user}",
                commands=[f"{_touch(cfg, REGROUP)} && echo {old} > {marker}", f"usermod -g {group} {user}"],
            )
        )
    ops.append(
        server.shell(
            name=f"Move {user}'s files from group {old} to {group}",
            commands=[f"find {roots} -xdev -user {user} -group {old} -exec chgrp -h {group} {{}} +", f"rm -f {marker}"],
        )
    )
    return ops


def _fish(cfg: DjangoSiteConfig) -> None:
    config_dir = cfg.home / ".config"
    # A missing ``~/.config`` is created as the service user; an existing one
    # (live hosts have ``<user>:root``) is never touched.
    if not host.get_fact(Directory, path=str(config_dir)):
        files.directory(
            name=f"Ensure directory {config_dir}",
            path=str(config_dir),
            user=cfg.user,
            group=cfg.group_name,
            mode="0755",
        )
    fish_dir = config_dir / "fish"
    files.directory(
        name=f"Ensure directory {fish_dir}", path=str(fish_dir), user=cfg.user, group=cfg.group_name, mode="0755"
    )
    files.put(
        name="Write fish config",
        src=StringIO(render("config.fish.j2", cfg)),
        dest=str(fish_dir / "config.fish"),
        user=cfg.user,
        group=cfg.group_name,
        mode="0644",
    )


def _step_group(
    cfg: DjangoSiteConfig, group: StepGroup, triggers: dict[str, Callable[[], bool]], secrets: SecretValues
) -> None:
    """One ``steps.extra`` group, gated by its triggers, its marker and ``when``."""

    left = False
    if group.marker:
        left = fact(f"test -e {_marker(cfg, group.marker)} && echo pending || true") == "pending"
    done = f"{group.marker}-done" if group.when == "first" else ""
    complete = bool(done) and fact(f"test -e {_marker(cfg, done)} && echo present || true") == "present"
    gate = [triggers[trigger] for trigger in sorted(group.triggers)]

    def needed() -> bool:
        return (
            group.when == "always"
            or left
            or (not complete if group.when == "first" else any(happened() for happened in gate))
        )

    if group.marker:
        server.shell(name=f"Mark {group.name} pending", commands=[_touch(cfg, group.marker)], _if=needed)
    for step in group.steps:
        command = site_shell(cfg, manage_script(cfg, *step.argv, stdin_env=bool(step.stdin_env)))
        if step.stdin_env:
            secret_stdin(
                name=step.name,
                command=command,
                content=stdin_env({entry.key: resolve(entry.value, secrets) for entry in step.stdin_env}),
                _if=needed,
            )
        else:
            server.shell(name=step.name, commands=[command], _if=needed)
    if done:
        server.shell(name=f"Record {group.name} completed", commands=[_touch(cfg, done)], _if=needed)
    if group.marker:
        server.shell(name=f"Clear {group.name} marker", commands=[f"rm -f {_marker(cfg, group.marker)}"], _if=needed)


def deploy_django_site(
    cfg: DjangoSiteConfig, secrets: SecretValues, rsync: RsyncRunner = subprocess_rsync_runner
) -> None:
    """Deploy one site; the operations are named ``Deploy <service_name> | ...``."""

    # Named per call, so a site's operations read like the ones of its old module.
    named = cast(
        Callable[[DjangoSiteConfig, SecretValues, RsyncRunner], None], deploy(f"Deploy {cfg.service_name}")(_deploy)
    )
    named(cfg, secrets, rsync)


def _deploy(cfg: DjangoSiteConfig, secrets: SecretValues, rsync: RsyncRunner) -> None:
    name, unit, front = cfg.service_name, cfg.unit_name, cfg.frontend
    # Everything is rendered (and every value checked) before any operation.
    env_content = render_env(cfg, secrets)
    launcher_text = render("gunicorn.sh.j2", cfg)
    unit_text = render("unit.service.j2", cfg)
    route_text = render("route.traefik.yml.j2", cfg)
    worker_texts = [
        (w, render("worker.sh.j2", cfg, worker=w), render("worker.service.j2", cfg, worker=w)) for w in cfg.workers
    ]
    next_texts = (render("next.sh.j2", cfg), render("unit.service.j2", cfg, frontend_unit=True)) if front else ("", "")
    # A stale certifi/pip lock fails here, before any operation.
    require_lock_floors(cfg.source.path / cfg.app.app_dir, f"{name} source", root=cfg.source.path)

    if isinstance(cfg.database, PostgresDb):
        db = cfg.database
        # Fail closed before any mutation: never install/start the shared server.
        ready = fact(f"runuser -u postgres -- pg_isready -q -p {db.port} && echo ready || true")
        if ready != "ready":
            raise ValueError("PostgreSQL is unavailable; provision the host separately")
    if front is not None:
        frontend.require_tools(front)
    if cfg.apt_packages:
        # Before the user: its login shell may be one of them (fish).
        apt.packages(name=f"Install {name} prerequisites", packages=list(cfg.apt_packages))
    system_user(
        cfg.user,
        group=cfg.group_name,
        home=cfg.home,
        shell=cfg.shell,
        directories=[cfg.site_path, cfg.cache_dir],
    )
    for path in cfg.data_dirs:
        files.directory(
            name=f"Ensure directory {path}", path=str(path), user=cfg.user, group=cfg.group_name, mode="0750"
        )
    if isinstance(cfg.database, PostgresDb) and cfg.media_root.is_relative_to(cfg.site_path):
        media = shlex.quote(str(cfg.media_root))
        script = (
            f"if test -L {media}; then echo invalid; "
            f"elif test -d {media}; then echo directory; "
            f"elif test -e {media}; then echo invalid; else echo missing; fi"
        )
        kind = fact(shlex.join(["sh", "-c", script]))
        if kind not in ("directory", "missing"):
            raise ValueError("media must be a real directory or an absent path")
        if kind == "missing":
            files.directory(
                name=f"Ensure directory {cfg.media_root}",
                path=str(cfg.media_root),
                user=cfg.user,
                group=cfg.group_name,
                mode="0755",
            )
    if cfg.fish:
        _fish(cfg)

    left = fact(markers_command(cfg)).split()
    _no_site_markers(cfg)
    restart_marker = RESTART.format(unit=unit)
    # Everything the unit's processes read (filled in below); a change marks
    # the restart it owes before it happens.
    unit_reads: list[OperationMeta] = []
    restart_mark = _mark(
        cfg,
        f"Mark {unit} for a restart",
        restart_marker,
        when=lambda: restart_marker in left or any(op.will_change for op in unit_reads),
    )
    # The frontend's unit: its restart marker and what its processes read.
    next_reads: list[OperationMeta] = []
    next_marker = RESTART.format(unit=front.unit) if front else ""
    next_mark = (
        _mark(
            cfg,
            f"Mark {front.unit} for a restart",
            next_marker,
            when=lambda: next_marker in left or any(op.will_change for op in next_reads),
        )
        if front
        else None
    )
    worker_reads: dict[str, list[OperationMeta]] = {w.unit: [] for w in cfg.workers}

    def worker_owed(unit: str) -> Callable[[], bool]:
        def needed() -> bool:
            return RESTART.format(unit=unit) in left or any(o.will_change for o in worker_reads[unit])

        return needed

    worker_marks = [
        _mark(cfg, f"Mark {w.unit} for a restart", RESTART.format(unit=w.unit), when=worker_owed(w.unit))
        for w in cfg.workers
    ]
    regroup = _primary_group(cfg)
    unit_reads += regroup
    next_reads += regroup
    for reads in worker_reads.values():
        reads += regroup

    # Written before the changes they stand for; the operations they watch are
    # added below (their ``will_change`` is known once planning is done).
    source_ops: list[OperationMeta] = []
    deps_owed: list[bool] = []
    pending = _mark(
        cfg,
        f"Mark the {name} source change pending",
        PENDING,
        when=lambda: PENDING in left or any(op.will_change for op in source_ops) or any(deps_owed),
    )
    code = sync_tree(
        name=f"Sync {name} source",
        src=cfg.source.path,
        dest=cfg.site_path,
        excludes=cfg.sync_excludes,
        delete=cfg.source.delete,
        runner=rsync,
        user=cfg.user,
        group=cfg.group_name,
    )
    source_ops.append(code)
    if front is not None and (middleware := frontend.install_middleware(cfg, front)) is not None:
        source_ops.append(middleware)
    if cfg.source.repair_ownership:
        _site_owned(cfg)

    deps_check = deps_probe(cfg)
    deps_state = probe(deps_check, name=f"{cfg.user} dependencies")
    # A missing or broken venv is "pending" too (uv would create it).
    deps_owed.append(deps_state != "current")
    missing_venv = fact(f"test -x {shlex.quote(str(cfg.venv_bin / 'python'))} && echo present || true") != "present"
    deps = server.shell(
        name=f"uv sync {cfg.app_path}",
        commands=[uv_command(cfg)],
        _if=lambda: missing_venv or deps_state != "current" or pending.did_change(),
    )
    if deps_state is None:
        verify_probe(deps_check, name=f"{cfg.user} dependencies", expect="current")
    verify_trust(cfg.venv_bin / "python", user=cfg.user, home=cfg.home, name=name)
    if cfg.fish:
        files.link(
            name="Link venv to .venv",
            path=str(cfg.app_path / "venv"),
            target=str(cfg.venv_path),
            user=cfg.user,
            group=cfg.group_name,
        )

    env = secret_file(
        name="Write .env", path=cfg.env_path, content=env_content, mode="0600", user=cfg.user, group=cfg.group_name
    )
    for reads in worker_reads.values():
        reads.append(env)
    if isinstance(cfg.database, PostgresDb):
        db = cfg.database
        postgres_database(
            db.name,
            owner=db.user,
            password=SecretStr(resolve(db.password, secrets)),
            port=db.port,
            manage_service=False,
        )
    migrations_check = migrations_probe(cfg)
    migrations = probe(migrations_check, name=f"{cfg.user} migrations")
    migrate = manage(
        cfg,
        f"Run {name} migrations",
        ("migrate", *cfg.steps.migrate_args),
        gate=[pending, deps],
        force=migrations != "current",
    )
    if migrations is None:
        verify_probe(migrations_check, name=f"{cfg.user} migrations", expect="current")

    def source_changed() -> bool:
        # This run changed the source, or an earlier one that did stopped before its end.
        return PENDING in left or any(op.did_change() for op in source_ops)

    triggers = {"source": source_changed, "deps": deps.did_change, "migrate": migrate.did_change}
    for group in cfg.steps.extra:
        if group.after == "migrate":
            _step_group(cfg, group, triggers, secrets)
    static = manage(
        cfg,
        "Collect static files",
        ("collectstatic", *cfg.steps.collectstatic_args),
        gate=[pending, deps],
        force=not static_collected(cfg),
        # The restart it owes is written down before the files change.
        before=_touch(cfg, restart_marker) if cfg.steps.restart_after_collectstatic else "",
    )

    for static_path in cfg.steps.required_static:
        target = shlex.quote(str(cfg.app_path / static_path))
        mark_read_only(server.shell(name=f"Verify required static path {static_path}", commands=[f"test -e {target}"]))

    def restarting_static() -> bool:
        return cfg.steps.restart_after_collectstatic and static.did_change()

    if cfg.repair_cache_ownership:
        cache = shlex.quote(str(cfg.cache_dir))
        wrong = fact(
            shlex.join(
                [
                    "sh",
                    "-c",
                    f"if test -d {cache}; then find {cache} "
                    f"\\( ! -user {cfg.user} -o ! -group {cfg.group_name} \\) -print -quit; fi",
                ]
            )
        )
        server.shell(
            name="Repair cache ownership",
            commands=[f"chown -hR {cfg.user}:{cfg.group_name} {cache}"],
            _if=lambda: bool(wrong),
        )
    for group in cfg.steps.extra:
        if group.after == "collectstatic":
            _step_group(cfg, group, triggers, secrets)
    if isinstance(cfg.admin, EnsureSuperuser):
        ensure_superuser(cfg, cfg.admin, secrets)
    elif cfg.admin is not None:
        bootstrap_superuser(cfg, cfg.admin, secrets)
    built = _frontend(cfg, front, source_changed, next_marker) if front else None

    launcher = files.put(
        name="Write gunicorn.sh",
        src=StringIO(launcher_text),
        dest=str(cfg.site_path / "gunicorn.sh"),
        user=cfg.user,
        group=cfg.group_name,
        mode="0755",
    )
    unit_op = systemd_unit(unit, unit_text)
    unit_reads += [env, launcher, unit_op]
    next_unit = _frontend_files(cfg, front, next_reads, *next_texts) if front else None
    # A leftover restart marker also reloads systemd: the unit file may be one
    # an earlier run installed and never loaded.
    service_rollout(
        unit,
        units=[unit_op, *([restart_mark] if restart_marker in left else [])],
        restart_when=[pending, deps, restart_mark, *([static] if cfg.steps.restart_after_collectstatic else [])],
    )
    for (worker, script, text), mark in zip(worker_texts, worker_marks, strict=True):
        launch = files.put(
            name=f"Write {worker.unit} launcher",
            src=StringIO(script),
            dest=str(cfg.site_path / f"{worker.unit}.sh"),
            user=cfg.user,
            group=cfg.group_name,
            mode="0755",
        )
        worker_unit = systemd_unit(worker.unit, text)
        worker_reads[worker.unit] += [launch, worker_unit]
        service_rollout(
            worker.unit,
            units=[worker_unit, *([mark] if RESTART.format(unit=worker.unit) in left else [])],
            restart_when=[pending, deps, mark],
        )
        # Type=simple can accept a start whose process exits immediately. Keep
        # restart obligations until the worker stays active without a restart.
        worker_name = shlex.quote(worker.unit + ".service")
        health = (
            f"before=$(systemctl show {worker_name} -p NRestarts --value) && sleep 2 && "
            f"systemctl is-active --quiet {worker_name} && "
            f"after=$(systemctl show {worker_name} -p NRestarts --value) && "
            '[ "$before" = "$after" ]'
        )
        mark_read_only(
            server.shell(name=f"Check worker {worker.unit} stays active", commands=[shlex.join(["sh", "-c", health])])
        )
    if front is not None and next_unit is not None and next_mark is not None and built is not None:
        service_rollout(
            front.unit,
            units=[next_unit, *([next_mark] if next_marker in left else [])],
            restart_when=[next_mark, built],
        )
    if cfg.route.noindex:
        route_put(
            name="Write noindex response middleware",
            src=render("noindex.traefik.yml.j2", cfg),
            dest=str(DYNAMIC_DIR / f"{cfg.route_name}-noindex.traefik.yml"),
            mode="0644",
        )

    # Never a Traefik restart: its file provider watches the directory.
    route = SiteRoute(name=cfg.route_name, host=cfg.route.fqdn, app_port=cfg.app.port, app_host=cfg.route.backend)
    traefik_route(route, renderer=lambda _route, _hash: route_text, restart="none")

    wait_port(cfg.app.port, host="127.0.0.1", retries=cfg.checks.port_retries)
    http_check(
        f"http://127.0.0.1:{cfg.app.port}{cfg.checks.path}", status=cfg.checks.statuses, host_header=cfg.route.fqdn
    )
    if front is not None:
        wait_port(front.port, host="127.0.0.1", retries=cfg.checks.port_retries)
        http_check(f"http://127.0.0.1:{front.port}{front.check_path}", status=front.check_statuses)
    public_checks(cfg)
    # Only a deploy that came up healthy records its commit and clears its markers.
    record_source(cfg.site_path, cfg.source.commit, user=cfg.user, group=cfg.group_name)
    marks = [*worker_marks, pending, restart_mark, *([next_mark] if next_mark else []), *([built] if built else [])]
    server.shell(
        name="Clear the pending markers",
        commands=[
            " ".join(
                [
                    "rm -f",
                    _marker(cfg, PENDING),
                    _marker(cfg, restart_marker),
                    *[_marker(cfg, RESTART.format(unit=w.unit)) for w in cfg.workers],
                    *_next_marker(cfg),
                ]
            )
        ],
        _if=lambda: any(op.did_change() for op in marks) or restarting_static(),
    )

    if (echoport_target := cfg.echoport) is not None:
        upsert_target(
            {
                "name": echoport_target.name,
                "description": echoport_target.description,
                "icon": echoport_target.icon,
                "service_name": echoport_target.service_name or f"{cfg.unit_name}.service",
                "restore_owner": echoport_target.restore_owner or f"{cfg.user}:{cfg.group_name}",
                "db_path": str(echoport_target.db_path or ""),
                "backup_files": [str(path) for path in echoport_target.backup_files],
                "schedule": echoport_target.schedule,
                "schedule_policy": "set" if echoport_target.update_schedule else "keep",
            },
            name=f"Upsert Echoport backup target {echoport_target.name}",
            missing=f"Echoport must be deployed on this host before {cfg.service_name} can register its backup target",
        )


def _next_marker(cfg: DjangoSiteConfig) -> list[str]:
    return [_marker(cfg, RESTART.format(unit=cfg.frontend.unit))] if cfg.frontend else []


def _frontend(
    cfg: DjangoSiteConfig, front: NextStandalone, source_changed: Callable[[], bool], marker: str
) -> OperationMeta:
    """The build (its restart marker first), the purge and the legacy guard.

    Both follow the source only: a change of the Python dependencies alone
    neither rebuilds nor purges.
    """

    built = frontend.build(cfg, front, before=_touch(cfg, marker), when=source_changed)
    frontend.purge_public_dirs(cfg, front, after=lambda: source_changed() or built.did_change())
    if front.legacy_guard is not None:
        frontend.legacy_guard(cfg, front.legacy_guard)
    return built


def _frontend_files(
    cfg: DjangoSiteConfig, front: NextStandalone, reads: list[OperationMeta], text: str, unit_text: str
) -> OperationMeta:
    """``next.sh`` and the frontend's unit; a launcher that differs only in comments is no restart."""

    path = cfg.site_path / "next.sh"
    launcher = files.put(
        name="Write next.sh", src=StringIO(text), dest=str(path), user=cfg.user, group=cfg.group_name, mode="0755"
    )
    if frontend.code_changed(text, host.get_fact(FileContents, path=str(path))):
        reads.append(launcher)
    unit = systemd_unit(front.unit, unit_text)
    reads.append(unit)
    return unit
