"""The step sequence every Django/Wagtail site shares.

A step runs when its input changed or a read-only probe says it is owed, so a
converged deploy changes nothing. Markers in ``/var/lib/ops-deploy/<service>/``,
written before the changes they stand for and removed when a run completed,
make the next run finish what a failed one left undone:

- ``.ops-deploy-pending``: the source or the dependencies changed; the steps
  they gate (migrations, static files, triggered step groups) and the restart
  are owed.
- ``.ops-deploy-restart-<unit>``: something the unit reads changed (``.env``,
  the launcher, the unit file, the user's primary group); the restart is owed.

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

from pyinfra import host
from pyinfra.api import deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import Directory
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
    uv_sync,
    wait_port,
)
from ops_deploy.helpers.probes import probe, verify_probe
from ops_deploy.helpers.traefik import DYNAMIC_DIR
from ops_deploy.ops import secret_file, sync_tree
from ops_deploy.services.django_site.config import DjangoSiteConfig, StepGroup
from ops_deploy.services.django_site.django import (
    deps_probe,
    ensure_superuser,
    fact,
    manage,
    manage_script,
    migrations_probe,
    site_shell,
    static_collected,
)
from ops_deploy.services.django_site.render import render, render_env

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


def _step_group(cfg: DjangoSiteConfig, group: StepGroup, triggers: dict[str, list[OperationMeta]]) -> None:
    """One ``steps.extra`` group, gated by its triggers, its marker and ``when``."""

    left = False
    if group.marker:
        left = fact(f"test -e {_marker(cfg, group.marker)} && echo pending || true") == "pending"
    gate = [op for trigger in sorted(group.triggers) for op in triggers[trigger]]

    def needed() -> bool:
        return group.when == "always" or left or any(op.did_change() for op in gate)

    if group.marker:
        server.shell(name=f"Mark {group.name} pending", commands=[_touch(cfg, group.marker)], _if=needed)
    for step in group.steps:
        server.shell(name=step.name, commands=[site_shell(cfg, manage_script(cfg, *step.argv))], _if=needed)
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
    name, unit = cfg.service_name, cfg.unit_name
    # Everything is rendered (and every value checked) before any operation.
    env_content = render_env(cfg, secrets)
    launcher_text = render("gunicorn.sh.j2", cfg)
    unit_text = render("unit.service.j2", cfg)
    route_text = render("route.traefik.yml.j2", cfg)

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
    if cfg.fish:
        _fish(cfg)

    left = fact(markers_command(cfg)).split()
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
    unit_reads += _primary_group(cfg)

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
    if cfg.source.repair_ownership:
        _site_owned(cfg)

    deps_check = deps_probe(cfg)
    deps_state = probe(deps_check, name=f"{cfg.user} dependencies")
    # A missing or broken venv is "pending" too (uv would create it).
    deps_owed.append(deps_state != "current")
    deps = uv_sync(
        cfg.app_path,
        user=cfg.user,
        home=cfg.home,
        venv=cfg.venv_path,
        python=cfg.app.python,
        args=cfg.app.uv_args,
        # None: run whatever the source did, when the environment is not as locked.
        when_changed=[pending] if deps_state == "current" else None,
    )
    if deps_state is None:
        verify_probe(deps_check, name=f"{cfg.user} dependencies", expect="current")
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
    migrations_check = migrations_probe(cfg)
    migrations = probe(migrations_check, name=f"{cfg.user} migrations")
    migrate = manage(cfg, f"Run {name} migrations", ("migrate",), gate=[pending, deps], force=migrations != "current")
    if migrations is None:
        verify_probe(migrations_check, name=f"{cfg.user} migrations", expect="current")
    triggers = {"source": [pending], "deps": [deps], "migrate": [migrate]}
    for group in cfg.steps.extra:
        if group.after == "migrate":
            _step_group(cfg, group, triggers)
    static = manage(
        cfg,
        "Collect static files",
        ("collectstatic", *cfg.steps.collectstatic_args),
        gate=[pending, deps],
        force=not static_collected(cfg),
        # The restart it owes is written down before the files change.
        before=_touch(cfg, restart_marker) if cfg.steps.restart_after_collectstatic else "",
    )

    def restarting_static() -> bool:
        return cfg.steps.restart_after_collectstatic and static.did_change()

    for group in cfg.steps.extra:
        if group.after == "collectstatic":
            _step_group(cfg, group, triggers)
    if cfg.admin is not None:
        ensure_superuser(cfg, cfg.admin, secrets)

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
    # A leftover restart marker also reloads systemd: the unit file may be one
    # an earlier run installed and never loaded.
    service_rollout(
        unit,
        units=[unit_op, *([restart_mark] if restart_marker in left else [])],
        restart_when=[pending, deps, restart_mark, *([static] if cfg.steps.restart_after_collectstatic else [])],
    )
    # Never a Traefik restart: its file provider watches the directory.
    route = SiteRoute(name=unit, host=cfg.route.fqdn, app_port=cfg.app.port, app_host="localhost")
    traefik_route(route, renderer=lambda _route, _hash: route_text, restart="none")

    wait_port(cfg.app.port, host="127.0.0.1", retries=cfg.checks.port_retries)
    http_check(
        f"http://127.0.0.1:{cfg.app.port}{cfg.checks.path}", status=cfg.checks.statuses, host_header=cfg.route.fqdn
    )
    # Last: only a deploy that came up healthy records its commit and clears its markers.
    record_source(cfg.site_path, cfg.source.commit, user=cfg.user, group=cfg.group_name)
    server.shell(
        name="Clear the pending markers",
        commands=[f"rm -f {_marker(cfg, PENDING)} {_marker(cfg, restart_marker)}"],
        _if=lambda: pending.did_change() or restart_mark.did_change() or restarting_static(),
    )
