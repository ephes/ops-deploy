"""Transitional: django_site does what the old split-site module did, scenario by scenario.

Every fake-connector scenario of the old module's tests runs through the
vendored old module (``tests/legacy_split_site``) and through
``deploy_django_site`` configured like it (``tests/django_site_split_fixtures``),
each host holding the files its own module writes. Compared: the mutating
operations (old names mapped to django_site's), the restarts, the
management commands, the uploads and stdin. The permitted differences are
listed below and in ``docs/services/django_site.md``.
"""

from __future__ import annotations

import base64
import re
import shlex
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.helpers.probes import FAILED
from ops_deploy.services.django_site import DjangoSiteConfig, deploy_django_site
from ops_deploy.testing import FakeRun, RecordingRsyncRunner, run_deploy_fake
from tests import django_site_split_fixtures as new
from tests import fakehost
from tests.legacy_split_site import LegacySplitConfig, deploy_legacy_split_site
from tests.legacy_split_site.deploy import BUILD_STAMP, LegacyGuard, UrlCheck, render, render_env, render_route

V = "Deploy splitsite | "
ITEMIZED_CHANGE = [">f.st...... django/app/views.py"]
COMMIT = "0123456789abcdef0123456789abcdef01234567"
RECORD = f"{new.SITE}/.ops-deploy-source"

# The old module's operation names that django_site names differently.
# The build copies public/ only when the app has one (django_site).
OLD_PUBLIC_COPY = "[ -e nextjs/.next/standalone/nextjs/public ] || cp -r"
PUBLIC_COPY = "[ -e nextjs/.next/standalone/nextjs/public ] || [ ! -e nextjs/public ] || cp -r"
RENAMED = {
    "Mark the source change pending": "Mark the splitsite source change pending",
    "Sync the source": "Sync splitsite source",
    "Run migrations": "Run splitsite migrations",
}
# The old module marked a dependency change separately (restart and
# collectstatic owed); django_site's pending marker covers both.
DEPS_MARK = "Mark splitsite-django for a restart and collectstatic (dependencies)"


def old_config(source: Path, **changes: Any) -> LegacySplitConfig:
    return LegacySplitConfig.model_validate(
        {
            "source_path": source,
            "secrets": SecretRef("secrets/staging/splitsite.yml"),
            "fqdn": new.FQDN,
            "mailgun_api_url": new.MAILGUN,
            "bootstrap_admin_email": "admin@fixture.example",
            "django_port": new.DJANGO_PORT,
            "next_port": new.NEXT_PORT,
            "next_path_prefixes": ("/cms", "/_next"),
            "middleware_from": "middleware.prod.ts",
            "content_import_command": "import_content",
            "purged_public_dirs": ("uploads",),
            "legacy_guard": LegacyGuard(
                tokens=("jwtVerify",), dirs=("*/app/admin",), search=("nextjs/.next/standalone",)
            ),
            "next_check_path": "/cms/login",
            "csrf_check_path": "/cms-api/session/",
            "public_checks": (
                UrlCheck(path="/", retries=10, delay=6),
                UrlCheck(path="/members", status=302, follow=False),
                UrlCheck(path="/preview/", contains=('name="robots"', "noindex")),
            ),
            "extra_source_excludes": ("/tests",),
            **changes,
        }
    )


def old_converged(cfg: LegacySplitConfig, secrets: SecretValues, **drift: Any) -> dict[str, Any]:
    """The old module's converged host (its own renders), as in its tests."""

    content = {
        new.LAUNCHER: render("gunicorn.sh.j2", cfg=cfg),
        new.NEXT_SH: render("next.sh.j2", cfg=cfg),
        new.MIDDLEWARE: new.MIDDLEWARE_PROD,
        new.FISH: render("user_config.fish.j2", cfg=cfg),
        new.UNIT: render("django.service.j2", cfg=cfg),
        new.NEXT_UNIT: render("next.service.j2", cfg=cfg),
        new.ROUTE: render_route(cfg),
    }
    content.update({k: v for k, v in drift.items() if k.startswith("/")})
    responses: dict[str, Any] = {
        **fakehost.LINUX,
        **fakehost.system_account(new.USER, new.HOME, shell="/usr/bin/fish"),
        "sync --locked --no-dev --dry-run": ["current"],
        "migrate --check": ["current"],
        "staticfiles.json": ["present"],
        "auth_user where username": ["present"],
        "bootstrap-admin-password-applied && echo present": ["present"],
        f"{BUILD_STAMP} 2>/dev/null": [new.STAMP, "built"],
        **fakehost.venv(new.VENV),
    }
    for path in ("", "/site", "/site/nextjs", "/site/cache", "/.config/fish"):
        responses.update(fakehost.directory(f"{new.HOME}{path}", user=new.USER))
    for path in ("/data", "/data/media", "/data/private_media"):
        responses.update(fakehost.directory(f"{new.HOME}{path}", user=new.USER, mode="drwxr-x---"))
    responses.update(fakehost.stat(f"{new.HOME}/.config", user=new.USER, group="root", mode="drwxr-xr-x"))
    for path in (new.UNITS, "/etc/traefik/dynamic"):
        responses.update(fakehost.directory(path))
    for path, text in content.items():
        owner = new.USER if path.startswith(new.HOME) else "root"
        mode = "-rwxr-xr-x" if path.endswith(".sh") else "-rw-r--r--"
        responses.update(fakehost.file(path, text, user=owner, mode=mode))
    env = render_env(cfg, secrets).reveal().decode()
    responses.update(fakehost.file(new.ENV, env, user=new.USER, mode="-rw-------"))
    for unit in (f"{new.USER}-django.service", f"{new.USER}-next.service"):
        responses.update(fakehost.service(unit))
    responses.update({k: v for k, v in drift.items() if not k.startswith("/")})
    return responses


MARKERS = "grep -x -e .ops-deploy-pending"
STALE_DEPS = {"sync --locked --no-dev --dry-run": ["pending"]}
PENDING_MARK = "Mark the splitsite source change pending"
# The old module reloaded systemd whenever a restart marker was written (an
# .env or launcher change too); django_site reloads it when a unit file changed
# or a restart marker is left over.
RELOAD_DJANGO = "Reload systemd for splitsite-django.service"
RELOAD_NEXT = "Reload systemd for splitsite-next.service"


@dataclass(frozen=True)
class Scenario:
    first: bool = False
    rsync: dict[str, list[str]] = field(default_factory=dict)
    # Fact answers or file content (by path) on top of each module's converged host.
    drift: Callable[[SecretValues], dict[str, Any]] = lambda _s: {}
    secrets: dict[str, str] = field(default_factory=dict)
    old_cfg: dict[str, Any] = field(default_factory=dict)
    new_cfg: dict[str, Any] = field(default_factory=dict)
    # Documented differences of the mutating operations (django_site's names).
    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()


def _constant(drift: dict[str, Any]) -> Callable[[SecretValues], dict[str, Any]]:
    return lambda _s: drift


SCENARIOS = {
    # The venv link is django_site's (fish config on PATH, as the other sites).
    "first run": Scenario(first=True, rsync={"--dry-run": ITEMIZED_CHANGE}, added=("Link venv to .venv",)),
    "converged": Scenario(),
    "code change": Scenario(rsync={"--dry-run": ITEMIZED_CHANGE}),
    "stopped after the sync": Scenario(drift=_constant({MARKERS: [".ops-deploy-pending"]})),
    "middleware drift": Scenario(drift=_constant({new.MIDDLEWARE: "import { jwtVerify } from 'jose';\n"})),
    "leftover django restart": Scenario(drift=_constant({MARKERS: [".ops-deploy-restart-splitsite-django"]})),
    "leftover next restart": Scenario(drift=_constant({MARKERS: [".ops-deploy-restart-splitsite-next"]})),
    "stale dependencies": Scenario(drift=_constant(STALE_DEPS)),
    "markers before changes": Scenario(
        rsync={"--dry-run": ITEMIZED_CHANGE},
        secrets={"django_mailgun_api_key": "rotated-fixture-mailgun-key"},
        removed=(RELOAD_DJANGO,),
    ),
    "env change": Scenario(secrets={"django_mailgun_api_key": "rotated-fixture-mailgun-key"}, removed=(RELOAD_DJANGO,)),
    "stale build stamp": Scenario(drift=_constant({".ops-deploy-next-build 2>/dev/null": ["other stamp", "built"]})),
    "no build": Scenario(drift=_constant({".ops-deploy-next-build 2>/dev/null": [new.STAMP]})),
    "no stamp": Scenario(drift=_constant({".ops-deploy-next-build 2>/dev/null": []})),
    "unapplied migrations": Scenario(drift=_constant({"migrate --check": []})),
    "missing static manifest": Scenario(drift=_constant({"staticfiles.json": []})),
    "failed dependency probe": Scenario(drift=_constant({"sync --locked --no-dev --dry-run": [FAILED]})),
    "missing bootstrap admin": Scenario(drift=_constant({"auth_user where username": ["absent"]})),
    "bootstrap password not applied": Scenario(
        drift=_constant({"bootstrap-admin-password-applied && echo present": []})
    ),
    "purged files present": Scenario(
        drift=_constant({"! -name .gitkeep \\) -print -quit": ["nextjs/public/uploads/a"]})
    ),
    "next.sh change": Scenario(drift=_constant({new.NEXT_SH: "#!/bin/sh\n"}), removed=(RELOAD_NEXT,)),
    "unit change": Scenario(drift=_constant({new.UNIT: "[Unit]\n"})),
    "next unit change": Scenario(drift=_constant({new.NEXT_UNIT: "[Unit]\n"})),
    "route change": Scenario(drift=_constant({new.ROUTE: "http: {}\n"})),
    "git source recorded": Scenario(old_cfg={"source_commit": COMMIT}, new_cfg={"commit": COMMIT}),
    "git source again": Scenario(
        old_cfg={"source_commit": COMMIT},
        new_cfg={"commit": COMMIT},
        drift=_constant(fakehost.file(RECORD, f"{COMMIT}\n", user=new.USER)),
    ),
    "local source forgets the record": Scenario(drift=_constant(fakehost.file(RECORD, f"{COMMIT}\n", user=new.USER))),
}


def run_old(scenario: Scenario, tmp: Path) -> FakeRun:
    cfg = old_config(new.make_source(tmp / "old"), **scenario.old_cfg)
    base = old_config(new.make_source(tmp / "old-base"))
    assert cfg.secrets is not None
    secrets = SecretValues(cfg.secrets, new.SECRET_VALUES)
    used = SecretValues(cfg.secrets, {**new.SECRET_VALUES, **scenario.secrets})
    facts = {**fakehost.LINUX} if scenario.first else old_converged(base, secrets, **scenario.drift(secrets))
    return run_deploy_fake(
        deploy_legacy_split_site, cfg, used, rsync=RecordingRsyncRunner(responses=scenario.rsync), responses=facts
    )


def new_config(source: Path, **changes: Any) -> DjangoSiteConfig:
    cfg = new.split_config(source)
    if "commit" in changes:
        cfg = cfg.model_copy(update={"source": cfg.source.model_copy(update={"commit": changes.pop("commit")})})
    return cfg.model_copy(update=changes)


def run_new(scenario: Scenario, tmp: Path) -> FakeRun:
    cfg = new_config(new.make_source(tmp / "new"), **scenario.new_cfg)
    base = new.split_config(new.make_source(tmp / "new-base"))
    secrets = new.values(cfg)
    used = new.values(cfg, **scenario.secrets)
    facts = {**fakehost.LINUX} if scenario.first else new.converged(base, secrets, **scenario.drift(secrets))
    return run_deploy_fake(
        deploy_django_site, cfg, used, rsync=RecordingRsyncRunner(responses=scenario.rsync), responses=facts
    )


def mutating(run: FakeRun, *, old: bool = False) -> Counter[str]:
    names = [RENAMED.get(n.removeprefix(V), n.removeprefix(V)) for n in run.mutating_changed_ops]
    if old and DEPS_MARK in names:
        names.remove(DEPS_MARK)
        if PENDING_MARK not in names:
            names.append(PENDING_MARK)
    return Counter(names)


def manage_commands(run: FakeRun) -> list[str]:
    """``manage.py <args>`` of every management command, in order (without the shell around it)."""

    return [c[c.index("manage.py") :] for c in run.executed_commands if "manage.py" in c]


def site_commands(run: FakeRun, needle: str) -> list[str]:
    """Commands run in the site as the service user containing ``needle``, without a marker written first."""

    found = [c for c in run.executed_commands if needle in c and "runuser" in c]
    return [c[c.index("cd ") :] for c in found]


def parse_env(text: str) -> dict[str, str]:
    pairs = {}
    for line in text.splitlines():
        if line and not line.startswith("#"):
            key, _, value = line.partition("=")
            [pairs[key]] = shlex.split(value)
    return pairs


def _payload(text: str) -> str:
    try:
        return base64.b64decode("".join(text.split()), validate=True).decode()
    except ValueError:
        return text


@pytest.mark.parametrize("name", list(SCENARIOS))
def test_django_site_runs_what_the_split_module_ran(tmp_path: Path, name: str) -> None:
    scenario = SCENARIOS[name]
    before = run_old(scenario, tmp_path)
    after = run_new(scenario, tmp_path)

    assert before.succeeded, before.error
    assert after.succeeded, after.error
    expected = mutating(before, old=True) + Counter(scenario.added) - Counter(scenario.removed)
    assert mutating(after) == expected
    if name == "converged":
        assert after.mutating_changed_ops == before.mutating_changed_ops == []
        assert after.uploads == before.uploads == []
    restarts = [c for c in before.executed_commands if c.startswith("systemctl restart")]
    assert sorted(c for c in after.executed_commands if c.startswith("systemctl restart")) == sorted(restarts)
    assert manage_commands(after) == manage_commands(before)
    assert site_commands(after, "npm ci") == [
        c.replace(OLD_PUBLIC_COPY, PUBLIC_COPY) for c in site_commands(before, "npm ci")
    ]
    # The purge is the old one behind a refusal of symlinked parent directories.
    purges = site_commands(before, "find nextjs/public")
    assert len(site_commands(after, "find nextjs/public")) == len(purges)
    for new_purge, old_purge in zip(site_commands(after, "find nextjs/public"), purges, strict=True):
        assert re.findall(r"find [^;]+", new_purge) == re.findall(r"find [^;]+", old_purge)
    # Uploads: the same paths; the launchers, units, fish config and route carry django_site's render.
    cfg = new_config(new.make_source(tmp_path / "render"), **scenario.new_cfg)
    documented = {path: text for path, text in new.files(cfg, new.values(cfg)).items() if path != new.ENV}
    documented.pop(new.MIDDLEWARE)
    assert sorted(after.uploaded_paths) == sorted(before.uploaded_paths)
    old_uploads = dict(before.uploads)
    for path, content in after.uploads:
        assert content == (documented[path].encode() if path in documented else old_uploads[path]), path
    # Stdin: the same commands and payloads; .env as the same keys and values.
    assert len(after.stdin) == len(before.stdin)
    old_stdin = sorted(before.stdin, key=lambda item: " .env " in item[0])
    new_stdin = sorted(after.stdin, key=lambda item: " .env " in item[0])
    for (command, payload), (old_command, old_payload) in zip(new_stdin, old_stdin, strict=True):
        if " .env " in command:
            assert " .env " in old_command
            assert parse_env(_payload(payload)) == parse_env(_payload(old_payload))
        else:
            assert command[command.index("manage.py") :] == old_command[old_command.index("manage.py") :]
            assert payload == old_payload


def old_host(tmp: Path) -> dict[str, Any]:
    """A host the old module deployed, with the owners it left: group root on what it wrote."""

    base = old_config(new.make_source(tmp / "old-base"))
    assert base.secrets is not None
    facts = old_converged(base, SecretValues(base.secrets, new.SECRET_VALUES))
    env = render_env(base, SecretValues(base.secrets, new.SECRET_VALUES)).reveal().decode()
    for path, text, mode in (
        (new.ENV, env, "-rw-------"),
        (new.LAUNCHER, render("gunicorn.sh.j2", cfg=base), "-rwxr-xr-x"),
        (new.NEXT_SH, render("next.sh.j2", cfg=base), "-rwxr-xr-x"),
        (new.FISH, render("user_config.fish.j2", cfg=base), "-rw-r--r--"),
    ):
        facts.update(fakehost.file(path, text, user=new.USER, mode=mode))
        facts.update(fakehost.stat(path, user=new.USER, group="root", mode=mode))
    for path in (f"{new.SITE}/cache", f"{new.HOME}/.config/fish"):
        facts.update(fakehost.stat(path, user=new.USER, group="root", mode="drwxr-xr-x"))
    # The ownership probe finds the files with group root.
    facts["-print -quit 2>/dev/null || true"] = [new.ENV]
    return facts


SWITCH = [
    f"{V}{name}"
    for name in (
        f"Ensure directory {new.SITE}/cache",
        f"Ensure directory {new.HOME}/.config/fish",
        "Write fish config",
        "Mark splitsite-django for a restart",
        "Mark splitsite-next for a restart",
        "Set ownership of the site tree",
        "Link venv to .venv",
        "Write .env",
        "Write gunicorn.sh",
        "Install systemd unit splitsite-django.service",
        "Write next.sh",
        "Install systemd unit splitsite-next.service",
        "Reload systemd for splitsite-django.service",
        "Restart splitsite-django.service",
        "Reload systemd for splitsite-next.service",
        "Restart splitsite-next.service",
        "Write Traefik route splitsite",
        "Clear the pending markers",
    )
]


def test_the_switch_from_the_old_module_rewrites_the_files_and_restarts_each_unit_once(tmp_path: Path) -> None:
    cfg = new.split_config(new.make_source(tmp_path / "new"))
    secrets = new.values(cfg)

    switch = run_deploy_fake(
        deploy_django_site, cfg, secrets, rsync=RecordingRsyncRunner(), responses=old_host(tmp_path)
    )
    again = run_deploy_fake(
        deploy_django_site, cfg, secrets, rsync=RecordingRsyncRunner(), responses=new.converged(cfg, secrets)
    )

    assert switch.succeeded, switch.error
    assert switch.mutating_changed_ops == SWITCH
    for unit in ("splitsite-django.service", "splitsite-next.service"):
        assert switch.executed_commands.count(f"systemctl restart {unit}") == 1
    # No source step: the same tree, the same dependencies, no migration, no build.
    for absent in ("npm ci", "manage.py", "uv sync"):
        assert not any(absent in c for c in switch.executed_commands), absent
    assert again.succeeded, again.error
    assert again.mutating_changed_ops == []
