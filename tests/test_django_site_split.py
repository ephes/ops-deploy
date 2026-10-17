"""django_site with a Next.js standalone frontend, against the fake connector and real shells."""

from __future__ import annotations

import base64
import os
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from ops_deploy.core import ConfigValidationError, SecretValues
from ops_deploy.core.secrets import MissingSecretKeysError
from ops_deploy.services.django_site import Checks, DjangoSiteConfig, LegacyGuard, UrlCheck, deploy_django_site
from ops_deploy.services.django_site.frontend import BUILD_STAMP, code_lines, legacy_guard_script, purge_script
from ops_deploy.services.django_site.public import CSRF_CHECK, url_check_script
from ops_deploy.services.django_site.render import MANAGED, render, render_env
from ops_deploy.testing import FakeRun, RecordingRsyncRunner, run_deploy_fake
from tests import fakehost
from tests.django_site_split_fixtures import (
    DATA,
    DJANGO_PORT,
    FQDN,
    HOME,
    NEXT_PORT,
    NEXT_SH,
    NEXT_UNIT,
    ROUTE,
    SECRET_ONLY,
    SECRET_VALUES,
    SITE,
    STAMP,
    UNIT,
    converged,
    make_source,
    split_config,
    values,
)
from tests.test_remote_shell_execution import LOGIN_SHELLS, run_remote

V = "Deploy splitsite | "
STATE = "/var/lib/ops-deploy/splitsite"
ITEMIZED_CHANGE = [">f.st...... django/app/views.py"]
MARKERS_LEFT = "grep -x -e .ops-deploy-pending"
BASE = f"https://{FQDN}"
READ_ONLY = [
    f"{V}{name}"
    for name in (
        "Require Node.js and uv",
        "Check purged public files are absent",
        "Check no legacy code is served",
        f"Wait for port 127.0.0.1:{DJANGO_PORT}",
        f"Check http://127.0.0.1:{DJANGO_PORT}/",
        f"Wait for port 127.0.0.1:{NEXT_PORT}",
        f"Check http://127.0.0.1:{NEXT_PORT}/cms/login",
        f"Check {BASE}/",
        f"Check {BASE}/members",
        f"Check {BASE}/preview/",
        f"Check the CSRF origin of {BASE}",
    )
]
RESTART_DJANGO = f"{V}Restart splitsite-django.service"
RESTART_NEXT = f"{V}Restart splitsite-next.service"
BUILD = f"{V}Build the Next.js app (npm ci, next build)"
CLEAR = f"{V}Clear the pending markers"
SOURCE_STEPS = [
    f"{V}Mark the splitsite source change pending",
    f"{V}Sync splitsite source",
    f"{V}uv sync /home/splitsite/site/django",
    f"{V}Run splitsite migrations",
    f"{V}Collect static files",
    f"{V}Import content",
    BUILD,
    f"{V}Remove purged public files",
    RESTART_DJANGO,
    RESTART_NEXT,
    CLEAR,
]


@pytest.fixture
def cfg(tmp_path: Path) -> DjangoSiteConfig:
    return split_config(make_source(tmp_path))


@pytest.fixture
def secrets(cfg: DjangoSiteConfig) -> SecretValues:
    return values(cfg)


def deploy(
    cfg: DjangoSiteConfig,
    secrets: SecretValues,
    responses: dict[str, Any] | None = None,
    rsync: RecordingRsyncRunner | None = None,
    *,
    succeed: bool = True,
) -> FakeRun:
    run = run_deploy_fake(
        deploy_django_site,
        cfg,
        secrets,
        rsync=rsync or RecordingRsyncRunner(),
        responses=responses if responses is not None else {**fakehost.LINUX},
    )
    if succeed:
        assert run.succeeded, run.error
    # Every command, also of the ops a gate skipped, reads the same through fish (root's login shell).
    assert run.fish_unsafe_commands == []
    return run


def changed() -> RecordingRsyncRunner:
    return RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE})


def touch(marker: str) -> str:
    return f"install -d -o root -g root -m 0700 {STATE} && touch {STATE}/{marker}"


# -- the files ---------------------------------------------------------------


def test_env_has_the_site_keys_at_the_site_root(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    env = render_env(cfg, secrets).reveal().decode()

    lines = env.splitlines()
    assert lines[0] == f"# {MANAGED}"
    keys = [line.partition("=")[0] for line in lines[1:]]
    assert keys[:5] == [
        "DJANGO_SETTINGS_MODULE",
        "DJANGO_SECRET_KEY",
        "DJANGO_ALLOWED_HOSTS",
        "DJANGO_CACHE_LOCATION",
        "DJANGO_DEPLOY_ENVIRONMENT",
    ]
    assert "DJANGO_ADMIN_URL" not in keys
    assert f"DJANGO_ALLOWED_HOSTS='{FQDN},localhost,127.0.0.1'" in lines
    assert f"DJANGO_CACHE_LOCATION='{SITE}/cache'" in lines
    assert f"DATABASE_NAME='{DATA}/db.sqlite3'" in lines
    # A joined value: a literal and a secret with its slashes stripped.
    assert f"WAGTAILADMIN_BASE_URL='https://{FQDN}/fixture-wagtail-admin'" in lines
    assert str(cfg.env_path) == f"{SITE}/.env"


def test_launchers(cfg: DjangoSiteConfig) -> None:
    gunicorn = render("gunicorn.sh.j2", cfg)
    next_sh = render("next.sh.j2", cfg)

    assert f"set -a; . {SITE}/.env; set +a\n\ncd {SITE}/django\nexec {SITE}/django/.venv/bin/gunicorn" in gunicorn
    assert "  -w 3 \\\n" in gunicorn
    assert next_sh == (
        f"#!/bin/bash\n# {MANAGED}\nset -euo pipefail\ncd {SITE}\nexport NODE_ENV=production\n"
        f"export PORT={NEXT_PORT}\nexport HOSTNAME=127.0.0.1\nexport DJANGO_BASE_URL=http://127.0.0.1:{DJANGO_PORT}\n"
        "exec /usr/bin/node nextjs/.next/standalone/nextjs/server.js\n"
    )


def test_units_are_strictly_sandboxed(cfg: DjangoSiteConfig) -> None:
    django = render("unit.service.j2", cfg)
    nextjs = render("unit.service.j2", cfg, frontend_unit=True)

    for line in (
        "Description=Split site web application",
        f"WorkingDirectory={SITE}/django",
        f"ExecStart={SITE}/gunicorn.sh",
    ):
        assert f"\n{line}\n" in django
    for line in (
        "Description=Split site Next.js server",
        "After=network.target splitsite-django.service",
        f"WorkingDirectory={SITE}",
        f"ExecStart={SITE}/next.sh",
    ):
        assert f"\n{line}\n" in nextjs
    for unit in (django, nextjs):
        for line in (
            "User=splitsite",
            "Group=splitsite",
            "RestartSec=5",
            "ProtectSystem=strict",
            "ProtectHome=read-only",
            # The data directory covers its media directories.
            f"ReadWritePaths={SITE} {SITE}/cache {DATA}",
            "ProtectKernelTunables=true",
            "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
            "SystemCallArchitectures=native",
        ):
            assert f"\n{line}\n" in unit
        assert "Environment" not in unit


def test_plain_hardening_keeps_the_home_writable(cfg: DjangoSiteConfig) -> None:
    unit = render("unit.service.j2", cfg.model_copy(update={"hardening": True}))

    assert "\nProtectHome=false\n" in unit
    assert "ProtectKernelTunables" not in unit


def test_route_sends_the_frontend_prefixes_to_the_frontend(cfg: DjangoSiteConfig) -> None:
    text = render("route.traefik.yml.j2", cfg)
    route = yaml.safe_load(text)["http"]

    paths = "Path(`/cms`) || PathPrefix(`/cms/`) || Path(`/_next`) || PathPrefix(`/_next/`)"
    routers = route["routers"]
    assert list(routers) == [
        f"{FQDN}-cms-router",
        f"{FQDN}-cms-secure-router",
        f"{FQDN}-router",
        f"{FQDN}-secure-router",
    ]
    for name, service, priority, middlewares in (
        ("cms-router", "next", 200, ["redirect"]),
        ("cms-secure-router", "next", 200, ["csrf", "sslHeaders", "gzip-compress"]),
        ("router", "django", 100, ["redirect", "csrf"]),
        ("secure-router", "django", 100, ["csrf", "sslHeaders", "gzip-compress", "redirect-www"]),
    ):
        router = routers[f"{FQDN}-{name}"]
        assert (router["service"], router["priority"], router["middlewares"]) == (
            f"{FQDN}-{service}",
            priority,
            middlewares,
        ), name
        assert router["rule"] == (f"Host(`{FQDN}`) && ({paths})" if "cms" in name else f"Host(`{FQDN}`)")
    assert route["services"] == {
        f"{FQDN}-django": {"loadBalancer": {"servers": [{"url": f"http://127.0.0.1:{DJANGO_PORT}"}]}},
        f"{FQDN}-next": {"loadBalancer": {"servers": [{"url": f"http://127.0.0.1:{NEXT_PORT}"}]}},
    }
    assert text.startswith(f"# {MANAGED}\n# Public website, no Basic Auth: Public website; the editors log in\n")


def test_a_host_rule_with_alternatives_is_grouped(cfg: DjangoSiteConfig) -> None:
    rule = f"Host(`{FQDN}`) || Host(`www.{FQDN}`)"
    site = cfg.model_copy(update={"route": cfg.route.model_copy(update={"host_rule": rule})})

    assert f'rule: "({rule}) && (Path(`/cms`)' in render("route.traefik.yml.j2", site)


def test_fish_config_and_venv_link_point_at_the_app(cfg: DjangoSiteConfig) -> None:
    fish = render("config.fish.j2", cfg)

    assert f'set -x VIRTUAL_ENV "{SITE}/django/venv"\n' in fish
    assert fish.endswith(f"cd {SITE}/django\n")


# -- deploy scenarios --------------------------------------------------------


def test_first_run_installs_everything(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, rsync=changed())

    commands = run.executed_commands
    order = [
        next(i for i, c in enumerate(commands) if needle in c)
        for needle in (
            "chmod 750 /home/splitsite/data",
            touch(".ops-deploy-pending"),
            "uv sync --locked --no-dev",
            "manage.py migrate --noinput",
            "manage.py collectstatic --noinput --clear",
            "manage.py import_content",
            "manage.py createsuperuser --noinput --username admin --email admin@fixture.example",
            "manage.py shell -c",
            "npm ci --no-audit --no-fund",
            "systemctl start splitsite-django.service",
            "systemctl start splitsite-next.service",
        )
    ]
    assert order == sorted(order)
    assert not any(c.startswith("systemctl restart") for c in commands)
    assert commands[-1] == (
        f"rm -f {STATE}/.ops-deploy-pending {STATE}/.ops-deploy-restart-splitsite-django "
        f"{STATE}/.ops-deploy-restart-splitsite-next"
    )
    # .env, the superuser password and the bootstrap password: stdin only.
    assert len(run.stdin) == 3
    assert run.upload(f"{SITE}/nextjs/middleware.ts").decode() == "export function middleware() {}\n"
    assert [op.name for op in run.ops if op.read_only] == READ_ONLY
    for path in (DATA, f"{DATA}/media", f"{DATA}/private_media"):
        assert f"chmod 750 {path}" in commands


def test_second_run_changes_nothing_mutating(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == []
    assert run.changed_ops == READ_ONLY
    assert run.uploads == []
    assert run.stdin == []


def test_code_change_runs_every_source_step_and_restarts_both_once(
    cfg: DjangoSiteConfig, secrets: SecretValues
) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets), rsync=changed())

    assert run.mutating_changed_ops == SOURCE_STEPS
    assert run.executed_commands.count("systemctl restart splitsite-django.service") == 1
    assert run.executed_commands.count("systemctl restart splitsite-next.service") == 1
    build = next(c for c in run.executed_commands if "npm ci" in c)
    assert build.startswith(f"{touch('.ops-deploy-restart-splitsite-next')} && cd {SITE} && runuser -u splitsite")
    assert f"rm -f {BUILD_STAMP}" in build
    assert f"env NODE_ENV=production WAGTAIL_BASE_URL=http://127.0.0.1:{DJANGO_PORT}" in build
    assert f"NEXT_PUBLIC_FQDN={FQDN} npm run build" in build
    assert f"> {BUILD_STAMP}" in build
    collect = next(c for c in run.executed_commands if "collectstatic" in c)
    assert collect.startswith(f"{touch('.ops-deploy-restart-splitsite-django')} && ")


def test_a_dependency_change_neither_rebuilds_nor_imports(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{"sync --locked --no-dev --dry-run": ["pending"]}))

    assert run.mutating_changed_ops == [
        f"{V}Mark the splitsite source change pending",
        f"{V}uv sync /home/splitsite/site/django",
        f"{V}Run splitsite migrations",
        f"{V}Collect static files",
        RESTART_DJANGO,
        CLEAR,
    ]


def test_a_leftover_pending_marker_repeats_the_source_steps(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{MARKERS_LEFT: [".ops-deploy-pending"]}))

    assert run.mutating_changed_ops == [step for step in SOURCE_STEPS if step != f"{V}Sync splitsite source"]


def test_middleware_drift_counts_as_a_source_change(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    drift = {f"{SITE}/nextjs/middleware.ts": "import { jwtVerify } from 'jose';\n"}

    run = deploy(cfg, secrets, converged(cfg, secrets, **drift))

    assert run.mutating_changed_ops == [
        SOURCE_STEPS[0],
        f"{V}Install nextjs/middleware.prod.ts as nextjs/middleware.ts",
        *SOURCE_STEPS[2:],
    ]


@pytest.mark.parametrize("answer", [["other stamp", "built"], [STAMP], []], ids=["env", "no build", "no stamp"])
def test_a_stale_build_is_rebuilt(cfg: DjangoSiteConfig, secrets: SecretValues, answer: list[str]) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{f"{BUILD_STAMP} 2>/dev/null": answer}))

    assert run.mutating_changed_ops == [BUILD, f"{V}Remove purged public files", RESTART_NEXT, CLEAR]


def test_a_build_env_change_rebuilds_and_rewrites(tmp_path: Path, cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    moved = split_config(make_source(tmp_path / "moved"), app=cfg.app.model_copy(update={"port": 10050}))
    front = moved.frontend
    assert front is not None
    url = "http://127.0.0.1:10050"
    moved = moved.model_copy(
        update={
            "frontend": front.model_copy(
                update={
                    "build_env": (front.build_env[0].model_copy(update={"value": url}), front.build_env[1]),
                    "runtime_env": (front.runtime_env[0].model_copy(update={"value": url}),),
                }
            )
        }
    )

    run = deploy(moved, secrets, converged(cfg, secrets))

    for name in (BUILD, f"{V}Write next.sh", RESTART_NEXT, RESTART_DJANGO, f"{V}Write Traefik route splitsite"):
        assert name in run.mutating_changed_ops
    assert run.executed_commands.count("systemctl restart splitsite-next.service") == 1


def test_a_comment_only_launcher_change_is_no_restart(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    text = render("next.sh.j2", cfg)
    deployed = text.replace("set -euo pipefail\n", "set -euo pipefail\n# an older comment\n\n")
    assert code_lines(deployed.splitlines()) == code_lines(text.splitlines())

    run = deploy(cfg, secrets, converged(cfg, secrets, **{NEXT_SH: deployed}))

    assert run.mutating_changed_ops == [f"{V}Write next.sh"]


@pytest.mark.parametrize(
    ("drift", "unit", "restart"),
    [
        ({NEXT_SH: "#!/bin/sh\n"}, "splitsite-next", RESTART_NEXT),
        ({NEXT_UNIT: "[Unit]\n"}, "splitsite-next", RESTART_NEXT),
        ({UNIT: "[Unit]\n"}, "splitsite-django", RESTART_DJANGO),
    ],
    ids=["launcher", "next unit", "django unit"],
)
def test_what_a_unit_reads_restarts_that_unit_only(
    cfg: DjangoSiteConfig, secrets: SecretValues, drift: dict[str, str], unit: str, restart: str
) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **drift))

    assert run.mutating_changed_ops[0] == f"{V}Mark {unit} for a restart"
    assert [op for op in run.mutating_changed_ops if op.startswith(f"{V}Restart")] == [restart]
    assert run.mutating_changed_ops[-1] == CLEAR


@pytest.mark.parametrize(("unit", "restart"), [("splitsite-django", RESTART_DJANGO), ("splitsite-next", RESTART_NEXT)])
def test_a_leftover_restart_is_repeated(cfg: DjangoSiteConfig, secrets: SecretValues, unit: str, restart: str) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{MARKERS_LEFT: [f".ops-deploy-restart-{unit}"]}))

    assert run.mutating_changed_ops == [
        f"{V}Mark {unit} for a restart",
        f"{V}Reload systemd for {unit}.service",
        restart,
        CLEAR,
    ]


def test_a_failed_build_keeps_the_restart_owed(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets, **{f"{BUILD_STAMP} 2>/dev/null": []}), "npm ci": {"success": False}}

    run = deploy(cfg, secrets, responses, succeed=False)

    assert any(c.startswith(touch(".ops-deploy-restart-splitsite-next")) for c in run.executed_commands)
    assert not any(c.startswith("rm -f /var/lib") for c in run.executed_commands)


def test_the_route_is_rewritten_without_a_restart(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{ROUTE: "http: {}\n"}))

    assert run.mutating_changed_ops == [f"{V}Write Traefik route splitsite"]


def test_purged_files_are_removed(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{"! -name .gitkeep \\) -print -quit": ["nextjs/public/x"]}))

    assert run.mutating_changed_ops == [f"{V}Remove purged public files"]


def test_missing_bootstrap_admin_is_created(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{"auth_user where username": ["absent"]}))

    assert run.mutating_changed_ops == [f"{V}Create the bootstrap admin"]
    [(command, payload)] = run.stdin
    assert "DJANGO_SUPERUSER_PASSWORD=fixture-bootstrap-password" in payload
    assert "fixture-bootstrap-password" not in command


def test_the_bootstrap_password_is_set_once(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{"bootstrap-admin-password-applied && echo present": []}))

    assert run.mutating_changed_ops == [f"{V}Set the bootstrap admin password (first deploy only)"]
    [(command, payload)] = run.stdin
    assert f"touch {DATA}/.bootstrap-admin-password-applied" in command
    assert "BOOTSTRAP_ADMIN_PASSWORD=fixture-bootstrap-password" in payload


def test_without_public_checks_only_the_local_ones_run(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    run = deploy(cfg.model_copy(update={"checks": Checks()}), secrets, converged(cfg, secrets))

    assert run.changed_ops == [name for name in READ_ONLY if f"Check {BASE}" not in name and "CSRF" not in name]


def test_a_site_without_a_frontend_has_none_of_its_steps(tmp_path: Path, secrets: SecretValues) -> None:
    bare = split_config(make_source(tmp_path), frontend=None)

    run = deploy(bare, secrets, rsync=changed())

    names = " ".join(op.name for op in run.ops)
    for absent in ("Node.js", "middleware", "next", "purged", "legacy code"):
        assert absent not in names
    assert "-next" not in render("route.traefik.yml.j2", bare)


def test_the_sync_deletes_but_keeps_what_the_host_writes(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    rsync = changed()

    deploy(cfg, secrets, converged(cfg, secrets), rsync=rsync)

    real = next(call for call in rsync.calls if "--dry-run" not in call)
    assert "--delete" in real
    assert "--chown=splitsite:splitsite" in real
    for pattern in (
        "/.env",
        "/cache",
        "/django/staticfiles",
        "/gunicorn.sh",
        "/next.sh",
        "/django/venv",
        "/nextjs/middleware.ts",
        "/nextjs/public/uploads/***",
        "node_modules",
        "/nextjs/.next",
        ".ops-deploy-*",
    ):
        assert f"--exclude={pattern}" in real


SPLIT_HOST_FILES = [
    "node_modules/x/index.js",
    "nextjs/node_modules/y/index.js",
    "nextjs/.next/standalone/nextjs/server.js",
    ".env",
    "cache/x",
    "gunicorn.sh",
    "next.sh",
    "django/staticfiles/staticfiles.json",
    "django/venv",
    "nextjs/middleware.ts",
    "nextjs/public/uploads/a.pdf",
    ".ops-deploy-next-build",
    ".ops-deploy-source",
]


@pytest.mark.parametrize("path", [*SPLIT_HOST_FILES, "django/app/views.py"])
def test_rsync_keeps_the_split_host_files(tmp_path: Path, cfg: DjangoSiteConfig, path: str) -> None:
    """Real rsync with --delete and the config's excludes: the host's files survive a source without them."""

    if not shutil.which("rsync"):
        pytest.skip("no rsync")
    src, dest = tmp_path / "src", tmp_path / "dest"
    src.mkdir()
    (src / "package.json").write_text("{}")
    (dest / path).parent.mkdir(parents=True, exist_ok=True)
    (dest / path).write_text("host")
    excludes = [f"--exclude={pattern}" for pattern in (*cfg.sync_excludes, ".ops-deploy-*")]
    subprocess.run(["rsync", "-rl", "--checksum", "--delete", *excludes, f"{src}/", f"{dest}/"], check=True)

    assert (dest / path).exists() == (path in SPLIT_HOST_FILES)


# -- secrets and validation --------------------------------------------------


def test_required_secrets_follow_the_config(cfg: DjangoSiteConfig) -> None:
    assert cfg.required_secret_keys == (
        "django_secret_key",
        "django_admin_url_path",
        "wagtail_admin_url_path",
        "mailgun_api_url",
        "mailgun_sender_domain",
        "django_mailgun_api_key",
        "django_default_from_email",
        "django_server_email",
        "django_email_subject_prefix",
        "bootstrap_admin_password",
    )


@pytest.mark.parametrize("scenario", ["first", "converged", "code change"])
def test_secrets_never_recorded(cfg: DjangoSiteConfig, secrets: SecretValues, scenario: str) -> None:
    responses = None if scenario == "first" else converged(cfg, secrets)

    run = deploy(cfg, secrets, responses, rsync=changed() if scenario == "code change" else None)

    text = run.all_text() + repr(run.ops)
    for value in SECRET_ONLY:
        assert value not in text


def test_secrets_ride_on_stdin_only(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets)

    payloads = []
    for command, payload in run.stdin:
        assert all(value not in command for value in SECRET_ONLY)
        try:
            payloads.append(base64.b64decode("".join(payload.split())).decode())
        except ValueError:
            payloads.append(payload)
    joined = "\n".join(payloads)
    assert f"DJANGO_SECRET_KEY='{SECRET_VALUES['django_secret_key']}'" in joined
    assert "BOOTSTRAP_ADMIN_PASSWORD=fixture-bootstrap-password" in joined


@pytest.mark.parametrize(
    ("changes", "match"),
    [
        ({"django_secret_key": "too-short"}, "django_secret_key must have at least 50"),
        ({"bootstrap_admin_password": "CHANGEME-later"}, "bootstrap_admin_password"),
        ({"django_mailgun_api_key": "CHANGEME"}, "django_mailgun_api_key"),
        ({"mailgun_api_url": "https://other.example.org/v3"}, "mailgun_api_url must be the configured value"),
        ({"django_admin_url_path": "/hidden-admin/"}, "django_admin_url_path must not be a refused path"),
        ({"wagtail_admin_url_path": "wagtail-admin"}, "wagtail_admin_url_path must not be a refused path"),
        ({"django_admin_url_path": "/cms/admin/"}, "reserved prefix"),
        ({"wagtail_admin_url_path": "_next"}, "reserved prefix"),
        ({"wagtail_admin_url_path": "static/x"}, "reserved prefix"),
        ({"wagtail_admin_url_path": "fixture-django-admin"}, "must differ"),
        ({"django_admin_url_path": "/"}, "django_admin_url_path must be a URL path"),
        ({"django_admin_url_path": "/a b/"}, "django_admin_url_path must be a URL path"),
        ({"django_server_email": "a@b\nX=1"}, "single line"),
    ],
)
def test_invalid_secrets_fail_before_any_operation(cfg: DjangoSiteConfig, changes: dict[str, str], match: str) -> None:
    with pytest.raises(ValueError, match=match) as excinfo:
        run_deploy_fake(deploy_django_site, cfg, values(cfg, **changes), responses={**fakehost.LINUX})

    for value in changes.values():
        if len(value) > 3:
            assert value not in str(excinfo.value)


def test_missing_secret_keys_fail(cfg: DjangoSiteConfig) -> None:
    assert cfg.secrets is not None
    partial = SecretValues(cfg.secrets, {"django_secret_key": SECRET_VALUES["django_secret_key"]})

    with pytest.raises(MissingSecretKeysError):
        run_deploy_fake(deploy_django_site, cfg, partial, responses={**fakehost.LINUX})


def _front(**changes: Any) -> dict[str, Any]:
    return {"frontend": {"unit": "x-next", "port": 10042, "app_dir": "nextjs", "path_prefixes": ("/cms",), **changes}}


@pytest.mark.parametrize(
    "changes",
    [
        _front(unit="splitsite-django"),
        _front(port=DJANGO_PORT),
        _front(middleware_from="missing.ts"),
        _front(middleware_from="../middleware.ts"),
        _front(purged_public_dirs=("..",)),
        _front(purged_public_dirs=(".",)),
        _front(path_prefixes=("/cms/",)),
        _front(path_prefixes=("/",)),
        _front(path_prefixes=()),
        _front(app_dir=""),
        _front(runtime_env=({"key": "A", "value": "two words"},)),
        _front(build_env=({"key": "A", "value": "$HOME"},)),
        _front(runtime_env=({"key": "A", "value": "~/uploads"},)),
        _front(legacy_guard={"search": ("nextjs/../..",)}),
        _front(router="Cms"),
        _front(router="secure"),
        {"hardening": "loose"},
        {"route": {"fqdn": FQDN, "host_rule": f"Host(`{FQDN}`)", "public_reason": "x", "backend": "0.0.0.0"}},
    ],
)
def test_config_validation(tmp_path: Path, changes: dict[str, Any]) -> None:
    base = split_config(make_source(tmp_path)).model_dump()
    with pytest.raises(ConfigValidationError):
        DjangoSiteConfig.model_validate({**base, **changes})


def test_the_frontend_needs_the_package_files(tmp_path: Path) -> None:
    source = make_source(tmp_path)
    (source / "package-lock.json").unlink()

    with pytest.raises(ConfigValidationError, match=r"package-lock\.json"):
        split_config(source)


# -- the scripts in real shells ----------------------------------------------


@pytest.mark.parametrize("login_shell", LOGIN_SHELLS)
@pytest.mark.parametrize(
    ("planted", "fails"),
    [
        ({}, False),
        # Under node_modules: unrelated dependency internals are ignored.
        ({"nextjs/.next/standalone/node_modules/jose/index.js": "jwtVerify"}, False),
        ({"nextjs/.next/standalone/nextjs/server.js": "jwtVerify(token)"}, True),
        ({"nextjs/app/api/admin/route.ts": "export {}"}, True),
        ({"nextjs/app/page.ts": "cookies.get('admin_session')"}, True),
        # A forbidden token on a line that also names node_modules still counts.
        ({"nextjs/.next/standalone/nextjs/chunk.js": "require('./node_modules/jose');jwtVerify(t)"}, True),
        # Dependencies are not the app: their directories do not count.
        ({"nextjs/.next/standalone/node_modules/x/app/api/admin/index.js": "x"}, False),
        # Tokens are fixed strings: the dot matches only a dot.
        ({"nextjs/app/x.ts": "legacyXauth"}, False),
        ({"nextjs/app/x.ts": "legacy.auth"}, True),
    ],
)
def test_legacy_guard_runs_in_real_shells(
    tmp_path: Path, login_shell: str, planted: dict[str, str], fails: bool
) -> None:
    for name, text in {"nextjs/app/page.tsx": "export default 1", **planted}.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    guard = LegacyGuard(
        tokens=("jwtVerify", "admin_session", "legacy.auth"),
        dirs=("*/app/api/admin",),
        search=("nextjs/.next/standalone", "nextjs/app"),
    )

    result = run_remote(f"cd {tmp_path} && {legacy_guard_script(guard)}", login_shell, os.environ["PATH"])

    assert (result.returncode != 0) == fails, result.stderr
    assert ("Legacy code found" in result.stderr) == fails


@pytest.mark.parametrize("login_shell", LOGIN_SHELLS)
def test_purge_removes_files_and_symlinks(tmp_path: Path, login_shell: str) -> None:
    private = tmp_path / "private"
    private.mkdir()
    (private / "doc.pdf").write_text("private")
    public = tmp_path / "nextjs/public"
    (public / "uploads").mkdir(parents=True)
    (public / "uploads/.gitkeep").write_text("")
    (public / "uploads/a.pdf").write_text("old")
    (public / "uploads/link.pdf").symlink_to(private / "doc.pdf")
    (public / "uploads/nested").mkdir()
    (public / "uploads/nested/.gitkeep").symlink_to(private)
    (public / "linked").symlink_to(private)
    dirs = ["nextjs/public/uploads", "nextjs/public/linked", "nextjs/public/missing"]

    found = run_remote(f"cd {tmp_path} && {purge_script(dirs, '-print -quit')}", login_shell, os.environ["PATH"])
    purged = run_remote(f"cd {tmp_path} && {purge_script(dirs, '-delete')}", login_shell, os.environ["PATH"])
    again = run_remote(f"cd {tmp_path} && {purge_script(dirs, '-print -quit')}", login_shell, os.environ["PATH"])

    assert found.stdout.strip()
    assert purged.returncode == 0, purged.stderr
    assert again.stdout.strip() == ""
    assert sorted(p.name for p in (public / "uploads").iterdir()) == [".gitkeep", "nested"]
    assert list((public / "uploads/nested").iterdir()) == []
    assert not (public / "linked").exists()
    assert not (public / "linked").is_symlink()
    assert (private / "doc.pdf").read_text() == "private"


@pytest.mark.parametrize("login_shell", LOGIN_SHELLS)
@pytest.mark.parametrize(
    ("get", "post", "fails"),
    [
        ('{"csrfToken": "t"}', "400", False),
        ('{"csrfToken": "t"}', "403", True),
        # A broken session endpoint fails even though the POST answers 400.
        ("FAIL", "400", True),
        ("not json", "400", True),
        ('{"csrfToken": ""}', "400", True),
    ],
)
def test_csrf_check_runs_in_real_shells(tmp_path: Path, login_shell: str, get: str, post: str, fails: bool) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    curl = bin_dir / "curl"
    # GET (-c jar): prints ``get`` or fails; POST (--data): prints ``post`` as the status.
    curl.write_text(
        "#!/bin/sh\n"
        'case " $* " in *" --data "*) printf %s "$POST" ;; *) [ "$GET" = FAIL ] && exit 22; echo "$GET" ;; esac\n'
    )
    curl.chmod(0o755)
    command = f"base=https://split.example.com; path=/cms-api/session/; {CSRF_CHECK}"

    result = run_remote(command, login_shell, f"{bin_dir}:{os.environ['PATH']}", GET=get, POST=post)

    assert (result.returncode != 0) == fails, result.stderr


@pytest.mark.parametrize("login_shell", LOGIN_SHELLS)
@pytest.mark.parametrize(
    ("check", "code", "body", "ok"),
    [
        (UrlCheck(path="/"), "200", "x", True),
        (UrlCheck(path="/"), "500", "x", False),
        (UrlCheck(path="/m", status=302, follow=False), "302", "", True),
        (
            UrlCheck(path="/p/", contains=('name="robots"', "noindex")),
            "200",
            '<meta name="robots" content="noindex">',
            True,
        ),
        (UrlCheck(path="/p/", contains=('name="robots"', "noindex")), "200", "<meta>", False),
    ],
)
def test_url_check_runs_in_real_shells(
    tmp_path: Path, login_shell: str, check: UrlCheck, code: str, body: str, ok: bool
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    curl = bin_dir / "curl"
    # Writes $BODY to the -o file and prints $CODE; records whether -L was given.
    curl.write_text(
        "#!/bin/sh\n"
        'out=; prev=; for a in "$@"; do [ "$prev" = -o ] && out=$a; [ "$a" = -L ] && touch "$MARK"; prev=$a; done\n'
        'printf %s "$BODY" > "$out"; printf %s "$CODE"\n'
    )
    curl.chmod(0o755)
    mark = tmp_path / "followed"
    script = url_check_script("https://example.com" + check.path, check.model_copy(update={"delay": 0}))

    result = run_remote(
        f"sh -c {shlex.quote(script)}",
        login_shell,
        f"{bin_dir}:{os.environ['PATH']}",
        BODY=body,
        CODE=code,
        MARK=str(mark),
    )

    assert (result.returncode == 0) == ok, result.stderr
    assert mark.exists() == check.follow


@pytest.mark.parametrize("login_shell", LOGIN_SHELLS)
def test_url_check_refuses_an_incomplete_transfer(tmp_path: Path, login_shell: str) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    curl = bin_dir / "curl"
    # Status 200 and part of the body, then a timeout (curl exits 28).
    curl.write_text(
        "#!/bin/sh\n"
        'out=; prev=; for a in "$@"; do [ "$prev" = -o ] && out=$a; prev=$a; done\n'
        'printf %s noindex > "$out"; printf 200; exit 28\n'
    )
    curl.chmod(0o755)
    script = url_check_script("https://example.com/", UrlCheck(path="/", contains=("noindex",), retries=2, delay=0))

    result = run_remote(f"sh -c {shlex.quote(script)}", login_shell, f"{bin_dir}:{os.environ['PATH']}")

    assert result.returncode != 0


def test_the_home_is_never_a_data_directory(tmp_path: Path) -> None:
    cfg = split_config(make_source(tmp_path), database={"path": f"{HOME}/db.sqlite3"})

    assert str(cfg.db_path) == f"{HOME}/db.sqlite3"
    assert [str(d) for d in cfg.data_dirs] == [f"{DATA}/media", f"{DATA}/private_media"]
    assert [str(d) for d in cfg.outside_dirs] == [HOME, f"{DATA}/media", f"{DATA}/private_media"]


@pytest.mark.parametrize("marker", [".ops-deploy-pending", ".ops-deploy-collectstatic", ".ops-deploy-restart-x"])
def test_markers_an_older_deploy_left_in_the_site_stop_the_deploy(
    cfg: DjangoSiteConfig, secrets: SecretValues, marker: str
) -> None:
    responses = {**converged(cfg, secrets), f"ls -1A {SITE} 2>/dev/null | grep": [marker]}

    with pytest.raises(ValueError, match=f"holds {marker} from an older deploy"):
        run_deploy_fake(deploy_django_site, cfg, secrets, responses=responses)


@pytest.mark.parametrize("in_source", [True, False], ids=["overwrite", "delete"])
@pytest.mark.parametrize(
    "path", ["django/private_media/doc.pdf", "django/.bootstrap-admin-password-applied", "django/views.py"]
)
def test_in_site_private_media_and_bootstrap_marker_survive_the_sync(
    tmp_path: Path, path: str, in_source: bool
) -> None:
    """Private media and the bootstrap marker inside the site: never overwritten or deleted."""

    if not shutil.which("rsync"):
        pytest.skip("no rsync")
    cfg = split_config(
        make_source(tmp_path / "checkout"),
        database={},
        media={"root": f"{SITE}/django/media", "private_root": f"{SITE}/django/private_media"},
    )
    assert str(cfg.bootstrap_marker) == f"{SITE}/django/.bootstrap-admin-password-applied"
    src, dest = tmp_path / "src", tmp_path / "dest"
    src.mkdir()
    (src / "package.json").write_text("{}")
    if in_source:
        (src / path).parent.mkdir(parents=True, exist_ok=True)
        (src / path).write_text("new")
    (dest / path).parent.mkdir(parents=True, exist_ok=True)
    (dest / path).write_text("host")
    excludes = [f"--exclude={pattern}" for pattern in cfg.sync_excludes]
    subprocess.run(["rsync", "-rl", "--checksum", "--delete", *excludes, f"{src}/", f"{dest}/"], check=True)

    if path.endswith("views.py"):
        assert (dest / path).exists() == in_source
    else:
        assert (dest / path).read_text() == "host"


def test_a_database_in_the_home_keeps_the_home_writable(tmp_path: Path) -> None:
    cfg = split_config(make_source(tmp_path), database={"path": f"{HOME}/db.sqlite3"})

    assert f"\nReadWritePaths={SITE} {SITE}/cache {HOME}\n" in render("unit.service.j2", cfg)


@pytest.mark.parametrize("login_shell", LOGIN_SHELLS)
def test_purge_refuses_a_symlinked_parent(tmp_path: Path, login_shell: str) -> None:
    private = tmp_path / "private"
    (private / "uploads").mkdir(parents=True)
    (private / "uploads/doc.pdf").write_text("private")
    (tmp_path / "nextjs").mkdir()
    (tmp_path / "nextjs/public").symlink_to(private)
    dirs = ["nextjs/public/uploads"]

    found = run_remote(f"cd {tmp_path} && {purge_script(dirs, '-print -quit')}", login_shell, os.environ["PATH"])
    purged = run_remote(f"cd {tmp_path} && {purge_script(dirs, '-delete')}", login_shell, os.environ["PATH"])

    assert found.stdout.strip() == "nextjs/public/uploads"
    assert purged.returncode != 0
    assert "a parent directory is a symlink" in purged.stderr
    assert (private / "uploads/doc.pdf").read_text() == "private"


def test_the_frontends_https_router_follows_the_tls_rule(cfg: DjangoSiteConfig) -> None:
    tls = f"Host(`{FQDN}`) || Host(`alias.example.com`)"
    site = cfg.model_copy(update={"route": cfg.route.model_copy(update={"tls_host_rule": tls})})

    routers = yaml.safe_load(render("route.traefik.yml.j2", site))["http"]["routers"]

    assert routers[f"{FQDN}-cms-router"]["rule"].startswith(f"Host(`{FQDN}`) && (Path(`/cms`)")
    assert routers[f"{FQDN}-cms-secure-router"]["rule"].startswith(f"({tls}) && (Path(`/cms`)")
    assert routers[f"{FQDN}-secure-router"]["rule"] == tls


@pytest.mark.parametrize("public", [True, False], ids=["public", "no public"])
def test_the_build_copies_public_only_when_the_app_has_one(
    tmp_path: Path, cfg: DjangoSiteConfig, secrets: SecretValues, public: bool
) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets, **{f"{BUILD_STAMP} 2>/dev/null": []}))
    build = next(c for c in run.executed_commands if "npm ci" in c)
    script = shlex.split(build.split(" sh -c ", 1)[1])[0]
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    # npm run build makes the standalone output, as next build does.
    (bin_dir / "npm").write_text(
        '#!/bin/sh\n[ "$1" = run ] && mkdir -p nextjs/.next/static nextjs/.next/standalone/nextjs/.next\nexit 0\n'
    )
    (bin_dir / "npm").chmod(0o755)
    site = tmp_path / "site"
    site.mkdir()
    if public:
        (site / "nextjs/public").mkdir(parents=True)
        (site / "nextjs/public/a.css").write_text("x")

    # Straight to sh: a login shell's config may put the real npm first on PATH.
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}
    result = subprocess.run(["sh", "-c", script], cwd=site, env=env, capture_output=True, text=True, check=False)

    assert result.returncode == 0, result.stderr
    assert (site / "nextjs/.next/standalone/nextjs/public/a.css").exists() == public
    assert (site / BUILD_STAMP).read_text().strip() == STAMP


def test_a_middleware_owner_repair_is_no_source_change(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    middleware = f"{SITE}/nextjs/middleware.ts"
    responses = {
        **converged(cfg, secrets),
        **fakehost.stat(middleware, user="splitsite", group="root", mode="-rw-r--r--"),
    }

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [f"{V}Install nextjs/middleware.prod.ts as nextjs/middleware.ts"]
