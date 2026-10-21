"""Deploy-level scenarios for django_site against the fake connector (marina's shape)."""

from __future__ import annotations

import base64
import shutil
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from ops_deploy.core import ConfigValidationError, SecretValues
from ops_deploy.core.secrets import MissingSecretKeysError
from ops_deploy.services.django_site import (
    DjangoSiteConfig,
    EnvEntry,
    EnvSpec,
    ManageStep,
    Route,
    Secret,
    StepGroup,
    Steps,
    deploy_django_site,
)
from ops_deploy.services.django_site.render import MANAGED, render, render_env
from ops_deploy.testing import FakeRun, RecordingRsyncRunner, run_deploy_fake
from tests import fakehost
from tests.django_site_fixtures import (
    ENV,
    FQDN,
    HOME,
    LAUNCHER,
    ROUTE,
    SECRET_VALUES,
    SITE,
    UNIT,
    converged,
    site_config,
    values,
)
from tests.marina_fixtures import make_source

ITEMIZED_CHANGE = [">f.st...... apps/marina/views.py"]
STATE = "/var/lib/ops-deploy/marina"
PENDING = f"{STATE}/.ops-deploy-pending"
RESTART = f"{STATE}/.ops-deploy-restart-marina"
CLEAR = f"rm -f {PENDING} {RESTART}"
MARKERS_LEFT = "grep -x -e .ops-deploy-pending"


def touch(path: str) -> str:
    """The marker command: the root-only state directory, then the marker."""

    return f"install -d -o root -g root -m 0700 {STATE} && touch {path}"


READ_ONLY = [
    "Deploy marina | Verify marina certifi/pip trust",
    "Deploy marina | Wait for port 127.0.0.1:10019",
    "Deploy marina | Check http://127.0.0.1:10019/",
]


@pytest.fixture
def cfg(tmp_path: Path) -> DjangoSiteConfig:
    return site_config(make_source(tmp_path))


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
    return run


def changed() -> RecordingRsyncRunner:
    return RecordingRsyncRunner(responses={"--dry-run": ITEMIZED_CHANGE})


# -- the canonical file set ------------------------------------------------


def test_env_is_single_quoted_after_a_header(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    assert render_env(cfg, secrets).reveal().decode() == (
        f"# {MANAGED}\n"
        "DJANGO_SETTINGS_MODULE='config.settings.production'\n"
        f"DJANGO_SECRET_KEY='{SECRET_VALUES['django_secret_key']}'\n"
        "DJANGO_ADMIN_URL='marina_admin/'\n"
        f"DJANGO_ALLOWED_HOSTS='{FQDN},localhost'\n"
        f"DJANGO_CACHE_LOCATION='{SITE}/cache'\n"
    )


def test_env_extra_entries_follow_in_order(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    extra = (EnvEntry(key="B_LITERAL", value="x y"), EnvEntry(key="A_SECRET", value=Secret(secret="admin_email")))
    site = cfg.model_copy(update={"env": EnvSpec(admin_url="marina_admin/", extra=extra)})

    lines = render_env(site, secrets).reveal().decode().splitlines()

    assert lines[-2:] == ["B_LITERAL='x y'", f"A_SECRET='{SECRET_VALUES['admin_email']}'"]


def test_launcher_sources_env_and_execs_gunicorn(cfg: DjangoSiteConfig) -> None:
    launcher = render("gunicorn.sh.j2", cfg)

    assert launcher.startswith(f"#!/bin/bash\n# {MANAGED}\nset -euo pipefail\nset -a; . {SITE}/.env; set +a\n")
    assert f"\ncd {SITE}\nexec {SITE}/.venv/bin/gunicorn \\\n" in launcher
    for arg in ("-w 4", "-t 3600", "-b 127.0.0.1:10019", "--access-logfile -", "--error-logfile -"):
        assert f"  {arg} \\\n" in launcher
    assert launcher.endswith("  config.wsgi\n")


def test_unit_runs_the_launcher_with_a_restart_delay(cfg: DjangoSiteConfig) -> None:
    unit = render("unit.service.j2", cfg)

    for line in (
        "Description=Marina web application",
        "User=marina",
        "Group=marina",
        f"WorkingDirectory={SITE}",
        f"ExecStart={SITE}/gunicorn.sh",
        "Restart=always",
        "RestartSec=5",
        "WantedBy=multi-user.target",
    ):
        assert f"\n{line}\n" in unit
    assert "Environment" not in unit
    assert "ProtectSystem" not in unit


def test_hardening_adds_the_sandbox_with_the_writable_paths(cfg: DjangoSiteConfig) -> None:
    unit = render("unit.service.j2", cfg.model_copy(update={"hardening": True}))

    assert "\nProtectSystem=strict\n" in unit
    assert f"\nReadWritePaths={SITE} {SITE}/cache\n" in unit


def test_route_keeps_the_router_service_and_middleware_names(cfg: DjangoSiteConfig) -> None:
    route = render("route.traefik.yml.j2", cfg)

    assert route.startswith(f"# {MANAGED}\n# Public website, no Basic Auth: Public portfolio website\nhttp:\n")
    for name in (f"{FQDN}-router:", f"{FQDN}-secure-router:", "redirect:", "csrf:", "sslHeaders:", "gzip-compress:"):
        assert f"    {name}\n" in route
    assert "certResolver: letsencrypt" in route
    assert "url: http://localhost:10019\n" in route


def test_route_tls_rule_defaults_to_the_host_rule(cfg: DjangoSiteConfig) -> None:
    tls = cfg.model_copy(update={"route": cfg.route.model_copy(update={"tls_host_rule": f"Host(`{FQDN}`)"})})

    assert render("route.traefik.yml.j2", cfg).count(cfg.route.host_rule) == 2
    assert f'rule: "Host(`{FQDN}`)"\n' in render("route.traefik.yml.j2", tls)


# -- deploy scenarios ------------------------------------------------------


def test_first_run_installs_everything_and_clears_its_markers(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, rsync=changed())

    commands = run.executed_commands
    assert "useradd -d /home/marina -s /usr/bin/fish -g marina -r -M marina" in commands
    sync = next(c for c in commands if "uv sync" in c)
    migrate = next(c for c in commands if "manage.py migrate" in c)
    assert commands.index(touch(PENDING)) < commands.index(sync) < commands.index(migrate)
    env_install = next(c for c in commands if " .env " in c)
    assert commands.index(touch(RESTART)) < commands.index(env_install)
    assert commands[-1] == CLEAR
    assert "systemctl restart marina.service" not in commands
    assert not any(path.endswith(".env") for path in run.uploaded_paths)
    assert [op.name for op in run.ops if op.read_only] == READ_ONLY
    assert run.upload(ROUTE).decode() == render("route.traefik.yml.j2", cfg)


def test_second_run_changes_nothing_mutating(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == []
    assert run.changed_ops == READ_ONLY
    assert run.uploads == []
    assert run.stdin == []
    assert not any(c.startswith(("systemctl", "cd ", "find ", "chown", "touch", "rm ")) for c in run.executed_commands)


def test_code_change_marks_pending_before_the_sync(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets), rsync=changed())

    assert run.mutating_changed_ops == [
        "Deploy marina | Mark the marina source change pending",
        "Deploy marina | Sync marina source",
        "Deploy marina | uv sync /home/marina/site",
        "Deploy marina | Run marina migrations",
        "Deploy marina | Collect static files",
        "Deploy marina | Restart marina.service",
        "Deploy marina | Clear the pending markers",
    ]
    assert run.executed_commands[-1] == CLEAR


def test_a_leftover_pending_marker_finishes_the_source_steps(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    # An earlier run synced new code and failed before collectstatic and the restart.
    responses = {**converged(cfg, secrets), MARKERS_LEFT: [".ops-deploy-pending"]}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [
        "Deploy marina | Mark the marina source change pending",
        "Deploy marina | uv sync /home/marina/site",
        "Deploy marina | Run marina migrations",
        "Deploy marina | Collect static files",
        "Deploy marina | Restart marina.service",
        "Deploy marina | Clear the pending markers",
    ]


def test_a_leftover_restart_marker_reloads_and_restarts(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    # An earlier run wrote a new unit or .env and failed before the restart.
    responses = {**converged(cfg, secrets), MARKERS_LEFT: [".ops-deploy-restart-marina"]}

    run = deploy(cfg, secrets, responses)

    assert run.mutating_changed_ops == [
        "Deploy marina | Mark marina for a restart",
        "Deploy marina | Reload systemd for marina.service",
        "Deploy marina | Restart marina.service",
        "Deploy marina | Clear the pending markers",
    ]


def test_a_failed_run_keeps_its_markers(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    responses = {**converged(cfg, secrets), "curl -sS": {"success": False}}

    run = deploy(cfg, values(cfg, django_secret_key="rotated-fixture-django-key-0123456789"), responses, succeed=False)

    assert not run.succeeded
    assert touch(RESTART) in run.executed_commands
    assert CLEAR not in run.executed_commands


def test_env_change_restarts_once(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, values(cfg, django_secret_key="rotated-fixture-django-key-0123456789"), converged(cfg, secrets))

    assert run.mutating_changed_ops == [
        "Deploy marina | Mark marina for a restart",
        "Deploy marina | Write .env",
        "Deploy marina | Ensure marina admin user",
        "Deploy marina | Record marina admin user",
        "Deploy marina | Restart marina.service",
        "Deploy marina | Clear the pending markers",
    ]
    assert "rotated-fixture-django-key" not in run.all_text()


def test_switching_from_the_old_files_rewrites_them_and_restarts_once(
    cfg: DjangoSiteConfig, secrets: SecretValues
) -> None:
    """A host with marina's old files: the documented rewrites, one restart, nothing else."""

    old = {
        ENV: "DJANGO_SETTINGS_MODULE=config.settings.production\n",
        LAUNCHER: "#!/bin/bash\n",
        f"{HOME}/.config/fish/config.fish": "alias bat=batcat\n",
        UNIT: "[Unit]\nDescription=Marina web application\n",
        ROUTE: "http:\n",
    }

    run = deploy(cfg, secrets, converged(cfg, secrets, **old))
    again = deploy(cfg, secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == [
        "Deploy marina | Write fish config",
        "Deploy marina | Mark marina for a restart",
        "Deploy marina | Write .env",
        "Deploy marina | Write gunicorn.sh",
        "Deploy marina | Install systemd unit marina.service",
        "Deploy marina | Reload systemd for marina.service",
        "Deploy marina | Restart marina.service",
        "Deploy marina | Write Traefik route marina",
        "Deploy marina | Clear the pending markers",
    ]
    assert run.executed_commands.count("systemctl restart marina.service") == 1
    assert again.mutating_changed_ops == []


def test_collectstatic_can_restart(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    site = cfg.model_copy(update={"steps": Steps(restart_after_collectstatic=True)})
    responses = {**converged(cfg, secrets), "staticfiles.json": []}

    plain = deploy(cfg, secrets, responses)
    restarting = deploy(site, secrets, responses)

    assert plain.mutating_changed_ops == ["Deploy marina | Collect static files"]
    assert restarting.mutating_changed_ops == [
        "Deploy marina | Collect static files",
        "Deploy marina | Restart marina.service",
        "Deploy marina | Clear the pending markers",
    ]
    # The restart is owed from before the files change: a failure after it leaves the marker.
    collect = next(c for c in restarting.executed_commands if "collectstatic" in c)
    assert collect.startswith(f"{touch(RESTART)} && ")


def test_a_failure_after_a_restarting_collectstatic_keeps_the_restart_owed(
    cfg: DjangoSiteConfig, secrets: SecretValues
) -> None:
    group = StepGroup(name="fails", steps=(ManageStep(name="Fail", argv=("fail",)),), when="always")
    site = cfg.model_copy(update={"steps": Steps(restart_after_collectstatic=True, extra=(group,))})
    responses = {**converged(cfg, secrets), "staticfiles.json": [], "manage.py fail": {"success": False}}

    run = deploy(site, secrets, responses, succeed=False)

    assert any(c.startswith(f"{touch(RESTART)} && ") for c in run.executed_commands)
    assert CLEAR not in run.executed_commands
    assert "systemctl restart marina.service" not in run.executed_commands


def test_without_fish_there_is_no_fish_config_or_venv_link(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    run = deploy(cfg.model_copy(update={"fish": False, "shell": "/bin/bash"}), secrets, rsync=changed())

    assert not any("fish" in path for path in run.uploaded_paths)
    assert not any("ln -s" in c for c in run.executed_commands)
    assert "useradd -d /home/marina -s /bin/bash -g marina -r -M marina" in run.executed_commands


# -- step groups -----------------------------------------------------------

GROUP = StepGroup(
    name="content reconcilers",
    steps=(
        ManageStep(name="Seed home content", argv=("seed_home_content",)),
        ManageStep(name="Seed subpages", argv=("seed_subpages_content", "--quiet")),
    ),
    marker=".ops-deploy-content-pending",
)
CONTENT = f"{STATE}/.ops-deploy-content-pending"
GROUP_OPS = [
    "Deploy marina | Mark content reconcilers pending",
    "Deploy marina | Seed home content",
    "Deploy marina | Seed subpages",
    "Deploy marina | Clear content reconcilers marker",
]


def with_group(cfg: DjangoSiteConfig, group: StepGroup = GROUP) -> DjangoSiteConfig:
    return cfg.model_copy(update={"steps": Steps(extra=(group,))})


def test_a_step_group_runs_after_a_code_change(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    run = deploy(with_group(cfg), secrets, converged(cfg, secrets), rsync=changed())

    ops = run.mutating_changed_ops
    assert ops[
        ops.index("Deploy marina | Collect static files") + 1 : ops.index("Deploy marina | Restart marina.service")
    ] == (GROUP_OPS)
    assert any(c.endswith("manage.py seed_subpages_content --quiet'") for c in run.executed_commands)
    assert run.executed_commands.index(touch(CONTENT)) < run.executed_commands.index(f"rm -f {CONTENT}")


def test_a_step_group_is_skipped_when_nothing_triggers_it(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    run = deploy(with_group(cfg), secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == []


@pytest.mark.parametrize(
    ("facts", "triggers", "runs"),
    [
        ({"migrate --check": []}, frozenset({"migrate"}), True),
        ({"migrate --check": []}, frozenset({"source"}), False),
        ({"--python 3.13 --dry-run": []}, frozenset({"deps"}), True),
        ({CONTENT: ["pending"]}, frozenset({"source"}), True),
    ],
    ids=["migrate", "not on migrate", "deps", "leftover marker"],
)
def test_a_step_group_follows_its_triggers_and_marker(
    cfg: DjangoSiteConfig, secrets: SecretValues, facts: dict[str, Any], triggers: frozenset[str], runs: bool
) -> None:
    group = GROUP.model_copy(update={"triggers": triggers})

    run = deploy(with_group(cfg, group), secrets, {**converged(cfg, secrets), **facts})

    assert (GROUP_OPS[1] in run.mutating_changed_ops) is runs


def test_an_always_group_runs_on_a_converged_host(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    group = StepGroup(
        name="index", steps=(ManageStep(name="Update the search index", argv=("update_index",)),), when="always"
    )

    run = deploy(with_group(cfg, group), secrets, converged(cfg, secrets))

    assert run.mutating_changed_ops == ["Deploy marina | Update the search index"]


# -- secrets and validation ------------------------------------------------


def test_required_secret_keys_follow_the_config(cfg: DjangoSiteConfig) -> None:
    assert cfg.required_secret_keys == ("django_secret_key", "admin_username", "admin_email", "admin_password")
    extra = EnvSpec(admin_url=Secret(secret="django_admin_url"))
    assert cfg.model_copy(update={"admin": None, "env": extra}).required_secret_keys == (
        "django_secret_key",
        "django_admin_url",
    )


@pytest.mark.parametrize("scenario", ["first", "converged", "rotated"])
def test_secrets_never_recorded(cfg: DjangoSiteConfig, secrets: SecretValues, scenario: str) -> None:
    responses = None if scenario == "first" else converged(cfg, secrets)
    used = values(cfg, django_secret_key="rotated-fixture-django-key-0123456789") if scenario == "rotated" else secrets

    run = deploy(cfg, used, responses)

    text = run.all_text() + repr(run.ops)
    for value in (*SECRET_VALUES.values(), "rotated-fixture-django-key"):
        assert value not in text


def test_secrets_ride_on_stdin_only(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets)

    payloads = []
    for command, payload in run.stdin:
        assert all(value not in command for value in SECRET_VALUES.values())
        try:
            payloads.append(base64.b64decode("".join(payload.split())).decode())
        except ValueError:
            payloads.append(payload)
    joined = "\n".join(payloads)
    assert f"DJANGO_SECRET_KEY='{SECRET_VALUES['django_secret_key']}'" in joined
    assert "ADMIN_PASSWORD=marina-fixture-admin-pw" in joined


@pytest.mark.parametrize(
    ("changes", "match"),
    [
        ({"django_secret_key": "CHANGEME"}, "secret django_secret_key must be set"),
        ({"django_secret_key": "it's"}, "secret django_secret_key for DJANGO_SECRET_KEY contains a single quote"),
        ({"django_secret_key": "$OTHER"}, "starts with \\$"),
        ({"django_secret_key": '"quoted"'}, "wrapped in double quotes"),
        ({"django_secret_key": "a${HOME}b"}, "contains \\$\\{"),
        ({"django_secret_key": "a\\\\b"}, "double backslash"),
        ({"django_secret_key": "ab\\"}, "ends with a backslash"),
        ({"admin_email": "a@b\nX=1"}, "secret admin_email must be a single line"),
    ],
)
def test_invalid_secrets_fail_before_any_operation(cfg: DjangoSiteConfig, changes: dict[str, str], match: str) -> None:
    with pytest.raises(ValueError, match=match) as excinfo:
        run_deploy_fake(deploy_django_site, cfg, values(cfg, **changes), responses={**fakehost.LINUX})
    assert "marina-fixture" not in str(excinfo.value)


def test_secrets_with_shell_characters_are_carried_as_they_are(cfg: DjangoSiteConfig) -> None:
    key = 'k$y with space; `x` \\ "q"'

    env = render_env(cfg, values(cfg, django_secret_key=key)).reveal().decode()

    assert f"DJANGO_SECRET_KEY='{key}'\n" in env


@pytest.mark.parametrize("key", ["admin_username", "admin_email", "admin_password"])
def test_admin_secrets_are_required(cfg: DjangoSiteConfig, key: str) -> None:
    with pytest.raises(MissingSecretKeysError, match=key):
        run_deploy_fake(deploy_django_site, cfg, values(cfg, **{key: ""}), responses={**fakehost.LINUX})


def test_source_must_have_the_required_files(tmp_path: Path) -> None:
    with pytest.raises(ConfigValidationError, match="not a marina checkout"):
        site_config(tmp_path)


@pytest.mark.parametrize(
    "changes",
    [
        {"route": {"fqdn": FQDN, "host_rule": f"Host(`{FQDN}`)"}},
        {"route": {"fqdn": FQDN, "host_rule": 'Host("a.b")', "public_reason": "x"}},
        {"route": {"fqdn": FQDN, "host_rule": f"Host(`{FQDN}`)", "public_reason": "line\nbreak"}},
        {"env": {"extra": [{"key": "DJANGO_SECRET_KEY", "value": "x"}]}},
        {"env": {"extra": [{"key": "A", "value": "1"}, {"key": "A", "value": "2"}]}},
        {"env": {"extra": [{"key": "A", "value": "it's"}]}},
        {"env": {"extra": [{"key": "lower", "value": "x"}]}},
        {"site_path": "/home/marina/my site"},
        {"home": "/home/../etc"},
        {"unit": "Marina.service"},
        {"steps": {"extra": [{"name": "g", "steps": [{"name": "s", "argv": ["x"]}], "marker": ".ops-deploy-pending"}]}},
        {
            "steps": {
                "extra": [{"name": "g", "steps": [{"name": "s", "argv": ["x"]}], "marker": ".ops-deploy-restart-x"}]
            }
        },
        {"title": "Marina\nExecStart=/bin/sh"},
    ],
)
def test_config_validation(tmp_path: Path, changes: dict[str, Any]) -> None:
    source = make_source(tmp_path)
    base = site_config(source).model_dump()
    with pytest.raises(ConfigValidationError):
        DjangoSiteConfig.model_validate({**base, **changes})


def test_route_needs_a_public_reason() -> None:
    with pytest.raises(ValueError, match="public_reason"):
        Route.model_validate({"fqdn": FQDN, "host_rule": f"Host(`{FQDN}`)"})


def test_the_sync_never_touches_what_the_host_writes(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    bare = cfg.model_copy(update={"source": cfg.source.model_copy(update={"excludes": (), "delete": True})})
    rsync = changed()

    deploy(bare, secrets, converged(cfg, secrets), rsync=rsync)

    real = next(call for call in rsync.calls if "--dry-run" not in call)
    assert "--delete" in real
    for pattern in ("/.env", "/cache", "/staticfiles", "/db.sqlite3*", "/media"):
        assert f"--exclude={pattern}" in real


HOST_FILES = ["db.sqlite3", "db.sqlite3-wal", "db.sqlite3-shm", "db.sqlite3-journal", "media/a.jpg", ".env", "cache/x"]


@pytest.mark.parametrize("in_source", [True, False], ids=["overwrite", "delete"])
@pytest.mark.parametrize("path", [*HOST_FILES, "staticfiles/staticfiles.json", "apps/db.sqlite3", "apps/views.py"])
def test_rsync_keeps_the_host_files(tmp_path: Path, cfg: DjangoSiteConfig, path: str, in_source: bool) -> None:
    """Real rsync with no source excludes and --delete: the host's own files are neither overwritten nor deleted."""

    if not shutil.which("rsync"):
        pytest.skip("no rsync")
    bare = cfg.model_copy(update={"source": cfg.source.model_copy(update={"excludes": ()})})
    src, dest = tmp_path / "src", tmp_path / "dest"
    src.mkdir()
    (src / "manage.py").write_text("new")
    if in_source:
        (src / path).parent.mkdir(parents=True, exist_ok=True)
        (src / path).write_text("new")
    (dest / path).parent.mkdir(parents=True, exist_ok=True)
    (dest / path).write_text("host")
    excludes = [f"--exclude={pattern}" for pattern in bare.sync_excludes]
    subprocess.run(["rsync", "-rl", "--checksum", "--delete", *excludes, f"{src}/", f"{dest}/"], check=True)

    kept = path in HOST_FILES or path.startswith("staticfiles/")
    if kept:
        assert (dest / path).read_text() == "host"
    elif in_source:
        assert (dest / path).read_text() == "new"
    else:
        assert not (dest / path).exists()


def test_prerequisites_are_installed_before_the_user(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    run = deploy(cfg.model_copy(update={"apt_packages": ("fish", "sqlite3")}), secrets, rsync=changed())

    commands = run.executed_commands
    install = next(c for c in commands if "apt-get" in c and "install" in c)
    assert "fish" in install
    assert "sqlite3" in install
    assert commands.index(install) < commands.index("useradd -d /home/marina -s /usr/bin/fish -g marina -r -M marina")
    assert run.ops[0].name == "Deploy marina | Install marina prerequisites"


def test_a_group_after_migrate_runs_before_collectstatic(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    early = GROUP.model_copy(update={"after": "migrate"})

    run = deploy(with_group(cfg, early), secrets, converged(cfg, secrets), rsync=changed())

    ops = run.mutating_changed_ops
    start = ops.index("Deploy marina | Run marina migrations")
    assert ops[start + 1 : start + 1 + len(GROUP_OPS)] == GROUP_OPS
    assert ops[start + 1 + len(GROUP_OPS)] == "Deploy marina | Collect static files"


def test_the_canonical_redirect_is_rendered_only_when_set(cfg: DjangoSiteConfig) -> None:
    route = cfg.route.model_copy(
        update={
            "canonical_redirect_regex": r"^https?://www\.a\.example(.*)$",
            "canonical_redirect_replacement": "https://a.example${1}",
        }
    )
    text = render("route.traefik.yml.j2", cfg.model_copy(update={"route": route}))

    assert "        - redirect-canonical-host\n        - redirect-www\n" in text
    assert "        regex: '^https?://www\\.a\\.example(.*)$'\n" in text
    assert "        replacement: 'https://a.example${1}'\n        permanent: true\n" in text
    assert "redirect-canonical-host" not in render("route.traefik.yml.j2", cfg)


@pytest.mark.parametrize(
    "redirect",
    [
        {"canonical_redirect_regex": "^x$"},
        {"canonical_redirect_replacement": "https://x"},
        {"canonical_redirect_regex": "it's", "canonical_redirect_replacement": "x"},
    ],
)
def test_the_canonical_redirect_is_validated(redirect: dict[str, str]) -> None:
    with pytest.raises(ValueError, match="canonical_redirect"):
        Route.model_validate({"fqdn": FQDN, "host_rule": f"Host(`{FQDN}`)", "public_reason": "x", **redirect})


# -- the service group as primary group -------------------------------------

REGROUP = f"{STATE}/.ops-deploy-regroup"
CHGRP = f"find {HOME} -xdev -user marina -group users -exec chgrp -h marina {{}} +"
GROUP_FIX = [
    "Deploy marina | Mark marina for a restart",
    "Deploy marina | Make marina the primary group of marina",
    "Deploy marina | Move marina's files from group users to marina",
    "Deploy marina | Restart marina.service",
    "Deploy marina | Clear the pending markers",
]


def wrong_group(cfg: DjangoSiteConfig, secrets: SecretValues, **extra: Any) -> dict[str, Any]:
    # A user an older deploy created with the group ``users``.
    return {**converged(cfg, secrets), "id -gn marina": ["users", HOME], **extra}


def test_another_primary_group_is_fixed_with_the_one_restart(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, wrong_group(cfg, secrets))

    assert run.mutating_changed_ops == GROUP_FIX
    commands = run.executed_commands
    order = [f"{touch(REGROUP)} && echo users > {REGROUP}", "usermod -g marina marina", CHGRP, f"rm -f {REGROUP}"]
    assert [commands.index(c) for c in order] == sorted(commands.index(c) for c in order)
    assert commands.index(f"rm -f {REGROUP}") < commands.index("systemctl restart marina.service")
    assert commands.count("systemctl restart marina.service") == 1


def test_the_group_fix_folds_into_the_switch_restart(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    responses = {**wrong_group(cfg, secrets), **fakehost.file(UNIT, "[Unit]\n")}

    run = deploy(cfg, secrets, responses)

    assert run.executed_commands.count("systemctl restart marina.service") == 1
    assert "Deploy marina | Make marina the primary group of marina" in run.mutating_changed_ops


def test_the_right_primary_group_changes_nothing(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, {**converged(cfg, secrets), "id -gn marina": ["marina", HOME]})

    assert run.mutating_changed_ops == []
    assert not any("usermod" in c or "chgrp" in c for c in run.executed_commands)


def test_a_failed_move_is_finished_by_the_next_run(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    failed = deploy(cfg, secrets, wrong_group(cfg, secrets, **{"-exec chgrp": {"success": False}}), succeed=False)
    # The old group is recorded before usermod and kept when the move fails.
    assert f"{touch(REGROUP)} && echo users > {REGROUP}" in failed.executed_commands
    assert f"rm -f {REGROUP}" not in failed.executed_commands

    again = deploy(cfg, secrets, {**converged(cfg, secrets), "id -gn marina": ["marina", HOME], REGROUP: ["users"]})

    assert again.mutating_changed_ops == [
        "Deploy marina | Mark marina for a restart",
        "Deploy marina | Move marina's files from group users to marina",
        "Deploy marina | Restart marina.service",
        "Deploy marina | Clear the pending markers",
    ]
    assert CHGRP in again.executed_commands
    assert not any("usermod" in c for c in again.executed_commands)


def test_a_site_outside_the_home_is_searched_too(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    outside = cfg.model_copy(update={"site_path": PurePosixPath("/srv/marina")})

    run = deploy(outside, secrets, {**fakehost.LINUX, "id -gn marina": ["users", HOME]})

    assert "find /home/marina /srv/marina -xdev -user marina -group users -exec chgrp -h marina {} +" in (
        run.executed_commands
    )


@pytest.mark.parametrize(
    ("fact", "found", "match"),
    [
        ("! -user marina -print -quit", [f"{HOME}/site/root-owned"], "files of other owners"),
        ("/proc/mounts", [f"{HOME}/data"], "files on other mounts"),
    ],
)
def test_usermod_side_effects_stop_the_deploy(
    cfg: DjangoSiteConfig, secrets: SecretValues, fact: str, found: list[str], match: str
) -> None:
    with pytest.raises(ValueError, match=match):
        run_deploy_fake(deploy_django_site, cfg, secrets, responses=wrong_group(cfg, secrets, **{fact: found}))


def test_an_unexpected_group_name_fails_while_planning(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    with pytest.raises(ValueError, match="primary group has an unexpected name"):
        run_deploy_fake(
            deploy_django_site, cfg, secrets, responses={**fakehost.LINUX, "id -gn marina": ["bad;name", HOME]}
        )


def test_another_passwd_home_stops_the_group_fix(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    # usermod would move files in the home passwd records, not the one the config names.
    responses = {**converged(cfg, secrets), "id -gn marina": ["users", "/srv/elsewhere"]}

    with pytest.raises(ValueError, match="home in passwd is not /home/marina"):
        run_deploy_fake(deploy_django_site, cfg, secrets, responses=responses)


def test_markers_live_in_a_root_only_directory(cfg: DjangoSiteConfig, secrets: SecretValues) -> None:
    run = deploy(cfg, secrets, converged(cfg, secrets), rsync=changed())

    marks = [c for c in run.executed_commands if "/var/lib/ops-deploy/marina" in c]
    assert marks == [touch(PENDING), CLEAR]
    assert not any(f"{HOME}/.ops-deploy-pending" in c for c in run.all_text().splitlines())


@pytest.mark.parametrize("fish", [False, True])
def test_rsync_preserves_existing_venv_alias_and_ignores_ruff_caches(
    tmp_path: Path, cfg: DjangoSiteConfig, fish: bool
) -> None:
    """The frozen Wagtail origin leaves a venv alias even without fish."""
    if not shutil.which("rsync"):
        pytest.skip("no rsync")
    bare = cfg.model_copy(update={"fish": fish, "source": cfg.source.model_copy(update={"excludes": (".venv",)})})
    src, dest = tmp_path / "sync-src", tmp_path / "sync-dest"
    src.mkdir()
    (dest / ".venv").mkdir(parents=True)
    (dest / ".venv/sentinel").write_text("existing environment")
    (dest / "venv").symlink_to(".venv", target_is_directory=True)
    for relative in (".ruff_cache", "nested/.ruff_cache"):
        directory = src / relative
        directory.mkdir(parents=True)
        (directory / "cache-entry").write_text("developer cache")
    excludes = [f"--exclude={pattern}" for pattern in bare.sync_excludes]
    subprocess.run(["rsync", "-rl", "--checksum", "--delete", *excludes, f"{src}/", f"{dest}/"], check=True)
    assert (dest / "venv").is_symlink()
    assert (dest / "venv/sentinel").read_text() == "existing environment"
    assert not (dest / ".ruff_cache").exists()
    assert not (dest / "nested/.ruff_cache").exists()
