"""``manage.py`` as the service runs it, the read-only probes, and the admin account.

Commands run as the service user through ``sh`` with ``.env`` loaded, like the
Ansible roles' ``set -a; . .env; set +a``. Secrets never reach a command line:
``.env`` is read on the host, and the admin account's values travel on stdin.
"""

from __future__ import annotations

import hashlib
import hmac
import shlex
from pathlib import PurePosixPath

from pyinfra import host
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.server import Command
from pyinfra.operations import server

from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers.probes import migrations_state, probe, verify_probe, when_present
from ops_deploy.helpers.python import DEFAULT_UV, _as_user
from ops_deploy.ops import secret_file, secret_stdin
from ops_deploy.services.django_site.config import BootstrapSuperuser, DjangoSiteConfig, EnsureSuperuser, SqliteDb
from ops_deploy.services.django_site.render import resolve

# Records which admin account was last ensured (an HMAC, never the password).
ADMIN_STAMP = ".ops-deploy-admin"

# Admin account probe (stdlib only, no secrets in it): one digest per row for
# "active staff superuser" and one for "has this email", so user names and
# addresses never reach the controller's output.
ADMIN_PROBE = """\
import hashlib, sqlite3, sys
db = sqlite3.connect("file:" + sys.argv[1] + "?mode=ro", uri=True)
try:
    rows = db.execute("select username, email, is_staff, is_superuser, is_active from auth_user").fetchall()
except sqlite3.OperationalError as exc:
    # Not migrated yet: no accounts. Any other database error fails the probe.
    if "no such table" not in str(exc):
        raise
    rows = []
digest = lambda *parts: hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()
for username, email, staff, superuser, active in rows:
    print("A", digest(username, staff, superuser, active))
    print("B", digest(username, email))
"""

# ``createsuperuser`` probe (stdlib only): does the bootstrap account exist?
BOOTSTRAP_PROBE = """\
import sqlite3, sys
db = sqlite3.connect("file:" + sys.argv[1] + "?mode=ro", uri=True)
try:
    found = db.execute("select count(*) from auth_user where username = ?", (sys.argv[2],)).fetchone()[0]
except sqlite3.OperationalError as exc:
    # Not migrated yet: no accounts. Any other database error fails the probe.
    if "no such table" not in str(exc):
        raise
    found = 0
print("present" if found else "absent")
"""
# Creates or updates the bootstrap superuser from the environment, one line.
SET_BOOTSTRAP_PASSWORD = (
    "import os; from django.contrib.auth import get_user_model; U = get_user_model(); "
    "u, _ = U.objects.get_or_create(username=os.environ['BOOTSTRAP_ADMIN_USERNAME'], "
    "defaults={'email': os.environ['BOOTSTRAP_ADMIN_EMAIL'], 'is_staff': True, 'is_superuser': True}); "
    "u.is_staff = True; u.is_superuser = True; u.email = os.environ['BOOTSTRAP_ADMIN_EMAIL']; "
    "u.set_password(os.environ['BOOTSTRAP_ADMIN_PASSWORD']); u.save()"
)

_READ_ENV = 'while IFS= read -r line && [ -n "$line" ]; do export "$line"; done'


def fact(command: str) -> str:
    return str(host.get_fact(Command, command=command) or "").strip()


def site_shell(cfg: DjangoSiteConfig, script: str, cwd: PurePosixPath | None = None) -> str:
    """``script`` run by ``sh`` in ``cwd`` (default: the app directory) as the service user."""

    shell = _as_user(cfg.user, cfg.home, {}, ["sh", "-c", script])
    return f"cd {shlex.quote(str(cwd or cfg.app_path))} && {shell}"


def manage_script(cfg: DjangoSiteConfig, *command: str, stdin_env: bool = False, then: str = "") -> str:
    """``set -a; . .env; set +a; python manage.py ...`` with the site's settings module.

    ``then``: a command run after a successful ``manage.py`` (instead of ``exec``).
    """

    lines = [
        "set -a",
        f". {shlex.quote(str(cfg.env_path))}",
        "set +a",
        f"export DJANGO_SETTINGS_MODULE={shlex.quote(cfg.app.settings_module)}",
    ]
    if stdin_env:
        lines.append(_READ_ENV)
    run = shlex.join([str(cfg.venv_bin / "python"), "manage.py", *command])
    lines.append(f"{run} && {then}" if then else f"exec {run}")
    return "; ".join(lines)


def manage(
    cfg: DjangoSiteConfig,
    name: str,
    command: tuple[str, ...],
    *,
    gate: list[OperationMeta],
    force: bool,
    before: str = "",
) -> OperationMeta:
    """``manage.py <command>`` when one of ``gate`` changed or ``force``; ``before``: a command run first."""

    shell = site_shell(cfg, manage_script(cfg, *command))
    return server.shell(
        name=name,
        commands=[f"{before} && {shell}" if before else shell],
        _if=lambda: force or any(meta.did_change() for meta in gate),
    )


def stdin_env(env: dict[str, str]) -> SecretContent:
    # One ``KEY=value`` per line; read back with ``export "$line"`` (no expansion).
    return SecretContent("".join(f"{key}={value}\n" for key, value in env.items()))


def migrations_probe(cfg: DjangoSiteConfig) -> str:
    """``migrate --check`` (read-only), only against an existing database (Django would create one)."""

    plan = site_shell(cfg, manage_script(cfg, "migrate", "--check", "--plan"))
    needed = (*([cfg.db_path] if isinstance(cfg.database, SqliteDb) else []), cfg.env_path, cfg.venv_bin / "python")
    return when_present(needed, migrations_state(plan), otherwise="pending")


def uv_args(cfg: DjangoSiteConfig) -> list[str]:
    return [*cfg.app.uv_args, *(["--python", cfg.app.python] if cfg.app.python else [])]


def uv_command(cfg: DjangoSiteConfig, *, dry: bool = False) -> str:
    argv = [str(DEFAULT_UV), "sync", *uv_args(cfg), *(["--dry-run"] if dry else [])]
    env = {e.key: e.value for e in cfg.app.uv_env}
    env["UV_PROJECT_ENVIRONMENT"] = str(cfg.venv_path)
    return f"cd {shlex.quote(str(cfg.app_path))} && {_as_user(cfg.user, cfg.home, env, argv)}"


def deps_probe(cfg: DjangoSiteConfig) -> str:
    """``uv sync --dry-run`` (read-only) finds nothing to install, remove or recreate.

    Catches an earlier run that stopped after the source sync and a changed
    Python version, neither of which the sync's own change shows.
    """

    sync = uv_command(cfg, dry=True)
    check = (
        f"out=$( {sync} 2>&1 ) || {{ printf '%s\\n' \"$out\" >&2; exit 1; }}; "
        "if printf '%s\\n' \"$out\" | grep -qx 'Would make no changes'; then echo current; else echo pending; fi"
    )
    # Nothing synced yet: the sync installs everything.
    return when_present([cfg.app_path / "uv.lock"], check, otherwise="pending")


def static_collected(cfg: DjangoSiteConfig) -> bool:
    manifest = shlex.quote(str(cfg.app_path / "staticfiles" / "staticfiles.json"))
    return fact(f"test -f {manifest} && echo present || true") == "present"


def digest(*parts: object) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()


def admin_values(admin: EnsureSuperuser, secrets: SecretValues) -> tuple[str, str, str]:
    return resolve(admin.username, secrets), resolve(admin.email, secrets), resolve(admin.password, secrets)


def admin_stamp(cfg: DjangoSiteConfig, admin: EnsureSuperuser, secrets: SecretValues) -> str:
    key = resolve(cfg.env.secret_key, secrets)
    material = "\0".join(admin_values(admin, secrets))
    return hmac.new(key.encode(), material.encode(), hashlib.sha256).hexdigest() + "\n"


def admin_probe(cfg: DjangoSiteConfig) -> str:
    """The account exists as an active staff superuser with the configured email."""

    argv = shlex.join(["python3", "-I", "-c", ADMIN_PROBE, str(cfg.db_path)])
    return when_present([cfg.db_path], argv, otherwise="none")


def admin_in_place(rows: str | None, username: str, email: str) -> bool:
    expected = {f"A {digest(username, 1, 1, 1)}", f"B {digest(username, email)}"}
    return rows is not None and expected <= set(rows.splitlines())


def ensure_superuser(cfg: DjangoSiteConfig, admin: EnsureSuperuser, secrets: SecretValues) -> None:
    """``manage.py ensure_superuser``, only when it may have something to do.

    The command is idempotent but reports nothing pyinfra can read, so it runs
    when the account is missing, inactive or lost its staff/superuser flags, or
    the admin secrets changed since the last run (stamp file). A password
    changed by hand stays until the secret changes.
    """

    stamp_path = cfg.home / ADMIN_STAMP
    stamp = admin_stamp(cfg, admin, secrets)
    username, email, password = admin_values(admin, secrets)
    check = admin_probe(cfg)
    rows = probe(check, name=f"{cfg.user} admin user")
    current = fact(f"cat {shlex.quote(str(stamp_path))} 2>/dev/null || true")
    if current == stamp.strip() and admin_in_place(rows, username, email):
        return
    # Name, email and password travel on stdin: never in a process's arguments.
    secret_stdin(
        name=f"Ensure {cfg.service_name} admin user",
        command=site_shell(cfg, manage_script(cfg, admin.command, stdin_env=True)),
        content=stdin_env({"ADMIN_USERNAME": username, "ADMIN_EMAIL": email, "ADMIN_PASSWORD": password}),
    )
    secret_file(
        name=f"Record {cfg.service_name} admin user",
        path=stamp_path,
        content=SecretContent(stamp),
        user="root",
        group="root",
    )
    if rows is None:
        verify_probe(check, name=f"{cfg.user} admin user")


def bootstrap_superuser(cfg: DjangoSiteConfig, admin: BootstrapSuperuser, secrets: SecretValues) -> None:
    """``createsuperuser`` when the account is missing, then its password set once.

    The account's existence is probed read-only (``createsuperuser`` itself
    fails on an existing account). The password is set on the first deploy,
    recorded by a marker; a password changed in the admin afterwards stays.
    """

    password = resolve(admin.password, secrets)
    check = shlex.join(["python3", "-I", "-c", BOOTSTRAP_PROBE, str(cfg.db_path), admin.username])
    check = when_present([cfg.db_path], check, otherwise="absent")
    state = probe(check, name=f"{cfg.user} bootstrap admin")
    if state != "present":
        args = ("createsuperuser", "--noinput", "--username", admin.username, "--email", admin.email)
        secret_stdin(
            name="Create the bootstrap admin",
            command=site_shell(cfg, manage_script(cfg, *args, stdin_env=True)),
            content=stdin_env({"DJANGO_SUPERUSER_PASSWORD": password}),
        )
        if state is None:
            verify_probe(check, name=f"{cfg.user} bootstrap admin", expect="present")
    marker = shlex.quote(str(cfg.bootstrap_marker))
    if fact(f"test -e {marker} && echo present || true") != "present":
        secret_stdin(
            name="Set the bootstrap admin password (first deploy only)",
            command=site_shell(
                cfg,
                manage_script(cfg, "shell", "-c", SET_BOOTSTRAP_PASSWORD, stdin_env=True, then=f"touch {marker}"),
            ),
            content=stdin_env(
                {
                    "BOOTSTRAP_ADMIN_USERNAME": admin.username,
                    "BOOTSTRAP_ADMIN_EMAIL": admin.email,
                    "BOOTSTRAP_ADMIN_PASSWORD": password,
                }
            ),
        )
