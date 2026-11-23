"""Original Paperless management commands with bounded status-only admission."""

from __future__ import annotations

import json
import shlex
from collections.abc import Generator, Sequence
from importlib.resources import files

from pydantic import SecretStr
from pyinfra import state
from pyinfra.api import DeployError, StringCommand, operation
from pyinfra.api.operation import OperationMeta

from ops_deploy.helpers.probes import StdinLines, migrations_state, probe

from .config import PaperlessConfig, PaperlessCredentials

COMPLETE = "paperless-managed-step-complete"


def shell_command(cfg: PaperlessConfig, *, apply: bool = False) -> str:
    # Django's implicit stdin mode uses a nonblocking select and can fall back
    # to an interactive console before SSH has delivered stdin. An explicit
    # non-secret command blocks for the complete protected program instead.
    command = manage(
        cfg,
        "shell",
        "--no-startup",
        "--no-imports",
        "--interface",
        "python",
        "--command",
        "import sys; exec(compile(sys.stdin.read(), '<paperless-managed-stdin>', 'exec'))",
    )
    if not apply:
        return command + " 2>/dev/null"
    script = (
        f"out=$({command} 2>/dev/null) || {{ echo 'Paperless managed step failed' >&2; exit 1; }}; "
        f'[ "$(printf \'%s\\n\' "$out" | tail -n 1)" = {COMPLETE} ] || '
        "{ echo 'Paperless managed step did not complete' >&2; exit 1; }"
    )
    return shlex.join(["sh", "-c", script])


def manage(cfg: PaperlessConfig, *arguments: str, quiet: bool = False) -> str:
    script = (
        f"set -a; . {shlex.quote(cfg.site_root + '/.env')}; set +a; "
        f"cd {shlex.quote(cfg.site_root + '/paperless-ngx/src')}; "
        "exec " + shlex.join([f"{cfg.site_root}/.venv/bin/python", "-B", "manage.py", *arguments])
    )
    command = shlex.join(["runuser", "-u", cfg.username, "--", "env", f"HOME={cfg.home_path}", "bash", "-euc", script])
    if quiet:
        # Application errors can include document/account metadata. Retain the
        # nonzero outcome, but do not export raw application output into logs.
        command += " >/dev/null 2>&1 || { echo 'Paperless management command failed' >&2; exit 1; }"
        command = shlex.join(["sh", "-c", command])
    return command


def migrations_pending(cfg: PaperlessConfig) -> bool:
    # Paperless system checks create/delete write-test files in data roots.
    # Only this status command skips them; managed migrations retain all checks.
    command = migrations_state(manage(cfg, "migrate", "--check", "--plan", "--skip-checks") + " 2>/dev/null")
    answer = probe(shlex.join(["sh", "-c", command]), name="Paperless migration state")
    if answer not in {"current", "pending"}:
        raise DeployError("Paperless migration inspection failed; refusing unknown schema changes")
    return answer == "pending"


def stop_units_command(cfg: PaperlessConfig) -> str:
    """Stop every loaded Paperless unit and fail unless each one is down.

    Units come from the manager's own state (``LoadState``/``ActiveState``),
    not from unit files: a unit whose file was removed may still run. Only a
    unit that is both ``not-found`` and ``inactive`` (first deployment) is
    skipped; an inspection error fails the step. One ``systemctl stop`` covers
    all the others, so no failure is masked by a later unit; then each must
    report ``inactive`` or ``failed`` (``activating``/``deactivating`` fail).
    """
    units = " ".join(shlex.quote(unit) for unit in cfg.units)
    script = (
        "set -eu; selected=; "
        f"for unit in {units}; do "
        'load=$(systemctl show --property=LoadState --value -- "$unit"); '
        'active=$(systemctl show --property=ActiveState --value -- "$unit"); '
        '[ -n "$load" ] && [ -n "$active" ] || { echo "cannot inspect $unit" >&2; exit 1; }; '
        'if [ "$load" = not-found ] && [ "$active" = inactive ]; then continue; fi; '
        'selected="$selected $unit"; done; '
        'if [ -z "$selected" ]; then exit 0; fi; '
        "systemctl stop -- $selected; "
        "for unit in $selected; do "
        'state=$(systemctl show --property=ActiveState --value -- "$unit"); '
        'case "$state" in inactive|failed) ;; '
        '*) echo "Paperless unit $unit is still $state" >&2; exit 1 ;; esac; done'
    )
    return shlex.join(["sh", "-c", script])


@operation()
def migrate(cfg: PaperlessConfig, deferred: bool = False) -> Generator[StringCommand, None, None]:
    if not (deferred and not state.is_executing) and not migrations_pending(cfg):
        return
    # Migrations run only after a confirmed stop of every Paperless unit, in the
    # same command: a failed stop never reaches `migrate`, even when the run
    # ignores errors. A retry after an interrupted upgrade (link already
    # current, migrations pending) stops the old processes the same way. The
    # rollout restarts the units afterwards (migrations are a restart trigger).
    yield StringCommand(stop_units_command(cfg) + " && " + manage(cfg, "migrate", quiet=True))


def admin_payload(cfg: PaperlessConfig, credentials: PaperlessCredentials) -> SecretStr:
    return SecretStr(
        json.dumps(
            {
                "manage_superuser": cfg.manage_superuser,
                "admin_user": cfg.admin_user,
                "admin_email": cfg.admin_email,
                "admin_password": credentials.admin_password.get_secret_value(),
                "existing_superusers": cfg.existing_superusers,
                "existing_superusers_strict": cfg.existing_superusers_strict,
            }
        )
    )


def admin_program(payload: SecretStr, *, apply: bool) -> str:
    source = files("ops_deploy.services.paperless").joinpath("files/admin.py").read_text()
    action = "apply_admin" if apply else "inspect_admin"
    # This whole program goes through protected stdin, never shell argv. JSON
    # nesting preserves arbitrary validated literal values without code eval.
    return (
        source
        + "\nimport json\nsettings=json.loads("
        + repr(payload.get_secret_value())
        + ")\n"
        + f"print(json.dumps({action}(settings), sort_keys=True))\n"
        + (f"print({COMPLETE!r})\n" if apply else "")
    )


def admin_pending(cfg: PaperlessConfig, payload: SecretStr) -> bool:
    command = shell_command(cfg)
    answer = probe(command, name="Paperless declared account flags", stdin=admin_program(payload, apply=False))
    try:
        result = json.loads(answer or "")
        if (
            not isinstance(result, dict)
            or set(result) != {"create", "promote", "missing"}
            or type(result["create"]) is not bool
        ):
            raise ValueError
        for field in ("promote", "missing"):
            values = result[field]
            if (
                not isinstance(values, list)
                or any(type(index) is not int or not 0 <= index < len(cfg.existing_superusers) for index in values)
                or len(set(values)) != len(values)
            ):
                raise ValueError
        return bool(result["create"] or result["promote"] or (result["missing"] and cfg.existing_superusers_strict))
    except ValueError:
        raise DeployError("Paperless declared account inspection failed") from None


@operation()
def ensure_admin(
    cfg: PaperlessConfig, payload: SecretStr, deferred: bool = False
) -> Generator[StringCommand, None, None]:
    if not cfg.manage_superuser and not cfg.existing_superusers:
        return
    if not (deferred and not state.is_executing) and not admin_pending(cfg, payload):
        return
    yield StringCommand(
        shell_command(cfg, apply=True),
        _stdin=StdinLines(admin_program(payload, apply=True)),
        _get_pty=False,
    )


def static_program(cfg: PaperlessConfig, *, apply: bool) -> str:
    source = files("ops_deploy.services.paperless").joinpath("files/static_assets.py").read_text()
    settings = {
        "release_dir": f"{cfg.site_root}/paperless-ngx-v{cfg.version}",
        "venv": f"{cfg.site_root}/.venv",
        "static_root": f"{cfg.site_root}/staticfiles",
    }
    action = "apply_static" if apply else "inspect_static"
    return (
        source
        + "\nimport json\nsettings=json.loads("
        + repr(json.dumps(settings))
        + ")\n"
        + f"print(json.dumps({action}(settings)))\n"
        + (f"print({COMPLETE!r})\n" if apply else "")
    )


def static_pending(cfg: PaperlessConfig) -> bool:
    command = shell_command(cfg)
    answer = probe(command, name="Paperless static program assets", stdin=static_program(cfg, apply=False))
    try:
        value = json.loads(answer or "")
        if not isinstance(value, dict) or set(value) != {"pending"} or type(value["pending"]) is not bool:
            raise ValueError
        return bool(value["pending"])
    except ValueError:
        raise DeployError("Paperless static program asset inspection failed") from None


@operation()
def collect_static(
    cfg: PaperlessConfig,
    changes: Sequence[OperationMeta] = (),
    deferred: bool = False,
) -> Generator[StringCommand, None, None]:
    planning_change = not state.is_executing and (deferred or any(meta.will_change for meta in changes))
    executed_change = state.is_executing and any(meta.did_change() for meta in changes)
    if not (planning_change or executed_change) and not static_pending(cfg):
        return
    yield StringCommand(
        shell_command(cfg, apply=True),
        _stdin=StdinLines(static_program(cfg, apply=True)),
        _get_pty=False,
    )
