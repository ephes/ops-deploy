"""Paperless-specific managed operations with fresh execution-time admission."""

from __future__ import annotations

import json
import shlex
from collections.abc import Generator, Sequence

from pydantic import SecretStr
from pyinfra import state
from pyinfra.api import DeployError, StringCommand, operation
from pyinfra.api.operation import OperationMeta

from ops_deploy.helpers.probes import StdinLines, probe

from .commands import host_command, index_payload, reindex_payload, scanner_acl_payload
from .config import PaperlessConfig
from .index_contract import document_count_command, parse_document_count


def as_service(cfg: PaperlessConfig, command: str) -> str:
    script = f"cd {shlex.quote(cfg.site_root)} && {command}"
    return shlex.join(["runuser", "-u", cfg.username, "--", "env", f"HOME={cfg.home_path}", "sh", "-c", script])


def status(script: str, payload: str) -> str:
    answer = probe(host_command(script), name=f"Paperless {script}", stdin=payload)
    if answer not in {"current", "pending", "missing", "unmanaged"}:
        raise DeployError(f"Paperless {script} returned an unknown state; refusing changes")
    return answer


@operation()
def scanner_password(payload: SecretStr, deferred: bool = False) -> Generator[StringCommand, None, None]:
    """Password-only convergence after the declared account creation operation."""
    settings = json.loads(payload.get_secret_value())
    settings["apply"] = False
    if not (deferred and not state.is_executing) and status("scanner_password", json.dumps(settings)) in {
        "current",
        "unmanaged",
    }:
        return
    settings["apply"] = True
    yield StringCommand(host_command("scanner_password"), _stdin=StdinLines(json.dumps(settings)), _get_pty=False)


@operation()
def scanner_acl(cfg: PaperlessConfig, deferred: bool = False) -> Generator[StringCommand, None, None]:
    """Default recursive ACL, after the consume root exists."""
    if (
        not (deferred and not state.is_executing)
        and status("scanner_acl", scanner_acl_payload(cfg, apply=False)) == "current"
    ):
        return
    yield StringCommand(
        host_command("scanner_acl"), _stdin=StdinLines(scanner_acl_payload(cfg, apply=True)), _get_pty=False
    )


@operation()
def scanner_mount(cfg: PaperlessConfig, deferred: bool = False) -> Generator[StringCommand, None, None]:
    settings = {
        "source": f"{cfg.external_storage_root}/consume",
        "target": f"{cfg.sftp_chroot_dir}/inbox",
        "apply": False,
    }
    if not (deferred and not state.is_executing):
        answer = probe(host_command("scanner_mount"), name="Paperless scanner bind mount", stdin=json.dumps(settings))
        try:
            value = json.loads(answer or "")
            if (
                not isinstance(value, dict)
                or set(value) != {"fstab", "mount"}
                or any(type(v) is not bool for v in value.values())
            ):
                raise ValueError
            if not any(value.values()):
                return
        except ValueError:
            raise DeployError("Paperless scanner bind mount inspection failed") from None
    settings["apply"] = True
    yield StringCommand(host_command("scanner_mount"), _stdin=StdinLines(json.dumps(settings)), _get_pty=False)


@operation()
def scanner_ssh(content: str) -> Generator[StringCommand, None, None]:
    settings = {"content": content, "apply": False}
    if status("scanner_ssh", json.dumps(settings)) == "current":
        return
    settings["apply"] = True
    yield StringCommand(host_command("scanner_ssh"), _stdin=StdinLines(json.dumps(settings)), _get_pty=False)


def release_state(cfg: PaperlessConfig) -> dict[str, bool]:
    answer = probe(
        as_service(cfg, host_command("release")),
        name="Paperless owned release state",
        stdin=json.dumps({"site_root": cfg.site_root, "apply": False}),
    )
    try:
        value = json.loads(answer or "")
        if (
            not isinstance(value, dict)
            or set(value) != {"release", "current"}
            or any(type(item) is not bool for item in value.values())
        ):
            raise ValueError
        return value
    except ValueError:
        raise DeployError("Paperless release inspection failed; refusing unknown source changes") from None


@operation()
def release(cfg: PaperlessConfig, deferred: bool = False) -> Generator[StringCommand, None, None]:
    if not (deferred and not state.is_executing) and not any(release_state(cfg).values()):
        return
    yield StringCommand(
        as_service(cfg, host_command("release")),
        _stdin=StdinLines(json.dumps({"site_root": cfg.site_root, "apply": True})),
        _get_pty=False,
    )


def index_needs_rebuild(cfg: PaperlessConfig, triggers: tuple[str, ...]) -> bool:
    count = probe(
        document_count_command(cfg.postgres_database, cfg.postgres_port), name="Paperless live document COUNT"
    )
    if count is None:
        raise DeployError("Paperless document count query failed; refusing an unknown index decision")
    try:
        document_count = parse_document_count(count)
    except ValueError:
        raise DeployError("Paperless document count query did not return one valid aggregate") from None
    answer = probe(
        host_command("index_state"),
        name="Paperless bounded index metadata",
        stdin=index_payload(cfg, document_count, triggers),
    )
    try:
        value = json.loads(answer or "")
        if not isinstance(value, dict) or set(value) != {"reindex", "reasons", "document_count", "indexed_count"}:
            raise ValueError
        if (
            type(value["reindex"]) is not bool
            or type(value["document_count"]) is not int
            or value["document_count"] != document_count
            or not isinstance(value["reasons"], list)
            or any(not isinstance(reason, str) for reason in value["reasons"])
            or value["reindex"] != bool(value["reasons"])
        ):
            raise ValueError
        indexed = value["indexed_count"]
        if indexed is not None and (type(indexed) is not int or not 0 <= indexed <= 2**63 - 1):
            raise ValueError
        if not value["reindex"] and indexed != document_count:
            raise ValueError
        return bool(value["reindex"])
    except ValueError:
        raise DeployError("Paperless index metadata inspection failed; refusing unsafe index changes") from None


@operation()
def rebuild_index(
    cfg: PaperlessConfig,
    changes: Sequence[tuple[str, OperationMeta]] = (),
    deferred: bool = False,
) -> Generator[StringCommand, None, None]:
    """Plan fresh prerequisites conservatively, then decide again after they run.

    The caller labels only release/package/migration changes. did_change is never
    evaluated during planning. A conditional plan remains a possible managed
    reindex; it must not be reported as a resolved zero-change plan.
    """
    if any(label not in {"release", "packages", "migrations"} for label, _ in changes):
        raise ValueError("unknown Paperless reindex change trigger")
    planning_change = not state.is_executing and (deferred or any(meta.will_change for _, meta in changes))
    if not planning_change:
        triggers = tuple(dict.fromkeys(label for label, meta in changes if state.is_executing and meta.did_change()))
        if not index_needs_rebuild(cfg, triggers):
            return
    yield StringCommand(host_command("reindex"), _stdin=StdinLines(reindex_payload(cfg)), _get_pty=False)


@operation()
def http_health(cfg: PaperlessConfig) -> Generator[StringCommand, None, None]:
    """Readiness follows only the release's one same-origin schema redirect."""
    yield StringCommand(host_command("health"), _stdin=StdinLines(json.dumps({"port": cfg.app_port})), _get_pty=False)
