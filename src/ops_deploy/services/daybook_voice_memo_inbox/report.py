"""Original optional interruption summary, separate from pure verification."""

from __future__ import annotations

import base64
import io
import json
import shlex
from collections.abc import Generator
from importlib.resources import files
from typing import Any

from pyinfra import host, logger
from pyinfra.api import Host, State, StringCommand, deploy, operation
from pyinfra.api.arguments import ConnectorArguments
from pyinfra.connectors.util import CommandOutput
from pyinfra.facts.server import Command, Os

from .config import PACKAGE, DaybookInboxConfig


def report_payload(cfg: DaybookInboxConfig, uid: int) -> dict[str, Any]:
    return {
        "user": cfg.daybook_voice_memo_inbox_service_user,
        "home": cfg.daybook_voice_memo_inbox_service_home,
        "uid": uid,
        "owner": "root",
        "checkout": cfg.daybook_voice_memo_inbox_checkout_path,
        "python": cfg.daybook_voice_memo_inbox_python,
        "python_install_dir": cfg.daybook_voice_memo_inbox_python_install_dir,
        "policy": cfg.daybook_voice_memo_inbox_policy_path,
    }


def report_command(action: str) -> str:
    if action not in {"available", "report"}:
        raise ValueError("Unsupported optional Inbox report action")
    parts = ["import base64,sys,types"]
    for module, package, filename in (
        ("ops_daybook_observer", "ops_deploy.services.daybook_operations_runtime", "runtime_state.py"),
        ("ops_inbox_controls", PACKAGE, "inbox_controls.py"),
        ("ops_inbox_python", PACKAGE, "inbox_python.py"),
    ):
        body = base64.b64encode(files(package).joinpath("files/" + filename).read_bytes()).decode()
        parts.append(
            f"m=types.ModuleType('{module}');sys.modules[m.__name__]=m;"
            f"exec(compile(base64.b64decode('{body}'),'<{module}>','exec'),m.__dict__)"
        )
    body = base64.b64encode(files(PACKAGE).joinpath("files/inbox_report.py").read_bytes()).decode()
    parts.append(f"exec(compile(base64.b64decode('{body}'),'<inbox-report>','exec'),{{'__name__':'__main__'}})")
    return shlex.join(["/usr/bin/python3", "-I", "-B", "-c", ";".join(parts), action])


class _ReportCommand(StringCommand):
    """Ordinary SDK execution/privilege context, sanitized aggregate logging."""

    def execute(
        self, state: State, target: Host, connector_arguments: ConnectorArguments
    ) -> tuple[bool, CommandOutput]:
        success, output = super().execute(state, target, connector_arguments)
        try:
            result = json.loads(output.stdout)
            count = result["long_in_flight_count"]
            if not success or result.get("reported") is not True or type(count) is not int or not 0 <= count < 10**20:
                raise ValueError()
        except (ValueError, TypeError, KeyError):
            logger.info("Optional Inbox interruption summary unavailable")
        else:
            logger.info(f"Inbox interruption summary: {count} long-lane item(s) in flight")
        # Never turn a genuine SDK/transport failure into operation success.
        return bool(success), output


@operation()
def _managed_report(body: str) -> Generator[StringCommand, None, None]:
    # Payload contains declared paths/UID only, no credential or policy body.
    # Stream repr keeps even these private paths out of verbose stdin logging.
    yield _ReportCommand(report_command("report"), _stdin=io.StringIO(body), _get_pty=False, _shell_executable="sh")


@deploy("Report original optional Inbox interruption count")
def report_daybook_inbox_interruption(cfg: DaybookInboxConfig) -> None:
    """For an explicit managed install/update, never the current/no-op path.

    Availability is metadata only. A missing/broken old app skips this optional
    report just as the original role did; no new refusal or acknowledgement.
    """
    if not cfg.daybook_voice_memo_inbox_enabled or host.get_fact(Os) != "Darwin":
        return
    uid = host.get_fact(
        Command,
        command=shlex.join(["/usr/bin/id", "-u", cfg.daybook_voice_memo_inbox_service_user]),
        _ignore_errors=True,
    )
    if not uid or not uid.isdecimal() or int(uid) <= 0:
        return
    body = json.dumps(report_payload(cfg, int(uid))) + "\n"
    with io.StringIO(body) as stream:
        observed = host.get_fact(
            Command, command=report_command("available"), _stdin=stream, _get_pty=False, _ignore_errors=True
        )
    try:
        present = json.loads(observed or "")
    except (ValueError, TypeError):
        return
    if not isinstance(present, dict) or present.get("available") is not True:
        return
    # Explicitly managed: the original application status can open its ledger.
    # Only validated nonnegative long_in_flight_count may leave the host helper.
    _managed_report(
        name="Report optional original Inbox long-lane interruption aggregate",
        body=body,
    )
