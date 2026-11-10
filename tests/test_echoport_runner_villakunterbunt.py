"""villakunterbunt-staging runner: a partial stop still restarts what stopped.

The runner stops Next.js, then Django. ``services_stopped`` arms the restart
in ``finally``; it must be set before the first stop, or a failed Django stop
after a successful Next.js stop would leave Next.js down.
"""

from __future__ import annotations

from importlib.resources import files

from ops_deploy.services._echoport_runner.render import FORKED, PACKAGE

TEMPLATE = "villakunterbunt_staging_backup.py.j2"


def test_the_template_is_forked() -> None:
    assert TEMPLATE in FORKED


def test_restart_is_armed_before_every_stop() -> None:
    text = files(PACKAGE).joinpath("templates", TEMPLATE).read_text()
    calls = [i for i in range(len(text)) if text.startswith("    stop_services(remote_host", i)]
    assert len(calls) == 2
    for call in calls:
        before = text[:call]
        arm = before.rfind("services_stopped = True")
        reset = before.rfind("services_stopped = False")
        assert arm > reset, "restart must be armed before the stop call"
        # nothing between arming and the stop call can fail without the flag
        assert "return 1" not in text[arm:call]
