"""``quiet_fact`` and the harness's verbose capture under concurrency."""

import threading
from typing import Any

import gevent  # type: ignore[import-untyped]
import pytest
from pyinfra.api import deploy
from pyinfra.api import output as pyinfra_output
from pyinfra.facts.server import Command

from ops_deploy.ops import quiet
from ops_deploy.ops.quiet import quiet_fact
from ops_deploy.testing import run_deploy_fake


class _State:
    print_fact_output = True


class _Host:
    """Stands in for one host; its fact takes ``delay`` and sees the shared flag."""

    def __init__(self, state: Any, delay: float) -> None:
        self.state = state
        self.delay = delay
        self.seen: list[bool] = []

    def get_fact(self, cls: Any, **kwargs: Any) -> str:
        self.seen.append(self.state.print_fact_output)
        gevent.sleep(self.delay)
        self.seen.append(self.state.print_fact_output)
        return "answer"


def test_overlapping_quiet_facts_restore_the_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    # Two hosts' greenlets share one state: the first quiet fact ends while the
    # second still runs (they finish in their starting order).
    state = _State()
    first, second = _Host(state, 0.02), _Host(state, 0.05)

    def run(fake: _Host, start: float) -> str:
        gevent.sleep(start)
        monkeypatch.setattr(quiet, "host", fake)
        return str(quiet_fact(Command, command="probe"))

    jobs = [gevent.spawn(run, first, 0), gevent.spawn(run, second, 0.01)]
    gevent.joinall(jobs, raise_error=True)

    assert [job.value for job in jobs] == ["answer", "answer"]
    assert first.seen == second.seen == [False, False]
    assert state.print_fact_output is True


@deploy("Print a fact")
def _print_fact(marker: str) -> None:
    from pyinfra import host

    host.get_fact(Command, command=f"echo {marker}")


def test_verbose_runs_in_threads_keep_their_own_output() -> None:
    before = pyinfra_output._echo
    runs: dict[str, Any] = {}

    def run(marker: str) -> None:
        runs[marker] = run_deploy_fake(_print_fact, marker, responses={f"echo {marker}": [marker]}, verbose=True)

    threads = [threading.Thread(target=run, args=(marker,)) for marker in ("first-marker", "second-marker")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    for marker, other in (("first-marker", "second-marker"), ("second-marker", "first-marker")):
        printed = "\n".join(runs[marker].printed)
        assert marker in printed
        assert other not in printed
    assert pyinfra_output._echo is before
