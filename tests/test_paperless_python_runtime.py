"""Interpreter/package recovery planning without installing any local package."""

from __future__ import annotations

import inspect
import shlex
from types import SimpleNamespace

import pytest
from pyinfra.api import DeployError

from ops_deploy.services.paperless import python_runtime
from ops_deploy.services.paperless.config import PaperlessConfig


@pytest.mark.parametrize(
    ("answer", "expected"),
    [("python=3.14", "current"), ("python=3.12", "wrong-version"), ("missing", "missing"), ("broken", "broken")],
)
def test_known_interpreter_recovery_states(answer: str, expected: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(python_runtime, "probe", lambda *args, **kwargs: answer)
    assert python_runtime.interpreter_state(PaperlessConfig(traefik_domain="home.example.test")) == expected


@pytest.mark.parametrize("answer", [None, "unsafe", "", "python=unknown"])
def test_unknown_interpreter_state_refuses(answer: str | None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(python_runtime, "probe", lambda *args, **kwargs: answer)
    with pytest.raises(DeployError, match="unsafe or unknown"):
        python_runtime.interpreter_state(PaperlessConfig(traefik_domain="home.example.test"))


def test_original_install_commands_keep_all_constraints_and_fido_order() -> None:
    cfg = PaperlessConfig(traefik_domain="home.example.test")
    commands = python_runtime.install_commands(cfg, application=True, supporting=True)
    assert len(commands) == 3
    scripts = [shlex.split(command)[-1] for command in commands]
    for script in scripts:
        assert script.startswith("cd /home/paperless/site && ")
        assert "--constraint /home/paperless/site/.python-security-constraints.txt" in script
    assert "-e '/home/paperless/site/paperless-ngx-v3.2.1[postgres]'" in scripts[0]
    assert scripts[1].endswith("gunicorn whitenoise setproctitle")
    assert scripts[2].endswith("--force-reinstall fido2==1.1.3")


def test_healthy_packages_skip_and_app_change_reapplies_fido_after_dependencies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(python_runtime, "state", SimpleNamespace(is_executing=True))
    actual = {"python": True, "application": True, "supporting": True}
    monkeypatch.setattr(python_runtime, "package_state", lambda cfg: actual)
    cfg = PaperlessConfig(traefik_domain="home.example.test")
    operation = inspect.unwrap(python_runtime.install_packages)
    assert list(operation(cfg)) == []
    actual["application"] = False
    assert len(list(operation(cfg))) == 3
    actual["application"] = True
    actual["supporting"] = False
    assert len(list(operation(cfg))) == 2


def test_constraints_alone_never_force_package_install(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(python_runtime, "state", SimpleNamespace(is_executing=True))
    monkeypatch.setattr(
        python_runtime, "package_state", lambda cfg: {"python": True, "application": True, "supporting": True}
    )
    cfg = PaperlessConfig(traefik_domain="home.example.test")
    assert python_runtime.constraints_text() == "certifi>=2026.10.19\npip>=26.2.2\n"
    assert list(inspect.unwrap(python_runtime.install_packages)(cfg, deferred=True)) == []


@pytest.mark.parametrize(("answer", "expected"), [("current", True), ("pending", False)])
def test_dependency_consistency_known_states(
    answer: str | None, expected: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(python_runtime, "probe", lambda *args, **kwargs: answer)
    assert python_runtime.dependencies_current(PaperlessConfig(traefik_domain="home.example.test")) is expected


@pytest.mark.parametrize("answer", [None, "", "error", "current\npending"])
def test_dependency_inspection_error_cannot_trigger_package_repair(
    answer: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(python_runtime, "probe", lambda *args, **kwargs: answer)
    with pytest.raises(DeployError, match="unknown package changes"):
        python_runtime.dependencies_current(PaperlessConfig(traefik_domain="home.example.test"))


def test_missing_dependency_invalidates_otherwise_current_application(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        python_runtime, "probe", lambda *args, **kwargs: '{"python":true,"application":true,"supporting":true}'
    )
    monkeypatch.setattr(python_runtime, "dependencies_current", lambda cfg: False)
    assert python_runtime.package_state(PaperlessConfig(traefik_domain="home.example.test")) == {
        "python": True,
        "application": False,
        "supporting": True,
    }
