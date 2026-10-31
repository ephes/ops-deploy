"""Bounded interpreter-only repair controls after child ownership admission."""

from __future__ import annotations

import os
import shlex
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ops_deploy.services.homeassistant import interpreter
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig

from .fixture import write
from .frozen_interpreter import load
from .interpreter_probe import probe
from .matter_ready import bounded_command


def direct(name: str, argv: list[str]) -> dict[str, Any]:
    result = bounded_command(argv, timeout=120)
    write(name + ".json", {"argv": argv, "cwd": os.getcwd(), **result})
    assert not result["timed_out"]
    assert not result["truncated"]
    return result


def sdk(
    name: str,
    *,
    frozen: bool = False,
    install: bool = True,
    retries: int = 0,
    retry_hook: Callable[[], None] | None = None,
) -> dict[str, Any]:
    result = probe(frozen=frozen, install=install, retries=retries, retry_hook=retry_hook)
    write(name + ".json", result)
    assert all(not command["truncated"] for command in result["commands"])
    return result


def successful_noop(result: dict[str, Any]) -> None:
    assert result["error"] is None
    assert result["failed_hosts"] == []
    assert result["planned_changes"] == [True]
    assert result["changes"] == [False]
    assert result["operations"] == [{"complete": True, "executed": False, "success": True}]
    assert not any("python install" in item["argv_shell"] for item in result["commands"])


def exercise() -> None:
    """Only invoked by interpreter_probe.main after its full child admission."""
    cfg = HomeAssistantRuntimeConfig()
    frozen = load()
    previous = Path.cwd()
    controller = Path("/opt/controller")
    controller_mode = stat.S_IMODE(controller.stat().st_mode)
    try:
        # Both controller cases retain the actual inaccessible .venv. Only
        # this admitted disposable controller directory has its mode varied.
        for name, cwd in (
            ("controller", Path("/opt/controller")),
            ("private", controller),
            ("neutral", Path("/home/homeassistant")),
        ):
            controller.chmod(0o700 if name == "private" else controller_mode)
            os.chdir(cwd)
            old = direct("repair-" + name + "-frozen-direct", shlex.split(frozen.interpreter_command(cfg, "find")))
            new = direct("repair-" + name + "-fixed-direct", shlex.split(interpreter.interpreter_command(cfg, "find")))
            assert new["exit"] == 0
            if name == "controller":
                assert old["exit"] != 0
                assert "Permission denied" in old["output"]
                negative = sdk("repair-controller-frozen-sdk", frozen=True)
                assert negative["operations"] == [{"complete": False, "executed": False, "success": None}]
                assert negative["failed_hosts"] == []
            elif name == "neutral":
                assert old["exit"] == 0
            successful_noop(sdk("repair-" + name + "-fixed-sdk"))
        os.chdir("/opt/controller")
        # Remove only the interpreter seeded for this disposable synthetic user;
        # no application exists. This makes the next real SDK install cold.
        removed = direct("repair-cold-uninstall", shlex.split(interpreter.interpreter_command(cfg, "uninstall")))
        assert removed["exit"] == 0
        cold = sdk("repair-cold-install")
        assert cold["error"] is None
        assert cold["failed_hosts"] == []
        assert cold["changes"] == [True]
        assert cold["operations"] == [{"complete": True, "executed": True, "success": True}]
        assert sum("python install" in item["argv_shell"] for item in cold["commands"]) == 1
        successful_noop(sdk("repair-cold-repeat"))
        # An owned inaccessible project in the selected home is a genuine
        # post-install discovery failure, not a mocked connector response.
        link = Path("/home/homeassistant/.venv")
        assert not link.exists()
        assert not link.is_symlink()
        link.symlink_to("/opt/controller/.venv")
        try:
            failed = sdk("repair-postfind-failure", retries=1)
            assert failed["operations"] == [{"complete": True, "executed": True, "success": False}]
            assert failed["failed_hosts"] == ["@local"]
            assert failed["changes"] == [False]
            assert sum("python install" in item["argv_shell"] for item in failed["commands"]) == 2
        finally:
            link.unlink()
        successful_noop(sdk("repair-after-fault-retry"))
        link.symlink_to("/opt/controller/.venv")
        try:
            recovered = sdk("repair-transient-postfind-retry", retries=1, retry_hook=link.unlink)
            assert recovered["operations"] == [{"complete": True, "executed": True, "success": True}]
            assert recovered["changes"] == [True]
            assert recovered["retries"] == [1]
            assert recovered["failed_hosts"] == []
            assert sum("python install" in item["argv_shell"] for item in recovered["commands"]) == 1
        finally:
            if link.is_symlink():
                link.unlink()
        successful_noop(sdk("repair-after-transient-repeat"))
    finally:
        controller.chmod(controller_mode)
        os.chdir(previous)
