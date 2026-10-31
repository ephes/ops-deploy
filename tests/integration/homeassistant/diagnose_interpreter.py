"""One owned UV/Python/SDK diagnostic; no HA/Matter application bootstrap."""

from __future__ import annotations

import os
import pwd
import sys
from pathlib import Path
from typing import Any

from .fixture import write
from .harness import admit
from .interpreter_original import verify_original_contexts
from .interpreter_probe import environment_keys
from .matter_ready import bounded_command
from .prerequisites import seed_uv_account

PREFIX = ["runuser", "-u", "homeassistant", "--", "env", "HOME=/home/homeassistant"]


def capture(name: str, argv: list[str], timeout: float) -> dict[str, Any]:
    result = bounded_command(argv, timeout=timeout)
    write(name + ".json", {"argv": argv, **result})
    if result["truncated"] or result["timed_out"]:
        raise RuntimeError("owned interpreter diagnostic exceeded bound")
    return result


def run() -> None:
    admit()
    completed = False
    try:
        assert os.environ["HOMEASSISTANT_FIXTURE_CASE"] == "current"
        write("interpreter-prerequisites.json", seed_uv_account())
        site = Path("/home/homeassistant/site")
        site.mkdir(mode=0o755)
        account = pwd.getpwnam("homeassistant")
        os.chown(site, account.pw_uid, account.pw_gid)
        result = capture(
            "interpreter-seed",
            [*PREFIX, "/usr/local/bin/uv", "venv", "--seed", "--python", "3.14.8", str(site / ".venv")],
            600,
        )
        if result["exit"]:
            raise RuntimeError("owned interpreter seed failed")
        capture("interpreter-direct-find", [*PREFIX, "/usr/local/bin/uv", "python", "find", "3.14.8"], 60)
        keys = environment_keys()
        capture(
            "interpreter-direct-find-without-candidate-environment",
            [
                *PREFIX[:4],
                "env",
                *[part for key in keys for part in ("-u", key)],
                "HOME=/home/homeassistant",
                "/usr/local/bin/uv",
                "python",
                "find",
                "3.14.8",
            ],
            60,
        )
        capture(
            "interpreter-effective-context",
            [
                *PREFIX,
                str(site / ".venv/bin/python"),
                "-I",
                "-B",
                "-c",
                "import json,os;print(json.dumps({'uid':os.getuid(),'gid':os.getgid(),"
                "'cwd':os.getcwd(),'environment_keys':sorted(k for k in os.environ "
                "if k.startswith(('UV_','XDG_')) or k=='VIRTUAL_ENV')}))",
            ],
            15,
        )
        verify_original_contexts()
        # Separate bounded child retains the actual inherited context, SDK
        # stderr/greenlet failure and per-operation completion. It never starts HA.
        result = capture(
            "interpreter-sdk-process",
            [sys.executable, "-m", "tests.integration.homeassistant.interpreter_probe"],
            900,
        )
        if result["exit"]:
            raise RuntimeError("owned interpreter SDK probe failed")
        completed = True
    finally:
        write(
            "summary.json",
            {
                "completed": completed,
                "purpose": "original command cwd/interpreter diagnostic; no application qualification",
                "original_command_contexts_requested": 3,
                "case": os.environ["HOMEASSISTANT_FIXTURE_CASE"],
                "typed_application_phases_executed": 0,
                "selected_original_phases_executed": 0,
                "scope": "owned synthetic UV/account/Python; no inventory, HA, Matter or hardware execution",
            },
        )


if __name__ == "__main__":
    run()
