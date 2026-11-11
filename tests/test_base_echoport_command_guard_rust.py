"""base.echoport_command_guard: the Rust guard (impl shadow/rust, install, pin and prune).

The role's ``rust.yml`` (install and check, no pin, no prune), ``forced_command.yml``
(the three command shapes) and ``confirm_live.yml`` (verify the written line,
then pin and prune) against the fake connector, and the host check script
(``files/echoport_rust_guard_check.py``) run locally.
"""

from __future__ import annotations

import base64
import os
import shlex
import stat
import subprocess
import sys
import types
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.base.echoport_command_guard import (
    RUST_CHECK_SCRIPT,
    RUST_CONSUMER,
    RUST_INSTALL_ROOT,
    RUST_NAME,
    EchoportCommandGuardConfig,
    EchoportGuardConfirmConfig,
    deploy_echoport_command_guard,
    deploy_echoport_command_guard_confirm,
    live_state,
    rust_check_command,
)
from ops_deploy.helpers.probes import FAILED
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost
from tests.test_base_echoport_command_guard import (
    DEPLOY_KEY,
    FORCED,
    OTHER,
    POLICY,
    STAGED,
    STAGING_POLICY,
    converged,
)

SHA = "a" * 64
VERSION = "0.2.0"
ROOT = RUST_INSTALL_ROOT
BINARY = f"{ROOT}/{VERSION}/{RUST_NAME}"
SHADOW = f"{BINARY} --shadow {POLICY} {FORCED}"
RUST = f"{BINARY} {POLICY}"
KEYS = "/root/.ssh/authorized_keys"
CHECK_SCRIPT = Path(__file__).parents[1] / "src/ops_deploy/base/files/echoport_rust_guard_check.py"
INSTALL = f"install --name {RUST_NAME} --root {ROOT}"
PIN = f"pin --name {RUST_NAME} --root {ROOT} --consumer {RUST_CONSUMER}"
PRUNE = f"prune --name {RUST_NAME} --root {ROOT}"


def guard(**overrides: Any) -> EchoportCommandGuardConfig:
    values: dict[str, Any] = {"policy": STAGING_POLICY}
    values.update(overrides)
    return EchoportCommandGuardConfig(**values)


def rust(impl: str = "python", **overrides: Any) -> EchoportCommandGuardConfig:
    return guard(impl=impl, rust_version=VERSION, rust_sha256=SHA, **overrides)


def line(command: str, key: str = DEPLOY_KEY) -> str:
    return f'from="100.93.155.101",restrict,command="{command}" {key} deploy@macmini backup automation'


def keys(*lines: str) -> str:
    return "\n".join([f"{OTHER} jochen@studio", *lines]) + "\n"


# --- config and forced command ------------------------------------------------


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"impl": "shadow"}, "needs rust_version"),
        ({"impl": "rust", "rust_version": VERSION}, "needs rust_version and either"),
        ({"impl": "rust", "rust_version": "v0.2", "rust_sha256": SHA}, "release version"),
        ({"impl": "shadow", "rust_version": VERSION, "rust_sha256": SHA, "rust_install_root": "/"}, "install_root"),
        (
            {"impl": "shadow", "rust_version": VERSION, "rust_sha256": SHA, "rust_install_root": "/opt/a b"},
            "install_root",
        ),
        ({"impl": "rust", "rust_version": VERSION, "rust_sha256": SHA, "rust_keep_versions": 0}, "keep_versions"),
        ({"impl": "lua"}, "impl"),
    ],
)
def test_shadow_and_rust_need_usable_rust_inputs(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        guard(**overrides)


def test_python_accepts_unusable_rust_inputs_and_reports_them() -> None:
    cfg = guard(rust_version="not-a-version", rust_install_root="/", rust_keep_versions=0)

    problems = cfg.rust_problems()

    assert len(problems) == 3
    assert cfg.forced_command() == FORCED


def test_a_local_archive_replaces_the_checksum(tmp_path: Path) -> None:
    archive = tmp_path / "guard.tar.gz"
    cfg = guard(impl="rust", rust_version=VERSION, rust_local_archive=archive)

    assert cfg.rust_binary == BINARY


def test_forced_command_shapes() -> None:
    # forced_command.yml: python byte for byte, shadow wraps it, rust replaces it.
    assert rust("python").forced_command() == FORCED
    assert rust("shadow").forced_command() == SHADOW
    assert rust("rust").forced_command() == RUST


# --- the deploy: rust.yml -------------------------------------------------------


def deploy(cfg: EchoportCommandGuardConfig, extra: dict[str, Any] | None = None) -> FakeRun:
    return run_deploy_fake(deploy_echoport_command_guard, cfg, responses={**(extra or {}), **converged(cfg)})


def commands_of(run: FakeRun, action: str) -> list[str]:
    return [c for c in run.executed_commands if f" - {action} " in c]


def test_python_without_rust_version_plans_no_rust_step() -> None:
    run = deploy(guard())

    assert run.succeeded, run.error
    assert not any(RUST_NAME in c for c in run.executed_commands + run.fact_commands)


def test_python_with_a_release_installs_softly_and_checks_it() -> None:
    cfg = rust("python")

    run = deploy(cfg)

    assert run.succeeded, run.error
    (install,) = commands_of(run, "install")
    argv = shlex.split(install)
    assert argv[argv.index("--version") + 1] == VERSION
    assert argv[argv.index("--sha256") + 1] == SHA
    assert "--soft" in argv
    assert rust_check_command(cfg) in run.executed_commands
    assert [s for c, s in run.stdin if c == rust_check_command(cfg)] == [RUST_CHECK_SCRIPT]
    # Install, then the check, then the policy: never a pin, never a prune.
    order = [op.name for op in run.ops]
    assert order.index(f"Echoport remote command guard | Install {RUST_NAME} {VERSION}") < order.index(
        f"Echoport remote command guard | Check the {RUST_NAME} {VERSION} binary and the policy"
    )
    assert not commands_of(run, "pin")
    assert not commands_of(run, "prune")


@pytest.mark.parametrize("impl", ["shadow", "rust"])
def test_shadow_and_rust_install_hard(impl: str) -> None:
    run = deploy(rust(impl))

    assert run.succeeded, run.error
    (install,) = commands_of(run, "install")
    assert "--soft" not in shlex.split(install)


def test_converged_release_changes_nothing() -> None:
    cfg = rust("shadow")
    extra = {
        **fakehost.directory(f"{ROOT}/{VERSION}"),
        f"--sha256 {SHA} --version {VERSION} --validate-user nobody --check": ["current"],
    }

    run = deploy(cfg, extra)

    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []


def test_a_failed_check_stops_shadow_before_the_policy() -> None:
    cfg = rust("shadow")
    responses = {**converged(cfg), **fakehost.file(POLICY, '{"units": []}\n')}
    refused = {"stderr": ["the Rust guard refuses the policy"], "success": False}
    responses = {rust_check_command(cfg): refused, **responses}

    run = run_deploy_fake(deploy_echoport_command_guard, cfg, responses=responses)

    assert not run.succeeded
    assert STAGED not in run.uploaded_paths


def test_a_failed_check_only_warns_with_python() -> None:
    cfg = rust("python")
    responses = {**converged(cfg), **fakehost.file(POLICY, '{"units": []}\n')}
    responses = {rust_check_command(cfg): {"stderr": ["refused"], "success": False}, **responses}

    run = run_deploy_fake(deploy_echoport_command_guard, cfg, responses=responses)

    # The failed check is reported (an ignored error) and the deploy goes on.
    assert run.error is None
    check = f"Echoport remote command guard | Check the {RUST_NAME} {VERSION} binary and the policy"
    assert not run.op(check).succeeded
    assert STAGED in run.uploaded_paths


def test_a_failed_soft_install_skips_the_check() -> None:
    cfg = rust("python")

    run = deploy(cfg, {INSTALL: {"stdout": ["failed the archive has another sha256"], "success": True}})

    assert run.succeeded, run.error
    assert rust_check_command(cfg) not in run.executed_commands
    assert STAGED not in run.uploaded_paths  # the converged policy stays


def test_python_with_unusable_rust_inputs_skips_the_rust_steps(caplog: pytest.LogCaptureFixture) -> None:
    run = deploy(guard(rust_version="not-a-version"))

    assert run.succeeded, run.error
    assert not any(RUST_NAME in c for c in run.executed_commands)
    assert "the Rust guard inputs are invalid" in caplog.text


# --- the host check script ------------------------------------------------------


def check_module() -> types.ModuleType:
    module = types.ModuleType("echoport_rust_guard_check")
    exec(compile(CHECK_SCRIPT.read_text(), str(CHECK_SCRIPT), "exec"), module.__dict__)
    return module


def fake_stat(mode: int, uid: int = 0, gid: int = 0) -> os.stat_result:
    return os.stat_result((mode, 0, 0, 1, uid, gid, 0, 0, 0, 0))


DIR, FILE = stat.S_IFDIR | 0o755, stat.S_IFREG | 0o755


def tree(**changes: os.stat_result) -> dict[str, os.stat_result]:
    entries = {
        BINARY: fake_stat(FILE),
        f"{ROOT}/{VERSION}": fake_stat(DIR),
        ROOT: fake_stat(DIR),
        "/usr/local/lib": fake_stat(DIR),
        "/usr/local": fake_stat(DIR),
        "/usr": fake_stat(DIR),
        "/": fake_stat(DIR),
    }
    entries.update(changes)
    return entries


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({}, None),
        ({"/usr": fake_stat(stat.S_IFDIR | 0o777)}, "group- or world-writable"),
        ({"/usr/local": fake_stat(stat.S_IFDIR | 0o755, uid=1000)}, "belong to root"),
        ({ROOT: fake_stat(stat.S_IFLNK | 0o777)}, "no symlink"),
        ({ROOT: fake_stat(stat.S_IFDIR | 0o700)}, "root:root and 0755"),
        ({f"{ROOT}/{VERSION}": fake_stat(DIR, gid=1)}, "root:root and 0755"),
        ({BINARY: fake_stat(stat.S_IFREG | 0o750)}, "root:root and 0755"),
        ({BINARY: fake_stat(DIR)}, "root:root and 0755"),
    ],
)
def test_path_chain_must_be_roots_alone(changes: dict[str, os.stat_result], message: str | None) -> None:
    module = check_module()
    entries = tree(**changes)

    def lstat(path: str) -> os.stat_result:
        return entries[path]

    if message is None:
        module.check_path(BINARY, lstat)
    else:
        with pytest.raises(module.Refused, match=message):
            module.check_path(BINARY, lstat)


def test_a_missing_component_is_refused() -> None:
    module = check_module()

    def lstat(path: str) -> os.stat_result:
        raise FileNotFoundError(2, "No such file or directory")

    with pytest.raises(module.Refused, match="cannot be read"):
        module.check_path(BINARY, lstat)


@pytest.mark.parametrize("path", ["relative/guard", "/usr/local/../lib/guard", "/usr//guard"])
def test_the_binary_path_must_be_normalised(path: str) -> None:
    module = check_module()
    with pytest.raises(module.Refused, match="normalised"):
        module.path_chain(path)


def test_check_policy_runs_the_binary_on_a_removed_scratch_copy(tmp_path: Path) -> None:
    module = check_module()
    seen = tmp_path / "seen"
    binary = tmp_path / "guard"
    paths = tmp_path / "paths"
    binary.write_text(
        "#!/bin/sh\n"
        f'echo "$2" >>{paths}\n'
        f'stat -f %Lp "$2" 2>/dev/null >{seen} || stat -c %a "$2" >{seen}\n'
        f'cat "$2" >>{seen}\n'
        'grep -q bad "$2" && { echo "unknown unit" >&2; exit 2; }\n'
        "exit 0\n"
    )
    binary.chmod(0o755)

    module.check_policy(str(binary), b'{"units": []}\n')
    mode, *content = seen.read_text().splitlines()
    assert mode == "600"
    assert content == ['{"units": []}']

    with pytest.raises(module.Refused, match=r"refuses the policy \(exit 2\): unknown unit"):
        module.check_policy(str(binary), b'{"units": ["bad"]}\n')
    # Both scratch copies are gone again, on the accept and the refuse path.
    scratch = paths.read_text().splitlines()
    assert len(scratch) == 2
    assert not any(Path(path).exists() for path in scratch)


def test_the_script_reports_and_exits_1() -> None:
    policy = base64.b64encode(b"{}\n").decode()
    done = subprocess.run(
        [sys.executable, "-I", "-", "/nonexistent/0.2.0/echoport-command-guard", policy],
        input=RUST_CHECK_SCRIPT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert done.returncode == 1
    assert done.stderr.startswith("echoport-command-guard check: /nonexistent")


def test_the_check_command_carries_the_policy_about_to_be_installed() -> None:
    cfg = rust("shadow")

    argv = shlex.split(rust_check_command(cfg))

    assert argv[:4] == ["/usr/bin/python3", "-I", "-", BINARY]
    assert base64.b64decode(argv[4]).decode() == cfg.policy_text()


# --- confirm_live -----------------------------------------------------------------


def confirm(
    cfg: EchoportCommandGuardConfig,
    content: str | None,
    *,
    root: bool = True,
    extra: dict[str, Any] | None = None,
) -> FakeRun:
    responses: dict[str, Any] = dict(extra or {})
    responses.setdefault(f"cat -- {KEYS}", [FAILED] if content is None else content.splitlines())
    responses.setdefault(f"realpath -- {ROOT}", [ROOT])
    if root:
        responses.setdefault(f"test -d {ROOT} && echo directory", ["directory"])
    responses.setdefault(f"{BINARY} --version", [f"{RUST_NAME} {VERSION} (0123456789abcdef)"])
    responses.update(fakehost.LINUX)
    return run_deploy_fake(
        deploy_echoport_command_guard_confirm,
        EchoportGuardConfirmConfig(guard=cfg, public_key=f"{DEPLOY_KEY} deploy@macmini"),
        responses=responses,
    )


def probes(run: FakeRun, action: str) -> list[list[str]]:
    return [shlex.split(c.split("( ", 1)[1].rsplit(" )", 1)[0]) for c in run.fact_commands if f" - {action} " in c]


def test_python_without_an_install_root_only_reads() -> None:
    run = confirm(guard(), keys(line(FORCED)), root=False)

    assert run.succeeded, run.error
    assert run.executed_commands == []
    # authorized_keys is read with output printing off, never as a fact (verbose prints facts).
    assert not any(KEYS in c for c in run.fact_commands)
    assert not probes(run, "pin")


@pytest.mark.parametrize(
    "content",
    [
        keys(),  # the line is missing
        keys(line(FORCED), line(FORCED)),  # twice
        keys(f"{DEPLOY_KEY} unrestricted", line(FORCED)),  # also unrestricted
        keys(line(SHADOW)),  # another command
        None,  # unreadable
    ],
)
def test_a_line_that_is_not_the_published_command_stops_before_any_pin(content: str | None) -> None:
    run = confirm(rust("python"), content)

    assert not run.succeeded
    assert "does not hold exactly one line for the pinned key" in str(run.error)
    assert run.executed_commands == []
    assert not probes(run, "pin")


def test_python_removes_the_pin_and_prunes_softly() -> None:
    cfg = rust("python")
    extra = {f"{PIN} --absent --check": [f"change {ROOT}/.pins/{RUST_CONSUMER}"]}

    run = confirm(cfg, keys(line(FORCED)), extra=extra)

    assert run.succeeded, run.error
    pin, prune = run.executed_commands
    assert shlex.split(pin)[3:] == ["pin", *shlex.split(PIN)[1:], "--absent"]
    # The configured version stays protected, as the role keeps it.
    assert shlex.split(prune)[3:] == [
        "prune",
        *("--name", RUST_NAME, "--root", ROOT, "--keep-versions", "3", "--protect", VERSION),
    ]


@pytest.mark.parametrize(("impl", "command"), [("shadow", SHADOW), ("rust", RUST)])
def test_shadow_and_rust_pin_the_target_after_the_version_check(impl: str, command: str) -> None:
    extra = {f"{PIN} --version {VERSION} --check": [f"change {ROOT}/.pins/{RUST_CONSUMER}"]}

    run = confirm(
        rust(impl), keys(line(command), f'command="{ROOT}/0.1.9/{RUST_NAME} {POLICY}" {OTHER} old'), extra=extra
    )

    assert run.succeeded, run.error
    pin, prune = run.executed_commands
    assert shlex.split(pin)[-2:] == ["--version", VERSION]
    argv = shlex.split(prune)
    # Every version a line names is protected, plus the target.
    assert [argv[i + 1] for i, a in enumerate(argv) if a == "--protect"] == ["0.1.9", VERSION]
    assert "--live-state-unknown" not in argv


def test_a_binary_that_is_not_the_target_version_stops_before_any_pin() -> None:
    run = confirm(rust("rust"), keys(line(RUST)), extra={f"{BINARY} --version": ["echoport-command-guard 0.1.9 (x)"]})

    assert not run.succeeded
    assert "expected echoport-command-guard 0.2.0" in str(run.error)
    assert run.executed_commands == []


@pytest.mark.parametrize(
    ("other_line", "extra"),
    [
        (f'command="sh -c {ROOT}/../evil" {OTHER} odd', {}),  # another mention of the root
        ("", {f"realpath -- {ROOT}": [FAILED]}),  # unresolvable root
    ],
)
def test_an_unknown_live_state_blocks_deletion(other_line: str, extra: dict[str, Any]) -> None:
    lines = [line(SHADOW)] + ([other_line] if other_line else [])
    run = confirm(rust("shadow"), keys(*lines), extra={**extra, f"{PRUNE}": ["remove x"]})

    assert run.succeeded, run.error
    (prune,) = [c for c in run.executed_commands if " - prune " in c]
    assert "--live-state-unknown" in shlex.split(prune)


def test_a_resolved_root_is_a_second_spelling() -> None:
    real = "/srv/guard"
    content = keys(line(SHADOW), f'command="{real}/0.1.8/{RUST_NAME} {POLICY}" {OTHER} via the real path')
    extra = {f"realpath -- {ROOT}": [real], f"{PRUNE}": ["remove x"]}

    run = confirm(rust("shadow"), content, extra=extra)

    assert run.succeeded, run.error
    (prune,) = [c for c in run.executed_commands if " - prune " in c]
    argv = shlex.split(prune)
    assert [argv[i + 1] for i, a in enumerate(argv) if a == "--protect"] == ["0.1.8", VERSION]


def test_a_failed_soft_pin_skips_the_prune() -> None:
    extra = {
        f"{PIN} --absent --check": [f"change {ROOT}/.pins/{RUST_CONSUMER}"],
        f"{PRUNE} --keep-versions 3 --protect {VERSION} --check": ["remove x"],
        f"{PIN} --absent": {"stderr": ["cannot write the pin"], "success": False},
    }

    run = confirm(rust("python"), keys(line(FORCED)), extra=extra)

    assert run.error is None
    assert [shlex.split(c)[3] for c in run.executed_commands] == ["pin"]


def test_a_failed_pin_stops_shadow() -> None:
    extra = {
        f"{PIN} --version {VERSION} --check": [f"change {ROOT}/.pins/{RUST_CONSUMER}"],
        f"{PIN} --version {VERSION}": {"stderr": ["cannot write the pin"], "success": False},
    }

    run = confirm(rust("shadow"), keys(line(SHADOW)), extra=extra)

    assert not run.succeeded
    assert [shlex.split(c)[3] for c in run.executed_commands] == ["pin"]


def test_invalid_rust_inputs_with_python_verify_the_line_only(caplog: pytest.LogCaptureFixture) -> None:
    run = confirm(guard(rust_version="nope"), keys(line(FORCED)))

    assert run.succeeded, run.error
    assert run.executed_commands == []
    assert "no pin moves and nothing is pruned" in caplog.text


def test_live_state_is_the_roles_filter() -> None:
    state = live_state(keys(line(SHADOW)), DEPLOY_KEY, [ROOT])

    assert state == {"commands": [[SHADOW]], "versions": [VERSION], "unknown": []}
    assert live_state(None, DEPLOY_KEY, [ROOT])["unknown"] == ["cannot read authorized_keys"]


def test_confirm_needs_a_public_key() -> None:
    with pytest.raises(ValidationError, match="public_key"):
        EchoportGuardConfirmConfig(guard=guard(), public_key="nope")
