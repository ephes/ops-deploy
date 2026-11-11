import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.base.echoport_command_guard import (
    GUARD_SOURCE,
    EchoportCommandGuardConfig,
    check_policy,
    deploy_echoport_command_guard,
    forced_commands_for_key,
    policy_check_command,
    render_policy,
)
from ops_deploy.testing import run_deploy_fake
from tests import fakehost
from tests.fakehost import LINUX

GUARD = "/usr/local/sbin/echoport-remote-command-guard"
POLICY = "/etc/echoport/remote-command-guard.json"
STAGED = POLICY + ".ops-deploy-new"
PYTHON = "/usr/bin/python3"
FORCED = f"{PYTHON} -I {GUARD} {POLICY}"
# The shape of staging's inventory policy (ops-control host_vars/staging.yml).
STAGING_POLICY: dict[str, Any] = {
    "postgres": {
        "dump_databases": ["homepage", "python-podcast"],
        "restore_databases": {"homepage": "homepage", "python-podcast": "python-podcast"},
        "temp_file_prefixes": ["homepage", "pp"],
    },
    "units": ["marina.service"],
    "path_roots": [{"path": "/home/marina/site", "owner": "marina:marina"}],
}


def key(seed: int) -> str:
    name = b"ssh-ed25519"
    blob = len(name).to_bytes(4, "big") + name + (32).to_bytes(4, "big") + bytes([seed]) * 32
    return f"ssh-ed25519 {base64.b64encode(blob).decode()}"


DEPLOY_KEY, OTHER = key(1), key(2)


def config(**overrides: Any) -> EchoportCommandGuardConfig:
    values: dict[str, Any] = {"policy": STAGING_POLICY}
    values.update(overrides)
    return EchoportCommandGuardConfig(**values)


def converged(cfg: EchoportCommandGuardConfig) -> dict[str, Any]:
    guard = GUARD_SOURCE.read_text()
    return {
        **LINUX,
        f"test -x {PYTHON} && echo present": ["present"],
        **fakehost.directory("/usr/local/sbin"),
        **fakehost.file(GUARD, guard, mode="-rwxr-xr-x"),
        **fakehost.directory("/etc/echoport"),
        **fakehost.file(POLICY, cfg.policy_text()),
    }


# --- the vendored guard and the policy rendering ------------------------------


def test_vendored_guard_is_the_roles_program_byte_for_byte() -> None:
    # The drift manifest records the role; this pins what ops-deploy ships.
    digest = hashlib.sha256(GUARD_SOURCE.read_bytes()).hexdigest()
    assert digest.startswith("14d13eb135edd0e3")


def test_policy_renders_like_to_nice_json() -> None:
    text = render_policy({"units": ["b.service"], "postgres": {"dump_databases": ["ü"]}})

    assert text == (
        '{\n    "postgres": {\n        "dump_databases": [\n            "\\u00fc"\n        ]\n    },\n'
        '    "units": [\n        "b.service"\n    ]\n}\n'
    )


def test_empty_policy_allows_nothing_and_renders_an_empty_object() -> None:
    assert EchoportCommandGuardConfig().policy_text() == "{}\n"


@pytest.mark.parametrize(
    ("policy", "message"),
    [
        ({"shell": []}, "unknown keys"),
        ({"postgres": []}, "postgres must be a mapping"),
        ({"units": "marina.service"}, "units must be a list"),
        ({"units": ["marina service"]}, "refuses the policy"),
        ({"path_roots": [{"path": "relative", "owner": "a:b"}]}, "refuses the policy"),
    ],
)
def test_bad_policies_are_refused_while_planning(policy: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        config(policy=policy)


def test_controller_check_matches_the_guards_own_check(tmp_path: Path) -> None:
    for policy, ok in ((STAGING_POLICY, True), ({"units": ["bad unit"]}, False)):
        path = tmp_path / "policy.json"
        path.write_text(render_policy(policy))
        result = subprocess.run(
            [sys.executable, "-I", str(GUARD_SOURCE), "--check-policy", str(path)], capture_output=True, check=False
        )
        assert (result.returncode == 0) is ok
        if ok:
            check_policy(policy)
        else:
            with pytest.raises(ValueError, match="refuses"):
                check_policy(policy)


@pytest.mark.parametrize(
    "overrides",
    [
        {"impl": "shadow"},
        {"impl": "rust"},
        {"path": "/usr/local/sbin/guard with space"},
        {"policy_path": "relative.json"},
        {"python": '/usr/bin/python3"'},
    ],
)
def test_incomplete_or_unsafe_settings_are_refused(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        config(**overrides)


def test_forced_command_is_the_roles_python_command() -> None:
    assert config().forced_command() == FORCED


def test_scratch_forced_command_is_the_roles_scratch_fact() -> None:
    # ops-library forced_command.yml: echoport_remote_command_guard_scratch_forced_command.
    assert config().scratch_forced_command() == f"{PYTHON} -I {GUARD} --restore-scratch {POLICY}"


# --- reading the live line back (confirm_live) --------------------------------


def test_pinned_line_with_the_forced_command_is_found() -> None:
    content = (
        "# Managed by Ansible - local.ops_library.ssh_authorized_keys_manage\n"
        f"{OTHER} jochen@studio\n"
        f'from="100.93.155.101",restrict,command="{FORCED}" {DEPLOY_KEY} deploy@macmini backup automation\n'
    )

    assert forced_commands_for_key(content, f"{DEPLOY_KEY} deploy@macmini") == [[FORCED]]


def test_unrestricted_duplicate_and_foreign_lines_are_reported() -> None:
    content = (
        f'restrict,command="{FORCED}" {DEPLOY_KEY} pinned\r\n'
        f"{DEPLOY_KEY} unrestricted copy\n"
        f'command="/bin/other" {OTHER} other\n'
        '   \n# command="x" ' + DEPLOY_KEY + "\n"
    )

    assert forced_commands_for_key(content, DEPLOY_KEY) == [[FORCED], []]


def test_quoted_quotes_and_malformed_options() -> None:
    content = (
        f'command="echo \\"hi\\"",restrict {DEPLOY_KEY} quoted\n'
        f'command="unterminated {DEPLOY_KEY} broken\n'
        f"command=bare {DEPLOY_KEY} bare\n"
    )

    assert forced_commands_for_key(content, DEPLOY_KEY) == [['echo "hi"']]


def test_public_key_must_be_a_key() -> None:
    with pytest.raises(ValueError, match="public_key"):
        forced_commands_for_key("", "not a key")


# --- the deploy ------------------------------------------------------------------


def test_converged_host_changes_nothing() -> None:
    cfg = config()

    run = run_deploy_fake(deploy_echoport_command_guard, cfg, responses=converged(cfg))

    assert run.succeeded, run.error
    assert run.changed_ops == []


def test_changed_policy_is_staged_checked_by_the_installed_guard_then_moved() -> None:
    cfg = config()
    responses = converged(cfg)
    responses.update(fakehost.file(POLICY, render_policy({"units": ["old.service"]})))

    run = run_deploy_fake(deploy_echoport_command_guard, cfg, responses=responses)

    assert run.succeeded, run.error
    assert [dest for dest, _ in run.uploads] == [STAGED]
    assert run.uploads[0][1] == cfg.policy_text().encode()
    assert policy_check_command(cfg, STAGED) in run.executed_commands
    assert not any(dest == GUARD for dest, _ in run.uploads)


def test_policy_check_command_moves_only_a_valid_policy(tmp_path: Path) -> None:
    live = tmp_path / "policy.json"
    staged = tmp_path / "policy.json.ops-deploy-new"
    guard = tmp_path / "guard"
    guard.write_text(GUARD_SOURCE.read_text())
    cfg = config(path=str(guard), policy_path=str(live), python=sys.executable)
    live.write_text("{}\n")

    staged.write_text(render_policy({"units": ["bad unit"]}))
    assert subprocess.run(["sh", "-c", policy_check_command(cfg, str(staged))], check=False).returncode == 1
    assert live.read_text() == "{}\n"
    assert not staged.exists()

    staged.write_text(cfg.policy_text())
    assert subprocess.run(["sh", "-c", policy_check_command(cfg, str(staged))], check=False).returncode == 0
    assert json.loads(live.read_text()) == STAGING_POLICY
    assert not staged.exists()


def test_wrong_mode_rewrites_the_policy() -> None:
    cfg = config()
    responses = converged(cfg)
    responses.update(fakehost.stat(POLICY, mode="-rw-rw-rw-"))

    run = run_deploy_fake(deploy_echoport_command_guard, cfg, responses=responses)

    assert run.succeeded, run.error
    assert [dest for dest, _ in run.uploads] == [STAGED]


def test_older_guard_is_replaced() -> None:
    cfg = config()
    responses = converged(cfg)
    responses.update(fakehost.file(GUARD, "#!/usr/bin/python3 -I\n# older guard\n", mode="-rwxr-xr-x"))

    run = run_deploy_fake(deploy_echoport_command_guard, cfg, responses=responses)

    assert run.succeeded, run.error
    assert [dest for dest, _ in run.uploads] == [GUARD]
    assert run.uploads[0][1] == GUARD_SOURCE.read_bytes()


def test_missing_python_is_refused() -> None:
    cfg = config()
    responses = converged(cfg)
    responses.pop(f"test -x {PYTHON} && echo present")

    run = run_deploy_fake(deploy_echoport_command_guard, cfg, responses=responses)

    assert not run.succeeded
    assert "needs Python 3" in str(run.error)


def test_symlinked_python_is_accepted() -> None:
    # Debian/Ubuntu: /usr/bin/python3 -> python3.12; the check follows it.
    cfg = config()
    responses = {**converged(cfg), **fakehost.symlink(PYTHON, "python3.12")}

    run = run_deploy_fake(deploy_echoport_command_guard, cfg, responses=responses)

    assert run.succeeded, run.error
    assert run.changed_ops == []


def test_policy_path_that_is_not_a_file_is_refused() -> None:
    cfg = config()
    responses = converged(cfg)
    responses.update(fakehost.directory(POLICY))

    run = run_deploy_fake(deploy_echoport_command_guard, cfg, responses=responses)

    assert not run.succeeded
    assert "not a regular file" in str(run.error)


def test_non_linux_is_refused() -> None:
    cfg = config()
    responses = {**converged(cfg), "uname -s": ["Darwin"]}

    run = run_deploy_fake(deploy_echoport_command_guard, cfg, responses=responses)

    assert not run.succeeded
