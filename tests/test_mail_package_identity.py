"""Package-owned Postfix identities are modified after known creation, never replaced."""

from __future__ import annotations

import grp
import os
import pwd
import shlex
import subprocess
import sys
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest
from pyinfra.api import DeployError, deploy
from pyinfra.operations import server

from ops_deploy.services import _mail_config
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost


def existing(groups: str) -> dict[str, Any]:
    return {
        **fakehost.LINUX,
        "cat /etc/group": ["root:x:0:", "postfix:x:901:", "other:x:902:postfix", "opendkim:x:903:postfix"],
        "cat /etc/passwd | cut": ["postfix:x:901:901::/var/spool/postfix:/usr/sbin/nologin|postfix|" + groups + "||!"],
    }


def run_existing(groups: str) -> FakeRun:
    @deploy("Mail group qualification")
    def role() -> None:
        _mail_config.postfix_group_access("opendkim")

    return run_deploy_fake(role, responses=existing(groups))


def test_current_supplemental_group_preserves_absent_home_and_has_no_commands() -> None:
    result = run_existing("postfix other opendkim")
    assert result.succeeded, result.error
    assert result.executed_commands == []
    assert not result.mutating_changed_ops


def test_missing_supplemental_group_appends_without_home_or_identity_rewrite() -> None:
    result = run_existing("postfix other")
    assert result.succeeded, result.error
    assert result.executed_commands == ["usermod -a -G opendkim postfix"]


def pending_program(monkeypatch: pytest.MonkeyPatch) -> tuple[str, str]:
    monkeypatch.setattr(_mail_config, "host", SimpleNamespace(get_fact=lambda fact: {}))
    shell = Mock()
    monkeypatch.setattr(server, "shell", shell)
    _mail_config.postfix_group_access("opendkim", postfix_package_pending=True)
    command = shlex.split(shell.call_args.kwargs["commands"][0])
    assert command[:3] == ["python3", "-I", "-c"]
    return command[3], command[4]


def test_missing_existing_identity_refuses_before_any_user_command(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_mail_config, "host", SimpleNamespace(get_fact=lambda fact: {}))
    shell = Mock()
    monkeypatch.setattr(server, "shell", shell)
    with pytest.raises(DeployError, match="no substitute account"):
        _mail_config.postfix_group_access("opendkim")
    shell.assert_not_called()


@pytest.mark.parametrize("group_current", [True, False])
def test_known_package_creation_rechecks_native_group_membership(
    monkeypatch: pytest.MonkeyPatch,
    group_current: bool,
) -> None:
    script, group = pending_program(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["-c", group])
    monkeypatch.setattr(pwd, "getpwnam", lambda name: SimpleNamespace(pw_name=name, pw_gid=901))
    monkeypatch.setattr(grp, "getgrnam", lambda name: SimpleNamespace(gr_name=name, gr_gid=903))
    monkeypatch.setattr(os, "getgrouplist", lambda user, primary: [901, 902, *([903] if group_current else [])])
    command = Mock(return_value=subprocess.CompletedProcess([], 0, "", ""))
    monkeypatch.setattr(subprocess, "run", command)
    exec(compile(script, "owned-mail-package-check", "exec"), {})
    if group_current:
        command.assert_not_called()
    else:
        assert len(command.call_args_list) == 3
        assert command.call_args_list[-1].args[0] == ["usermod", "-a", "-G", "opendkim", "postfix"]
        assert command.call_args_list[1].args[0][-2:] == ["/dev/null", "/var/lib/ops-deploy/mail-core/postfix.restart"]


@pytest.mark.parametrize("missing", ["user", "group"])
def test_failed_package_identity_cannot_create_a_substitute_account(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    missing: str,
) -> None:
    script, group = pending_program(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["-c", group])
    user = Mock(return_value=SimpleNamespace(pw_name="postfix", pw_gid=901))
    lookup = Mock(return_value=SimpleNamespace(gr_name="opendkim", gr_gid=903))
    (user if missing == "user" else lookup).side_effect = KeyError("owned missing package identity")
    monkeypatch.setattr(pwd, "getpwnam", user)
    monkeypatch.setattr(grp, "getgrnam", lookup)
    command = Mock()
    monkeypatch.setattr(subprocess, "run", command)
    with pytest.raises(SystemExit) as result:
        exec(compile(script, "owned-mail-package-check", "exec"), {})
    assert result.value.code == 1
    assert "no substitute account created" in capsys.readouterr().err
    command.assert_not_called()
