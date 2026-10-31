"""Original work-source bytes, managed planning and non-disclosing declarations."""

from __future__ import annotations

import hashlib
import json
import os
from importlib.resources import files
from pathlib import Path
from typing import Any

import pyinfra.api.facts as sdk_facts
import pytest
import yaml
from pydantic import ValidationError
from pyinfra.facts.files import Directory, File, Link, Sha1File
from pyinfra.facts.server import Command, Os

from ops_deploy.services.daybook_work_source_access import (
    DaybookWorkSourceAccessConfig,
    DaybookWorkSourceCredentials,
    install_daybook_work_source_access,
)
from ops_deploy.services.daybook_work_source_access.deploy import PACKAGE, payload
from ops_deploy.testing import run_deploy_fake

ACCESS = "OwnedWorkSource123456"
SECRET = "owned-fixture-secret-" * 3


def credentials() -> DaybookWorkSourceCredentials:
    return DaybookWorkSourceCredentials(access_key=ACCESS, secret_key=SECRET)


def test_payload_is_only_original_request_and_repr_is_private() -> None:
    cfg = DaybookWorkSourceAccessConfig()
    values = credentials()
    request = payload(cfg, values)
    assert json.loads(request.reveal()) == {
        "access_key": ACCESS,
        "secret_key": SECRET,
        **cfg.model_dump(exclude={"python"}),
    }
    assert ACCESS not in repr(values) + repr(request)
    assert SECRET not in repr(values) + repr(request)


@pytest.mark.parametrize(
    "values",
    [
        {"access_key": "CHANGEME", "secret_key": SECRET},
        {"access_key": "short", "secret_key": SECRET},
        {"access_key": ACCESS, "secret_key": "short"},
        {"access_key": ACCESS, "secret_key": SECRET + "\n"},
        {"access_key": ACCESS, "secret_key": SECRET + "\x7f"},
    ],
)
def test_invalid_credentials_refuse_without_echo(values: dict[str, str]) -> None:
    with pytest.raises(ValidationError) as caught:
        DaybookWorkSourceCredentials(**values)
    assert values["access_key"] not in str(caught.value)
    assert values["secret_key"] not in str(caught.value)


@pytest.mark.parametrize(
    "values",
    [
        {"state_dir": "/tmp/foreign"},
        {"state_dir": "/var/lib/a/b"},
        {"alias": "local; bad"},
        {"python": "python"},
        {"mc_bin": "mc"},
    ],
)
def test_original_role_path_constraints(values: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        DaybookWorkSourceAccessConfig(**values)


def test_packaged_provisioner_and_defaults_match_actual_original_role() -> None:
    source = os.environ.get("OPS_LIBRARY_PATH")
    if not source:
        pytest.skip("OPS_LIBRARY_PATH unset; paired original-role check is separate")
    root = Path(source) / "roles/daybook_work_source_access_deploy"
    helper = files(PACKAGE).joinpath("files/provision_source.py").read_bytes()
    assert helper == (root / "files/provision_source.py").read_bytes()
    defaults = yaml.safe_load((root / "defaults/main.yml").read_text())
    cfg = DaybookWorkSourceAccessConfig()
    assert cfg.model_dump() == {key: defaults["daybook_work_source_access_" + key] for key in cfg.model_dump()}


def install_facts(monkeypatch: pytest.MonkeyPatch, facts: dict[Any, Any]) -> None:
    original = sdk_facts._get_fact

    def fact(
        state: Any,
        host: Any,
        cls: Any,
        args: Any = None,
        kwargs: Any = None,
        ensure_hosts: Any = None,
        apply_failed_hosts: bool = True,
    ) -> Any:
        key = (cls, ((kwargs or {}).get("path", (kwargs or {}).get("command")),))
        if key in facts:
            return facts[key]
        if cls in facts:
            return facts[cls]
        return original(state, host, cls, args, kwargs, ensure_hosts, apply_failed_hosts)

    monkeypatch.setattr(sdk_facts, "_get_fact", fact)


def test_current_repeat_still_queues_original_managed_provisioner_without_iam_facts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = DaybookWorkSourceAccessConfig()
    helper = cfg.state_dir + "/provision_source.py"
    body = files(PACKAGE).joinpath("files/provision_source.py").read_bytes()
    facts = {
        Os: "Linux",
        (Command, ("/usr/bin/id -u",)): "0",
        (Directory, (cfg.state_dir,)): {"mode": 700, "user": "root", "group": "root"},
        (Link, (cfg.state_dir,)): None,
        (File, (helper,)): {"mode": 700, "user": "root", "group": "root"},
        (Sha1File, (helper,)): hashlib.sha1(body).hexdigest(),
    }
    install_facts(monkeypatch, facts)
    run = run_deploy_fake(install_daybook_work_source_access, cfg, credentials=credentials())
    assert run.succeeded, run.error
    managed = run.mutating_changed_ops
    assert len(managed) == 1
    assert managed[0].endswith("Provision and verify original dedicated work source permissions")
    text = "\n".join(event.value for event in run.events) + repr([op.args for op in run.ops])
    assert ACCESS not in text
    assert SECRET not in text
    assert "admin user" not in text
    assert "admin policy" not in text
    assert helper in text


@pytest.mark.parametrize(
    ("os_name", "uid", "directory", "link"),
    [
        ("Darwin", "0", None, None),
        ("Linux", "501", None, None),
        ("Linux", "0", False, None),
        ("Linux", "0", None, {"link_target": "/foreign"}),
    ],
)
def test_original_host_and_redirected_state_refusals(
    os_name: str, uid: str, directory: object, link: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = DaybookWorkSourceAccessConfig()
    install_facts(
        monkeypatch,
        {
            Os: os_name,
            (Command, ("/usr/bin/id -u",)): uid,
            (Directory, (cfg.state_dir,)): directory,
            (Link, (cfg.state_dir,)): link,
        },
    )
    run = run_deploy_fake(
        install_daybook_work_source_access,
        cfg,
        credentials=credentials(),
    )
    assert not run.succeeded
    assert not run.mutating_changed_ops
