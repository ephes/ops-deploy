"""Bound-source, site-free identity child tests use synthetic code/files only."""

from __future__ import annotations

import hashlib
import json
import os
import py_compile
import runpy
import subprocess
import sys
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest

ASSET = files("ops_deploy.services.daybook_sessions").joinpath("files/identity_host.py")
MODULE = runpy.run_path(str(ASSET))


@pytest.fixture
def identity(tmp_path: Path) -> tuple[dict[str, Any], Path]:
    root = tmp_path.resolve()
    package = root / "checkout/src/daybook"
    package.mkdir(parents=True)
    hashes = {}
    for name in MODULE["MODULES"]:
        path = package / (name + ".py")
        path.write_text("MARK=1\n")
        hashes["src/daybook/" + name + ".py"] = hashlib.sha256(path.read_bytes()).hexdigest()
    helper = root / "helper.py"
    helper.write_text(
        "from daybook import composer\n"
        "def verify(*paths):\n"
        " assert composer.MARK==1 and len(paths)==3\n"
        " return {'schema_version':1,'status':'attestation_verified','plan_hash':'" + "a" * 64 + "'}\n"
    )
    data = {
        "python_version": ".".join(str(n) for n in sys.version_info[:3]),
        "checkout": str(root / "checkout"),
        "module_hashes": hashes,
        "helper": str(helper),
        "helper_sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
        "paths": [str(root / name) for name in ("seed.json", "plan.json", "attestation.json")],
    }
    return data, root


def child(data: dict[str, Any], root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", "-B", "-S", str(ASSET)],
        input=json.dumps(data),
        capture_output=True,
        text=True,
        timeout=10,
        env={**os.environ, "PYTHONPATH": str(root)},
        cwd=root,
    )


def test_verified_source_bytes_bypass_valid_unbound_bytecode_and_site_startup(
    identity: tuple[dict[str, Any], Path],
) -> None:
    data, root = identity
    composer = root / "checkout/src/daybook/composer.py"
    evil = root / "evil.py"
    evil.write_text("boom()\n")  # same length, different code
    os.utime(evil, ns=(composer.stat().st_atime_ns, composer.stat().st_mtime_ns))
    cache = (
        composer.parent
        / "__pycache__"
        / ("composer.cpython-" + str(sys.version_info.major) + str(sys.version_info.minor) + ".pyc")
    )
    cache.parent.mkdir()
    py_compile.compile(str(evil), cfile=str(cache), dfile=str(composer), doraise=True)
    (root / "sitecustomize.py").write_text("raise RuntimeError('unbound site startup executed')\n")
    result = child(data, root)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"schema_version": 1, "status": "attestation_verified", "plan_hash": "a" * 64}
    assert result.stderr == ""
    assert cache.is_file()


@pytest.mark.parametrize("fault", ["hash", "extra_module", "helper", "version", "link"])
def test_binding_fault_refuses_before_any_application_module_execution(
    identity: tuple[dict[str, Any], Path],
    fault: str,
) -> None:
    data, root = identity
    initial = root / "checkout/src/daybook/__init__.py"
    initial.write_text("raise AssertionError('module must not execute before all bindings pass')\n")
    data["module_hashes"]["src/daybook/__init__.py"] = hashlib.sha256(initial.read_bytes()).hexdigest()
    if fault == "hash":
        data["module_hashes"]["src/daybook/cast_client.py"] = "0" * 64
    elif fault == "extra_module":
        data["module_hashes"]["src/daybook/operations_runtime.py"] = "0" * 64
    elif fault == "helper":
        data["helper_sha256"] = "0" * 64
    elif fault == "version":
        data["python_version"] = "0.0.0"
    else:
        target = root / "helper-copy.py"
        target.write_bytes(Path(data["helper"]).read_bytes())
        Path(data["helper"]).unlink()
        Path(data["helper"]).symlink_to(target)
    if fault == "link":
        with pytest.raises(OSError, match=r"\[Errno "):
            MODULE["verify"](data)
    else:
        with pytest.raises(
            MODULE["IdentityError"], match=r"^sessions_identity_(code_binding_failed|interpreter_mismatch)$"
        ):
            MODULE["verify"](data)
    result = child(data, root)
    assert result.returncode == 1
    assert json.loads(result.stdout) == {"schema_version": 1, "status": "failed", "reason_code": "identity_gate_failed"}
    assert result.stderr == ""
    assert "module must not execute" not in result.stdout


def test_application_exception_is_fixed_category_without_private_message(
    identity: tuple[dict[str, Any], Path],
) -> None:
    data, root = identity
    private = "UNUSABLE-OWNED-PRIVATE-IDENTITY"
    helper = Path(data["helper"])
    helper.write_text("def verify(*paths):raise ValueError('" + private + "')\n")
    data["helper_sha256"] = hashlib.sha256(helper.read_bytes()).hexdigest()
    result = child(data, root)
    assert result.returncode == 1
    assert json.loads(result.stdout)["reason_code"] == "identity_gate_failed"
    assert result.stderr == ""
    assert private not in result.stdout


@pytest.mark.parametrize("valid", [True, False])
def test_bound_pinned_policy_validator_does_not_open_identity_helper_or_store(
    identity: tuple[dict[str, Any], Path], valid: bool
) -> None:
    data, root = identity
    policy = root / "checkout/src/daybook/weeknotes_privacy.py"
    policy.write_text(
        "def public_repository_policy_from_env(env):\n"
        " assert env=={'DAYBOOK_WEEKNOTES_PUBLIC_REPOSITORIES_JSON':'OWNED-PUBLIC-POLICY'}\n"
        + (" return object()\n" if valid else " raise ValueError('UNUSABLE-PRIVATE-POLICY-ERROR')\n")
    )
    data["module_hashes"]["src/daybook/weeknotes_privacy.py"] = hashlib.sha256(policy.read_bytes()).hexdigest()
    Path(data["helper"]).unlink()
    data.update(
        action="policy", policy_environment={"DAYBOOK_WEEKNOTES_PUBLIC_REPOSITORIES_JSON": "OWNED-PUBLIC-POLICY"}
    )
    result = child(data, root)
    assert result.returncode == (0 if valid else 1)
    assert result.stderr == ""
    assert "UNUSABLE" not in result.stdout
    assert "OWNED-PUBLIC-POLICY" not in result.stdout
    if valid:
        assert json.loads(result.stdout) == {"schema_version": 1, "policy_verified": True}
    else:
        assert json.loads(result.stdout) == {
            "schema_version": 1,
            "status": "failed",
            "reason_code": "identity_gate_failed",
        }
    assert not any(Path(p).exists() for p in data["paths"])


def test_unknown_bound_loader_action_refuses_before_application_import(
    identity: tuple[dict[str, Any], Path],
) -> None:
    data, root = identity
    (root / "checkout/src/daybook/__init__.py").write_text("raise AssertionError('no app import')\n")
    data["action"] = "prepare"
    with pytest.raises(MODULE["IdentityError"], match=r"^sessions_identity_request_invalid$"):
        MODULE["verify"](data)
