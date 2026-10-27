"""Real archive lifecycle failures, retained fallback and authoritative render parity."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import tarfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlunsplit

import pytest
from pyinfra.api import deploy

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.helpers.traefik import route_guard_command
from ops_deploy.services.mailgun_relay import MailgunRelayConfig
from ops_deploy.services.mailgun_relay.deploy import _ingress, render_role, validate_secrets
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

REF = SecretRef("fixture.yml")


def values(**changes: str) -> SecretValues:
    return SecretValues(
        REF,
        {
            "smtp_username": "fixture@example.test",
            "smtp_password": "fixture-pass",
            "envelope_sender": "fixture@example.test",
            "tokens": json.dumps(
                [
                    {
                        "label": "fixture",
                        "token_sha256": "a" * 64,
                        "mailgun_domains": ["mg.example.test"],
                        "allowed_from_domains": ["example.test"],
                        "allowed_from_addresses": ["fixture@example.test"],
                    }
                ]
            ),
            **changes,
        },
    )


def config(**changes: Any) -> MailgunRelayConfig:
    return MailgunRelayConfig(secrets=REF, **changes)


@pytest.mark.parametrize(
    "change",
    [
        {"impl": "rust"},
        {"rust_version": "../1.2.3"},
        {"rust_version": "1.2.3"},
        {"rust_sha256": "a" * 64},
        {"rust_keep_versions": True},
        {"rust_install_root": "/opt/apps/mailgun-relay/site/releases"},
        {"rust_release_url": urlunsplit(("https", "user:pass@example.test", "/file", "", ""))},
        {"ingress_backend_url": "http://127.0.0.1:8085\nunsafe"},
    ],
)
def test_invalid_config_refused(change: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match=r"validation error|selection unchanged"):
        config(**change)


def test_python_preservation_never_expires() -> None:
    cfg = config(impl="rust", rust_version="0.2.2", rust_sha256="a" * 64)
    assert cfg.python_deploy == "preserve"
    assert cfg.source_path is None
    assert not any("date" in name or "deadline" in name for name in type(cfg).model_fields)


@pytest.mark.parametrize(
    "change",
    [
        {"smtp_password": 'cannot"inject'},
        {"smtp_username": "injected\nline"},
        {"envelope_sender": "two addresses@example.test"},
        {"tokens": "{}"},
        {"tokens": '[{"label":"private-value","token_sha256":"private-value"}]'},
    ],
)
def test_secret_validation_does_not_echo_values(change: dict[str, str]) -> None:
    with pytest.raises(ValueError, match=r"credentials|envelope_sender|tokens") as caught:
        validate_secrets(values(**change))
    for value in change.values():
        assert value not in str(caught.value)


def test_role_defaults_and_templates() -> None:
    cfg = config(impl="rust", rust_version="0.2.2", rust_sha256="a" * 64, ingress_enabled=True)
    inputs = validate_secrets(values())
    env = render_role("mailgun-relay.env.j2", cfg, inputs)
    assert "MAILGUN_RELAY_SMTP_STARTTLS=true\n" in env
    assert "MAX_CONCURRENCY" not in env
    assert "MAILGUN_RELAY_SMTP_MAX_CONCURRENCY=4\n" in render_role(
        "mailgun-relay.env.j2",
        config(smtp_max_concurrency=4),
        inputs,
    )
    assert "ExecStart=/opt/mailgun-relay/0.2.2/mailgun-relay" in render_role("impl.conf.j2", cfg)
    assert "MALLOC_MMAP_THRESHOLD_=131072" in render_role("impl.conf.j2", cfg)
    unit = render_role("mailgun-relay.service.j2", cfg)
    assert "ExecStart=/opt/apps/mailgun-relay/site/.venv/bin/python -m mailgun_relay" in unit
    assert "ProtectSystem=strict\n" in unit
    assert "ReadWritePaths=\n" in unit
    route = render_role("traefik-mailgun-relay.yml.j2", cfg)
    assert "basicAuth" not in route
    assert "stsPreload" not in route
    assert "maxRequestBodyBytes: 26214400" in route


def test_optional_actual_role_template_bytes() -> None:
    library = os.environ.get("OPS_LIBRARY_PATH")
    if not library:
        pytest.skip("OPS_LIBRARY_PATH not set")
    packaged = Path(__file__).parents[1] / "src/ops_deploy/services/mailgun_relay/templates"
    count = 0
    for role in ("mailgun_relay_deploy", "mailgun_relay_ingress_deploy"):
        for template in (Path(library) / "roles" / role / "templates").glob("*.j2"):
            assert template.read_bytes() == (packaged / template.name).read_bytes()
            count += 1
    assert count == 5


def test_ingress_guards_changed_route_and_skips_unchanged() -> None:
    cfg = config(ingress_enabled=True)
    text = render_role("traefik-mailgun-relay.yml.j2", cfg)
    path = str(cfg.ingress_traefik_config_path)

    @deploy("Relay ingress")
    def write() -> None:
        _ingress(cfg, text)

    base = {**fakehost.LINUX, **fakehost.directory(str(cfg.ingress_traefik_config_path.parent))}
    changed = run_deploy_fake(write, responses={**base, **fakehost.file(path, "old\n")})
    assert changed.succeeded, changed.error
    assert changed.executed_commands[0] == route_guard_command()
    assert changed.uploaded_paths == [path]
    held = run_deploy_fake(
        write,
        responses={**base, **fakehost.file(path, "old\n"), "traefik-route-guard": {"success": False}},
    )
    assert not held.succeeded
    assert held.uploaded_paths == []
    same = run_deploy_fake(write, responses={**base, **fakehost.file(path, text)})
    assert same.succeeded, same.error
    assert same.executed_commands == []
    assert same.changed_ops == []


@pytest.fixture
def release_module() -> Any:
    path = Path(__file__).parents[1] / "src/ops_deploy/services/mailgun_relay/files/mailgun_release_host.py"
    spec = importlib.util.spec_from_file_location("relay_release", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def archive(tmp_path: Path, *, link: bool = False, extra: bool = False) -> Path:
    path = tmp_path / "release.tar.gz"
    with tarfile.open(path, "w:gz") as tar:
        for name in ["mailgun-relay", "LICENSE", *(["extra"] if extra else [])]:
            info = tarfile.TarInfo(name)
            body = b"synthetic-release"
            info.size = len(body)
            if link and name == "mailgun-relay":
                info.type = tarfile.SYMTYPE
                info.linkname = "/outside"
                info.size = 0
            tar.addfile(info, io.BytesIO(body) if info.isfile() else None)
    return path


def release_cfg(tmp_path: Path, source: Path) -> dict[str, Any]:
    root = tmp_path / "releases"
    root.mkdir()
    return {
        "root": str(root),
        "version": "1.2.3",
        "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "upload": str(source),
        "url": "https://example.test/unused",
        "impl": "rust",
    }


@pytest.fixture
def installer_module() -> Any:
    from types import ModuleType

    from ops_deploy.helpers.rust_release import HOST_SCRIPT

    module = ModuleType("shared_installer")
    exec(HOST_SCRIPT, module.__dict__)
    return module


def install(module: Any, cfg: dict[str, Any], *, soft: bool = False) -> int:
    args = [
        "install",
        "--name",
        "mailgun-relay",
        "--root",
        cfg["root"],
        "--version",
        cfg["version"],
        "--sha256",
        cfg["sha256"],
        "--upload",
        cfg["upload"],
        "--owner",
        str(os.getuid()),
        "--group",
        str(os.getgid()),
    ]
    return int(module.main([*args, *(["--soft"] if soft else [])]))


@pytest.mark.parametrize("failure", ["checksum", "symlink", "extra", "version"])
def test_shared_installer_failure_cleans_rejected_release(
    tmp_path: Path,
    installer_module: Any,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    source = archive(tmp_path, link=failure == "symlink", extra=failure == "extra")
    cfg = release_cfg(tmp_path, source)
    if failure == "checksum":
        cfg["sha256"] = "0" * 64

    def reject(*_: Any) -> None:
        raise ValueError("owned fixture version rejection")

    monkeypatch.setattr(installer_module, "validate", reject)
    assert install(installer_module, cfg) == 1
    assert list(Path(cfg["root"]).iterdir()) == []


def test_python_rollback_ignores_failed_shared_install(
    tmp_path: Path,
    installer_module: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    cfg = release_cfg(tmp_path, archive(tmp_path, link=True))
    assert install(installer_module, cfg, soft=True) == 0
    assert "failed " in capsys.readouterr().out
    assert list(Path(cfg["root"]).iterdir()) == []


@pytest.mark.parametrize("impl", ["rust", "python"])
def test_config_rejection_cleans_only_a_fresh_install_and_hides_details(
    tmp_path: Path,
    release_module: Any,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    impl: str,
) -> None:
    cfg = release_cfg(tmp_path, archive(tmp_path))
    cfg.update(impl=impl, fresh=True)
    dest = Path(cfg["root"]) / cfg["version"]
    dest.mkdir()
    (dest / ".archive-sha256").write_text(cfg["sha256"])

    def reject(*_: Any) -> None:
        raise ValueError("secret detail must not escape")

    monkeypatch.setattr(release_module, "validate", reject)
    if impl == "rust":
        with pytest.raises(ValueError, match="selection unchanged") as caught:
            release_module.candidate(cfg)
        assert "secret detail" not in str(caught.value)
    else:
        release_module.candidate(cfg)
        assert "failed candidate" in capsys.readouterr().out
    assert not dest.exists()


def test_installed_version_not_overwritten(tmp_path: Path, release_module: Any) -> None:
    cfg = release_cfg(tmp_path, archive(tmp_path))
    dest = Path(cfg["root"]) / cfg["version"]
    dest.mkdir()
    (dest / ".archive-sha256").write_text("existing-archive")
    (dest / "mailgun-relay").write_text("existing-binary")
    with pytest.raises(ValueError, match=r"validation error|selection unchanged"):
        release_module.candidate(cfg)
    assert (dest / "mailgun-relay").read_text() == "existing-binary"
    assert (dest / ".archive-sha256").read_text() == "existing-archive"


def test_prune_keeps_pin_live_previous_and_newest(
    tmp_path: Path,
    release_module: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "releases"
    root.mkdir()
    for index in range(7):
        path = root / f"0.2.{index}"
        path.mkdir()
        os.utime(path, (index, index))
    (root / "not-a-version").mkdir()
    (root / ".previous-version").write_text("0.2.0\n")
    monkeypatch.setattr(release_module.subprocess, "run", lambda *a, **k: SimpleNamespace(stdout="0"))
    cfg = {"root": str(root), "version": "0.2.1", "unit": "fixture", "keep": 3}
    assert {path.name for path in release_module.prunable(cfg)} == {"0.2.2", "0.2.3"}


def test_production_live_check_requires_exact_native_binary(
    release_module: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = {"root": "/opt/fixture", "version": "0.2.2", "unit": "fixture", "impl": "rust"}
    monkeypatch.setattr(release_module, "command", lambda argv: "active" if "is-active" in argv else "321")
    monkeypatch.setattr(release_module.os, "readlink", lambda _: "/opt/fixture/0.2.2/mailgun-relay")
    assert release_module.live(cfg) == "/opt/fixture/0.2.2/mailgun-relay"
    for wrong in ("/opt/fixture/0.2.1/mailgun-relay", "/mnt/lima-rosetta/rosetta", "/usr/bin/python3"):
        monkeypatch.setattr(release_module.os, "readlink", lambda _, target=wrong: target)
        with pytest.raises(ValueError, match="live executable"):
            release_module.live(cfg)


def test_pruning_projection_accounts_for_new_install_before_repeat(
    tmp_path: Path,
    release_module: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "releases"
    root.mkdir()
    for index in range(3):
        p = root / f"0.2.{index}"
        p.mkdir()
        os.utime(p, (index, index))
    dropin = tmp_path / "impl.conf"
    dropin.write_text(f"ExecStart={root}/0.2.2/mailgun-relay\n")
    (root / ".previous-version").write_text("0.2.0\n")
    monkeypatch.setattr(release_module.subprocess, "run", lambda *a, **k: SimpleNamespace(stdout="0"))
    cfg = {"root": str(root), "version": "0.2.3", "unit": "fixture", "keep": 2, "dropin": str(dropin), "impl": "rust"}
    assert {p.name for p in release_module.prunable(cfg, projected=True)} == {"0.2.0", "0.2.1"}
