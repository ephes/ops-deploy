"""Optional generic Echoport targets through the Django deploy entry point."""

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.services.django_site import DjangoSiteConfig, EchoportTarget, deploy_django_site
from ops_deploy.testing import RecordingRsyncRunner, run_deploy_fake
from tests import fakehost

CHECK = "if test -e /home/echoport/site/manage.py; then"
TARGET = {
    "name": "example-backup",
    "description": "Example site data",
    "db_path": "/home/example/site/db.sqlite3",
    "backup_files": ("/home/example/site/media", "/home/example/site/private"),
    "schedule": "30 3 * * *",
}


def config(tmp_path: Path, echoport: dict[str, Any] | None) -> DjangoSiteConfig:
    for name in ("manage.py", "pyproject.toml", "uv.lock", "config/wsgi.py"):
        path = tmp_path / name
        path.parent.mkdir(exist_ok=True)
        path.write_text("")
    # A mapping, as supplied by an ops-control SiteSpec.config.
    return DjangoSiteConfig.model_validate(
        {
            "service_name": "example_site",
            "title": "Example site",
            "user": "example",
            "group": "webdata",
            "home": "/home/example",
            "site_path": "/home/example/site",
            "source": {"path": tmp_path},
            "app": {"settings_module": "config.settings.production", "port": 10019},
            "route": {
                "fqdn": "example.com",
                "host_rule": "Host(`example.com`)",
                "public_reason": "Public example site",
            },
            "secrets": SecretRef("secrets/example.yml"),
            "echoport": echoport,
        }
    )


@pytest.mark.parametrize("state", ["pending", "unchanged"])
def test_target_upsert_and_convergence(tmp_path: Path, state: str) -> None:
    cfg = config(tmp_path, TARGET)
    assert cfg.secrets is not None
    run = run_deploy_fake(
        deploy_django_site,
        cfg,
        SecretValues(cfg.secrets, {"django_secret_key": "synthetic-example-key"}),
        rsync=RecordingRsyncRunner(),
        responses={**fakehost.LINUX, CHECK: [state]},
    )
    assert run.succeeded, run.error
    probe = next(c for c in run.fact_commands if CHECK in c)
    for fragment in (
        '"name": "example-backup"',
        '"service_name": "example-site.service"',
        '"restore_owner": "example:webdata"',
        '"db_path": "/home/example/site/db.sqlite3"',
        '"backup_files": ["/home/example/site/media", "/home/example/site/private"]',
        '"schedule": "30 3 * * *"',
        '"schedule_policy": "keep"',
    ):
        assert fragment in probe
    applies = [c for c in run.executed_commands if '"mode": "apply"' in c]
    assert len(applies) == (1 if state == "pending" else 0)
    if applies:
        clear = next(i for i, c in enumerate(run.executed_commands) if c.startswith("rm -f /var/lib/ops-deploy/"))
        assert clear < run.executed_commands.index(applies[0])


def test_overrides_and_files_only_target(tmp_path: Path) -> None:
    target = {
        **TARGET,
        "db_path": None,
        "service_name": "custom.service",
        "restore_owner": "example:restore",
        "update_schedule": True,
    }
    cfg = config(tmp_path, target)
    assert cfg.secrets is not None
    run = run_deploy_fake(
        deploy_django_site,
        cfg,
        SecretValues(cfg.secrets, {"django_secret_key": "synthetic-example-key"}),
        rsync=RecordingRsyncRunner(),
        responses={**fakehost.LINUX, CHECK: ["pending"]},
    )
    assert run.succeeded, run.error
    apply = next(c for c in run.executed_commands if '"mode": "apply"' in c)
    for fragment in (
        '"db_path": ""',
        '"service_name": "custom.service"',
        '"restore_owner": "example:restore"',
        '"schedule_policy": "set"',
    ):
        assert fragment in apply


def test_unset_target_does_not_contact_echoport(tmp_path: Path) -> None:
    cfg = config(tmp_path, None)
    assert cfg.secrets is not None
    run = run_deploy_fake(
        deploy_django_site,
        cfg,
        SecretValues(cfg.secrets, {"django_secret_key": "synthetic-example-key"}),
        rsync=RecordingRsyncRunner(),
        responses=fakehost.LINUX,
    )
    assert run.succeeded, run.error
    assert not any("echoport" in c.lower() for c in run.fact_commands + run.executed_commands)


@pytest.mark.parametrize(
    "changes",
    [
        {"db_path": None, "backup_files": ()},
        {"backup_files": ("/home/example/site",)},
        {"backup_files": ("/home/example/other/db.sqlite3",)},
        {"backup_files": ("/home/example/site/db.sqlite3-wal",)},
        {"db_path": "relative.sqlite3"},
        {"backup_files": ("/etc/passwd",)},
        {"backup_files": ("/home/example/../other",)},
        {"backup_files": ("/home/example/manifest.json",)},
        {"service_name": "invalid unit"},
        {"restore_owner": "root"},
        {"schedule": "invalid"},
        {"unknown": True},
    ],
)
def test_invalid_target_is_rejected(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        EchoportTarget.model_validate({**TARGET, **changes})
