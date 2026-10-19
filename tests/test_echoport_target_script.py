"""The shared Echoport target upsert, executed against a stand-in of Echoport's model.

``backups.models`` and ``django.db`` are small fakes on ``PYTHONPATH``; the
targets live in a JSON file, so each run sees what the previous one saved.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.services._echoport import target_code

FAKE_MODELS = """
import enum, json, os

STORE = os.environ["FAKE_ECHOPORT_STORE"]
FIELDS = {
    "name": "", "description": "", "icon": "", "fastdeploy_service": "", "service_token": "",
    "service_name": "", "restore_owner": "", "target_mode": "generic_paths", "db_path": "",
    "backup_files": [], "schedule": "", "schedule_required": False, "status": "active",
    "retention_days": 7, "timeout_seconds": 300, "storage_bucket": "",
}
if os.environ.get("FAKE_ECHOPORT_OLD"):
    del FIELDS["schedule_required"]


class BackupStatus(str, enum.Enum):
    ACTIVE = "active"


class BackupTargetMode(str, enum.Enum):
    GENERIC_PATHS = "generic_paths"
    SERVICE_OWNED = "service_owned"


def _load():
    try:
        with open(STORE) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


class _Field:
    def __init__(self, name):
        self.name = name


class _Meta:
    db_table = "backups_backuptarget"

    def get_fields(self):
        return [_Field(n) for n in FIELDS]


class _Query:
    def __init__(self, rows):
        self.rows = rows

    def first(self):
        return self.rows[0] if self.rows else None


class _Manager:
    def filter(self, name):
        row = _load().get(name)
        return _Query([BackupTarget(**row)] if row else [])


class BackupTarget:
    _meta = _Meta()
    objects = _Manager()

    def __init__(self, **values):
        self._loaded_name = values.get("name")
        for key, default in FIELDS.items():
            setattr(self, key, values.get(key, json.loads(json.dumps(default))))

    def save(self):
        rows = _load()
        if self._loaded_name and self._loaded_name != self.name:
            rows.pop(self._loaded_name, None)
        row = {}
        for key in FIELDS:
            value = getattr(self, key)
            row[key] = value.value if isinstance(value, enum.Enum) else value
        rows[self.name] = row
        with open(STORE, "w") as f:
            json.dump(rows, f)
"""

FAKE_DB = """
import contextlib
from backups.models import FIELDS


class _Column:
    def __init__(self, name):
        self.name = name


class _Introspection:
    def get_table_description(self, cursor, table):
        return [_Column(n) for n in FIELDS]


class _Connection:
    introspection = _Introspection()

    @contextlib.contextmanager
    def cursor(self):
        yield None


connection = _Connection()
"""

GENERIC = {
    "name": "radarr",
    "description": "Radarr database and config",
    "icon": "film",
    "service_name": "radarr.service",
    "restore_owner": "radarr:media",
    "db_path": "/mnt/cryptdata/media-apps/radarr/radarr.db",
    "backup_files": ["/mnt/cryptdata/media-apps/radarr/config.xml", "/mnt/cryptdata/media-apps/secrets/radarr-apikey"],
    "schedule": "15 3 * * *",
}


@pytest.fixture
def site(tmp_path: Path) -> Path:
    (tmp_path / "backups").mkdir()
    (tmp_path / "backups" / "__init__.py").write_text("")
    (tmp_path / "backups" / "models.py").write_text(FAKE_MODELS)
    (tmp_path / "django").mkdir()
    (tmp_path / "django" / "__init__.py").write_text("")
    (tmp_path / "django" / "db.py").write_text(FAKE_DB)
    return tmp_path


def run(site: Path, params: dict[str, Any], mode: str, stdin: str = "", **env: str) -> subprocess.CompletedProcess[str]:
    environ = {**os.environ, "PYTHONPATH": str(site), "FAKE_ECHOPORT_STORE": str(site / "store.json"), **env}
    return subprocess.run(
        [sys.executable, "-c", target_code(params, mode)],  # type: ignore[arg-type]
        input=stdin,
        capture_output=True,
        text=True,
        env=environ,
        cwd=site,
        check=False,
    )


def out(site: Path, params: dict[str, Any], mode: str, stdin: str = "") -> str:
    result = run(site, params, mode, stdin)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def stored(site: Path) -> dict[str, Any]:
    path = site / "store.json"
    return json.loads(path.read_text()) if path.exists() else {}


def edit(site: Path, name: str, **fields: Any) -> None:
    rows = stored(site)
    rows[name].update(fields)
    (site / "store.json").write_text(json.dumps(rows))


def jwt(claims: dict[str, Any]) -> str:
    def part(data: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

    return f"{part({'alg': 'HS256'})}.{part(claims)}.signature"


def test_a_new_target_is_created_with_the_fixed_fields(site: Path) -> None:
    assert out(site, GENERIC, "check") == "pending"
    assert stored(site) == {}

    assert out(site, GENERIC, "apply") == "created"
    row = stored(site)["radarr"]
    assert row["backup_files"] == GENERIC["backup_files"]
    assert row["db_path"] == GENERIC["db_path"]
    assert row["target_mode"] == "generic_paths"
    assert row["fastdeploy_service"] == "echoport-backup"
    assert (row["schedule"], row["schedule_required"]) == ("15 3 * * *", True)
    assert (row["status"], row["retention_days"], row["timeout_seconds"], row["storage_bucket"]) == (
        "active",
        30,
        900,
        "backups",
    )

    assert out(site, GENERIC, "check") == "unchanged"
    assert out(site, GENERIC, "apply") == "unchanged"


def test_drift_is_corrected_and_check_never_writes(site: Path) -> None:
    out(site, GENERIC, "apply")
    edit(site, "radarr", backup_files=[], restore_owner="root:root")

    assert out(site, GENERIC, "check") == "pending"
    assert stored(site)["radarr"]["backup_files"] == []
    assert out(site, GENERIC, "apply") == "updated"
    assert stored(site)["radarr"]["restore_owner"] == "radarr:media"


def test_a_schedule_set_in_the_ui_is_kept_unless_the_policy_sets_it(site: Path) -> None:
    out(site, GENERIC, "apply")
    edit(site, "radarr", schedule="0 5 * * 1")

    assert out(site, GENERIC, "check") == "unchanged"
    assert out(site, {**GENERIC, "schedule_policy": "set"}, "apply") == "updated"
    assert stored(site)["radarr"]["schedule"] == "15 3 * * *"

    edit(site, "radarr", schedule="")
    assert out(site, GENERIC, "apply") == "updated"
    assert stored(site)["radarr"]["schedule"] == "15 3 * * *"


def test_schedule_required_is_set_on_an_existing_target(site: Path) -> None:
    out(site, GENERIC, "apply")
    edit(site, "radarr", schedule_required=False)

    assert out(site, GENERIC, "apply") == "updated"
    assert stored(site)["radarr"]["schedule_required"] is True


@pytest.mark.parametrize(
    ("params", "env", "message"),
    [
        ({**GENERIC, "schedule": " "}, {}, "Refusing to register an empty Echoport schedule"),
        ({**GENERIC, "schedule_policy": "always"}, {}, "unknown schedule_policy"),
        (GENERIC, {"FAKE_ECHOPORT_OLD": "1"}, "deploy migration 0008 first"),
    ],
)
def test_refusals(site: Path, params: dict[str, Any], env: dict[str, str], message: str) -> None:
    result = run(site, params, "apply", **env)

    assert result.returncode != 0
    assert message in result.stderr
    assert stored(site) == {}


def test_a_legacy_name_is_renamed(site: Path) -> None:
    out(site, {**GENERIC, "name": "radarr-old"}, "apply")
    params = {**GENERIC, "legacy_name": "radarr-old"}

    assert out(site, params, "check") == "pending"
    assert out(site, params, "apply") == "updated"
    assert set(stored(site)) == {"radarr"}
    assert out(site, params, "check") == "unchanged"


SERVICE_OWNED = {
    "name": "weeknotes_home",
    "legacy_name": "weeknotes-home",
    "description": "weeknotes.home PostgreSQL backups via service-owned FastDeploy runner",
    "icon": "notebook",
    "target_mode": "service_owned",
    "fastdeploy_service": "weeknotes-home-backup",
    "service_name": "weeknotes-home",
    "restore_owner": "weeknotes:weeknotes",
    "schedule": "10 4 * * *",
    "schedule_policy": "set",
    "service_token": {"renewal_days": 14, "force_rotate": False},
}


def test_a_service_owned_target_asks_for_a_token_and_never_prints_it(site: Path) -> None:
    token = jwt(
        {"type": "service", "service": "weeknotes-home-backup", "jti": "1", "exp": int(time.time()) + 90 * 86400}
    )

    assert out(site, SERVICE_OWNED, "check") == "pending"
    assert out(site, SERVICE_OWNED, "apply") == "need-token"
    assert stored(site) == {}

    result = run(site, SERVICE_OWNED, "apply", stdin=token + "\n")
    assert result.stdout.strip() == "created"
    assert token not in result.stdout + result.stderr
    row = stored(site)["weeknotes_home"]
    assert (row["service_token"], row["target_mode"], row["db_path"], row["backup_files"]) == (
        token,
        "service_owned",
        "",
        [],
    )
    assert out(site, SERVICE_OWNED, "check") == "unchanged"


@pytest.mark.parametrize(
    "claims",
    [
        {"type": "service", "service": "other", "jti": "1", "exp": 4102444800},
        {"type": "service", "service": "weeknotes-home-backup", "exp": 4102444800},
        {"type": "service", "service": "weeknotes-home-backup", "jti": "1", "exp": int(time.time()) + 86400},
    ],
)
def test_a_wrong_or_expiring_token_is_rotated(site: Path, claims: dict[str, Any]) -> None:
    out(site, SERVICE_OWNED, "apply", stdin=jwt(claims) + "\n")

    assert out(site, SERVICE_OWNED, "check") == "pending"
    assert out(site, SERVICE_OWNED, "apply") == "need-token"


def test_force_rotate_and_no_token_handling_for_generic_targets(site: Path) -> None:
    valid = jwt({"type": "service", "service": "weeknotes-home-backup", "jti": "1", "exp": 4102444800})
    out(site, SERVICE_OWNED, "apply", stdin=valid + "\n")
    forced = {**SERVICE_OWNED, "service_token": {"renewal_days": 14, "force_rotate": True}}
    assert out(site, forced, "check") == "pending"

    # Without "service_token" the stored token is neither checked nor changed.
    out(site, GENERIC, "apply")
    edit(site, "radarr", service_token="kept")
    assert out(site, GENERIC, "check") == "unchanged"
    assert stored(site)["radarr"]["service_token"] == "kept"
