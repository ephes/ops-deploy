"""Archive and Chesslab backups through the registered echoport-backup runner (their plays' shell task)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from ops_deploy.services._lifecycle.echoport_runner import RUNNER, backup_script
from ops_deploy.services.archive import ArchiveBackupConfig, deploy_archive_backup
from ops_deploy.services.chesslab import ChesslabBackupConfig, deploy_chesslab_backup
from ops_deploy.testing import run_deploy_fake

INSTALLED = {f"test -e {RUNNER} &&": ["yes"]}


def test_without_the_runner_the_backup_refuses_with_the_plays_message() -> None:
    result = run_deploy_fake(deploy_archive_backup, ArchiveBackupConfig())

    assert not result.succeeded
    assert str(result.error).endswith("echoport-backup must be registered before Archive backups can run.")
    assert result.executed_commands == []


def test_with_the_runner_one_step_runs_the_plays_script() -> None:
    cfg = ChesslabBackupConfig(prefix="pre-deploy")

    result = run_deploy_fake(deploy_chesslab_backup, cfg, responses=INSTALLED)

    assert result.succeeded, result.error
    (command,) = result.executed_commands
    assert backup_script(cfg).strip().splitlines()[-1] in command
    assert [op.split(" | ", 1)[1] for op in result.changed_ops] == [
        "Run Chesslab SQLite backup through echoport-backup"
    ]


@pytest.mark.parametrize(
    ("cfg", "expected"),
    [
        (
            ArchiveBackupConfig(),
            {
                "ECHOPORT_TARGET": "archive",
                "ECHOPORT_RUN_ID": "manual-STAMP",
                "ECHOPORT_DB_PATH": "/home/archive/site/db.sqlite3",
                "ECHOPORT_BACKUP_FILES": "",
                "ECHOPORT_BUCKET": "backups",
                "ECHOPORT_KEY_PREFIX": "archive/manual-STAMP",
                "ECHOPORT_TIMESTAMP": "STAMP",
            },
        ),
        (
            ChesslabBackupConfig(prefix="nightly"),
            {
                "ECHOPORT_TARGET": "chesslab",
                "ECHOPORT_RUN_ID": "nightly-STAMP",
                "ECHOPORT_DB_PATH": "/home/chesslab/data/chess.db",
                "ECHOPORT_BACKUP_FILES": "",
                "ECHOPORT_SERVICE_NAME": "chesslab.service",
                "ECHOPORT_RESTORE_OWNER": "chesslab:chesslab",
                "ECHOPORT_BUCKET": "backups",
                "ECHOPORT_KEY_PREFIX": "chesslab/nightly-STAMP",
                "ECHOPORT_TIMESTAMP": "STAMP",
            },
        ),
    ],
)
def test_the_script_hands_the_runner_the_plays_config_and_removes_it(
    tmp_path: Path, cfg: ArchiveBackupConfig, expected: dict[str, str]
) -> None:
    runner = tmp_path / "backup.py"
    seen = tmp_path / "seen.json"
    runner.write_text(
        "import json, os, sys\n"
        f"path = sys.argv[2]\nconfig = json.load(open(path))\n"
        f"config['_mode'] = oct(os.stat(path).st_mode & 0o777)\nconfig['_path'] = path\n"
        f"json.dump(config, open({str(seen)!r}, 'w'))\n"
    )
    script = backup_script(cfg.model_copy(update={"runner": str(runner)}))

    subprocess.run(["bash", "-c", script], check=True)

    config = json.loads(seen.read_text())
    env = config["context"]["env"]
    stamp = env["ECHOPORT_TIMESTAMP"]
    assert len(stamp) == 19
    assert stamp[4] == "-"
    assert stamp[10] == "T"
    assert list(env) == list(expected)
    assert env == {key: value.replace("STAMP", stamp) for key, value in expected.items()}
    assert config["_mode"] == "0o600"
    assert config["_path"].startswith(f"/tmp/{cfg.target}-backup-")
    assert not Path(config["_path"]).exists()


def test_values_that_would_break_the_heredoc_are_refused() -> None:
    with pytest.raises(ValidationError):
        ArchiveBackupConfig(prefix="x$(id)")
    with pytest.raises(ValidationError):
        ChesslabBackupConfig(restore_owner='a:b"')
