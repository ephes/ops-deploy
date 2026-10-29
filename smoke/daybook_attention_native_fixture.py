"""Owned disabled attention wheel, actual root/GUI/SFTP and import failure."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import os
import plistlib
import pwd
import sys
import zipfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

import paramiko
from daybook_resources_native_fixture import provenance
from daybook_runtime_native_fixture import snapshot
from mac_apps_owned import OwnedMac, command, job_pid
from pyinfra.api.exceptions import PyinfraError

from ops_deploy.services.daybook_voice_memo_attention import (
    DaybookVoiceMemoAttentionConfig,
    install_daybook_voice_memo_attention,
)
from ops_deploy.testing import run_deploy_ssh


def wheel(path: Path, counter: Path, *, faulty: bool = False) -> None:
    code = (
        "from pathlib import Path\nPath("
        + repr(str(counter.parent / "owned-failed-import"))
        + ").write_text('1')\nraise RuntimeError('owned import failure')\n"
        if faulty
        else (
            "from pathlib import Path\np=Path(" + repr(str(counter)) + ")\n"
            "p.write_text(str(int(p.read_text())+1) if p.exists() else '1')\n"
        )
    )
    body = {
        "daybook/__init__.py": b"# owned inert package, no application dependency\n",
        "daybook/attention.py": code.encode(),
        "daybook-0.0.0.dist-info/METADATA": b"Metadata-Version: 2.1\nName: daybook\nVersion: 0.0.0\n\n",
        "daybook-0.0.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\nGenerator: owned\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
    }
    records = io.StringIO()
    writer = csv.writer(records, lineterminator="\n")
    for name, raw in body.items():
        writer.writerow(
            [name, "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("="), len(raw)]
        )
    writer.writerow(["daybook-0.0.0.dist-info/RECORD", "", ""])
    body["daybook-0.0.0.dist-info/RECORD"] = records.getvalue().encode()
    with zipfile.ZipFile(path, "w") as archive:
        for name, raw in body.items():
            archive.writestr(name, raw)


def run(owned: OwnedMac, transport: dict[str, Any], cfg: DaybookVoiceMemoAttentionConfig, name: str) -> Any:
    counts = {"attempted": 0, "succeeded": 0}
    original = paramiko.SFTPClient.putfo

    def transfer(client: Any, stream: Any, destination: str, *args: Any, **kwargs: Any) -> Any:
        counts["attempted"] += 1
        result = original(client, stream, destination, *args, **kwargs)
        counts["succeeded"] += 1
        return result

    with patch.object(paramiko.SFTPClient, "putfo", transfer):
        result = run_deploy_ssh(
            install_daybook_voice_memo_attention, cfg, host_name="owned-attention", host_data=transport, _sudo=True
        )
    owned.report.setdefault("phases", {})[name] = {
        "succeeded": result.succeeded,
        "managed": len(result.mutating_changed_ops),
        "actual_sftp": counts,
        "error_type": type(result.error).__name__ if result.error else None,
    }
    assert job_pid(owned.report["unrelated_keeper_service"]) == owned.report["unrelated_keeper_pid"]
    return result


def main() -> None:
    owned = OwnedMac("daybook-attention")
    failure: BaseException | None = None
    try:
        provenance(owned)
        actor = pwd.getpwnam("runner")
        home = owned.root / "home"
        home.mkdir(mode=0o700)
        os.chown(home, actor.pw_uid, actor.pw_gid)
        runtime = home / ".local/state/daybook/voice-memo-attention"
        counter = runtime / "owned-import-counter"
        artifact = owned.root / "daybook-0.0.0-py3-none-any.whl"
        wheel(artifact, counter)
        cfg = DaybookVoiceMemoAttentionConfig(
            daybook_voice_memo_attention_service_user=actor.pw_name,
            daybook_voice_memo_attention_wheel_src=str(artifact),
            daybook_voice_memo_attention_config={
                "version": 1,
                "enabled": False,
                "profile": "synthetic",
                "state_path": "/Users/runner/.local/state/daybook/voice-memo-attention/state.sqlite3",
                "source": {"kind": "synthetic"},
            },
        )
        install = owned.root / "Daybook/voice-memo-attention"
        label = "com.example.ops-mac-apps.attention." + owned.suffix
        paths = {
            "service_home": str(home),
            "install_root": str(install),
            "venv": str(install / "venv"),
            "uv_bin": str(Path(sys.executable).parent / "uv"),
            "python_install_dir": str(owned.root / "Daybook/python"),
            "runtime_dir": str(runtime),
            "config_path": str(runtime / "config.json"),
            "launchd_label": label,
            "plist_path": str(home / "Library/LaunchAgents" / (label + ".plist")),
            "config": {**cfg.daybook_voice_memo_attention_config, "state_path": str(runtime / "state.sqlite3")},
        }
        cfg = cfg.model_copy(update={"daybook_voice_memo_attention_" + key: value for key, value in paths.items()})
        owned.adopt_gui_label(actor.pw_uid, label)
        service = "gui/" + str(actor.pw_uid) + "/" + label
        keeper_label = "com.example.ops-mac-apps.attention-keeper." + owned.suffix
        owned.adopt_gui_label(actor.pw_uid, keeper_label)
        keeper_plist = owned.root / "keeper.plist"
        keeper_plist.write_bytes(
            plistlib.dumps({"Label": keeper_label, "ProgramArguments": ["/bin/sleep", "600"], "RunAtLoad": True})
        )
        command("/bin/launchctl", "bootstrap", "gui/" + str(actor.pw_uid), str(keeper_plist))
        keeper_service = "gui/" + str(actor.pw_uid) + "/" + keeper_label
        from daybook_resources_native_fixture import wait

        wait(lambda: job_pid(keeper_service) is not None)
        owned.report.update(unrelated_keeper_service=keeper_service, unrelated_keeper_pid=job_pid(keeper_service))
        transport = owned.ssh_transport()
        first = run(owned, transport, cfg, "first")
        assert first.succeeded, type(first.error).__name__
        assert len(first.mutating_changed_ops) == 6
        assert owned.report["phases"]["first"]["actual_sftp"] == {"attempted": 1, "succeeded": 1}
        assert counter.read_text() == "1"
        assert job_pid(service) is None
        assert plistlib.loads(Path(cfg.daybook_voice_memo_attention_plist_path).read_bytes())["Disabled"] is True
        receipt = install / "installed-wheel.sha1"
        assert receipt.read_text() == hashlib.sha1(artifact.read_bytes()).hexdigest() + "\n"
        # Synthetic state/log bodies are seeded only inside this owned fixture.
        for name in ("state.sqlite3", "activation.json", "tick.log", "tick.err.log"):
            path = runtime / name
            path.write_text("OWNED retained synthetic sentinel " + name)
            os.chown(path, actor.pw_uid, actor.pw_gid)
        protected = snapshot(
            [runtime / name for name in ("state.sqlite3", "activation.json", "tick.log", "tick.err.log")]
        )
        code = snapshot([install, home / "Library/LaunchAgents", runtime / "config.json"])
        repeat = run(owned, transport, cfg, "repeat")
        assert repeat.succeeded
        assert len(repeat.mutating_changed_ops) == 1
        assert owned.report["phases"]["repeat"]["actual_sftp"] == {"attempted": 0, "succeeded": 0}
        assert counter.read_text() == "2"
        assert snapshot([install, home / "Library/LaunchAgents", runtime / "config.json"]) == code
        assert (
            snapshot([runtime / name for name in ("state.sqlite3", "activation.json", "tick.log", "tick.err.log")])
            == protected
        )

        # The original wrong-interpreter path replaces only this owned venv.
        python = install / "venv/bin/python"
        python.unlink()
        python.symlink_to("/usr/bin/python3")
        (install / "venv/pyvenv.cfg").write_text("home = /usr/bin\n")
        rebuilt = run(owned, transport, cfg, "wrong-interpreter")
        assert rebuilt.succeeded
        assert len(rebuilt.mutating_changed_ops) == 2
        assert counter.read_text() == "3"
        assert job_pid(service) is None

        original_receipt = receipt.read_bytes()
        wheel(artifact, counter, faulty=True)
        failed = run(owned, transport, cfg, "genuine-import-failure")
        assert not failed.succeeded
        assert type(failed.error) is PyinfraError
        assert (runtime / "owned-failed-import").read_text() == "1"
        import_op = next(
            row for row in failed.ops if row.name == "Verify original attention isolated application import"
        )
        assert not import_op.succeeded
        assert receipt.read_bytes() == original_receipt
        assert counter.read_text() == "3"
        assert job_pid(service) is None
        assert (
            snapshot([runtime / name for name in ("state.sqlite3", "activation.json", "tick.log", "tick.err.log")])
            == protected
        )
        wheel(artifact, counter)
        recovered = run(owned, transport, cfg, "recovery")
        assert recovered.succeeded
        assert counter.read_text() == "4"
        final = run(owned, transport, cfg, "final-repeat")
        assert final.succeeded
        assert len(final.mutating_changed_ops) == 1
        assert counter.read_text() == "5"
        owned.report.update(
            successful_inert_module_imports=5,
            failed_inert_module_imports=1,
            managed_import_each_repeat=True,
            protected_synthetic_state_and_log_metadata_exact=True,
            real_inventory_or_application_calls=False,
            status="passed",
        )
    except BaseException as error:
        failure = error
        owned.fail(error)
    finally:
        try:
            owned.cleanup()
        except BaseException as error:
            failure = failure or error
        owned.receipt()
    if failure is not None:
        raise failure


if __name__ == "__main__":
    main()
