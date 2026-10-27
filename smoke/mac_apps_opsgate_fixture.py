"""Actual ARM OpsGate install/update/fault/Python rollback and zero repeats."""

from __future__ import annotations

import os
import pwd
from pathlib import Path
from typing import Any

import bcrypt
from mac_apps_owned import OwnedMac, command, file_state, port

from ops_deploy.base import UvInstallConfig, deploy_uv_install
from ops_deploy.services.opsgate import OpsGateConfig, deploy_opsgate
from ops_deploy.services.opsgate.render import payload
from ops_deploy.testing import run_deploy_ssh

APP = "9c82952d82dfa2e4d046b1039b25dd80c3482243"
ARCHIVE = "60af210304b7c530b3db6e4132e24d7f2fb6cbc5fde949b4099afd5159898902"
UV_SHA = "743f85035a1996ecb350659e01cd9faea9709829be09b1b4b03c73eaf3c9cd73"


def main() -> None:
    owned = OwnedMac("opsgate")
    failure: BaseException | None = None
    try:
        owned.verify_implementation()
        owned.report["stage"] = "owned source and transport"
        source = owned.source("opsgate", APP)
        transport = owned.ssh_transport()
        rsync_path = transport.pop("remote_rsync_path")
        uv_cfg = UvInstallConfig(
            darwin=True,
            version="0.13.5",
            checksums={"aarch64-apple-darwin": UV_SHA},
            install_dir=str(owned.root / "tool-bin"),
            owner="root",
            group="wheel",
        )
        installed_uv = run_deploy_ssh(deploy_uv_install, uv_cfg, host_name="@local", host_data={})
        assert installed_uv.succeeded, str(installed_uv.error)
        owned.report["uv_prerequisite_changes"] = installed_uv.mutating_changed_ops
        uv = owned.root / "tool-bin/uv"
        # Public fixture input selects the existing production rollback Python.
        # The wrapper only supplies uv's standard public interpreter selector;
        # all installs and version checks execute the real verified uv binary.
        selected_uv = owned.root / "uv-with-selected-python"
        selected_uv.write_text("#!/bin/sh\nexec /usr/bin/env UV_PYTHON=3.15.0 " + str(uv) + ' "$@"\n')
        selected_uv.chmod(0o755)
        runner, api = owned.user("ops"), owned.user("api")
        api_label, runner_label = owned.label("opsgate-api"), owned.label("opsgate-runner")
        bind_port = port()
        repository = owned.root / "workspace-origin.git"
        seed = owned.root / "workspace-seed"
        command("git", "init", "--bare", str(repository))
        command("git", "init", "--initial-branch=main", str(seed))
        (seed / "owned.txt").write_text("owned workspace v1\n")
        command("git", "-C", str(seed), "add", "owned.txt")
        command(
            "git",
            "-C",
            str(seed),
            "-c",
            "user.name=Owned Fixture",
            "-c",
            "user.email=fixture@example.test",
            "commit",
            "-m",
            "owned baseline",
        )
        command("git", "-C", str(seed), "push", str(repository), "main")
        command("git", "-C", str(repository), "symbolic-ref", "HEAD", "refs/heads/main")
        cfg = OpsGateConfig(
            remote_rsync_path=rsync_path,
            opsgate_source_path=str(source),
            opsgate_uv_bin=str(selected_uv),
            ops_user=runner,
            ops_group=runner,
            ops_home_dir=str(owned.root / "runner-home"),
            control_service_user=api,
            control_service_group=api,
            control_service_home_dir=str(owned.root / "api-home"),
            opsgate_config_dir=str(owned.root / "config"),
            opsgate_log_dir=str(owned.root / "logs"),
            opsgate_runtime_dir=str(owned.root / "run"),
            opsgate_rust_install_root=str(owned.root / "releases"),
            opsgate_api_launchd_label=api_label,
            opsgate_runner_launchd_label=runner_label,
            opsgate_api_launchd_plist_path=str(owned.root / "config/api.plist"),
            opsgate_runner_launchd_plist_path=str(owned.root / "config/runner.plist"),
            opsgate_rust_version="0.3.0",
            opsgate_rust_sha256=ARCHIVE,
            opsgate_api_impl="rust",
            opsgate_runner_impl="rust",
            opsgate_launchd_manage_state=True,
            opsgate_launchd_start_services=True,
            opsgate_launchd_verify_retries=30,
            opsgate_launchd_verify_delay=1,
            opsgate_api_bind_host="127.0.0.1",
            opsgate_api_bind_port=bind_port,
            opsgate_ops_manage_workspace_repos=False,
            opsgate_ops_workspace_repositories=[{"name": "owned", "repo": repository.as_uri(), "version": "main"}],
        )
        values = {
            "opsgate_session_secret": "owned-fixture-session-" + owned.suffix,
            "opsgate_ui_password_bcrypt": bcrypt.hashpw(b"owned-fixture-password", bcrypt.gensalt(rounds=4)).decode(),
            "opsgate_submit_token_nyxmon": "owned-fixture-nyxmon-" + owned.suffix,
            "opsgate_submit_token_operator": "owned-fixture-operator-" + owned.suffix,
            "opsgate_runner_token": "owned-fixture-runner-" + owned.suffix,
        }

        def deploy(config: OpsGateConfig, *, succeeds: bool = True) -> list[str]:
            result = run_deploy_ssh(deploy_opsgate, config, values, host_name="@local", host_data=transport)
            assert result.succeeded is succeeds, str(result.error)
            for value in values.values():
                assert value not in str(result.error)
            return result.mutating_changed_ops

        def state(config: OpsGateConfig) -> dict[str, Any]:
            paths = [Path(path) for path in payload(config, values)["contents"]]
            paths += [
                Path(config.opsgate_rust_install_root) / "0.3.0" / name
                for name in ["opsgate", "LICENSE", ".archive-sha256"]
            ]
            git_dir = Path(config.opsgate_ops_workspace_dir) / "owned/.git"
            paths += [p for p in git_dir.rglob("*") if p.is_file()]
            paths += [p for p in Path(config.opsgate_rust_install_root).rglob("*") if p.is_file()]
            return {"files": file_state(paths), "api_pid": owned.pid(api_label), "runner_pid": owned.pid(runner_label)}

        def no_op(config: OpsGateConfig, name: str) -> None:
            before = state(config)
            changes = deploy(config)
            after = state(config)
            # Operation names and owned fixture paths only; recorded before asserting.
            owned.report["repeats"][name] = changes
            drift = sorted(
                k
                for k in before["files"].keys() | after["files"].keys()
                if before["files"].get(k) != after["files"].get(k)
            )
            owned.report.setdefault("repeat_drift", {})[name] = {
                "files": drift[:40],
                "pids_changed": (before["api_pid"], before["runner_pid"]) != (after["api_pid"], after["runner_pid"]),
            }
            assert changes == []
            assert after == before

        owned.report["stage"] = "fresh full role"
        owned.report["first_changes"] = deploy(cfg)
        assert owned.report["first_changes"]
        for path in [cfg.opsgate_app_dir, cfg.opsgate_runner_app_dir]:
            version = command(path + "/.venv/bin/python", "--version").stdout.strip()
            assert version == "Python 3.15.0"
        owned.report["python_rollback"] = "3.15.0"
        owned.report["actual_rust_version"] = command(
            cfg.opsgate_rust_install_root + "/0.3.0/opsgate", "--version"
        ).stdout.strip()
        no_op(cfg, "fresh")
        owned.report["stage"] = "branch tracking and source update without Rust restart"
        before_pids = owned.pid(api_label), owned.pid(runner_label)
        # The fixture's local bare origin becomes owned by the newly created
        # runner account. No global Git safe.directory exception is introduced.
        account = pwd.getpwnam(runner)
        for tree in [seed, repository]:
            for leaf in [tree, *tree.rglob("*")]:
                os.chown(leaf, account.pw_uid, account.pw_gid)
        cfg = OpsGateConfig.model_validate({**cfg.model_dump(), "opsgate_ops_manage_workspace_repos": True})
        owned.report["workspace_bootstrap_changes"] = deploy(cfg)
        assert (owned.pid(api_label), owned.pid(runner_label)) == before_pids
        no_op(cfg, "workspace-bootstrap")
        (seed / "owned.txt").write_text("owned workspace v2\n")
        command("/usr/bin/sudo", "-H", "-u", runner, "--", "/usr/bin/git", "-C", str(seed), "add", "owned.txt")
        command(
            "/usr/bin/sudo",
            "-H",
            "-u",
            runner,
            "--",
            "/usr/bin/git",
            "-C",
            str(seed),
            "-c",
            "user.name=Owned Fixture",
            "-c",
            "user.email=fixture@example.test",
            "commit",
            "-m",
            "owned update",
        )
        command(
            "/usr/bin/sudo", "-H", "-u", runner, "--", "/usr/bin/git", "-C", str(seed), "push", str(repository), "main"
        )
        owned.report["workspace_update_changes"] = deploy(cfg)
        assert (owned.pid(api_label), owned.pid(runner_label)) == before_pids
        assert (Path(cfg.opsgate_ops_workspace_dir) / "owned/owned.txt").read_text() == "owned workspace v2\n"
        no_op(cfg, "workspace-update")
        with (source / "README.md").open("a") as output:
            output.write("\nOwned fixture source update.\n")
        owned.report["source_update_changes"] = deploy(cfg)
        assert (owned.pid(api_label), owned.pid(runner_label)) == before_pids
        no_op(cfg, "source-update")
        owned.report["stage"] = "changed config and repeat"
        next_port = port()
        changed = OpsGateConfig.model_validate(
            {
                **cfg.model_dump(),
                "opsgate_api_bind_port": next_port,
                "opsgate_runner_api_base_url": "http://127.0.0.1:" + str(next_port),
            }
        )
        owned.report["config_update_changes"] = deploy(changed)
        assert (owned.pid(api_label), owned.pid(runner_label)) != before_pids
        no_op(changed, "configuration")
        owned.report["stage"] = "rejected candidate retains current services"
        bad = OpsGateConfig.model_validate(
            {
                **changed.model_dump(),
                "opsgate_rust_version": "0.3.1",
                "opsgate_rust_sha256": "0" * 64,
                "opsgate_rust_release_url": "https://github.com/ephes/opsgate/releases/download/rs-v0.3.0/opsgate-0.3.0-aarch64-apple-darwin.tar.gz",
            }
        )
        before = state(changed)
        deploy(bad, succeeds=False)
        assert state(changed) == before
        assert not (Path(cfg.opsgate_rust_install_root) / "0.3.1").exists()
        no_op(changed, "post-fault")
        owned.report["stage"] = "Python fallback despite rejected optional Rust"
        fallback = OpsGateConfig.model_validate(
            {**bad.model_dump(), "opsgate_api_impl": "python", "opsgate_runner_impl": "python"}
        )
        owned.report["python_fallback_changes"] = deploy(fallback)
        healthy_python = OpsGateConfig.model_validate(
            {
                **fallback.model_dump(),
                "opsgate_rust_version": "",
                "opsgate_rust_sha256": "",
                "opsgate_rust_local_archive": "",
            }
        )
        no_op(healthy_python, "python-rollback")
        owned.report["no_ticket_agent_or_inference_job_executed"] = True
        owned.report["status"] = "passed"
    except BaseException as error:
        failure = error
    finally:
        failure = owned.finish(failure)
    if failure is not None:
        raise failure
    print("owned ARM OpsGate install/update/fault/rollback/repeat passed; fixture removed")


if __name__ == "__main__":
    main()
