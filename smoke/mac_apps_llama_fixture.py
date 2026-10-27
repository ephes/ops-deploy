"""Real pinned ARM detector, public GGUF, authentication and no inference."""

from __future__ import annotations

import hashlib
import re
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any

from mac_apps_owned import OwnedMac, command, file_state, port

from ops_deploy.services.llama_server import LlamaServerConfig, deploy_llama_server


def diagnostics(owned: OwnedMac) -> dict[str, Any]:
    """Public build/job facts and the owned server log tail; the fixture key is redacted."""

    found: dict[str, Any] = {}
    try:
        for name, argv in {
            "formula": [
                "/usr/bin/sudo",
                "-H",
                "-u",
                "runner",
                "--",
                "/opt/homebrew/bin/brew",
                "list",
                "--versions",
                "llama.cpp",
            ],
            "version": ["/opt/homebrew/bin/llama-server", "--version"],
        }.items():
            result = command(*argv, check=False)
            found[name] = (result.stdout + result.stderr)[-1500:]
        for label in owned.labels:
            output = command("/bin/launchctl", "print", label, check=False).stdout
            found[label] = [
                line.strip() for line in output.splitlines() if re.search(r"state =|last exit|runs =", line)
            ]
        for log in sorted((owned.root / "logs").glob("*.log")):
            text = log.read_text(errors="replace")[-4000:]
            found[log.name] = re.sub(r"owned-detector-[A-Za-z0-9-]+", "<fixture-key>", text)
    except Exception as error:  # diagnostics never mask the original failure
        found["diagnostics_error"] = type(error).__name__
    return found


def main() -> None:
    owned = OwnedMac("llama")
    failure: BaseException | None = None
    try:
        owned.verify_implementation()
        owned.report["stage"] = "public wrapper and fresh package"
        brew = "/opt/homebrew/bin/brew"
        before = command(
            "/usr/bin/sudo",
            "-H",
            "-u",
            "runner",
            "--",
            "/usr/bin/env",
            "HOMEBREW_NO_AUTO_UPDATE=1",
            brew,
            "list",
            "--formula",
            "--versions",
            "llama.cpp",
            check=False,
        )
        assert before.returncode != 0, "owned fresh-install fixture requires the formula initially absent"
        wrapper = owned.root / "owned-detector-wrapper.sh"
        # Authored public fixture material, not a copy of the private Delve app.
        wrapper.write_text("""#!/bin/bash
set -euo pipefail
GGUF_SHA256="3605803b982cb64aead44f6c1b2ae36e3acdb41d8e46c8a94c6533bc4c67e597"
/usr/bin/python3 -B - "$DELVE_LLAMA_SERVER" "$DELVE_DETECTOR_BUILD" "$DELVE_DETECTOR_GGUF" "$GGUF_SHA256" <<'VERIFY'
import hashlib,re,subprocess,sys
binary,wanted,path,pin=sys.argv[1:]
result=subprocess.run([binary,"--version"],capture_output=True,text=True,check=True)
match=re.search(r"\\(build ([0-9]+), commit ([0-9a-f]+)\\)",result.stdout+result.stderr)
assert match and "b"+match[1]+"-"+match[2]==wanted
digest=hashlib.sha256()
with open(path,"rb") as model:
    while True:
        block=model.read(1024*1024)
        if not block:break
        digest.update(block)
assert digest.hexdigest()==pin
VERIFY
exec "$DELVE_LLAMA_SERVER" -m "$DELVE_DETECTOR_GGUF" --host "$DELVE_DETECTOR_HOST" --port "$DELVE_DETECTOR_PORT" \\
 --alias qwen3-4b-instruct-2507-q4km-3605803b --api-key-file "$DELVE_DETECTOR_API_KEY_FILE" \\
 --no-ui --no-slots -c 16384 -np 1 -ngl 99 -b 512 -ub 512 --flash-attn auto --seed 42 --cache-ram 0
""")
        label = owned.label("detector")
        cfg = LlamaServerConfig(
            user="runner",
            group="staff",
            home=PurePosixPath("/Users/runner"),
            brew_user="runner",
            wrapper_source=wrapper,
            install_dir=PurePosixPath(owned.root / "runtime"),
            config_dir=PurePosixPath(owned.root / "config"),
            log_dir=PurePosixPath(owned.root / "logs"),
            bind_host="127.0.0.1",
            port=port(),
            launchd_label=label,
            launchd_plist_path=PurePosixPath(owned.root / "config/detector.plist"),
            healthcheck_retries=120,
            healthcheck_delay=1,
        )
        token = "owned-detector-first-key-" + owned.suffix

        def deploy(config: LlamaServerConfig, value: str = token, *, succeeds: bool = True) -> list[str]:
            from ops_deploy.testing import run_deploy_ssh

            result = run_deploy_ssh(deploy_llama_server, config, {"api_key": value}, host_name="@local", host_data={})
            assert result.succeeded is succeeds, str(result.error)
            assert value not in str(result.error)
            return result.mutating_changed_ops

        def model_metadata(config: LlamaServerConfig) -> tuple[int, ...]:
            assert config.model_dir is not None
            info = Path(config.model_dir / config.model_file).stat()
            return (
                info.st_dev,
                info.st_ino,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
                info.st_uid,
                info.st_gid,
                info.st_mode,
            )

        def state(config: LlamaServerConfig) -> dict[str, Any]:
            assert config.wrapper_path is not None
            assert config.api_key_path is not None
            assert config.launchd_plist_path is not None
            paths = [Path(config.wrapper_path)]
            if config.enabled:
                paths += [Path(config.api_key_path), Path(config.launchd_plist_path)]
            return {
                "files": file_state(paths),
                "model_metadata": model_metadata(config),
                "pid": owned.pid(label) if config.enabled else None,
            }

        def no_op(config: LlamaServerConfig, value: str, name: str) -> None:
            before_state = state(config)
            changes = deploy(config, value)
            assert changes == []
            assert state(config) == before_state
            owned.report["repeats"][name] = changes

        def auth(config: LlamaServerConfig, value: str | None) -> int:
            request = urllib.request.Request(
                "http://127.0.0.1:" + str(config.port) + "/v1/models",
                headers={"Authorization": "Bearer " + value} if value else {},
            )
            try:
                with urllib.request.urlopen(request, timeout=10) as response:
                    return int(response.status)
            except urllib.error.HTTPError as error:
                return int(error.code)

        owned.report["first_changes"] = deploy(cfg)
        assert owned.report["first_changes"]
        assert auth(cfg, token) == 200
        assert auth(cfg, None) == 401
        assert cfg.model_dir is not None
        digest = hashlib.sha256()
        with Path(cfg.model_dir / cfg.model_file).open("rb") as stream:
            while block := stream.read(1024 * 1024):
                digest.update(block)
        assert digest.hexdigest() == cfg.model_sha256
        owned.report["fresh_model_sha256"] = digest.hexdigest()
        owned.report["model_size"] = model_metadata(cfg)[2]
        owned.report["actual_build"] = command(str(cfg.binary), "--version").stdout.strip()
        owned.report["wrapper_scope"] = (
            "authored public fixture; profile/auth/build preserved; model load and no HTTP inference requests"
        )
        no_op(cfg, token, "fresh")
        owned.report["stage"] = "invalid build retains process and model"
        before_state = state(cfg)
        bad = cfg.model_copy(update={"build": "b1-111111111"})
        deploy(bad, succeeds=False)
        assert state(cfg) == before_state
        no_op(cfg, token, "post-fault")
        owned.report["stage"] = "configuration and key rotation"
        rotated = "owned-detector-rotated-key-" + owned.suffix
        changed = cfg.model_copy(update={"port": port()})
        original_model = model_metadata(cfg)
        old_pid = owned.pid(label)
        owned.report["configuration_changes"] = deploy(changed, rotated)
        assert owned.pid(label) != old_pid
        assert model_metadata(changed) == original_model
        assert auth(changed, rotated) == 200
        assert auth(changed, token) == 401
        no_op(changed, rotated, "rotated-config")
        owned.report["stage"] = "disabled resource retention"
        disabled = changed.model_copy(update={"enabled": False})
        owned.report["disabled_changes"] = deploy(disabled, rotated)
        assert changed.api_key_path is not None
        assert changed.launchd_plist_path is not None
        assert not Path(changed.api_key_path).exists()
        assert not Path(changed.launchd_plist_path).exists()
        assert model_metadata(disabled) == original_model
        no_op(disabled, rotated, "disabled")
        owned.report["inference_requests"] = 0
        owned.report["limitations"].append(
            "Binary startup may execute its normal warmup; no user inference, physical GPU "
            "or device qualification is claimed."
        )
        owned.report["status"] = "passed"
    except BaseException as error:
        failure = error
        owned.report["diagnostics"] = diagnostics(owned)
    finally:
        failure = owned.finish(failure)
    if failure is not None:
        raise failure
    print("owned ARM detector install/auth/config/fault/disable/repeat passed; no inference; fixture removed")


if __name__ == "__main__":
    main()
