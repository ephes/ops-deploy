"""Pinned native detector operations; standard library only on Darwin."""

import base64
import grp
import hashlib
import ipaddress
import json
import os
import platform
import plistlib
import pwd
import re
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


def run(argv, *, check=True, user=None):
    env = {"PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
           "HOMEBREW_NO_AUTO_UPDATE": "1", "HOMEBREW_NO_ANALYTICS": "1"}
    cwd = "/"
    if user:
        account = pwd.getpwnam(user)
        cwd = env["HOME"] = account.pw_dir
        if os.geteuid() != account.pw_uid:
            if os.geteuid() != 0:
                raise RuntimeError("detector operation requires the declared runtime owner")
            argv = ["/usr/bin/sudo", "-H", "-u", user, "--", *argv]
    if user and os.geteuid() != pwd.getpwnam(user).pw_uid:
        argv = argv[:5] + ["/usr/bin/env", *[key + "=" + value for key, value in env.items()], *argv[5:]]
    result = subprocess.run(argv, capture_output=True, text=True, env=env, cwd=cwd, timeout=600)
    if check and result.returncode:
        raise RuntimeError("native detector command failed")
    return result


def metadata(path, uid, gid, mode, directory=False):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    valid = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1
    if not valid:
        raise RuntimeError("detector managed resource has an unsafe file type")
    return (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (uid, gid, mode)


def job(cfg):
    out = run(["/bin/launchctl", "print", "system/" + cfg["launchd_label"]], check=False)
    return out.returncode == 0, out.returncode == 0 and bool(re.search(r"^\s*state = running$", out.stdout, re.M))


def prepare(cfg):
    if platform.system() != "Darwin":
        raise RuntimeError("llama-server deployment requires Darwin")
    if not cfg["enabled"]:
        return cfg
    cfg["uid"] = pwd.getpwnam(cfg["user"]).pw_uid
    cfg["gid"] = grp.getgrnam(cfg["group"]).gr_gid
    cfg["wheel"] = grp.getgrnam("wheel").gr_gid
    brew = cfg.get("brew_bin") or next((p for p in ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"] if Path(p).is_file()), None)
    if not brew or (os.geteuid() == 0 and not cfg.get("brew_user")):
        raise RuntimeError("detector requires existing Homebrew and its declared owner")
    cfg["brew"] = brew
    bind = cfg["bind_host"]
    if bind == "tailnet":
        out = run(["/sbin/ifconfig", "-a"]).stdout
        addresses = sorted({a for a in re.findall(r"\binet ([0-9.]+)", out) if ipaddress.ip_address(a) in ipaddress.ip_network("100.64.0.0/10")})
        if len(addresses) != 1:
            raise RuntimeError("detector tailnet binding requires exactly one Tailscale IPv4 address")
        bind = addresses[0]
    address = ipaddress.ip_address(bind)
    if address.version != 4 or not (address.is_loopback or address in ipaddress.ip_network("100.64.0.0/10")):
        raise RuntimeError("detector requires loopback or Tailscale IPv4 binding")
    cfg["bind_address"] = str(address)
    cfg["model_path"] = str(Path(cfg["model_dir"]) / cfg["model_file"])
    for path in [cfg["wrapper_path"], cfg["api_key_path"], cfg["launchd_plist_path"], cfg["model_path"], cfg["stdout_log"], cfg["stderr_log"]]:
        if os.path.lexists(path):
            metadata(path, 0, 0, 0)
    cfg["plist"] = cfg["plist_template"].replace("__LLAMA_BIND_ADDRESS__", cfg["bind_address"])
    plistlib.loads(cfg["plist"].encode())
    cfg["hashes"][cfg["launchd_plist_path"]] = hashlib.sha256(cfg["plist"].encode()).hexdigest()
    return cfg


def installed(cfg):
    # The role's own check: `brew list --versions <formula>` exits nonzero only
    # when the formula is absent, and also resolves renamed/aliased formulae.
    # (Current Homebrew rejects combining --full-name with --versions.) A
    # formula from a repository that is not tapped is absent; it is never
    # resolved during planning, so nothing is tapped automatically.
    formula = cfg["brew_formula"]
    repository = formula.rsplit("/", 1)[0] if formula.count("/") == 2 else ""
    if repository and repository != "homebrew/core":
        if repository not in run([cfg["brew"], "tap"], user=cfg.get("brew_user")).stdout.split():
            return False
    return run([cfg["brew"], "list", "--formula", "--versions", formula], check=False, user=cfg.get("brew_user")).returncode == 0


def version(cfg):
    if not Path(cfg["binary"]).is_file():
        return False
    out = run([cfg["binary"], "--version"])
    match = re.search(r"\(build ([0-9]+), commit ([0-9a-f]+)\)", out.stdout + out.stderr)
    if not match or "b" + match[1] + "-" + match[2] != cfg["build"]:
        raise RuntimeError("installed llama-server does not match the declared pinned build")
    return True


def resources(cfg):
    return [
        (cfg["install_dir"], 0, cfg["wheel"], 0o755),
        (cfg["model_dir"], 0, cfg["wheel"], 0o755),
        (cfg["config_dir"], 0, cfg["gid"], 0o750),
        (cfg["log_dir"], 0, cfg["wheel"], 0o755),
    ]


def file_info(cfg, path):
    if path == cfg["api_key_path"]:
        return cfg["uid"], cfg["gid"], 0o600
    return 0, cfg["wheel"], 0o644 if path == cfg["launchd_plist_path"] else 0o755


def current(cfg):
    loaded, running = job(cfg)
    if not cfg["enabled"]:
        return not loaded and all(not os.path.lexists(cfg[p]) for p in ["launchd_plist_path", "api_key_path"])
    if not installed(cfg) or not version(cfg):
        return False
    if any(not metadata(p, uid, gid, mode, True) for p, uid, gid, mode in resources(cfg)):
        return False
    # Existing model continuity is metadata-only. Its already-installed wrapper
    # carries the pin and verifies weights on a requested process start.
    if not metadata(cfg["model_path"], 0, cfg["wheel"], 0o644) or Path(cfg["model_path"]).stat().st_size == 0:
        return False
    for path, expected in cfg["hashes"].items():
        if not metadata(path, *file_info(cfg, path)) or hashlib.sha256(Path(path).read_bytes()).hexdigest() != expected:
            return False
    for path in [cfg["stdout_log"], cfg["stderr_log"]]:
        if not metadata(path, cfg["uid"], cfg["gid"], 0o644):
            return False
    return loaded and running


def ensure_directory(path, uid, gid, mode):
    if metadata(path, uid, gid, mode, True):
        return
    Path(path).mkdir(parents=True, exist_ok=True)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def put(path, content, uid, gid, mode):
    target = Path(path)
    exists = target.exists()
    if exists:
        metadata(path, uid, gid, mode)
        if target.read_bytes() == content:
            if not metadata(path, uid, gid, mode):
                os.chown(path, uid, gid)
                os.chmod(path, mode)
            return False
    descriptor, temporary = tempfile.mkstemp(prefix=".llama-server-", dir=target.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchown(stream.fileno(), uid, gid)
            os.fchmod(stream.fileno(), mode)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return True


def stage_model(cfg):
    model = Path(cfg["model_path"])
    wrapper = Path(cfg["wrapper_path"])
    marker = 'GGUF_SHA256="' + cfg["model_sha256"] + '"'
    if model.is_file() and model.stat().st_size > 0 and wrapper.is_file() and marker in wrapper.read_text():
        return None
    # Only fresh or explicitly changed model provisioning downloads/hashes;
    # an existing running profile never reads model contents during a no-op.
    descriptor, temporary = tempfile.mkstemp(prefix=".llama-model-", dir=cfg["model_dir"])
    try:
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "wb") as stream, urllib.request.urlopen(cfg["model_url"], timeout=120) as response:
            while True:
                data = response.read(1024 * 1024)
                if not data:
                    break
                digest.update(data)
                stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchown(stream.fileno(), 0, cfg["wheel"])
            os.fchmod(stream.fileno(), 0o644)
        if digest.hexdigest() != cfg["model_sha256"]:
            raise RuntimeError("downloaded detector model checksum differs from its pin")
        return temporary
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise


def unload(cfg):
    run(["/bin/launchctl", "bootout", "system/" + cfg["launchd_label"]], check=False)
    for _ in range(100):
        if not job(cfg)[0]:
            return
        time.sleep(0.1)
    raise RuntimeError("detector job did not unload; managed runtime files were retained")


def apply(cfg, data):
    if not cfg["enabled"]:
        for key in ["launchd_plist_path", "api_key_path"]:
            if os.path.lexists(cfg[key]):
                metadata(cfg[key], 0, 0, 0)
        if job(cfg)[0]:
            unload(cfg)
        for key in ["launchd_plist_path", "api_key_path"]:
            path = Path(cfg[key])
            if os.path.lexists(path):
                if path.is_symlink() or not path.is_file():
                    raise RuntimeError("detector removal resource has an unsafe file type")
                path.unlink()
        return
    for path, expected in cfg["hashes"].items():
        value = cfg["plist"] if path == cfg["launchd_plist_path"] else data["contents"][path]
        if hashlib.sha256(value.encode()).hexdigest() != expected:
            raise RuntimeError("detector input does not match the planned resource digest")
    if not installed(cfg):
        run([cfg["brew"], "install", cfg["brew_formula"]], user=cfg.get("brew_user"))
    if not version(cfg):
        raise RuntimeError("detector binary is unavailable after installation")
    for item in resources(cfg):
        ensure_directory(*item)
    staged = stage_model(cfg)
    try:
        changed = staged is not None or any(
            not Path(path).is_file() or hashlib.sha256(Path(path).read_bytes()).hexdigest() != expected
            for path, expected in cfg["hashes"].items()
        )
        loaded, running = job(cfg)
        # Unload before publishing runtime changes. An interrupted publication
        # remains visibly unloaded and retries naturally, without a second journal.
        if changed and loaded:
            unload(cfg)
            loaded = running = False
        if staged is not None:
            os.replace(staged, cfg["model_path"])
            staged = None
        elif not metadata(cfg["model_path"], 0, cfg["wheel"], 0o644):
            os.chown(cfg["model_path"], 0, cfg["wheel"])
            os.chmod(cfg["model_path"], 0o644)
        for path in cfg["hashes"]:
            value = cfg["plist"] if path == cfg["launchd_plist_path"] else data["contents"][path]
            put(path, value.encode(), *file_info(cfg, path))
        for path in [cfg["stdout_log"], cfg["stderr_log"]]:
            if not os.path.lexists(path):
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
                os.close(descriptor)
            if not metadata(path, cfg["uid"], cfg["gid"], 0o644):
                os.chown(path, cfg["uid"], cfg["gid"])
                os.chmod(path, 0o644)
        if not loaded:
            run(["/bin/launchctl", "bootstrap", "system", cfg["launchd_plist_path"]])
            run(["/bin/launchctl", "enable", "system/" + cfg["launchd_label"]])
        if changed or not loaded or not running:
            run(["/bin/launchctl", "kickstart", "-k", "system/" + cfg["launchd_label"]])
    finally:
        if staged is not None and os.path.exists(staged):
            os.unlink(staged)


def health(cfg):
    token = Path(cfg["api_key_path"]).read_text().strip()
    origin = "http://" + cfg["bind_address"] + ":" + str(cfg["port"])
    def read(path, authenticated):
        request = urllib.request.Request(origin + path, headers={"Authorization": "Bearer " + token} if authenticated else {})
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, {}
    code, models = read("/v1/models", True)
    props_code, props = read("/props", True)
    unauth, _ = read("/v1/models", False)
    return code == props_code == 200 and unauth == 401 and [v.get("id") for v in models.get("data", [])] == [cfg["alias"]] and props.get("build_info") == cfg["build"] and props.get("total_slots") == 1


def verify(cfg):
    for attempt in range(cfg["healthcheck_retries"]):
        try:
            if not cfg["enabled"]:
                if current(cfg):
                    return
            elif job(cfg) == (True, True) and (not cfg["healthcheck_enabled"] or health(cfg)):
                return
        except (OSError, ValueError, urllib.error.URLError):
            pass
        if attempt + 1 < cfg["healthcheck_retries"]:
            time.sleep(cfg["healthcheck_delay"])
    raise RuntimeError("detector launchd/authenticated profile readiness failed")


def main():
    action = sys.argv[1]
    cfg = prepare(json.loads(base64.b64decode(sys.argv[2])))
    if action == "status":
        print("current" if current(cfg) else "drift")
    elif action == "apply":
        apply(cfg, json.load(sys.stdin))
    elif action == "verify":
        verify(cfg)
    else:
        raise RuntimeError("unknown detector operation")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # HTTP/process/parser errors can contain credentials; expose no raw text.
        print("native detector operation failed; package/configuration/readiness did not satisfy its contract", file=sys.stderr)
        sys.exit(1)
