"""Native remote-worker role operations; no transcription or pruning is invoked."""

import base64
import grp
import hashlib
import json
import os
import platform
import plistlib
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path


def run(argv, c, user=None, check=True, extra=None):
    env = {"PATH": c["launchd_path"], "PYTHONDONTWRITEBYTECODE": "1", "HOMEBREW_NO_AUTO_UPDATE": "1",
           "HOMEBREW_NO_ANALYTICS": "1", "HF_HUB_DISABLE_TELEMETRY": "1"}
    cwd = "/"
    if user:
        account = pwd.getpwnam(user)
        cwd = env["HOME"] = account.pw_dir
        if os.geteuid() != account.pw_uid:
            argv = ["/usr/bin/sudo", "-H", "-u", user, "--", *argv]
    env.update(extra or {})
    if user and os.geteuid() != pwd.getpwnam(user).pw_uid:
        # Only public paths/feature flags are carried here, never credentials.
        argv = argv[:5] + ["/usr/bin/env", *[key + "=" + value for key, value in env.items()], *argv[5:]]
    result = subprocess.run(argv, capture_output=True, text=True, env=env, cwd=cwd, timeout=3600)
    if check and result.returncode:
        raise RuntimeError("native Voxhelm remote-worker command failed")
    return result


def metadata(path, owner, group, mode, directory=False):
    try:
        value = os.lstat(path)
    except FileNotFoundError:
        return False
    valid = stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode) and value.st_nlink == 1
    if not valid:
        raise RuntimeError("remote-worker managed resource has an unsafe type")
    return (value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode)) == (pwd.getpwnam(owner).pw_uid, grp.getgrnam(group).gr_gid, mode)


def directory(path, owner, group, mode):
    if metadata(path, owner, group, mode, True):
        return
    # Like Ansible's file state=directory, every directory created here
    # (including missing ancestors, e.g. ~/Library/Caches/voxhelm) receives
    # the requested owner and mode; existing ancestors are left untouched.
    missing = []
    current = Path(path)
    while not os.path.lexists(current):
        missing.append(current)
        current = current.parent
    uid, gid = pwd.getpwnam(owner).pw_uid, grp.getgrnam(group).gr_gid
    for created in reversed(missing):
        created.mkdir()
        os.chown(created, uid, gid)
        os.chmod(created, mode)
    if not missing:
        os.chown(path, uid, gid)
        os.chmod(path, mode)


def put(path, resource):
    content = resource["content"].encode()
    good = metadata(path, resource["owner"], resource["group"], resource["mode"])
    if os.path.exists(path) and Path(path).read_bytes() == content:
        if not good:
            os.chown(path, pwd.getpwnam(resource["owner"]).pw_uid, grp.getgrnam(resource["group"]).gr_gid)
            os.chmod(path, resource["mode"])
        return
    fd, temporary = tempfile.mkstemp(prefix=".voxhelm-worker-", dir=Path(path).parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchown(stream.fileno(), pwd.getpwnam(resource["owner"]).pw_uid, grp.getgrnam(resource["group"]).gr_gid)
            os.fchmod(stream.fileno(), resource["mode"])
        if path.endswith(".plist"):
            plistlib.loads(content)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def resource_current(path, resource):
    return metadata(path, resource["owner"], resource["group"], resource["mode"]) and hashlib.sha256(Path(path).read_bytes()).hexdigest() == resource["sha256"]


def prepare(c):
    if platform.system() != "Darwin" or os.geteuid() != 0:
        raise RuntimeError("remote worker requires the declared Darwin management privilege")
    account = pwd.getpwnam(c["service_user"])
    if account.pw_dir != c["service_home"]:
        raise RuntimeError("remote worker must retain the existing account's actual home")
    grp.getgrnam(c["service_group"])
    c["brew"] = c["brew_bin"] or next((p for p in ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"] if Path(p).is_file()), "")
    c["packages"] = sorted(set(c["brew_packages"] + (c["ad_analysis_brew_packages"] if c["ad_analysis_enabled"] else [])))
    if c["packages"] and (not c["brew"] or not c["brew_user"]):
        raise RuntimeError("remote worker requires its existing Homebrew binary and declared owner")
    c["package_spec"] = c["package_name"] + ("[" + ",".join(c["package_extras"]) + "]" if c["package_extras"] else "") + "==" + c["package_version"]
    return c


def directories(c, apply=False):
    specs = [(c["config_dir"], "root", c["service_group"], 0o750), (c["log_dir"], "root", "wheel", 0o755)]
    specs += [(c[key], c["service_user"], c["service_group"], 0o750) for key in ["work_dir", "model_cache_dir"]]
    good = True
    for path, owner, group, mode in specs:
        if not metadata(path, owner, group, mode, True):
            good = False
            if apply:
                directory(path, owner, group, mode)
    for key in ["stdout_log", "stderr_log"]:
        path = c[key]
        if not metadata(path, c["service_user"], c["service_group"], 0o644):
            good = False
            if apply:
                if not os.path.lexists(path):
                    Path(path).touch(mode=0o644)
                os.chown(path, pwd.getpwnam(c["service_user"]).pw_uid, grp.getgrnam(c["service_group"]).gr_gid)
                os.chmod(path, 0o644)
    return good


def packages(c, apply=False):
    if not c["packages"]:
        return True
    # The role's per-formula check; it also resolves renamed formulae such as
    # whisper-cpp (now an old name of whisper.cpp). Current Homebrew rejects
    # combining --full-name with --versions.
    missing = [p for p in c["packages"] if run([c["brew"], "list", "--formula", "--versions", p], c, user=c["brew_user"], check=False).returncode]
    if apply:
        if c["brew_update"]:
            run([c["brew"], "update"], c, user=c["brew_user"])
        for package in missing:
            run([c["brew"], "install", package], c, user=c["brew_user"])
    return not missing and not c["brew_update"]


def tool_version(c, binary, package):
    path = Path(binary)
    if not path.is_file():
        return "", ""
    python = path.resolve().parent / "python"
    if not python.is_file():
        return "", ""
    code = "import importlib.metadata,json,platform;print(json.dumps([importlib.metadata.version(" + repr(package) + "),platform.python_version()]))"
    result = run([str(python), "-B", "-c", code], c, user=c["service_user"], check=False)
    if result.returncode:
        return "", ""
    value = json.loads(result.stdout)
    return value[0], value[1]


def runtime(c, apply=False):
    version, python = tool_version(c, c["binary_path"], "voxhelm")
    transcript = Path(c["install_transcript_path"])
    transcript_current = False
    if transcript.is_file():
        if transcript.stat().st_size > 4 * 1024 * 1024:
            raise RuntimeError("remote-worker install transcript is unexpectedly large")
        transcript_current = "package=" + c["package_spec"] in transcript.read_text()
    needed = c["force_install"] or version != c["package_version"] or python != c["python_version"] or not transcript_current
    if not needed:
        return True
    if not apply:
        return False
    argv = [c["uv_bin"], "tool", "install", *( ["--force"] if c["force_install"] else []), "--python", c["python_version"],
            "--default-index", c["public_index_url"], "--no-sources", c["package_spec"]]
    # The package/index selection contains no private credentials or sources.
    result = run(argv, c, user=c["service_user"], extra={"UV_NO_SOURCES": "1"})
    text = "command=" + " ".join(argv) + "\nindex=" + c["public_index_url"] + "\npackage=" + c["package_spec"] + "\ninstall_needed=True\nstdout:\n" + result.stdout + "\nstderr:\n" + result.stderr
    put(c["install_transcript_path"], {"owner": "root", "group": c["service_group"], "mode": 0o640, "content": text})
    return True


def nonempty(path):
    p = Path(path)
    if not os.path.lexists(p):
        return False
    # A configured source link is retained and inspected through metadata only.
    if not p.is_file() or p.stat().st_size == 0:
        raise RuntimeError("remote-worker model resource must resolve to a nonempty regular file")
    return True


def whisper_link(c, apply=False):
    if not c["whispercpp_model_source"]:
        return True
    source = Path(c["whispercpp_model_source"])
    if not nonempty(source):
        raise RuntimeError("configured whisper model source is unavailable")
    path = Path(c["model_cache_dir"]) / c["whispercpp_model"]
    if os.path.lexists(path):
        return nonempty(path)
    if apply:
        path.symlink_to(source)
        os.lchown(path, pwd.getpwnam(c["service_user"]).pw_uid, grp.getgrnam(c["service_group"]).gr_gid)
    return False


def parakeet(c, apply=False):
    if not c["parakeet_enabled"]:
        return True
    version, python = tool_version(c, c["parakeet_bin"], "parakeet-mlx")
    cli_current = version == c["parakeet_package_version"] and (python == c["parakeet_python_version"] or python.startswith(c["parakeet_python_version"] + "."))
    if not cli_current and apply:
        run([c["uv_bin"], "tool", "install", "--python", c["parakeet_python_version"], "--default-index", c["public_index_url"], "parakeet-mlx==" + c["parakeet_package_version"]], c, user=c["service_user"])
    destination = Path(c["parakeet_model_dir"])
    marker = "repo=" + c["parakeet_model_repo"] + "\nrevision=" + c["parakeet_model_revision"] + "\nmodel.safetensors sha256=" + c["parakeet_model_sha256"] + "\n"
    recorded = destination / "VOXHELM_MODEL_REVISION"
    model_current = all(nonempty(destination / name) for name in ["config.json", "model.safetensors", "VOXHELM_MODEL_REVISION"]) and recorded.read_text() == marker
    if model_current or not apply:
        return cli_current and model_current
    directory(c["parakeet_model_root"], c["service_user"], c["service_group"], 0o750)
    tool = run([c["uv_bin"], "tool", "dir"], c, user=c["service_user"]).stdout.strip()
    partial = Path(tempfile.mkdtemp(prefix=".parakeet-", dir=c["parakeet_model_root"]))
    os.chown(partial, pwd.getpwnam(c["service_user"]).pw_uid, grp.getgrnam(c["service_group"]).gr_gid)
    try:
        run([tool + "/parakeet-mlx/bin/hf", "download", c["parakeet_model_repo"], "config.json", "model.safetensors", "--revision", c["parakeet_model_revision"], "--local-dir", str(partial)], c, user=c["service_user"])
        digest = hashlib.sha256()
        with (partial / "model.safetensors").open("rb") as stream:
            while block := stream.read(1024 * 1024):
                digest.update(block)
        if digest.hexdigest() != c["parakeet_model_sha256"]:
            raise RuntimeError("downloaded Parakeet model checksum differs; existing model retained")
        shutil.rmtree(partial / ".cache", ignore_errors=True)
        put(str(partial / "VOXHELM_MODEL_REVISION"), {"owner": c["service_user"], "group": c["service_group"], "mode": 0o640, "content": marker})
        # This path is explicitly requested to change; retain the old complete
        # model until the replacement download has passed its weight checksum.
        if destination.exists():
            if destination.is_symlink() or not destination.is_dir():
                raise RuntimeError("Parakeet model directory has an unsafe type")
            shutil.rmtree(destination)
        os.rename(partial, destination)
    finally:
        if partial.exists():
            shutil.rmtree(partial)
    return True


def artifact_metadata(path):
    try:
        info = Path(path).lstat()
    except FileNotFoundError:
        return None
    def fields(value):
        return {"dev": value.st_dev, "ino": value.st_ino, "size": value.st_size, "mtime_ns": value.st_mtime_ns,
                "uid": value.st_uid, "gid": value.st_gid, "mode": stat.S_IMODE(value.st_mode)}
    if stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
        return {**fields(info), "kind": "regular", "target": None, "referent": None}
    if stat.S_ISLNK(info.st_mode):
        resolved = Path(path).stat()
        if not stat.S_ISREG(resolved.st_mode):
            raise RuntimeError("artifact link must resolve to a regular model file")
        return {**fields(info), "kind": "symlink", "target": os.readlink(path), "referent": fields(resolved)}
    raise RuntimeError("artifact continuity requires a regular file or declared model link")


def model_pin(c, path):
    record = Path(c["config_dir"]) / ".native-artifacts.json"
    pins = {}
    if record.exists():
        if not metadata(record, "root", c["service_group"], 0o640):
            raise RuntimeError("artifact provenance has unsafe ownership or mode")
        pins = json.loads(record.read_text())
    # An existing native record for this path always outranks the initial
    # continuity input, including when the wanted pin rolls back later.
    candidate = pins[str(path)] if str(path) in pins else c.get("preserved_artifacts", {}).get(str(path))
    if not isinstance(candidate, dict) or candidate.get("metadata") != artifact_metadata(path):
        return None
    return candidate.get("pin")


def window_model(c, apply=False):
    if not c["ad_analysis_enabled"]:
        return True
    path = Path(c["model_cache_dir"]) / c["window_model"]
    source = Path(c["window_model_source"]) if c["window_model_source"] else None
    if nonempty(path) and model_pin(c, path) == c["window_model_sha256"] and (source is None or (path.is_symlink() and path.readlink() == source)):
        return True
    if not apply:
        return False
    for key in ["whispercpp_bin", "ffprobe_bin"]:
        if not Path(c[key]).is_file():
            raise RuntimeError("ad-analysis runtime executable is unavailable")
    temporary = None
    try:
        digest = hashlib.sha256()
        if source is None:
            fd, temporary = tempfile.mkstemp(prefix=".window-model-", dir=c["model_cache_dir"])
            with os.fdopen(fd, "wb") as output, urllib.request.urlopen(c["window_model_url"], timeout=120) as response:
                while block := response.read(1024 * 1024):
                    digest.update(block)
                    output.write(block)
                output.flush()
                os.fsync(output.fileno())
            candidate = Path(temporary)
        else:
            if not nonempty(source):
                raise RuntimeError("window model source is unavailable")
            with source.open("rb") as stream:
                while block := stream.read(1024 * 1024):
                    digest.update(block)
            candidate = source
        if digest.hexdigest() != c["window_model_sha256"]:
            raise RuntimeError("window model checksum differs; current cache retained")
        if source is None:
            os.chown(candidate, pwd.getpwnam(c["service_user"]).pw_uid, grp.getgrnam(c["service_group"]).gr_gid)
            os.chmod(candidate, 0o640)
            os.replace(candidate, path)
        else:
            fd, link = tempfile.mkstemp(prefix=".window-link-", dir=path.parent)
            os.close(fd)
            os.unlink(link)
            try:
                os.symlink(source, link)
                os.lchown(link, pwd.getpwnam(c["service_user"]).pw_uid, grp.getgrnam(c["service_group"]).gr_gid)
                os.replace(link, path)
            finally:
                if os.path.lexists(link):
                    os.unlink(link)
        record = Path(c["config_dir"]) / ".native-artifacts.json"
        pins = json.loads(record.read_text()) if record.exists() else {}
        pins[str(path)] = {"pin": c["window_model_sha256"], "metadata": artifact_metadata(path)}
        put(str(record), {"owner": "root", "group": c["service_group"], "mode": 0o640, "content": json.dumps(pins, sort_keys=True) + "\n"})
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)
    return True


def job(c):
    result = run(["/bin/launchctl", "print", "system/" + c["launchd_label"]], c, check=False)
    if result.returncode:
        if result.returncode != 113:
            raise RuntimeError("remote-worker launchd status could not be read")
        return False, False
    return True, bool(re.search(r"^\s*state = running$", result.stdout, re.M))


def restart_marker(c):
    return Path(c["config_dir"]) / ".ops-deploy-restart"


def restart_intent(c):
    marker = restart_marker(c)
    if not os.path.lexists(marker):
        return None
    if not metadata(marker, "root", "wheel", 0o600):
        raise RuntimeError("remote-worker restart intent has unsafe metadata")
    return json.loads(marker.read_text())


def current(c):
    if not directories(c) or not packages(c) or not runtime(c) or not whisper_link(c) or not parakeet(c) or not window_model(c):
        return False
    if any(not resource_current(path, resource) for path, resource in c["contents"].items()):
        return False
    if not c["launchd_manage_state"]:
        return True
    if restart_intent(c) is not None:
        return False
    loaded, running = job(c)
    return loaded and (running or not c["launchd_start_service"])


def apply(c):
    directories(c, True)
    packages(c, True)
    plist = c["launchd_plist_path"]
    plist_changed = not resource_current(plist, c["contents"][plist])
    changed = not runtime(c) or not parakeet(c) or not window_model(c) or any(
        not resource_current(path, resource) for path, resource in c["contents"].items())
    intent = restart_intent(c) if c["launchd_manage_state"] else None
    if c["launchd_manage_state"] and changed:
        # Like the role, the running worker keeps serving while the new runtime,
        # models and files are published; it is reloaded/restarted afterwards.
        # The persisted intent keeps that restart owed if a later step fails.
        intent = {"reload": plist_changed or bool(intent and intent.get("reload"))}
        put(str(restart_marker(c)), {"owner": "root", "group": "wheel", "mode": 0o600, "content": json.dumps(intent) + "\n"})
    runtime(c, True)
    whisper_link(c, True)
    parakeet(c, True)
    window_model(c, True)
    for path, resource in c["contents"].items():
        put(path, resource)
    if c["launchd_manage_state"]:
        service = "system/" + c["launchd_label"]
        loaded, running = job(c)
        if loaded and intent and intent.get("reload"):
            run(["/bin/launchctl", "bootout", service], c)
            loaded = False
        bootstrapped = not loaded
        if bootstrapped:
            run(["/bin/launchctl", "bootstrap", "system", plist], c)
            run(["/bin/launchctl", "enable", service], c)
        if c["launchd_start_service"] and (bootstrapped or intent is not None or not running):
            run(["/bin/launchctl", "kickstart", "-k", service], c)
        if intent is not None:
            restart_marker(c).unlink()


def main():
    action = sys.argv[1]
    data = json.loads(sys.stdin.read()) if action == "apply" else json.loads(base64.b64decode(sys.argv[2]))
    c = {key.removeprefix("voxhelm_remote_worker_"): value for key, value in data.items()}
    if not c["enabled"]:
        # The original role skips every deployment task when disabled. It does
        # not remove or stop an already installed worker.
        if action == "status":
            print("current")
        return
    c = prepare(c)
    if action == "status":
        print("current" if current(c) else "drift")
    elif action == "apply":
        apply(c)
    elif action == "verify":
        c["force_install"] = False
        c["brew_update"] = False
        for _ in range(50):
            if current(c):
                return
            time.sleep(0.2)
        raise RuntimeError("remote-worker deployment did not converge")
    else:
        raise RuntimeError("unknown remote-worker operation")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("native Voxhelm remote-worker operation failed; no credential diagnostics are emitted", file=sys.stderr)
        sys.exit(1)
