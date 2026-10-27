"""Service-local native Voxhelm control plane; model bodies are read only for selected fresh/change verification."""

import base64
import grp
import hashlib
import json
import os
import platform
import plistlib
import pwd
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

def run(argv, c, user=None, check=True, extra=None, cwd=None):
    env = {"PATH": c["launchd_path"], "PYTHONDONTWRITEBYTECODE": "1", "HOMEBREW_NO_AUTO_UPDATE": "1",
           "HOMEBREW_NO_ANALYTICS": "1", "HF_HUB_DISABLE_TELEMETRY": "1"}
    working_directory = cwd or "/"
    if user:
        account = pwd.getpwnam(user)
        env["HOME"] = account.pw_dir
        working_directory = cwd or account.pw_dir
        if os.geteuid() != account.pw_uid:
            argv = ["/usr/bin/sudo", "-H", "-u", user, "--", *argv]
    env.update(extra or {})
    if user and os.geteuid() != pwd.getpwnam(user).pw_uid:
        # Only public paths/feature flags are carried here, never credentials.
        argv = argv[:5] + ["/usr/bin/env", *[key + "=" + value for key, value in env.items()], *argv[5:]]
    result = subprocess.run(argv, capture_output=True, text=True, env=env, cwd=working_directory, timeout=3600)
    if check and result.returncode:
        raise RuntimeError("native Voxhelm Voxhelm command failed")
    return result


def metadata(path, owner, group, mode, directory=False):
    try:
        value = os.lstat(path)
    except FileNotFoundError:
        return False
    valid = stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode) and value.st_nlink == 1
    if not valid:
        raise RuntimeError("Voxhelm managed resource has an unsafe type")
    return (value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode)) == (pwd.getpwnam(owner).pw_uid, grp.getgrnam(group).gr_gid, mode)


def directory(path, owner, group, mode):
    if metadata(path, owner, group, mode, True):
        return
    Path(path).mkdir(parents=True, exist_ok=True)
    os.chown(path, pwd.getpwnam(owner).pw_uid, grp.getgrnam(group).gr_gid)
    os.chmod(path, mode)


def put(path, resource):
    content = resource["content"].encode()
    good = metadata(path, resource["owner"], resource["group"], resource["mode"])
    if os.path.exists(path) and Path(path).read_bytes() == content:
        if not good:
            os.chown(path, pwd.getpwnam(resource["owner"]).pw_uid, grp.getgrnam(resource["group"]).gr_gid)
            os.chmod(path, resource["mode"])
        return
    fd, temporary = tempfile.mkstemp(prefix=".voxhelm-", dir=Path(path).parent)
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


def nonempty(path):
    p = Path(path)
    if not os.path.lexists(p):
        return False
    # A configured source link is retained and inspected through metadata only.
    if not p.is_file() or p.stat().st_size == 0:
        raise RuntimeError("Voxhelm model resource must resolve to a nonempty regular file")
    return True


def prepare(c):
    if platform.system() != "Darwin" or os.geteuid() != 0:
        raise RuntimeError("Voxhelm control deployment requires the existing root Darwin connection")
    c["brew"] = c["brew_bin"] or next((p for p in ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"] if Path(p).is_file()), "")
    if not c["brew"]:
        raise RuntimeError("Voxhelm requires its existing Homebrew installation")
    c["brew_owner"] = c["brew_user"] or pwd.getpwuid(Path(c["brew"]).stat().st_uid).pw_name
    c["packages"] = ["whisper-cpp"] + (["whisperkit-cli"] if c["whisperkit_enabled"] else []) + (["espeak-ng"] if c["tts_kokoro_enabled"] else [])
    return c


def directories(c, apply=False):
    good = True
    for key in ["app_dir", "config_dir", "log_dir", "model_cache_dir", "piper_voice_dir", "kokoro_model_dir", "lane_scheduler_dir"]:
        mode = 0o750 if key == "config_dir" else 0o755
        if not metadata(c[key], "root", "wheel", mode, True):
            good = False
            if apply:
                directory(c[key], "root", "wheel", mode)
    paths = [c[key] for key in ["launchd_stdout_log", "launchd_stderr_log", "worker_stdout_log", "worker_stderr_log",
                               "whisperkit_stdout_log", "whisperkit_stderr_log"]]
    if c["wyoming_stt_enabled"]:
        paths += [c["wyoming_stt_stdout_log"], c["wyoming_stt_stderr_log"]]
    for path in paths:
        if not metadata(path, "root", "wheel", 0o644):
            good = False
            if apply:
                if not os.path.lexists(path):
                    Path(path).touch(mode=0o644)
                os.chown(path, 0, grp.getgrnam("wheel").gr_gid)
                os.chmod(path, 0o644)
    return good


def packages(c, apply=False):
    # The role's per-formula check; it also resolves renamed formulae such as
    # whisper-cpp (now an old name of whisper.cpp). Current Homebrew rejects
    # combining --full-name with --versions.
    missing = [p for p in c["packages"] if run([c["brew"], "list", "--formula", "--versions", p], c, user=c["brew_owner"], check=False).returncode]
    if apply:
        for package in missing:
            run([c["brew"], "install", package], c, user=c["brew_owner"])
    return not missing


def pending(c):
    return Path(c["config_dir"]) / ".ops-deploy-pending"


def mark(c):
    put(str(pending(c)), {"owner": "root", "group": "wheel", "mode": 0o600, "content": "pending\n"})


def selected_extras(c):
    return list(dict.fromkeys(c["uv_extras"] + (["diarization"] if c["diarization_backend"].strip().lower() == "pyannote" else [])
                              + (["kokoro"] if c["tts_kokoro_enabled"] else []) + (["routing"] if c["tts_language_routing_enabled"] else [])))


# Read-only: installed metadata only. A requirement gated by an extra alone
# must be installed for every selected extra; requirements with any other
# marker condition are not judged here.
RUNTIME_PROBE = r'''
import importlib.metadata as m, json, platform, re, sys
selected = set(json.loads(sys.argv[1]))
missing = []
for requirement in m.distribution("voxhelm").requires or []:
    spec, _, marker = requirement.partition(";")
    found = re.fullmatch(r"\s*extra\s*==\s*[\"']([^\"']+)[\"']\s*", marker)
    if not found or found.group(1) not in selected:
        continue
    name = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", spec).group(1)
    try:
        m.distribution(name)
    except m.PackageNotFoundError:
        missing.append(name)
print(json.dumps([m.version("voxhelm"), platform.python_version(), sorted(missing)]))
'''


def runtime_current(c):
    if pending(c).exists():
        return False
    python = Path(c["app_dir"]) / ".venv/bin/python"
    if not python.is_file():
        return False
    result = run([str(python), "-B", "-c", RUNTIME_PROBE, json.dumps(selected_extras(c))], c, check=False)
    if result.returncode:
        return False
    version, interpreter, missing = json.loads(result.stdout)
    return version == c["project_version"] and interpreter == c["python_version"] and not missing


def runtime_apply(c):
    # As in the role, running units keep serving during the interpreter/venv/
    # sync steps; the pending marker makes launchd-apply restart them after a
    # successful sync, and keeps that restart owed if this step fails.
    mark(c)
    found = run([c["uv_bin"], "python", "find", "--managed-python", "--no-project", "--resolve-links", c["python_version"]], c, check=False)
    if found.returncode:
        run([c["uv_bin"], "python", "install", c["python_version"]], c)
        found = run([c["uv_bin"], "python", "find", "--managed-python", "--no-project", "--resolve-links", c["python_version"]], c)
    selected = found.stdout.strip()
    venv = Path(c["app_dir"]) / ".venv"
    if (venv / "bin/python").is_file():
        actual = run([str(venv / "bin/python"), "-B", "-c", "import sys;print(getattr(sys,'_base_executable',sys.executable))"], c).stdout.strip()
        if actual != selected:
            if venv.is_symlink() or not venv.is_dir():
                raise RuntimeError("Voxhelm virtualenv has an unsafe type")
            shutil.rmtree(venv)
    if not (venv / "bin/python").is_file():
        run([c["uv_bin"], "venv", "--python", selected, str(venv)], c)
    extras = selected_extras(c)
    argv = [c["uv_bin"], "sync", "--frozen", "--no-dev"]
    for extra in extras:
        argv += ["--extra", extra]
    # The project directory is explicit; no activated controller environment is inherited.
    run(argv, c, cwd=c["app_dir"], extra={"VIRTUAL_ENV": str(venv), "UV_PROJECT_ENVIRONMENT": str(venv)})


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
        if not metadata(record, "root", "wheel", 0o640):
            raise RuntimeError("artifact provenance has unsafe ownership or mode")
        pins = json.loads(record.read_text())
    # An existing native record for this path always outranks the initial
    # continuity input, including when the wanted pin rolls back later.
    candidate = pins[str(path)] if str(path) in pins else c.get("preserved_artifacts", {}).get(str(path))
    if not isinstance(candidate, dict) or candidate.get("metadata") != artifact_metadata(path):
        return None
    return candidate.get("pin")


def download(c, path, url, checksum=""):
    fd, temporary = tempfile.mkstemp(prefix=".voxhelm-model-", dir=path.parent)
    try:
        digest = hashlib.sha256()
        with os.fdopen(fd, "wb") as output, urllib.request.urlopen(url, timeout=120) as response:
            while block := response.read(1024 * 1024):
                digest.update(block)
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
            os.fchown(output.fileno(), 0, grp.getgrnam("wheel").gr_gid)
            os.fchmod(output.fileno(), 0o644)
        if checksum and digest.hexdigest() != checksum:
            raise RuntimeError("Voxhelm artifact checksum differs; existing model retained")
        if Path(temporary).stat().st_size == 0:
            raise RuntimeError("Voxhelm artifact download is empty")
        os.replace(temporary, path)
        if checksum:
            record = Path(c["config_dir"]) / ".native-artifacts.json"
            pins = json.loads(record.read_text()) if record.exists() else {}
            pins[str(path)] = {"pin": checksum, "metadata": artifact_metadata(path)}
            put(str(record), {"owner": "root", "group": "wheel", "mode": 0o640, "content": json.dumps(pins, sort_keys=True) + "\n"})
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def models(c, apply=False):
    good = True
    whisper = Path(c["model_cache_dir"]) / c["whispercpp_model"]
    whisper_pin = c.get("whispercpp_model_sha256", "")
    if not nonempty(whisper) or (whisper_pin and model_pin(c, whisper) != whisper_pin):
        good = False
        if apply:
            download(c, whisper, c["whispercpp_model_url"], whisper_pin)
    for voice in c["piper_voices"]:
        if not all(nonempty(Path(c["piper_voice_dir"]) / (voice + suffix)) for suffix in [".onnx", ".onnx.json"]):
            good = False
            if apply:
                run([c["app_dir"] + "/.venv/bin/python", "-B", "-m", "piper.download_voices", "--download-dir", c["piper_voice_dir"], voice], c)
    if c["tts_kokoro_enabled"]:
        for artifact in c["kokoro_artifacts"]:
            path = Path(c["kokoro_model_dir"]) / artifact["dest"]
            if not nonempty(path) or model_pin(c, path) != artifact["sha256"]:
                good = False
                if apply:
                    download(c, path, artifact["url"], artifact["sha256"])
    return good


def job(c, unit):
    result = run(["/bin/launchctl", "print", "system/" + unit["label"]], c, check=False)
    if result.returncode:
        if result.returncode != 113:
            raise RuntimeError("Voxhelm launchd status could not be read")
        return False, False
    return True, bool(re.search(r"^\s*state = running$", result.stdout, re.M))


def restart_marker(c, unit):
    return Path(c["config_dir"]) / (".ops-deploy-restart-" + unit["label"])


def launchd_current(c):
    if not c["launchd_manage_state"]:
        return True
    for unit in c["units"]:
        loaded, running = job(c, unit)
        if not loaded or (unit["start"] and not running) or restart_marker(c, unit).exists():
            return False
    if not c["prune_enabled"]:
        if job(c, {"label": c["prune_label"]})[0] or any(os.path.lexists(c[key]) for key in ["prune_plist_path", "prune_script_path"]):
            return False
    return True


def config_current(c):
    return all(resource_current(path, resource) for path, resource in c["contents"].items())


def config_apply(c):
    env = c["config_dir"] + "/voxhelm.env"
    common_change = not resource_current(env, c["contents"][env])
    for unit in c["units"]:
        plist_changed = not resource_current(unit["plist"], c["contents"][unit["plist"]])
        changed = plist_changed or (not unit["periodic"] and (common_change or not resource_current(unit["script"], c["contents"][unit["script"]])))
        if c["launchd_manage_state"] and changed:
            marker = restart_marker(c, unit)
            previous = {}
            if marker.exists():
                if not metadata(marker, "root", "wheel", 0o600):
                    raise RuntimeError("Voxhelm restart intent has unsafe metadata")
                previous = json.loads(marker.read_text())
            put(str(marker), {"owner": "root", "group": "wheel", "mode": 0o600,
                              "content": json.dumps({"reload": plist_changed or previous.get("reload", False)}) + "\n"})
    for path, resource in c["contents"].items():
        put(path, resource)


def launchd_apply(c):
    if not c["launchd_manage_state"]:
        return
    for unit in c["units"]:
        loaded, running = job(c, unit)
        service = "system/" + unit["label"]
        marker = restart_marker(c, unit)
        reload_unit = marker.exists() and json.loads(marker.read_text()).get("reload", False)
        if reload_unit and loaded:
            run(["/bin/launchctl", "bootout", service], c)
            loaded = False
        if not loaded:
            run(["/bin/launchctl", "bootstrap", "system", unit["plist"]], c)
            run(["/bin/launchctl", "enable", service], c)
        if unit["start"] and (marker.exists() or pending(c).exists() or not loaded or not running):
            run(["/bin/launchctl", "kickstart", "-k", service], c)
    if not c["prune_enabled"]:
        if job(c, {"label": c["prune_label"]})[0]:
            run(["/bin/launchctl", "bootout", "system/" + c["prune_label"]], c)
        if job(c, {"label": c["prune_label"]})[0]:
            raise RuntimeError("disabled Voxhelm pruning job remains loaded")
        for key in ["prune_plist_path", "prune_script_path"]:
            if os.path.lexists(c[key]):
                metadata(c[key], "root", "wheel", 0)
                Path(c[key]).unlink()


def health(c):
    for attempt in range(c["healthcheck_retries"]):
        try:
            if c["launchd_manage_state"] and any(not job(c, unit)[0] or (unit["start"] and not job(c, unit)[1]) for unit in c["units"]):
                raise RuntimeError("ordinary Voxhelm unit is not ready")
            if c["healthcheck_enabled"]:
                with urllib.request.urlopen(c["healthcheck_url"], timeout=5) as response:
                    if response.status != 200 or json.load(response).get("status") != "ok":
                        raise RuntimeError("Voxhelm health is not ready")
                if c["wyoming_stt_enabled"]:
                    host = "127.0.0.1" if c["wyoming_stt_host"] in ["0.0.0.0", "::"] else c["wyoming_stt_host"]
                    with socket.create_connection((host, c["wyoming_stt_port"]), timeout=5):
                        pass
                if c["whisperkit_enabled"]:
                    host = "127.0.0.1" if c["whisperkit_host"] in ["0.0.0.0", "::"] else c["whisperkit_host"]
                    with urllib.request.urlopen("http://" + host + ":" + str(c["whisperkit_port"]) + "/health", timeout=5) as response:
                        if response.status != 200 or json.load(response).get("status") != "ok":
                            raise RuntimeError("WhisperKit health is not ready")
            return
        except (OSError, ValueError, RuntimeError):
            if attempt + 1 == c["healthcheck_retries"]:
                raise RuntimeError("Voxhelm health did not converge") from None
            time.sleep(c["healthcheck_delay"])


def finish(c):
    health(c)
    for unit in c["units"] + [{"label": c["prune_label"]}]:
        marker = restart_marker(c, unit)
        if marker.exists():
            if not metadata(marker, "root", "wheel", 0o600):
                raise RuntimeError("Voxhelm restart intent has unsafe metadata")
            marker.unlink()
    if pending(c).exists():
        metadata(pending(c), "root", "wheel", 0o600)
        pending(c).unlink()


def django(c, arguments, check=True, input_data=None):
    env_file = c["config_dir"] + "/voxhelm.env"
    argv = [c["app_dir"] + "/.venv/bin/python", "-B", *arguments]
    shell = "set -a; . " + shlex.quote(env_file) + "; set +a; cd " + shlex.quote(c["app_dir"]) + "; exec " + shlex.join(argv)
    result = subprocess.run(["/bin/bash", "-c", shell], input=input_data, capture_output=True, text=True,
                            env={"PATH": c["launchd_path"], "PYTHONDONTWRITEBYTECODE": "1"}, timeout=300)
    if check and result.returncode:
        raise RuntimeError("Voxhelm database operation failed without credential diagnostics")
    return result


def migrations_current(c):
    if not (Path(c["app_dir"]) / "db.sqlite3").is_file() or not (Path(c["app_dir"]) / ".venv/bin/python").is_file() or not (Path(c["config_dir"]) / "voxhelm.env").is_file():
        return False
    return django(c, ["manage.py", "migrate", "--check", "--plan"], check=False).returncode == 0


BOOTSTRAP = r'''
import json,os,sys
value=json.load(sys.stdin)
readonly=value.pop("readonly")
os.environ.setdefault("DJANGO_SETTINGS_MODULE","config.settings")
from django.conf import settings
if readonly:
    database=dict(settings.DATABASES["default"])
    database["NAME"]="file:"+str(database["NAME"])+"?mode=ro"
    database["OPTIONS"]={**database.get("OPTIONS",{}),"uri":True}
    settings.DATABASES["default"]=database
import django
django.setup()
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
User=get_user_model()
username=value["username"].strip()
email=value["email"].strip()
user=User.objects.filter(username=username).first()
current=user is not None and user.is_staff and user.is_active and (not email or user.email==email) and check_password(value["password"],user.password,setter=None)
if readonly:
    print("current" if current else "drift")
elif current:
    print("unchanged")
else:
    if user is None:
        user=User.objects.create_user(username=username,email=email,password=value["password"],is_staff=True,is_active=True)
    else:
        fields=[]
        if email and user.email!=email:
            user.email=email;fields.append("email")
        for field in ["is_staff","is_active"]:
            if not getattr(user,field):
                setattr(user,field,True);fields.append(field)
        if not check_password(value["password"],user.password,setter=None):
            user.set_password(value["password"]);fields.append("password")
        if fields:
            user.save(update_fields=fields)
    print("changed")
'''


def bootstrap(c, check):
    if check and not migrations_current(c):
        return "drift"
    value = {**c["bootstrap"], "readonly": check}
    result = django(c, ["-c", BOOTSTRAP], input_data=json.dumps(value) + "\n")
    if result.stdout.strip() not in ["current", "drift", "changed", "unchanged"]:
        raise RuntimeError("Voxhelm bootstrap operation returned an unexpected result")
    return result.stdout.strip()


def main():
    action = sys.argv[1]
    data = json.loads(sys.stdin.read()) if action in ["config-apply", "bootstrap-check", "bootstrap-apply"] else json.loads(base64.b64decode(sys.argv[2]))
    c = prepare({key.removeprefix("voxhelm_"): value for key, value in data.items()})
    if action == "prepare-status":
        print("current" if directories(c) else "drift")
    elif action == "prepare-apply":
        directories(c, True)
    elif action == "mark":
        mark(c)
    elif action == "runtime-status":
        print("current" if runtime_current(c) else "drift")
    elif action == "runtime-apply":
        runtime_apply(c)
    elif action == "models-status":
        print("current" if packages(c) and models(c) else "drift")
    elif action == "models-apply":
        packages(c, True)
        models(c, True)
    elif action == "config-status":
        print("current" if config_current(c) else "drift")
    elif action == "config-apply":
        config_apply(c)
    elif action == "launchd-status":
        print("current" if launchd_current(c) else "drift")
    elif action == "launchd-apply":
        launchd_apply(c)
    elif action == "migrations-status":
        print("current" if migrations_current(c) else "drift")
    elif action == "migrations-apply":
        if not migrations_current(c):
            django(c, ["manage.py", "migrate", "--noinput"])
    elif action in ["bootstrap-check", "bootstrap-apply"]:
        print(bootstrap(c, action == "bootstrap-check"))
    elif action == "finish":
        finish(c)
    elif action == "verify":
        health(c)
    else:
        raise RuntimeError("unknown Voxhelm operation")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("native Voxhelm operation failed; private payload diagnostics are suppressed", file=sys.stderr)
        sys.exit(1)
