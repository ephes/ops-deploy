"""Service-local Darwin accounts, credentials, workspaces and launchd operations."""

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
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path


def run(argv, user=None, cwd="/", extra=None, check=True):
    env = {"PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "GIT_OPTIONAL_LOCKS": "0",
           "PYTHONDONTWRITEBYTECODE": "1", "HOMEBREW_NO_AUTO_UPDATE": "1", "HOMEBREW_NO_ANALYTICS": "1"}
    if user:
        account = pwd.getpwnam(user)
        env["HOME"] = account.pw_dir
        if os.geteuid() != account.pw_uid:
            argv = ["/usr/bin/sudo", "-H", "-u", user, "--", *argv]
    env.update(extra or {})
    if user and os.geteuid() != pwd.getpwnam(user).pw_uid:
        argv = argv[:5] + ["/usr/bin/env", *[key + "=" + value for key, value in env.items()], *argv[5:]]
    result = subprocess.run(argv, capture_output=True, text=True, env=env, cwd=cwd, timeout=900)
    if check and result.returncode:
        raise RuntimeError("native OpsGate command failed")
    return result


def record(kind, name):
    result = run(["/usr/bin/dscl", "-plist", ".", "-read", "/" + kind + "/" + name], check=False)
    if result.returncode:
        return None
    return {key.removeprefix("dsAttrTypeStandard:"): value for key, value in plistlib.loads(result.stdout.encode()).items()}


def accounts(cfg, apply=False):
    current = True
    for user, group, home, shell in [
        (cfg["ops_user"], cfg["ops_group"], cfg["ops_home_dir"], cfg["ops_shell"]),
        (cfg["control_service_user"], cfg["control_service_group"], cfg["control_service_home_dir"], cfg["control_service_shell"]),
    ]:
        group_record = record("Groups", group)
        if group_record is None:
            current = False
            if apply:
                run(["/usr/sbin/dseditgroup", "-o", "create", "-L", group])
                group_record = record("Groups", group)
        account = record("Users", user)
        desired = {"NFSHomeDirectory": [home], "UserShell": [shell]}
        if group_record:
            desired["PrimaryGroupID"] = group_record["PrimaryGroupID"]
        if account is None or any(account.get(k) != v for k, v in desired.items()):
            current = False
            if apply:
                if account is None:
                    listing = run(["/usr/bin/dscl", ".", "-list", "/Users", "UniqueID"]).stdout
                    used = [int(line.split()[-1]) for line in listing.splitlines() if line.split()[-1].lstrip("-").isdigit()]
                    run(["/usr/bin/dscl", ".", "-create", "/Users/" + user])
                    desired.update(UniqueID=[str(max([500, *used]) + 1)], RealName=[user])
                    if user == cfg["control_service_user"]:
                        desired["IsHidden"] = ["1"]
                for key, value in desired.items():
                    if account is None or account.get(key) != value:
                        run(["/usr/bin/dscl", ".", "-create", "/Users/" + user, key, *value])
    for user, group in [(cfg["ops_user"], cfg["control_service_group"]), (cfg["control_service_user"], cfg["ops_group"])]:
        result = run(["/usr/sbin/dseditgroup", "-o", "checkmember", "-m", user, group], check=False)
        if result.returncode or not result.stdout.startswith("yes "):
            current = False
            if apply:
                run(["/usr/sbin/dseditgroup", "-o", "edit", "-a", user, "-t", "user", group])
    return current


def identifiers(owner, group):
    return pwd.getpwnam(owner).pw_uid, grp.getgrnam(group).gr_gid


def metadata(path, owner, group, mode, directory=False):
    try:
        value = os.lstat(path)
    except FileNotFoundError:
        return False
    valid = stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode) and value.st_nlink == 1
    if not valid:
        raise RuntimeError("OpsGate managed resource has an unsafe file type")
    return (value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode)) == (*identifiers(owner, group), mode)


def ensure_directory(path, owner, group, mode):
    if metadata(path, owner, group, mode, True):
        return
    Path(path).mkdir(parents=True, exist_ok=True)
    os.chown(path, *identifiers(owner, group))
    os.chmod(path, mode)


def directory_specs(c):
    result = [(c[k], "root", "wheel", 0o755) for k in ["config_dir", "log_dir", "runtime_dir"]]
    result += [(c[k], c["control_service_user"], c["control_service_group"], 0o750)
               for k in ["control_service_home_dir", "app_dir", "state_dir"]]
    result += [(c[k], c["ops_user"], c["ops_group"], 0o700 if k == "tmux_tmpdir" else 0o750)
               for k in ["ops_home_dir", "ops_workspace_dir", "runner_app_dir", "execution_data_dir", "tickets_dir",
                         "session_artifacts_dir", "runner_tmp_dir", "tmux_tmpdir"]]
    result += [(c["ops_home_dir"] + suffix, c["ops_user"], c["ops_group"], 0o700)
               for suffix in ["/.ssh", "/.config", "/.config/sops", "/.config/sops/age"]]
    result += [(c["ops_workspace_dir"] + "/" + repo["name"], c["ops_user"], c["ops_group"], 0o750)
               for repo in c["ops_workspace_repositories"]]
    result += [(c["launchd_python_plist_dir"], "root", "wheel", 0o755)]
    return result


def preparation(c, apply=False):
    identities = accounts(c, apply) if c["manage_users"] else True
    if not identities and not apply:
        return False
    good = True
    for path, owner, group, mode in directory_specs(c):
        if not metadata(path, owner, group, mode, True):
            good = False
            if apply:
                ensure_directory(path, owner, group, mode)
    for unit, owner, group in [("api", c["control_service_user"], c["control_service_group"]),
                               ("runner", c["ops_user"], c["ops_group"])]:
        for stream in ["stdout", "stderr"]:
            path = c[unit + "_" + stream + "_log"]
            if not metadata(path, owner, group, 0o640):
                good = False
                if apply:
                    if not os.path.lexists(path):
                        Path(path).touch(mode=0o640)
                    os.chown(path, *identifiers(owner, group))
                    os.chmod(path, 0o640)
    return good and identities


def put(path, resource):
    content = resource["content"].encode()
    good = metadata(path, resource["owner"], resource["group"], resource["mode"])
    if os.path.exists(path) and Path(path).read_bytes() == content:
        if not good:
            os.chown(path, *identifiers(resource["owner"], resource["group"]))
            os.chmod(path, resource["mode"])
        return
    fd, temporary = tempfile.mkstemp(prefix=".opsgate-", dir=Path(path).parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
            os.fchown(handle.fileno(), *identifiers(resource["owner"], resource["group"]))
            os.fchmod(handle.fileno(), resource["mode"])
        if path.endswith(".plist"):
            plistlib.loads(content)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def resource_current(path, resource):
    return metadata(path, resource["owner"], resource["group"], resource["mode"]) and hashlib.sha256(Path(path).read_bytes()).hexdigest() == resource["sha256"]


def marker(c, unit):
    return Path(c["config_dir"]) / (".ops-deploy-pending-" + unit)


def mark(c, unit, reason="source"):
    path = marker(c, unit)
    if not path.exists():
        put(str(path), {"owner": "root", "group": "wheel", "mode": 0o600, "content": reason + "\n"})
    else:
        metadata(path, "root", "wheel", 0o600)
        if reason == "config" and path.read_text() != "config\n":
            put(str(path), {"owner": "root", "group": "wheel", "mode": 0o600, "content": "config\n"})


def runtime_current(c, unit):
    if marker(c, unit).exists():
        return False
    path = c["app_dir" if unit == "api" else "runner_app_dir"]
    binary = Path(path) / ".venv/bin/python"
    if not binary.is_file():
        return False
    owner = c["control_service_user" if unit == "api" else "ops_user"]
    out = run([str(binary), "-B", "-c", "import importlib.metadata;print(importlib.metadata.version('opsgate'))"], user=owner, cwd=path, check=False)
    return out.returncode == 0 and out.stdout.strip() == c["project_version"]


def sync_runtime(c, unit):
    path = c["app_dir" if unit == "api" else "runner_app_dir"]
    owner = c["control_service_user" if unit == "api" else "ops_user"]
    mark(c, unit)
    run([c["uv_bin"], "sync", "--frozen", "--no-dev"], user=owner, cwd=path)


def job(c, unit):
    result = run(["/bin/launchctl", "print", "system/" + c[unit + "_launchd_label"]], check=False)
    if result.returncode:
        if result.returncode != 113:
            raise RuntimeError("OpsGate launchd state could not be read")
        return {"loaded": False, "running": False, "pid": None, "comm": "", "args": ""}
    match = re.search(r"^\s*pid = ([1-9][0-9]*)$", result.stdout, re.M)
    process = int(match[1]) if match else None
    return {"loaded": True, "running": bool(re.search(r"^\s*state = running$", result.stdout, re.M)), "pid": process,
            "comm": run(["/bin/ps", "-o", "comm=", "-p", str(process)]).stdout.strip() if process else "",
            "args": run(["/bin/ps", "-o", "args=", "-p", str(process)]).stdout.strip() if process else ""}


def validate_rust(c, binary):
    out = run([binary, "--version"], user=c["control_service_user"]).stdout.strip()
    if not re.fullmatch(r"opsgate " + re.escape(c["rust_version"]) + r" \([^)]+\)", out):
        raise RuntimeError("OpsGate Rust release reports an unexpected version")
    for unit, user in [("api", c["control_service_user"]), ("runner", c["ops_user"])]:
        run([binary, "check-config", unit], user=user, extra={"OPSGATE_ENV_FILE": c[unit + "_environment"].get("OPSGATE_ENV_FILE", c["config_dir"] + "/opsgate-" + unit + ".env")})
    if Path(c["db_path"]).exists():
        run([binary, "check-db", "--db", c["db_path"]], user=c["control_service_user"])


def rust_impl(c, apply=False):
    if not c["rust_version"]:
        return True
    destination = Path(c["rust_install_root"]) / c["rust_version"]
    existed = destination.exists()
    if existed:
        if destination.is_symlink() or not destination.is_dir() or (destination / ".archive-sha256").read_text().strip() != c["rust_sha256"]:
            raise RuntimeError("OpsGate installed version must retain its original archive pin")
        validate_rust(c, str(destination / "opsgate"))
        return True
    if not apply:
        return False
    ensure_directory(c["rust_install_root"], "root", "wheel", 0o755)
    try:
        with tempfile.TemporaryDirectory(prefix=".staging-", dir=c["rust_install_root"]) as temporary:
            stage = Path(temporary)
            stage.chmod(0o755)
            archive = stage / "archive.tar.gz"
            if c.get("archive_payload"):
                archive.write_bytes(base64.b64decode(c["archive_payload"]))
            else:
                digest = hashlib.sha256()
                with urllib.request.urlopen(c["rust_release_url"], timeout=30) as source, archive.open("wb") as output:
                    while block := source.read(1024 * 1024):
                        output.write(block)
                        digest.update(block)
                if digest.hexdigest() != c["rust_sha256"]:
                    raise RuntimeError("OpsGate Rust archive checksum differs")
            if hashlib.sha256(archive.read_bytes()).hexdigest() != c["rust_sha256"]:
                raise RuntimeError("OpsGate local Rust archive checksum differs")
            tree = stage / "tree"
            tree.mkdir(mode=0o755)
            with tarfile.open(archive, "r:gz") as release:
                members = release.getmembers()
                if sorted(m.name.removeprefix("./") for m in members) != ["LICENSE", "opsgate"] or any(not m.isfile() for m in members):
                    raise RuntimeError("OpsGate archive must contain exactly two regular release files")
                for member in members:
                    name = member.name.removeprefix("./")
                    source = release.extractfile(member)
                    if source is None:
                        raise RuntimeError("OpsGate archive member is unreadable")
                    with source, (tree / name).open("wb") as output:
                        shutil.copyfileobj(source, output)
                    os.chmod(tree / name, 0o755 if name == "opsgate" else 0o644)
                    os.chown(tree / name, *identifiers("root", "wheel"))
            (tree / ".archive-sha256").write_text(c["rust_sha256"] + "\n")
            os.chmod(tree / ".archive-sha256", 0o644)
            # Validate before the release is made selectable by any live plist.
            validate_rust(c, str(tree / "opsgate"))
            os.rename(tree, destination)
        return True
    except Exception:
        if not existed and destination.exists():
            shutil.rmtree(destination)
        if c["api_impl"] == "rust" or c["runner_impl"] == "rust":
            raise
        print("WARNING: rejected candidate Rust release; keeping Python and all releases", file=sys.stderr)
        return False


def rust(c, apply=False):
    try:
        return rust_impl(c, apply)
    except Exception:
        if c["api_impl"] == "rust" or c["runner_impl"] == "rust":
            raise
        if apply:
            print("WARNING: rejected candidate Rust release; keeping Python and all existing releases", file=sys.stderr)
        return False


def git(c, arguments, check=True):
    ssh = shlex.join(["/usr/bin/ssh", "-F", c["ops_ssh_config_path"], "-o", "BatchMode=yes", "-o", "UpdateHostKeys=no",
                      "-o", "ControlMaster=no", "-o", "ControlPath=none", "-o", "StrictHostKeyChecking=yes",
                      "-o", "UserKnownHostsFile=" + c["ops_ssh_known_hosts_path"]])
    return run(["/usr/bin/git", "--no-optional-locks", "-c", "core.sshCommand=" + ssh, *arguments], user=c["ops_user"], check=check)


def repo_state(c, repo, apply=False):
    directory = Path(c["ops_workspace_dir"]) / repo["name"]
    url = repo["repo"]
    if repo["name"] in c["deploy_key_names"]:
        url = url.replace("git@github.com:", "git@github-" + repo["name"] + ":").replace("ssh://git@github.com/", "ssh://git@github-" + repo["name"] + "/")
    user = c["ops_user"]
    version = repo["version"]
    if re.fullmatch(r"[0-9a-f]{40}", version):
        expected = version
    else:
        response = git(c, ["ls-remote", url, version, "refs/heads/" + version, "refs/tags/" + version, "refs/tags/" + version + "^{}"]).stdout
        refs = [line.split() for line in response.splitlines() if len(line.split()) == 2]
        peeled = [sha for sha, ref in refs if ref.endswith("^{}")]
        commits = set(peeled or [sha for sha, _ in refs])
        if len(commits) != 1:
            raise RuntimeError("OpsGate workspace remote ref is ambiguous or unavailable")
        expected = next(iter(commits))
    exists = (directory / ".git").is_dir()
    head = git(c, ["-C", str(directory), "rev-parse", "HEAD"]).stdout.strip() if exists else ""
    origin = git(c, ["-C", str(directory), "remote", "get-url", "origin"]).stdout.strip() if exists else ""
    if exists and git(c, ["-C", str(directory), "--no-optional-locks", "status", "--porcelain", "--untracked-files=normal"]).stdout.strip():
        raise RuntimeError("OpsGate workspace has local changes; preserving them")
    if head == expected and origin == url:
        return True
    if not apply:
        return False
    if not exists:
        git(c, ["clone", url, str(directory)])
    elif origin != url:
        git(c, ["-C", str(directory), "remote", "set-url", "origin", url])
    git(c, ["-C", str(directory), "fetch", "origin", version])
    if re.fullmatch(r"[0-9a-f]{40}", version) or version.startswith("refs/tags/"):
        git(c, ["-C", str(directory), "checkout", "--detach", expected])
    else:
        # No force checkout/reset: preserve the original non-forcing update contract.
        branch = git(c, ["-C", str(directory), "symbolic-ref", "--short", "-q", "HEAD"], check=False).stdout.strip()
        if branch != version:
            git(c, ["-C", str(directory), "checkout", version])
        git(c, ["-C", str(directory), "merge", "--ff-only", expected])
    return True


def known_hosts(c, apply=False):
    if not c["ops_manage_workspace_repos"]:
        return True
    path = Path(c["ops_ssh_known_hosts_path"])
    if path.exists():
        metadata(path, c["ops_user"], c["ops_group"], 0o600)
        lines = path.read_text().splitlines()
    else:
        lines = []
    expected = c["ops_github_host_key"]
    present = expected in lines
    good_mode = metadata(path, c["ops_user"], c["ops_group"], 0o600)
    if (not present or not good_mode) and apply:
        # Replace only github.com's managed plain entry; retain all other hosts.
        content = "\n".join([line for line in lines if not line.startswith("github.com ")] + [expected]) + "\n"
        put(str(path), {"content": content, "owner": c["ops_user"], "group": c["ops_group"], "mode": 0o600})
    return present and good_mode


def verified(c, unit):
    live = job(c, unit)
    if not (c[unit + "_launchd_manage_state"] and c[unit + "_launchd_start_service"]):
        return True
    if not live["loaded"] or not live["running"] or not live["pid"]:
        return False
    if c[unit + "_impl"] == "rust":
        return live["comm"] == c["rust_binary"] and live["args"] == c["rust_binary"] + (" serve" if unit == "api" else " runner")
    return not live["comm"].startswith(c["rust_install_root"] + "/") and bool(re.search(r" -m opsgate " + ("serve" if unit == "api" else "runner") + "$", live["args"]))


def verify(c):
    for unit in ["api", "runner"]:
        for attempt in range(c["launchd_verify_retries"]):
            if verified(c, unit):
                break
            time.sleep(c["launchd_verify_delay"])
        else:
            raise RuntimeError("OpsGate launchd unit does not run the selected implementation")
    if c["api_launchd_manage_state"] and c["api_launchd_start_service"]:
        for attempt in range(c["launchd_verify_retries"]):
            try:
                with urllib.request.urlopen("http://127.0.0.1:" + str(c["api_bind_port"]) + "/api/v1/health", timeout=5) as response:
                    if response.status == 200 and json.load(response).get("status") == "ok":
                        return
            except (OSError, ValueError):
                pass
            time.sleep(c["launchd_verify_delay"])
        raise RuntimeError("OpsGate health endpoint did not become ready")


def unit_apply(c, unit, plist_changed):
    if not c[unit + "_launchd_manage_state"]:
        return
    live = job(c, unit)
    service = "system/" + c[unit + "_launchd_label"]
    if plist_changed and live["loaded"]:
        run(["/bin/launchctl", "bootout", service])
    if plist_changed or not live["loaded"]:
        run(["/bin/launchctl", "bootstrap", "system", c[unit + "_launchd_plist_path"]])
        run(["/bin/launchctl", "enable", service])
    if c[unit + "_launchd_start_service"] and (plist_changed or (marker(c, unit).exists() and (c[unit + "_impl"] == "python" or marker(c, unit).read_text() == "config\n")) or not live["running"]):
        run(["/bin/launchctl", "kickstart", "-k", service])


def prune(c, rust_ok, apply=True):
    if not c["rust_version"] or not rust_ok:
        return True
    root = Path(c["rust_install_root"])
    pattern = r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?"
    versions = [p for p in root.iterdir() if p.is_dir() and not p.is_symlink() and re.fullmatch(pattern, p.name)]
    keep = {c["rust_version"]}
    for unit in ["api", "runner"]:
        live = job(c, unit)
        command = live["comm"]
        if command.startswith(str(root) + "/"):
            match = re.fullmatch(re.escape(str(root)) + "/(" + pattern + ")/opsgate", command)
            if match is None:
                return True
            keep.add(match[1])
        previous = root / (".previous-" + unit)
        if previous.exists() and re.fullmatch(pattern, previous.read_text().strip()):
            keep.add(previous.read_text().strip())
        plist = Path(c[unit + "_launchd_plist_path"])
        if plist.exists():
            keep.update(re.findall(re.escape(str(root)) + "/(" + pattern + ")/opsgate", plist.read_text()))
    keep.update(p.name for p in sorted(versions, key=lambda p: (p.stat().st_mtime_ns, p.name), reverse=True)[:c["rust_keep_versions"]])
    obsolete = [path for path in versions if path.name not in keep]
    if apply:
        for path in obsolete:
            shutil.rmtree(path)
    return not obsolete


def config_current(c):
    if any(not resource_current(path, resource) for path, resource in c["contents"].items()):
        return False
    if any(os.path.lexists(p) for p in c["remove"]) or any(marker(c, u).exists() for u in ["api", "runner"]):
        return False
    if not known_hosts(c):
        return False
    if c["ops_manage_workspace_repos"] and any(not repo_state(c, r) for r in c["ops_workspace_repositories"]):
        return False
    if not rust(c):
        return False
    return all(verified(c, unit) for unit in ["api", "runner"]) and prune(c, True, False)


def config_apply(c):
    # Record env changes before publishing them so interrupted runs still restart.
    for unit in ["api", "runner"]:
        env = c[unit + "_environment"].get("OPSGATE_ENV_FILE", c["config_dir"] + "/opsgate-" + unit + ".env")
        if env in c["contents"] and not resource_current(env, c["contents"][env]):
            mark(c, unit, "config")
    plist_paths = {c[u + "_launchd_plist_path"] for u in ["api", "runner"]}
    for path, resource in c["contents"].items():
        if path not in plist_paths:
            put(path, resource)
    for path in c["remove"]:
        if os.path.lexists(path):
            metadata(path, c["ops_user"], c["ops_group"], 0o600)
            Path(path).unlink()
    known_hosts(c, True)
    if c["ops_manage_workspace_repos"]:
        for repo in c["ops_workspace_repositories"]:
            repo_state(c, repo, True)
    rust_ok = rust(c, True)
    for unit in ["api", "runner"]:
        path = c[unit + "_launchd_plist_path"]
        changed = not resource_current(path, c["contents"][path])
        if changed and Path(path).exists():
            previous = re.search(re.escape(c["rust_install_root"]) + r"/([0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?)/opsgate", Path(path).read_text())
            selected = c["rust_version"] if c[unit + "_impl"] == "rust" else ""
            if previous and previous[1] != selected and (Path(c["rust_install_root"]) / previous[1]).is_dir():
                put(c["rust_install_root"] + "/.previous-" + unit, {"owner": "root", "group": "wheel", "mode": 0o644, "content": previous[1] + "\n"})
        put(path, c["contents"][path])
        unit_apply(c, unit, changed)
    verify(c)
    prune(c, rust_ok)
    for unit in ["api", "runner"]:
        if marker(c, unit).exists():
            marker(c, unit).unlink()


def main():
    if platform.system() != "Darwin" or os.geteuid() != 0:
        raise RuntimeError("OpsGate deployment requires its existing root Darwin management connection")
    action = sys.argv[1]
    data = json.loads(sys.stdin.read()) if action in ["config-apply"] else json.loads(base64.b64decode(sys.argv[2]))
    c = {key.removeprefix("opsgate_"): value for key, value in data.items()}
    if action == "prepare-status":
        print("current" if preparation(c) else "drift")
    elif action == "prepare-apply":
        preparation(c, True)
    elif action.startswith("mark-"):
        mark(c, action.removeprefix("mark-"))
    elif action.startswith("runtime-status-"):
        print("current" if runtime_current(c, action.removeprefix("runtime-status-")) else "drift")
    elif action.startswith("runtime-apply-"):
        sync_runtime(c, action.removeprefix("runtime-apply-"))
    elif action == "config-status":
        print("current" if config_current(c) else "drift")
    elif action == "config-apply":
        config_apply(c)
    elif action == "verify":
        verify(c)
    else:
        raise RuntimeError("unknown OpsGate operation")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("native OpsGate operation failed; inspect the selected configuration and owned runtime", file=sys.stderr)
        sys.exit(1)
