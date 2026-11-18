"""Pinned native detector operations; standard library only on Darwin."""

import base64
import fcntl
import grp
import hashlib
import ipaddress
import json
import os
import platform
import plistlib
import pwd
import re
import resource
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

# Source mode (cfg["source_build"]): see docs/services/llama_server.md.
LOCK_PATH = "/private/var/db/de.wersdoerfer.llama-server-deploy.lock"
SYSTEM_LINKS = {"/etc": "private/etc", "/var": "private/var"}
BUILD_PATH = "/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
GIT = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "gc.auto=0",
       "-c", "maintenance.auto=false"]
CMAKE_FLAGS = [
    "-DCMAKE_BUILD_TYPE=Release", "-DBUILD_SHARED_LIBS=OFF", "-DGGML_NATIVE=OFF", "-DGGML_METAL=ON",
    "-DGGML_METAL_EMBED_LIBRARY=ON", "-DGGML_BLAS=ON", "-DGGML_CCACHE=OFF", "-DLLAMA_BUILD_TESTS=OFF",
    "-DLLAMA_BUILD_EXAMPLES=OFF", "-DLLAMA_BUILD_SERVER=ON", "-DLLAMA_BUILD_UI=OFF",
    "-DLLAMA_USE_PREBUILT_UI=OFF", "-DLLAMA_OPENSSL=OFF", "-DLLAMA_BUILD_IS_DEV=OFF", "-DLLAMA_ALL_WARNINGS=OFF",
]
STEP_TIMEOUT = 600
BINARY_CAP = 256 * 1024 * 1024
OUTPUT_CAP = 1024 * 1024
COMMIT_MARKER = "SOURCE_COMMIT"


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
    if source(cfg):
        if cfg["uid"] == 0:
            raise RuntimeError("source build requires a non-root service user")
    else:
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
            if source(cfg) and path in (cfg["wrapper_path"], cfg["api_key_path"], cfg["launchd_plist_path"]):
                # A multiply linked runtime file is drift there: replaced, never read.
                regular(path)
            else:
                metadata(path, 0, 0, 0)
    cfg["plist"] = cfg["plist_template"].replace("__LLAMA_BIND_ADDRESS__", cfg["bind_address"])
    plistlib.loads(cfg["plist"].encode())
    cfg["hashes"][cfg["launchd_plist_path"]] = hashlib.sha256(cfg["plist"].encode()).hexdigest()
    return cfg


def installed(cfg):
    if source(cfg):
        return source_installed(cfg)
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


def version(cfg, binary=None):
    binary = binary or cfg["binary"]
    if not Path(binary).is_file():
        return False
    if source(cfg):
        # Root never executes source-mode artifacts; the service user does.
        output = build_run(cfg, [binary, "--version"])
    else:
        out = run([binary, "--version"])
        output = out.stdout + out.stderr
    match = re.search(r"\(build ([0-9]+), commit ([0-9a-f]+)\)", output)
    if not match or "b" + match[1] + "-" + match[2] != cfg["build"]:
        raise RuntimeError("installed llama-server does not match the declared pinned build")
    return True


def source(cfg):
    return cfg.get("source_build")


def regular(path):
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode):
        raise RuntimeError("detector managed resource has an unsafe file type")
    return info


def has_acl(path):
    # `ls -lde` prints the mode line and then one line per ACL entry; the mode
    # marker is `@` instead of `+` when extended attributes exist too.
    out = run(["/bin/ls", "-lde", path], check=False)
    lines = out.stdout.splitlines()
    if out.returncode or not lines or not lines[0].split():
        raise RuntimeError("cannot read the ACL of a detector path")
    return len(lines) != 1 or "+" in lines[0].split()[0]


def trusted_dir(path, gid=None, mode=None):
    info = os.lstat(path)
    perms = stat.S_IMODE(info.st_mode)
    return (
        stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not perms & 0o022
        and (gid is None or info.st_gid == gid) and (mode is None or perms == mode) and not has_acl(path)
    )


def exact_file(path, uid, gid, mode):
    """Regular, single link, exact owner and mode (no set-id bits), no ACL."""
    try:
        info = regular(path)
    except FileNotFoundError:
        return False
    return (info.st_nlink, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (1, uid, gid, mode) and not has_acl(path)


def chain(path, create_gid=None):
    """Verify that ``path`` and every ancestor are root-only directories.

    Only the root-owned system links /etc and /var are followed. With
    ``create_gid``, missing components are created root-owned, mode 0755.
    """
    if not trusted_dir("/"):
        raise RuntimeError("detector path chain is not root-only")
    current = "/"
    for part in Path(path).parts[1:]:
        candidate = os.path.join(current, part)
        try:
            info = os.lstat(candidate)
        except FileNotFoundError:
            if create_gid is None:
                raise
            os.mkdir(candidate, 0o700)
            os.chown(candidate, 0, create_gid)
            os.chmod(candidate, 0o755)
            info = os.lstat(candidate)
        if stat.S_ISLNK(info.st_mode):
            if info.st_uid != 0 or SYSTEM_LINKS.get(candidate) != os.readlink(candidate):
                raise RuntimeError("detector path chain contains an untrusted link")
            # Re-walk the target from / so /private itself is checked too.
            current = chain("/" + SYSTEM_LINKS[candidate])
            continue
        if not trusted_dir(candidate):
            raise RuntimeError("detector path chain is not root-only")
        current = candidate
    return current


def managed_dirs(cfg):
    return [cfg["install_dir"], cfg["model_dir"], cfg["config_dir"], cfg["log_dir"], str(Path(cfg["launchd_plist_path"]).parent)]


def prefix(cfg):
    return os.path.join(cfg["install_dir"], "llama.cpp-" + cfg["build"])


def source_installed(cfg):
    target = prefix(cfg)
    if not os.path.lexists(target):
        return False
    chain(cfg["install_dir"])
    marker = os.path.join(target, COMMIT_MARKER)
    if not (trusted_dir(target, cfg["wheel"], 0o755) and trusted_dir(os.path.join(target, "bin"), cfg["wheel"], 0o755)
            and exact_file(cfg["binary"], 0, cfg["wheel"], 0o755) and exact_file(marker, 0, cfg["wheel"], 0o644)):
        raise RuntimeError("existing source build prefix is not the expected root-only layout")
    # The prefix name carries only the short commit; the marker, written by
    # root from the config at publication, carries the full one.
    if Path(marker).read_text() != source(cfg)["commit"] + "\n":
        raise RuntimeError("existing source build prefix was built from another commit")
    return True


def acquire_lock():
    chain(os.path.dirname(LOCK_PATH))
    descriptor = os.open(LOCK_PATH, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077 or has_acl(LOCK_PATH):
            raise RuntimeError("detector deploy lock is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


# The group leader: runs the step with stdin from /dev/null, reports its exit
# status on the status pipe, then blocks until root closes its stdin. While it
# waits, the step's process group (and so its ID) still exists, so root's
# SIGKILL to the group can only reach processes of this step.
# SIGXFSZ is ignored (and so for the step too): a write over the size limit
# fails with EFBIG instead of killing the leader before it reports. The status
# pipe is always fd 8 (dup2 in the child; single digit for any POSIX sh); the
# step gets it closed and stdin from /dev/null, the leader waits on stdin.
STATUS_FD = 8
LEADER = 'trap "" XFSZ; "$@" </dev/null 8>&-; echo "$?" >&8; read _'


def build_run(cfg, argv, *, stdout=None, quiet=False, fsize=None, tmpdir=None):
    """Run one build step as the non-root service user in its own process group.

    cwd is "/" (CPython chdirs before dropping privileges); steps use absolute
    paths. Captured output goes through an unlinked root-created file with a
    size limit. After the step (or its timeout) the whole group is killed
    while its leader still holds the group ID, then reaped.
    """
    account = pwd.getpwnam(cfg["user"])
    if account.pw_uid == 0:
        raise RuntimeError("source build requires a non-root service user")
    identity = {}
    if os.geteuid() == 0:
        identity = {"user": account.pw_uid, "group": account.pw_gid, "extra_groups": []}
    elif os.geteuid() != account.pw_uid:
        raise RuntimeError("detector build requires root or the service user")
    env = {"PATH": BUILD_PATH, "HOME": account.pw_dir, "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0"}
    if tmpdir:
        env["TMPDIR"] = tmpdir
    capture = None if quiet or stdout is not None else tempfile.TemporaryFile()
    limit = fsize or (OUTPUT_CAP if capture else None)
    status_read, status_write = os.pipe()

    def preexec():
        # Runs in the child after the identity switch, before the other
        # descriptors are closed (fd 8 is kept through pass_fds).
        os.dup2(status_write, STATUS_FD)
        if limit:
            resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))

    try:
        process = subprocess.Popen(
            ["/bin/sh", "-c", LEADER, "detector-build", *argv], cwd="/", env=env,
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL if quiet else (stdout if stdout is not None else capture),
            stderr=subprocess.DEVNULL if quiet or stdout is not None else capture, pass_fds=(STATUS_FD,),
            start_new_session=True, preexec_fn=preexec, **identity)
    except BaseException:
        os.close(status_read)
        os.close(status_write)
        if capture:
            capture.close()
        raise
    os.close(status_write)
    status = b""
    timed_out = False
    try:
        deadline = time.monotonic() + STEP_TIMEOUT
        while not status.endswith(b"\n") and len(status) < 16:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([status_read], [], [], remaining)[0]:
                timed_out = True
                break
            chunk = os.read(status_read, 16)
            if not chunk:
                break
            status += chunk
    finally:
        os.close(status_read)
        # The leader is alive (blocked on stdin) or unreaped: the group exists.
        # (EPERM: Darwin's answer when only the zombie leader is left.)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        process.stdin.close()
        process.wait()
        for _ in range(100):
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                break
            except PermissionError:
                pass  # only zombies left; their parents reap them
            time.sleep(0.1)
        else:
            raise RuntimeError("detector build processes did not exit")
    try:
        if timed_out:
            raise subprocess.TimeoutExpired(argv, STEP_TIMEOUT)
        if status != b"0\n":
            raise RuntimeError("detector build step failed")
        if not capture:
            return ""
        capture.seek(0)
        return capture.read(OUTPUT_CAP).decode(errors="replace")
    finally:
        if capture:
            capture.close()


def build_source(cfg, workspace):
    spec = source(cfg)
    src, build, tmp = workspace + "/src", workspace + "/build", workspace + "/tmp"
    step = lambda argv, **kw: build_run(cfg, argv, tmpdir=tmp, **kw).strip()
    build_run(cfg, ["/bin/mkdir", tmp])
    step(GIT + ["clone", "-q", "--filter=blob:none", "--no-checkout", spec["repository"], src], quiet=True)
    step(GIT + ["-C", src, "checkout", "-q", "--detach", spec["commit"]], quiet=True)
    def verify_tree():
        if (step(GIT + ["-C", src, "rev-parse", "HEAD"]) != spec["commit"]
                or step(GIT + ["-C", src, "rev-parse", "--verify", "refs/tags/" + spec["tag"] + "^{commit}"]) != spec["commit"]
                or step(GIT + ["-C", src, "status", "--porcelain"]) != ""):
            raise RuntimeError("source checkout does not match the pinned commit")
    verify_tree()
    if step(GIT + ["-C", src, "rev-list", "--count", "HEAD"]) != spec["tag"][1:]:
        raise RuntimeError("source checkout does not match the pinned build number")
    step(["cmake", "-S", src, "-B", build, *CMAKE_FLAGS], quiet=True)
    step(["cmake", "--build", build, "--target", "llama-server", "-j", "8"], quiet=True)
    verify_tree()
    binary = build + "/bin/llama-server"
    if not version(cfg, binary):
        raise RuntimeError("source build produced no llama-server")
    return binary


def make_workspace(cfg):
    home = pwd.getpwnam(cfg["user"]).pw_dir
    parent = home + "/Library/Caches/llama-server-build"
    build_run(cfg, ["/bin/mkdir", "-p", parent])
    workspace = build_run(cfg, ["/usr/bin/mktemp", "-d", parent + "/run.XXXXXX"]).strip()
    if not re.fullmatch(re.escape(parent) + r"/run\.[A-Za-z0-9]+", workspace):
        raise RuntimeError("unexpected detector build workspace")
    return workspace


def publish_binary(cfg):
    """Build the pinned source as the service user and publish it root-owned."""
    target = prefix(cfg)
    if os.path.lexists(target):
        if source_installed(cfg) and version(cfg):
            return
        raise RuntimeError("existing source build prefix does not match the pin")
    workspace = staging = None
    try:
        workspace = make_workspace(cfg)
        built = build_source(cfg, workspace)
        staging = tempfile.mkdtemp(prefix=".llama-install-", dir=cfg["install_dir"])
        os.chown(staging, 0, cfg["wheel"])
        bindir = os.path.join(staging, "bin")
        os.mkdir(bindir, 0o700)
        os.chown(bindir, 0, cfg["wheel"])
        os.chmod(bindir, 0o755)
        staged = os.path.join(bindir, "llama-server")
        descriptor = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
        try:
            # Root reads nothing in the workspace: the service user streams the
            # binary into this root-created file, size-capped by RLIMIT_FSIZE.
            build_run(cfg, ["/bin/cat", built], stdout=descriptor, fsize=BINARY_CAP)
            size = os.fstat(descriptor).st_size
            if not 0 < size <= BINARY_CAP:
                raise RuntimeError("source build binary has an unexpected size")
            os.fsync(descriptor)
            os.fchown(descriptor, 0, cfg["wheel"])
            os.fchmod(descriptor, 0o755)
        finally:
            os.close(descriptor)
        put(os.path.join(staging, COMMIT_MARKER), (source(cfg)["commit"] + "\n").encode(), 0, cfg["wheel"], 0o644, fresh=True)
        os.chmod(staging, 0o755)
        if not (trusted_dir(staging, cfg["wheel"], 0o755) and trusted_dir(bindir, cfg["wheel"], 0o755)
                and exact_file(staged, 0, cfg["wheel"], 0o755) and version(cfg, staged)):
            raise RuntimeError("staged source build does not match the pin")
        if os.path.lexists(target):
            raise RuntimeError("source build prefix appeared during publication")
        os.rename(staging, target)
        staging = None
        if not (source_installed(cfg) and version(cfg)):
            raise RuntimeError("published source build does not match the pin")
    finally:
        if staging is not None:
            shutil.rmtree(staging)
        if workspace is not None:
            try:
                build_run(cfg, ["/bin/rm", "-rf", workspace])
            except (OSError, RuntimeError, subprocess.SubprocessError):
                pass  # the user's cache keeps an inert leftover; documented


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
    if source(cfg) and cfg["enabled"]:
        try:
            for path in managed_dirs(cfg):
                chain(path)
        except FileNotFoundError:
            return False
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
        if not runtime_file_ok(cfg, path) or hashlib.sha256(Path(path).read_bytes()).hexdigest() != expected:
            return False
    for path in [cfg["stdout_log"], cfg["stderr_log"]]:
        if not metadata(path, cfg["uid"], cfg["gid"], 0o644):
            return False
    return loaded and running


def runtime_file_ok(cfg, path):
    """Owner/mode of a wrapper/key/plist; in source mode also one link, no ACL.

    In source mode a file that fails is never read: it is drift and gets a
    fresh inode.
    """
    if source(cfg):
        return exact_file(path, *file_info(cfg, path))
    return metadata(path, *file_info(cfg, path))


def ensure_directory(path, uid, gid, mode):
    if metadata(path, uid, gid, mode, True):
        return
    Path(path).mkdir(parents=True, exist_ok=True)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def put(path, content, uid, gid, mode, fresh=False):
    target = Path(path)
    exists = target.exists()
    if fresh:
        # Source mode never repairs in place: unchanged only when the file is
        # exactly right, otherwise a new root-created inode replaces it.
        if exact_file(path, uid, gid, mode) and target.read_bytes() == content:
            return False
    elif exists:
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
    if fresh and not exact_file(path, uid, gid, mode):
        raise RuntimeError("published detector file is not exactly owned")
    return True


def stage_model(cfg):
    model = Path(cfg["model_path"])
    wrapper = Path(cfg["wrapper_path"])
    marker = 'GGUF_SHA256="' + cfg["model_sha256"] + '"'
    safe = not source(cfg) or exact_file(str(wrapper), 0, cfg["wheel"], 0o755)
    if model.is_file() and model.stat().st_size > 0 and wrapper.is_file() and safe and marker in wrapper.read_text():
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
    if not source(cfg):
        return apply_unlocked(cfg, data)
    lock = acquire_lock()
    try:
        return apply_unlocked(cfg, data)
    finally:
        os.close(lock)


def apply_unlocked(cfg, data):
    if not cfg["enabled"]:
        if source(cfg):
            for key in ["launchd_plist_path", "api_key_path"]:
                try:
                    chain(os.path.dirname(cfg[key]))
                except FileNotFoundError:
                    pass  # a missing directory holds nothing to remove
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
    if source(cfg):
        # Under the lock: verify (and create) the root-only directory chains,
        # then build and publish the binary while the live job is untouched.
        for path in managed_dirs(cfg):
            chain(path, create_gid=None if path == managed_dirs(cfg)[-1] else cfg["wheel"])
        for item in resources(cfg):
            ensure_directory(*item)
        for path in managed_dirs(cfg):
            chain(path)
        publish_binary(cfg)
    elif not installed(cfg):
        run([cfg["brew"], "install", cfg["brew_formula"]], user=cfg.get("brew_user"))
    if not version(cfg):
        raise RuntimeError("detector binary is unavailable after installation")
    for item in resources(cfg):
        ensure_directory(*item)
    staged = stage_model(cfg)
    try:
        changed = staged is not None or any(
            not Path(path).is_file()
            or (source(cfg) and not runtime_file_ok(cfg, path))
            or hashlib.sha256(Path(path).read_bytes()).hexdigest() != expected
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
            put(path, value.encode(), *file_info(cfg, path), fresh=bool(source(cfg)))
        for path in [cfg["stdout_log"], cfg["stderr_log"]]:
            if not os.path.lexists(path):
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
                os.close(descriptor)
            if not metadata(path, cfg["uid"], cfg["gid"], 0o644):
                os.chown(path, cfg["uid"], cfg["gid"])
                os.chmod(path, 0o644)
        if not loaded:
            # enable first: a job left disabled (docs: failed rollout) can bootstrap.
            run(["/bin/launchctl", "enable", "system/" + cfg["launchd_label"]])
            run(["/bin/launchctl", "bootstrap", "system", cfg["launchd_plist_path"]])
        if changed or not loaded or not running:
            run(["/bin/launchctl", "kickstart", "-k", "system/" + cfg["launchd_label"]])
    finally:
        if staged is not None and os.path.exists(staged):
            os.unlink(staged)


def health(cfg):
    if source(cfg):
        chain(cfg["config_dir"])
        if not exact_file(cfg["api_key_path"], cfg["uid"], cfg["gid"], 0o600):
            raise RuntimeError("detector API key file is not exactly owned")
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
