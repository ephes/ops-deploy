"""Original Photos protected-checkout admission, code/metadata only.

The root checkout excludes the user-writable .venv from privileged walking.
No Photos library, ledger, environment body or application is opened here.
"""

import base64
import grp
import json
import os
import pathlib
import re
import stat
import subprocess

ATTESTATION = b"daybook-photos-offload-root-checkout-v1\n"
CONFIG_NAME = re.compile(
    r"^(core\.(repositoryformatversion|filemode|bare|logallrefupdates|ignorecase|precomposeunicode)"
    r"|remote\.origin\.(url|fetch)|branch\.[^.]+\.(remote|merge))$"
)


class PhotosSourceError(RuntimeError):
    pass


def no_links(path):
    path = pathlib.Path(path)
    for item in reversed((path, *path.parents)):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise PhotosSourceError("photos_source_linked_path")


def metadata(path):
    try:
        return pathlib.Path(path).lstat()
    except FileNotFoundError:
        return None


def protected(info, *, directory=False, exact_mode=None):
    return (
        info is not None
        and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
        and info.st_uid == 0
        and not info.st_mode & 0o022
        and (directory or info.st_nlink == 1)
        and (exact_mode is None or stat.S_IMODE(info.st_mode) == exact_mode)
    )


class PhotosProbes:
    def __init__(self, data):
        import pwd

        self.data = data
        self.account = pwd.getpwnam(data["user"])
        if self.account.pw_uid <= 0:
            raise PhotosSourceError("photos_source_gui_account_unavailable")

    def info(self, path):
        return metadata(path)

    def fstat(self, descriptor):
        return os.fstat(descriptor)

    def acl_free(self, path):
        try:
            result = subprocess.run(["/bin/ls", "-lde", str(path)], capture_output=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            raise PhotosSourceError("photos_source_acl_unavailable") from None
        if result.returncode:
            raise PhotosSourceError("photos_source_acl_unavailable")
        return len(result.stdout.splitlines()) == 1

    def run(self, argv, *, user=False, extra=None, managed=False):
        # Pure identity/Git probes use the already qualified direct GUI context;
        # managed UV/build work separately retains original login (-H -i).
        data = self.data
        env = {
            "HOME": data["home"] if user else "/var/root",
            "USER": data["user"] if user else "root",
            "LOGNAME": data["user"] if user else "root",
            "PATH": data["path"],
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        if extra:
            env.update(extra)
        command = ["/usr/bin/env", "-i", *[key + "=" + value for key, value in env.items()], *argv]
        if user and os.geteuid() != self.account.pw_uid:
            command = ["/usr/bin/sudo", "-n", "-H", "-u", data["user"], "--", *command]
        try:
            return subprocess.run(command, capture_output=True, cwd="/", timeout=None if managed else 30)
        except (OSError, subprocess.TimeoutExpired):
            raise PhotosSourceError("photos_source_probe_unavailable") from None

    def managed_user(self, argv, *, cwd, extra=None):
        data = self.data
        env = {
            "HOME": data["home"],
            "USER": data["user"],
            "LOGNAME": data["user"],
            "PATH": data["path"],
            **(extra or {}),
        }
        # Original command chdir/env occurs AFTER the login transition. sudo -i
        # leaves dollar signs for the login shell to expand, so carry the fixed
        # cwd/argv/env as base64 data, not shell parameters or interpolated paths.
        encoded = base64.b64encode(json.dumps({"cwd": str(cwd), "argv": argv, "env": env}).encode()).decode()
        script = ("import base64,json,os;d=json.loads(base64.b64decode('" + encoded + "'));"
                  "os.chdir(d['cwd']);os.execve(d['argv'][0],d['argv'],d['env'])")
        command = ["/usr/bin/python3", "-I", "-B", "-S", "-c", script]
        if os.geteuid() != self.account.pw_uid:
            command = ["/usr/bin/sudo", "-n", "-H", "-i", "-u", data["user"], "--", *command]
        try:
            # Original managed UV/login behavior has no invented whole-call
            # deadline; the normal caller owns its outer job supervision.
            return subprocess.run(command, capture_output=True, cwd=cwd)
        except OSError:
            raise PhotosSourceError("photos_source_managed_user_failed") from None

    def git(self, *args, user=False, managed=False):
        root = self.data["checkout"]
        result = self.run(
            [
                "/usr/bin/git",
                "--no-optional-locks",
                "-C",
                root,
                "-c",
                "safe.directory=" + root,
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                # Keep original synchronous mutation complete before the strict
                # protected-tree observation. Do not leave implicit background
                # pack maintenance replacing files after fetch has returned.
                "-c", "maintenance.auto=false", "-c", "gc.auto=0",
                *args,
            ],
            user=user,
            managed=managed,
        )
        if result.returncode:
            raise PhotosSourceError("photos_source_git_unavailable")
        return result.stdout


def attest(path, probes, *, required):
    info = probes.info(path)
    if info is None:
        if required:
            raise PhotosSourceError("photos_source_attestation_missing")
        return
    no_links(path)
    if not protected(info, exact_mode=0o600) or not probes.acl_free(path):
        raise PhotosSourceError("photos_source_attestation_unsafe")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = probes.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino) or not protected(opened, exact_mode=0o600):
            raise PhotosSourceError("photos_source_attestation_replaced")
        if os.read(fd, len(ATTESTATION) + 1) != ATTESTATION:
            raise PhotosSourceError("photos_source_attestation_invalid")
    finally:
        os.close(fd)


def checkout_tree(root, probes):
    # Never inspect or harden user-writable environment descendants as root.
    excluded = pathlib.Path(root) / ".venv"
    for base, dirs, names in os.walk(root, topdown=True, followlinks=False):
        dirs[:] = [name for name in dirs if pathlib.Path(base) / name != excluded]
        for path in [pathlib.Path(base), *[pathlib.Path(base) / name for name in dirs + names]]:
            if path == excluded:
                continue
            info = probes.info(path)
            if info is None or not protected(info, directory=stat.S_ISDIR(info.st_mode)) or not probes.acl_free(path):
                raise PhotosSourceError("photos_source_checkout_unsafe")


def check_checkout(data, probes):
    root = pathlib.Path(data["checkout"])
    no_links(root)
    no_links(root / ".venv")
    environment = probes.info(root / ".venv")
    if environment is not None and not stat.S_ISDIR(environment.st_mode):
        raise PhotosSourceError("photos_source_environment_substituted")
    info = probes.info(root)
    attest(data["attestation"], probes, required=info is not None)
    if info is None:
        return False
    if not protected(info, directory=True) or not protected(probes.info(root / ".git"), directory=True):
        raise PhotosSourceError("photos_source_checkout_unsafe")
    if root.resolve(strict=True) != root or (root / ".git").resolve(strict=True) != root / ".git":
        raise PhotosSourceError("photos_source_checkout_not_canonical")
    checkout_tree(root, probes)
    names = probes.git("config", "--no-includes", "--local", "--name-only", "--list").decode().splitlines()
    if any(CONFIG_NAME.fullmatch(name) is None for name in names):
        raise PhotosSourceError("photos_source_git_config_unsafe")
    if probes.git("rev-parse", "--show-toplevel", user=True).decode().strip() != str(root):
        raise PhotosSourceError("photos_source_checkout_not_canonical")
    if probes.git("status", "--porcelain=v1", "--untracked-files=all", user=True).strip():
        raise PhotosSourceError("photos_source_checkout_modified")
    if re.search(rb"(?m)^[a-zS]", probes.git("ls-files", "-v", user=True)):
        raise PhotosSourceError("photos_source_index_flags_unsafe")
    if probes.git("remote", "get-url", "origin", user=True).decode().strip() != data["bundle"]:
        raise PhotosSourceError("photos_source_origin_mismatch")
    probes.git("diff", "--no-ext-diff", "--no-textconv", "--quiet", "HEAD", "--")
    ignored = probes.git("ls-files", "--others", "--ignored", "--exclude-standard", "--directory", user=True)
    if any(not row.startswith(b".venv/") for row in ignored.splitlines()):
        raise PhotosSourceError("photos_source_ignored_content_unsafe")
    revision = probes.git("rev-parse", "HEAD", user=True).decode().strip()
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise PhotosSourceError("photos_source_revision_unavailable")
    return revision == data["revision"]


FIXED_ANCESTORS = ("/Library", "/Library/Application Support")


def ancestors_current(data, probes):
    root = pathlib.Path(data["checkout"])
    fixed = [pathlib.Path(p) for p in FIXED_ANCESTORS]
    for path in [*fixed, root.parent.parent, root.parent]:
        no_links(path)
        info = probes.info(path)
        if not protected(info, directory=True) or not probes.acl_free(path):
            return False
        if path not in fixed and (
            stat.S_IMODE(info.st_mode) != 0o755 or info.st_gid != grp.getgrnam(data["system_group"]).gr_gid
        ):
            return False
    return True


def prepare_ancestors(data, probes):
    from ops_photos_filesystem import ensure_directory

    if os.geteuid() != 0:
        raise PhotosSourceError("photos_source_original_root_required")
    for name in FIXED_ANCESTORS:
        no_links(name)
        if not protected(probes.info(name), directory=True) or not probes.acl_free(name):
            raise PhotosSourceError("photos_source_fixed_ancestor_unsafe")
    root = pathlib.Path(data["checkout"])
    for path in (root.parent.parent, root.parent):
        ensure_directory({"path": str(path), "owner": "root", "group": data["system_group"], "mode": 0o755})
        if not probes.acl_free(path):
            result = probes.run(["/bin/chmod", "-N", str(path)])
            if result.returncode:
                raise PhotosSourceError("photos_source_ancestor_acl_clear_failed")
    if not ancestors_current(data, probes):
        raise PhotosSourceError("photos_source_ancestor_not_protected")


def require_bundle(data, probes):
    path = pathlib.Path(data["bundle"])
    no_links(path)
    info = probes.info(path)
    if info is None:
        raise PhotosSourceError("photos_source_bundle_missing")
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise PhotosSourceError("photos_source_bundle_unsafe")
    if not protected(info, exact_mode=0o600) or not probes.acl_free(path):
        raise PhotosSourceError("photos_source_bundle_drift")
    heads = probes.run(["/usr/bin/git", "bundle", "list-heads", str(path)])
    if heads.returncode or heads.stdout.decode("ascii", "replace").strip() != data["revision"] + " refs/heads/main":
        raise PhotosSourceError("photos_source_bundle_wrong_main")


def converge_source(data, probes, controls):
    from ops_photos_filesystem import ensure_directory, put_resource

    if os.geteuid() != 0:
        raise PhotosSourceError("photos_source_original_root_required")
    controls.require_quiescent()  # ONLY its own Photos label, no global keeper barrier.
    prepare_ancestors(data, probes)
    current = check_checkout(data, probes)  # Existing trust/cleanliness before any Git mutation.
    require_bundle(data, probes)
    root = pathlib.Path(data["checkout"])
    previous_umask = os.umask(0o022)
    try:
        if probes.info(root) is None:
            result = probes.run(
                [
                    "/usr/bin/git",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "core.fsmonitor=false",
                    "-c", "maintenance.auto=false", "-c", "gc.auto=0",
                    "clone",
                    "--no-checkout",
                    "--branch",
                    "main",
                    data["bundle"],
                    str(root),
                ],
                managed=True,
            )
            if result.returncode:
                raise PhotosSourceError("photos_source_clone_failed")
        else:
            probes.git("fetch", "--no-tags", "--force", "origin", "refs/heads/main", managed=True)
        probes.git("checkout", "--detach", data["revision"], managed=True)
    finally:
        os.umask(previous_umask)
    # Preserve the original protected checkout/.git and GUI-only .venv boundary.
    for path in (root, root / ".git"):
        ensure_directory({"path": str(path), "owner": "root", "group": data["system_group"], "mode": 0o755})
    checkout_tree(root, probes)
    put_resource(
        {
            "path": data["attestation"],
            "owner": "root",
            "group": data["system_group"],
            "mode": 0o600,
            "content": ATTESTATION.decode(),
        }
    )
    if not check_checkout(data, probes):
        raise PhotosSourceError("photos_source_not_current_after_checkout")
    return {"source_changed": not current}
