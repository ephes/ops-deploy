"""Controller-bundle Sessions source/environment convergence, stdlib only.

Git/uv child output is private in memory, never a deployment log. No application
CLI/import, model download, content store or activation is part of this stage.
"""

import hashlib
import json
import os
import pathlib
import re
import stat
import grp
import subprocess
import sys

from ops_daybook_observer import MAX_INPUT, NativeProbes, ObservationError, safe_file
from ops_daybook_stage import directory_fd


class SourceError(RuntimeError):
    pass


class SourceProbes(NativeProbes):
    def __init__(self, data):
        super().__init__(data)
        grp.getgrnam(data["group"])  # fail before any staging if the declared group is missing

    def locked_environment_current(self):
        argv = [self.data["uv_bin"], "--directory", self.data["checkout"], *self.data["sync_args"],
                "--check", "--offline", "--no-python-downloads", "--no-build", "--no-cache"]
        return self.run(argv, user=True, extra={
            "UV_PROJECT_ENVIRONMENT": self.data["checkout"] + "/.venv",
            "UV_PYTHON_PREFERENCE": "only-managed", "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD": "1",
        }).returncode == 0

    def managed(self, argv):
        # Original service-user login context, explicit module environment after
        # sudo, no invented outer Git/build/synchronization deadline.
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0",
               "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
               "PYTHONDONTWRITEBYTECODE": "1", "UV_PROJECT_ENVIRONMENT": self.data["checkout"] + "/.venv",
               "UV_PYTHON_PREFERENCE": "only-managed", "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD": "1",
               "PATH": self.data["path"]}
        target = ["/usr/bin/env", *[key + "=" + env[key] for key in (
            "GIT_TERMINAL_PROMPT", "GIT_OPTIONAL_LOCKS", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
            "PYTHONDONTWRITEBYTECODE", "UV_PROJECT_ENVIRONMENT", "UV_PYTHON_PREFERENCE",
            "PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD", "PATH")], *argv]
        if os.geteuid() != self.account.pw_uid:
            target = ["/usr/bin/sudo", "-H", "-S", "-n", "-i", "-u", self.data["user"], "--", *target]
        result = subprocess.run(target, capture_output=True, env=env, cwd="/")
        if result.returncode:
            raise SourceError("sessions_source_command_failed")

    def git_command(self, *args):
        return ["/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-c", "core.autocrlf=false",
                "-C", self.data["checkout"], *args]


def checkout_shape(data, account):
    root = pathlib.Path(data["checkout"])
    for path in (root, *root.parents):
        if path.is_symlink():
            raise SourceError("sessions_source_linked_checkout")
    if not root.exists():
        if not data["allow_create"]:
            raise SourceError("sessions_source_preexisting_checkout_required")
        if not root.parent.is_dir():
            raise SourceError("sessions_source_parent_required")
        return False
    if not root.is_dir() or root.stat().st_uid != account.pw_uid:
        raise SourceError("sessions_source_checkout_owner_invalid")
    metadata = root / ".git"
    if (metadata.is_symlink() or not (metadata.is_dir() or metadata.is_file())
            or metadata.stat().st_uid != account.pw_uid):
        raise SourceError("sessions_source_git_metadata_invalid")
    return True


def inspect(data, probes):
    exists = checkout_shape(data, probes.account)
    if not data["source_hashes"] or len(data["source_hashes"]) > 2048:
        raise SourceError("sessions_source_manifest_invalid")
    needs_bundle, code = True, False
    if exists:
        head = probes.run(["/usr/bin/git", "-C", data["checkout"], "rev-parse", "--verify", "--quiet", "HEAD"], user=True)
        if head.returncode:
            if not data["allow_create"]:
                raise SourceError("sessions_source_preexisting_head_required")
            # A run may have initialized the declared repo before a later fetch
            # failed. Preserve that valid unborn checkout and retry normally.
            symbolic = probes.run(["/usr/bin/git", "-C", data["checkout"], "symbolic-ref", "--quiet", "HEAD"], user=True)
            if head.returncode != 1 or symbolic.returncode or not symbolic.stdout.startswith(b"refs/heads/"):
                raise SourceError("sessions_source_head_unavailable")
            reference = symbolic.stdout.decode().strip()
            reference_exists = probes.run(["/usr/bin/git", "-C", data["checkout"], "show-ref", "--verify", "--quiet", reference], user=True)
            if reference_exists.returncode != 1:
                raise SourceError("sessions_source_head_unavailable")
        revision = head.stdout.decode().strip()
        tracked = probes.git("status", "--porcelain", "--untracked-files=no").strip()
        untracked = probes.git("ls-files", "--others", "--exclude-standard").strip()
        if untracked and not data["allow_create"]:
            raise SourceError("sessions_source_untracked_files_refused")
        if tracked and not data["force"]:
            raise SourceError("sessions_source_tracked_changes_refused")
        has = probes.run(["/usr/bin/git", "-C", data["checkout"], "cat-file", "-e",
                          data["revision"] + "^{commit}"], user=True)
        needs_bundle = has.returncode != 0
        code = revision == data["revision"] and not tracked
        for relative, digest in data["source_hashes"].items():
            if pathlib.PurePosixPath(relative).is_absolute() or ".." in pathlib.PurePosixPath(relative).parts:
                raise SourceError("sessions_source_manifest_invalid")
            result = safe_file(pathlib.Path(data["checkout"]) / relative)
            code = result is not None and hashlib.sha256(result[1]).hexdigest() == digest and code
    current = exists and code and probes.runtime_current()
    reconcile_ready = True
    if not current and data["require_reconcile_quiescence"]:
        # The complete role performs the original early quiesce. This source
        # component only verifies its precondition, never unloads/repairs here.
        label = "de.wersdoerfer.daybook.weeknotes-reconcile"
        loaded = probes.run(["/bin/launchctl", "print", "system/" + label])
        disabled = probes.run(["/bin/launchctl", "print-disabled", "system"])
        marker = re.findall(r'(?m)^\s*"' + re.escape(label) + r'"\s*=>\s*(true|disabled|false|enabled)\s*$',
                            disabled.stdout.decode("utf-8", "replace"))
        if loaded.returncode not in {0, 113} or disabled.returncode:
            raise SourceError("sessions_source_reconcile_probe_failed")
        reconcile_ready = loaded.returncode == 113 and marker in (["true"], ["disabled"])
    return {"current": bool(current), "needs_bundle": needs_bundle,
            "delegate": os.geteuid() != probes.account.pw_uid, "reconcile_ready": reconcile_ready}


def require_reconcile_quiescent(state):
    if state["current"]:
        return
    if not state["reconcile_ready"]:
        raise SourceError("sessions_source_requires_reconcile_disabled_unloaded")


def transfer_path(data):
    path = pathlib.Path(data["transfer_dir"])
    if path.parent not in {pathlib.Path("/private/var/tmp"), pathlib.Path("/tmp")} or not re.fullmatch(
        r"ops-deploy-daybook-source-[0-9a-f]{32}", path.name
    ):
        raise SourceError("sessions_source_transfer_path_invalid")
    if pathlib.Path(data["bundle_path"]).parent != path:
        raise SourceError("sessions_source_transfer_path_invalid")
    return path


def prepare_transfer(data):
    path = transfer_path(data)
    with directory_fd(path.parent) as parent:
        # Never adopt/repair an existing directory. Ordinary explicit managed
        # preparation; no directory creation occurs in status/verify facts.
        info = os.fstat(parent)
        if info.st_uid not in {0, os.geteuid()} or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
            raise SourceError("sessions_source_transfer_parent_invalid")
        os.mkdir(path.name, 0o700, dir_fd=parent)
        try:
            with directory_fd(path) as created:
                os.fchmod(created, 0o700)
        except BaseException:
            os.rmdir(path.name, dir_fd=parent)
            raise


def publish_transfer(data, probes):
    path = transfer_path(data)
    with directory_fd(path) as directory:
        info = os.fstat(directory)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise SourceError("sessions_source_transfer_owner_invalid")
        bundle = pathlib.Path(data["bundle_path"])
        fd = os.open(bundle.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise SourceError("sessions_source_transfer_file_invalid")
            gid = grp.getgrnam(data["group"]).gr_gid
            if (info.st_uid, info.st_gid) != (probes.account.pw_uid, gid):
                os.fchown(fd, probes.account.pw_uid, gid)
            # Only traversal is shared: the bundle remains owner-only 0600 and
            # the directory stays owned by the original connecting identity.
            os.fchmod(directory, 0o755)
        finally:
            os.close(fd)


def cleanup_transfer(data):
    path = transfer_path(data)
    with directory_fd(path.parent) as parent:
        try:
            with directory_fd(path) as directory:
                if os.fstat(directory).st_uid != os.geteuid():
                    raise SourceError("sessions_source_transfer_owner_invalid")
                try:
                    os.unlink(pathlib.Path(data["bundle_path"]).name, dir_fd=directory)
                except FileNotFoundError:
                    pass
            os.rmdir(path.name, dir_fd=parent)
        except FileNotFoundError:
            pass

def apply(data, probes):
    try:
        state = inspect(data, probes)
        if state["current"]:
            return
        require_reconcile_quiescent(state)
        if not pathlib.Path(data["checkout"]).exists():
            probes.managed(["/usr/bin/git", "init", "--quiet", "--template=", data["checkout"]])
            probes.managed(probes.git_command("remote", "add", "origin", data["repo_url"]))
        # If a fresh update failed after init but before origin creation,
        # recovery must still leave the declared origin; no-fetch never adopts
        # an unborn checkout. Existing non-unborn origins stay untouched.
        head = probes.run(["/usr/bin/git", "-C", data["checkout"], "rev-parse", "--verify", "--quiet", "HEAD"], user=True)
        if data["allow_create"] and head.returncode == 1:
            origin = probes.run(probes.git_command("remote", "get-url", "origin"), user=True)
            if origin.returncode == 2:
                probes.managed(probes.git_command("remote", "add", "origin", data["repo_url"]))
            elif origin.returncode or origin.stdout.decode().strip() != data["repo_url"]:
                raise SourceError("sessions_source_recovery_origin_mismatch")
        if state["needs_bundle"]:
            publish_transfer(data, probes)
            heads = probes.run(["/usr/bin/git", "bundle", "list-heads", data["bundle_path"]], user=True)
            if heads.returncode or not any(
                line.startswith(data["revision"].encode() + b" refs/") for line in heads.stdout.splitlines()
            ):
                raise SourceError("sessions_source_bundle_mismatch")
            probes.managed(probes.git_command("fetch", "--quiet", "--no-tags", data["bundle_path"],
                                              "+refs/*:refs/bundle/*"))
        probes.managed(probes.git_command("checkout", "--detach", *(["--force"] if data["force"] else []),
                                          data["revision"]))
        python = pathlib.Path(data["python"])
        if python.exists():
            alive = probes.run([str(python), "-I", "-B", "-c", ""], user=True).returncode == 0
        else:
            alive = False
        if not alive and os.path.lexists(python.parent.parent):
            probes.managed(["/usr/bin/python3", "-I", "-B", "-c",
                "import pathlib,shutil,sys;p=pathlib.Path(sys.argv[1]);"
                "p.unlink() if p.is_symlink() else shutil.rmtree(p)", str(python.parent.parent)])
        probes.managed([data["uv_bin"], "--directory", data["checkout"], *data["sync_args"]])
        if not inspect(data, probes)["current"]:
            raise SourceError("sessions_source_not_current_after_sync")
    finally:
        if data["staged_bundle"]:
            cleanup_transfer(data)


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise SourceError("sessions_source_request_too_large")
        data = json.loads(raw)
        probes = SourceProbes(data)
        action = sys.argv[1]
        if action == "prepare-transfer":
            require_reconcile_quiescent(inspect(data, probes))
            prepare_transfer(data)
            print("prepared")
        elif action == "cleanup-transfer":
            cleanup_transfer(data)
            print("removed")
        elif action == "apply":
            apply(data, probes)
            print("current")
        elif action == "status":
            print(json.dumps(inspect(data, probes), sort_keys=True))
        elif action == "verify":
            if not inspect(data, probes)["current"]:
                raise SourceError("sessions_source_not_current")
            print("current")
        else:
            raise SourceError("sessions_source_action_invalid")
    except (SourceError, ObservationError, KeyError, ValueError, TypeError, OSError, RecursionError) as error:
        print(str(error) if isinstance(error, (SourceError, ObservationError)) else "sessions_source_failed", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
