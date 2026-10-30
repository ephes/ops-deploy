"""Original direct-owner source/env mechanism; no archive/data-body operation.

The two generated resources are dormant. Only the explicit smoke action runs
the original application --help. No action executes the archive launcher.
"""

import grp
import hashlib
import json
import os
import pathlib
import plistlib
import pwd
import shutil
import stat
import subprocess
import sys

from ops_archive_controls import PhotosControls, PhotosControlError
from ops_archive_filesystem import (
    ResourceError, directory_fd, directory_matches, ensure_directory,
    file_matches, put_resource,
)


class ArchiveError(RuntimeError):
    pass


class Archive:
    def __init__(self, data):
        self.data = data
        self.account = pwd.getpwnam(data["service_user"])
        self.uid = self.account.pw_uid
        if self.uid <= 0 or os.geteuid() != self.uid or data["uid"] != self.uid:
            raise ArchiveError("archive_original_connecting_user_required")
        self.root = pathlib.Path(data["checkout_path"])
        self.venv = pathlib.Path(data["venv_path"])
        self.bundle = pathlib.Path(data["repo_bundle_path"])
        self.controls = PhotosControls({"uid": self.uid, "label": data["launchd_label"],
                                        "plist": data["launchd_plist_path"]})

    def run(self, argv, *, managed=False, cwd="/", extra=None):
        env = {**os.environ, "HOME": self.data["service_home"], "PATH": self.data["path"],
               "UV_PYTHON_PREFERENCE": "only-managed", "UV_PROJECT_ENVIRONMENT": str(self.venv),
               "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
               "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", **(extra or {})}
        try:
            result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, timeout=None if managed else 30)
        except (OSError, subprocess.TimeoutExpired):
            raise ArchiveError("archive_tool_unavailable") from None
        return result

    def require(self, argv, *, cwd="/"):
        if self.run(argv, managed=True, cwd=cwd).returncode:
            raise ArchiveError("archive_managed_command_failed")

    def path_shape(self, path, *, directory):
        path = pathlib.Path(path)
        try:
            with directory_fd(path.parent):
                info = path.lstat()
        except FileNotFoundError:
            return False
        valid = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1
        if not valid:
            raise ArchiveError("archive_managed_path_substituted")
        if info.st_uid != self.uid:
            raise ArchiveError("archive_managed_owner_invalid")
        return True

    def directories(self):
        rows = [{"path": self.data[key], "owner": self.account.pw_name,
                 "group": self.data["service_group"], "mode": 0o700}
                for key in ("install_root", "runtime_dir", "log_dir", "config_dir")]
        agents = pathlib.Path(self.data["launchd_plist_path"]).parent
        if self.path_shape(agents, directory=True):
            mode = stat.S_IMODE(agents.lstat().st_mode)
        else:
            mask = os.umask(0)
            os.umask(mask)
            mode = 0o777 & ~mask
        # Original LaunchAgents task sets owner/group without changing an
        # existing mode; retain that distinction from private 0700 directories.
        rows.append({"path": str(agents), "owner": self.account.pw_name,
                     "group": self.data["service_group"], "mode": mode})
        return rows

    def validate_paths(self):
        for spec in self.directories():
            self.path_shape(spec["path"], directory=True)
        self.path_shape(self.root, directory=True)
        self.path_shape(self.venv, directory=True)
        self.path_shape(self.bundle, directory=False)
        for spec in self.data["resources"]:
            self.path_shape(spec["path"], directory=False)
        # Library, working camera folder, mount, ledger, folder map and logs
        # are declaration-only data paths. Do not open/list their bodies.

    def public_bytes(self, path, maximum):
        path = pathlib.Path(path)
        try:
            with directory_fd(path.parent):
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return None
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != self.uid or info.st_size > maximum:
                raise ArchiveError("archive_code_resource_invalid")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                return stream.read(maximum + 1)
        finally:
            os.close(fd)

    def bundle_current(self):
        body = self.public_bytes(self.bundle, 256 * 1024 * 1024)
        if body is None:
            return False
        info = self.bundle.lstat()
        return (hashlib.sha256(body).hexdigest() == self.data["bundle_sha256"]
                and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_gid == grp.getgrnam(self.data["service_group"]).gr_gid)

    def git(self, *args, managed=False):
        return self.run(["/usr/bin/git", "-C", str(self.root), "-c", "core.fsmonitor=false", *args], managed=managed)

    def checkout_exists(self):
        if not self.path_shape(self.root, directory=True):
            return False
        metadata = self.root / ".git"
        if not self.path_shape(metadata, directory=True):
            # Original git clone also accepts an existing empty directory;
            # it refuses a nonempty unknown directory without overwriting it.
            return False
        return True

    def clean(self):
        result = self.git("status", "--porcelain=v1", "--untracked-files=all")
        if result.returncode or result.stdout.strip():
            raise ArchiveError("archive_dirty_checkout_refused")

    def source_current(self):
        if not self.checkout_exists():
            return False
        # Original interrupted --no-checkout clone recovery: no Git index yet.
        # Never discard changes in an indexed checkout to make a run converge.
        if not self.path_shape(self.root / ".git/index", directory=False):
            return False
        self.clean()
        head = self.git("rev-parse", "HEAD")
        if head.returncode or head.stdout.decode().strip() != self.data["repo_ref"]:
            return False
        for relative, digest in self.data["source_hashes"].items():
            if pathlib.PurePosixPath(relative).is_absolute() or any(part in {".", ".."} for part in relative.split("/")):
                raise ArchiveError("archive_source_manifest_invalid")
            body = self.public_bytes(self.root / relative, 8 * 1024 * 1024)
            if body is None or hashlib.sha256(body).hexdigest() != digest:
                return False
        return True

    def interpreter_current(self):
        binary = self.venv / "bin/python"
        if not binary.is_file():
            return False
        expression = ("import sys;v='%d.%d.%d'%sys.version_info[:3];"
                      "raise SystemExit(0 if v==sys.argv[1] and '/uv/python/cpython-'+v+'-' in sys.base_prefix else 1)")
        try:
            return self.run([str(binary), "-I", "-B", "-S", "-c", expression, self.data["python_version"]]).returncode == 0
        except ArchiveError:
            return False

    def environment_current(self):
        if not self.interpreter_current():
            return False
        result = self.run([self.data["uv_bin"], "sync", "--check", "--frozen", "--no-dev", "--python",
                           self.data["python_version"], "--offline", "--no-python-downloads", "--no-cache"], cwd=self.root)
        return result.returncode == 0

    def tools(self):
        for binary, flag in ((self.data["uv_bin"], "--version"), (self.data["timeout_bin"], "--version"),
                             ("/opt/homebrew/bin/exiftool", "-ver")):
            if self.run([binary, flag]).returncode:
                raise ArchiveError("archive_original_prerequisite_missing")

    def status(self):
        self.validate_paths()
        self.tools()
        state = self.controls.snapshot()
        if not state["domain_available"] or state["disabled"] is None or state["loaded"] is None:
            raise ArchiveError("archive_original_gui_domain_unavailable")
        return {"quiescent": state["disabled"] is True and state["known_absent"],
                "directories": all(directory_matches(spec) for spec in self.directories()),
                "bundle": self.bundle_current(), "source": self.source_current(),
                "environment": self.environment_current(),
                "resources": all(file_matches(spec, content=True) for spec in self.data["resources"])}

    def source(self):
        self.controls.require_quiescent()
        if not self.bundle_current():
            raise ArchiveError("archive_uploaded_bundle_mismatch")
        advertised = self.run(["/usr/bin/git", "bundle", "list-heads", str(self.bundle)])
        if advertised.returncode or advertised.stdout.decode().strip() != self.data["repo_ref"] + " refs/heads/main":
            raise ArchiveError("archive_bundle_head_mismatch")
        if not self.checkout_exists():
            self.require(["/usr/bin/git", "clone", "--no-checkout", "--branch", "main", str(self.bundle), str(self.root)])
        elif self.path_shape(self.root / ".git/index", directory=False):
            self.clean()
        for args in (("fetch", "--no-tags", str(self.bundle), self.data["repo_ref"]),
                     ("checkout", "--detach", self.data["repo_ref"])):
            if self.git(*args, managed=True).returncode:
                raise ArchiveError("archive_source_materialization_failed")
        self.clean()
        if not self.source_current():
            raise ArchiveError("archive_source_verification_failed")

    def environment(self):
        self.controls.require_quiescent()
        if not self.source_current():
            raise ArchiveError("archive_environment_source_mismatch")
        binary = self.venv / "bin/python"
        if self.venv.exists():
            try:
                broken = self.run([str(binary), "-I", "-B", "-S", "-c", ""]).returncode != 0
            except ArchiveError:
                broken = True
            if broken:
                shutil.rmtree(self.venv)
        self.require([self.data["uv_bin"], "sync", "--frozen", "--no-dev", "--python", self.data["python_version"]], cwd=self.root)
        if not self.interpreter_current():
            raise ArchiveError("archive_pinned_interpreter_unavailable")
        self.clean()

    def smoke(self):
        self.controls.require_quiescent()
        if not self.source_current() or not self.interpreter_current():
            raise ArchiveError("archive_smoke_source_or_python_mismatch")
        self.require([str(self.venv / "bin/daybook"), "--help"])
        self.clean()

    def resources(self):
        self.controls.require_quiescent()
        for spec in self.data["resources"]:
            if spec["path"].endswith(".plist"):
                plistlib.loads(spec["content"].encode())
            put_resource(spec)

    def verify(self):
        state = self.status()
        if not all(state[key] for key in ("directories", "bundle", "source", "environment", "resources")):
            raise ArchiveError("archive_final_resource_mismatch")
        if self.data["launchd_enabled"]:
            selected = self.controls.snapshot(final=True)
            if selected["disabled"] is not False or selected["loaded"] is not True:
                raise ArchiveError("archive_final_activation_mismatch")
        else:
            self.controls.require_quiescent()


def main():
    try:
        archive = Archive(json.load(sys.stdin))
        action = sys.argv[1]
        if action == "status":
            print(json.dumps(archive.status(), sort_keys=True))
            return 0
        archive.validate_paths()
        if action == "quiesce":
            archive.controls.quiesce(force=True)
        elif action == "directories":
            archive.controls.require_quiescent()
            for spec in archive.directories():
                ensure_directory(spec)
        elif action == "source":
            archive.source()
        elif action == "environment":
            archive.environment()
        elif action == "smoke":
            archive.smoke()
        elif action == "resources":
            archive.resources()
        elif action == "activate":
            archive.controls.activate()
        elif action == "verify":
            archive.verify()
        else:
            raise ArchiveError("archive_action_invalid")
        return 0
    except ArchiveError as error:
        print(str(error), file=sys.stderr)  # All categories above are fixed literals.
    except (ResourceError, PhotosControlError):
        print("archive_resource_or_launchd_boundary_failed", file=sys.stderr)
    except Exception:
        print("archive_component_failed", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
