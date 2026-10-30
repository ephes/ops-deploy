"""Original disabled wheel mechanism; no discovery, state or log-body reads."""

import contextlib
import hashlib
import json
import os
import pathlib
import pwd
import re
import shutil
import stat
import subprocess
import sys
from urllib.parse import urlsplit

from ops_attention_filesystem import (
    ResourceError, directory_fd, directory_matches, ensure_directory,
    file_matches, put_bytes, put_resource, resource_path,
)


class AttentionError(RuntimeError):
    pass


def run(argv, *, env=None, cwd="/", pure=False, content=None):
    try:
        result = subprocess.run(argv, capture_output=True, cwd=cwd, input=content,
                                env={**os.environ, **(env or {})}, timeout=30 if pure else None)
    except (OSError, subprocess.TimeoutExpired):
        raise AttentionError("attention_command_unavailable") from None
    return result


class Installation:
    def __init__(self, data):
        self.data = data
        self.root = pathlib.Path(data["install_root"])
        self.venv = pathlib.Path(data["venv"])
        self.python_root = pathlib.Path(data["python_install_dir"])
        self.account = pwd.getpwnam(data["service_user"])
        if self.account.pw_uid <= 0:
            raise AttentionError("attention_owner_invalid")
        self.domain = "gui/" + str(self.account.pw_uid)
        self.service = self.domain + "/" + data["launchd_label"]
        self.wheel = self.root / data["wheel_name"]
        self.receipt = self.root / "installed-wheel.sha1"

    def paths(self):
        data = self.data
        home = pathlib.Path(data["service_home"])
        return [pathlib.Path("/Library/Application Support"), self.root.parent,
                self.root, self.venv, self.receipt, self.wheel, home,
                home / ".local", home / ".local/state", home / ".local/state/daybook",
                pathlib.Path(data["runtime_dir"]), pathlib.Path(data["config_path"]),
                home / "Library", home / "Library/LaunchAgents", pathlib.Path(data["plist_path"])]

    def validate_paths(self):
        for declared in self.paths():
            path = resource_path(str(declared))
            try:
                with directory_fd(path.parent):
                    info = path.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(info.st_mode) or (not stat.S_ISDIR(info.st_mode) and info.st_nlink != 1):
                raise AttentionError("attention_managed_path_linked")
            directories = set(self.paths()) - {self.wheel, self.receipt,
                                              pathlib.Path(self.data["config_path"]), pathlib.Path(self.data["plist_path"])}
            if path in directories and not stat.S_ISDIR(info.st_mode):
                raise AttentionError("attention_managed_directory_invalid")

    def controls(self):
        domain = run(["/bin/launchctl", "print", self.domain], pure=True)
        loaded = run(["/bin/launchctl", "print", self.service], pure=True)
        disabled = run(["/bin/launchctl", "print-disabled", self.domain], pure=True)
        absent = 'Could not find service "' + self.data["launchd_label"] + '" in domain for user gui: ' + str(self.account.pw_uid)
        known_absent = loaded.returncode == 113 and absent in loaded.stderr.decode("utf-8", "replace")
        override = disabled.stdout.decode("utf-8", "replace")
        return domain.returncode == 0 and disabled.returncode == 0 and known_absent and any(
            '"' + self.data["launchd_label"] + '" => ' + value in override for value in ("disabled", "true")
        )

    def require_quiescent(self):
        if not self.controls():
            raise AttentionError("attention_not_disabled_unloaded")

    def quiesce(self):
        if run(["/bin/launchctl", "print", self.domain], pure=True).returncode:
            raise AttentionError("attention_gui_domain_unavailable")
        # Original disable and bootout attempt both execute; final real state
        # determines success, never the bootout error category alone.
        for action in ("disable", "bootout"):
            with contextlib.suppress(AttentionError):
                run(["/bin/launchctl", action, self.service])
        self.require_quiescent()

    def directories(self):
        home = self.data["service_home"]
        return [
            {"path": str(self.root), "owner": "root", "group": "wheel", "mode": 0o755},
            {"path": str(self.python_root), "owner": "root", "group": "wheel", "mode": 0o755},
            {"path": self.data["runtime_dir"], "owner": self.account.pw_name, "group": "staff", "mode": 0o700},
            {"path": home + "/Library/LaunchAgents", "owner": self.account.pw_name, "group": "staff", "mode": 0o755},
        ]

    def validate_configuration(self, value):
        if (not isinstance(value, dict)
                or set(value) != {"version", "enabled", "profile", "state_path", "source"}
                or type(value["version"]) is not int or value["version"] != 1
                or value["enabled"] is not False
                or value["profile"] not in {"synthetic", "production"}
                or value["state_path"] != self.data["runtime_dir"] + "/state.sqlite3"
                or not isinstance(value["source"], dict)):
            raise AttentionError("attention_existing_configuration_invalid")
        source = value["source"]
        if value["profile"] == "synthetic":
            valid = source == {"kind": "synthetic"}
        else:
            valid = set(source) == {"kind", "endpoint_url", "credentials_file"} and source["kind"] == "s3"
            if valid:
                try:
                    url = urlsplit(source["endpoint_url"])
                    valid = (url.scheme == "https" and bool(url.hostname) and not url.username
                             and not url.password and not url.query and not url.fragment and url.path in {"", "/"})
                except (TypeError, ValueError):
                    valid = False
        if not valid:
            raise AttentionError("attention_existing_configuration_invalid")

    def configuration_current(self):
        # Installed private configuration is authoritative for this disabled
        # installer. It is never serialized to the controller or rewritten.
        path = resource_path(self.data["config_path"])
        try:
            with directory_fd(path.parent) as parent:
                fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        except FileNotFoundError:
            return False
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_uid != self.account.pw_uid or before.st_mode & 0o077
                    or before.st_size > 65536):
                raise AttentionError("attention_existing_configuration_unsafe")
            body = os.read(fd, 65537)
            fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink",
                      "st_size", "st_mtime_ns", "st_ctime_ns")
            after = os.fstat(fd)
            with directory_fd(path.parent) as parent:
                current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if len(body) != before.st_size or any(
                    getattr(before, key) != getattr(info, key) for info in (after, current) for key in fields):
                raise AttentionError("attention_existing_configuration_changed")
            try:
                value = json.loads(body)
                self.validate_configuration(value)
            except (ValueError, TypeError, KeyError):
                raise AttentionError("attention_existing_configuration_invalid") from None
            return True
        finally:
            os.close(fd)

    def seed_resource(self):
        self.validate_configuration(self.data["config"])
        return {"path": self.data["config_path"],
                "content": json.dumps(self.data["config"], indent=4, sort_keys=True) + "\n",
                "owner": self.account.pw_name, "group": "staff", "mode": 0o600}

    def plist_resource(self):
        return {"path": self.data["plist_path"], "content": self.data["plist"],
                "owner": self.account.pw_name, "group": "staff", "mode": 0o644}

    def resources(self):
        # Missing config is a fresh-install seed, not authority to overwrite an
        # existing disabled production/synthetic document with a placeholder.
        rows = [self.plist_resource()]
        if not self.configuration_current():
            rows.insert(0, self.seed_resource())
        return rows

    def publish_resources(self):
        if run(["/usr/bin/plutil", "-lint", "-"], pure=True, content=self.data["plist"].encode()).returncode:
            raise AttentionError("attention_plist_invalid")
        if not self.configuration_current():
            seed = self.seed_resource()
            put_bytes(seed, seed["content"].encode(), replace=False)
        # A concurrent creator wins no-replace publication. Validate that real
        # document and preserve it; never fall back to an overwrite.
        if not self.configuration_current():
            raise AttentionError("attention_configuration_seed_unavailable")
        put_resource(self.plist_resource())

    def code_tree(self, *, skip_venv=False):
        roots = (self.root, self.python_root)
        for root in roots:
            for parent in (root, *root.parents):
                try:
                    info = parent.lstat()
                except FileNotFoundError:
                    continue
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                        or info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
                    raise AttentionError("attention_root_code_boundary_invalid")
            if not root.exists():
                continue
            def unavailable(error):
                raise error
            for parent, directories, names in os.walk(root, followlinks=False, onerror=unavailable):
                if skip_venv:
                    directories[:] = [name for name in directories if pathlib.Path(parent) / name != self.venv]
                for name in [*directories, *names]:
                    path = pathlib.Path(parent) / name
                    info = path.lstat()
                    if info.st_uid != 0:
                        raise AttentionError("attention_root_code_boundary_invalid")
                    if stat.S_ISLNK(info.st_mode):
                        target = path.resolve(strict=True)
                        if not any(target == allowed or allowed in target.parents for allowed in roots):
                            raise AttentionError("attention_root_code_boundary_invalid")
                    elif path.name == ".lock":
                        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o111:
                            raise AttentionError("attention_root_code_boundary_invalid")
                    elif not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)) or info.st_mode & 0o022:
                        raise AttentionError("attention_root_code_boundary_invalid")

    def public_file(self, path, limit):
        try:
            with directory_fd(path.parent):
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            return None
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022 or info.st_size > limit:
                raise AttentionError("attention_public_code_file_invalid")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                return stream.read(limit + 1)
        finally:
            os.close(fd)

    def wheel_current(self):
        body = self.public_file(self.wheel, 256 * 1024 * 1024)
        return body is not None and hashlib.sha1(body).hexdigest() == self.data["wheel_sha1"]

    def environment(self, *, downloads=False):
        values = {"HOME": "/var/root", "UV_NO_PROGRESS": "1", "PYTHONDONTWRITEBYTECODE": "1",
                  "UV_PYTHON_INSTALL_DIR": str(self.python_root), "UV_PYTHON_PREFERENCE": "only-managed"}
        if not downloads:
            values["UV_PYTHON_DOWNLOADS"] = "never"
        return values

    def uv(self, *argv, downloads=False, pure=False):
        result = run([self.data["uv_bin"], *argv], env=self.environment(downloads=downloads), pure=pure)
        if result.returncode:
            raise AttentionError("attention_python_command_failed")
        return result.stdout.decode().strip()

    def interpreter(self):
        source = self.uv("python", "find", "--no-project", self.data["python_version"], pure=True)
        expected = re.escape(str(self.python_root) + "/cpython-" + self.data["python_version"]) + r"-[^/]+/bin/python3\.14"
        if not re.fullmatch(expected, source):
            raise AttentionError("attention_interpreter_path_invalid")
        info = pathlib.Path(source).lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise AttentionError("attention_interpreter_owner_invalid")
        return pathlib.Path(source)

    def venv_current(self, source):
        body = self.public_file(self.venv / "pyvenv.cfg", 65536)
        match = re.search(rb"(?m)^home = (.*)$", body or b"")
        return bool(match and match[1].decode().strip() == str(source.parent) and (self.venv / "bin/python").is_file())

    def environment_current(self):
        # An old root-owned venv may point at Homebrew Python. Inspect its
        # bounded root-owned pyvenv.cfg before deciding to rebuild; do not
        # execute or adopt its Python merely to make that determination.
        self.code_tree(skip_venv=True)
        try:
            source = self.interpreter()
        except (AttentionError, FileNotFoundError):
            return False
        if not self.venv_current(source):
            return False
        self.code_tree()
        return self.public_file(self.receipt, 41) == (self.data["wheel_sha1"] + "\n").encode()

    def install_environment(self):
        self.require_quiescent()
        self.code_tree(skip_venv=True)
        if not self.wheel_current():
            raise AttentionError("attention_installed_wheel_mismatch")
        self.uv("python", "install", "--no-bin", self.data["python_version"], downloads=True)
        source = self.interpreter()
        if self.venv.exists() and not self.venv_current(source):
            shutil.rmtree(self.venv)
        self.code_tree()
        if not (self.venv / "bin/python").exists():
            self.uv("venv", "--python", self.data["python_version"], str(self.venv))
        if not self.venv_current(source):
            raise AttentionError("attention_venv_interpreter_mismatch")
        self.uv("pip", "install", "--python", str(self.venv / "bin/python"), "--reinstall-package", "daybook", str(self.wheel), downloads=True)

    def verify_import(self):
        self.require_quiescent()
        self.code_tree()
        if not self.wheel_current() or not self.venv_current(self.interpreter()):
            raise AttentionError("attention_import_inputs_invalid")
        argv = ["/usr/bin/sudo", "-n", "-H", "-u", self.account.pw_name, "--",
                str(self.venv / "bin/python"), "-I", "-c", "import daybook.attention"]
        if run(argv, cwd=self.data["service_home"]).returncode:
            raise AttentionError("attention_application_import_failed")
        # Success publication follows the real isolated import. Failure leaves
        # the prior receipt untouched and the exact label disabled/unloaded.
        put_resource({"path": str(self.receipt), "content": self.data["wheel_sha1"] + "\n",
                      "owner": "root", "group": "wheel", "mode": 0o644})

    def status(self):
        self.validate_paths()
        self.configuration_current()
        return {"quiescent": self.controls(),
                "directories": all(directory_matches(spec) for spec in self.directories()),
                "wheel": self.wheel_current(), "environment": self.environment_current(),
                "resources": all(file_matches(spec, content=True) for spec in self.resources())}


def main():
    try:
        installation = Installation(json.load(sys.stdin))
        action = sys.argv[1]
        if action == "status":
            print(json.dumps(installation.status(), sort_keys=True))
            return 0
        if os.geteuid() != 0:
            raise AttentionError("attention_original_root_required")
        installation.validate_paths()
        installation.configuration_current()
        if action == "quiesce":
            installation.quiesce()
        else:
            installation.require_quiescent()
            if action == "directories":
                for spec in installation.directories():
                    ensure_directory(spec)
            elif action == "environment":
                installation.install_environment()
            elif action == "verify-import":
                installation.verify_import()
            elif action == "resources":
                installation.publish_resources()
            else:
                raise AttentionError("attention_action_invalid")
        installation.configuration_current()
        return 0
    except Exception:
        # Child/tool output, wheel module output and private config stay in RAM.
        print("attention_component_failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
