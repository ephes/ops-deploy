"""Owned root Inbox Python parity; no inventory, app import, model or launchd."""

from __future__ import annotations

import importlib.resources
import os
import pwd
import runpy
import shutil
import stat
from pathlib import Path
from typing import Any

from daybook_resources_native_fixture import provenance
from mac_apps_owned import OwnedMac, command


def metadata(paths: list[Path]) -> dict[str, tuple[int, ...]]:
    return {
        str(path): (
            s.st_dev,
            s.st_ino,
            s.st_uid,
            s.st_gid,
            s.st_mode,
            s.st_nlink,
            s.st_size,
            s.st_mtime_ns,
            s.st_ctime_ns,
        )
        for root in paths
        for path in [root, *root.rglob("*")]
        for s in [path.lstat()]
    }


def metadata_diagnostic(owned: OwnedMac, checkout: Path, tree: Path) -> dict[str, Any]:
    """Owned code/package metadata only; never change the actual guard result."""
    categories: dict[str, dict[str, Any]] = {}
    roots = (checkout, tree)
    boundary = checkout.parent.parent

    def note(category: str, path: Path, info: os.stat_result) -> None:
        row = categories.setdefault(
            category,
            {
                "count": 0,
                "first_path": str(path.relative_to(owned.root))
                if path.is_relative_to(owned.root)
                else "system-ancestor",
                "first_uid": info.st_uid,
                "first_mode": oct(stat.S_IMODE(info.st_mode)),
            },
        )
        row["count"] += 1
        row.setdefault("entries", []).append(
            {
                "path": str(path.relative_to(owned.root)) if path.is_relative_to(owned.root) else "system-ancestor",
                "uid": info.st_uid,
                "gid": info.st_gid,
                "mode": oct(stat.S_IMODE(info.st_mode)),
                "nlink": info.st_nlink,
                "regular": stat.S_ISREG(info.st_mode),
                "directory": stat.S_ISDIR(info.st_mode),
            }
        )

    for root in roots:
        for path in (root, *root.parents):
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
                note("ancestor-kind-owner", path, info)
            protected = path == boundary or boundary in path.parents
            if info.st_mode & 0o022 and (protected or not info.st_mode & stat.S_ISVTX):
                note("ancestor-writable", path, info)
        for parent, dirs, names in os.walk(root, followlinks=False):
            for name in [*dirs, *names]:
                path = Path(parent) / name
                info = path.lstat()
                if info.st_uid != 0:
                    note("entry-owner", path, info)
                if stat.S_ISLNK(info.st_mode):
                    try:
                        target = path.resolve(strict=True)
                    except (OSError, RuntimeError):
                        note("linked-missing-or-loop", path, info)
                    else:
                        if not any(target == own or own in target.parents for own in roots):
                            note("linked-outside-protected-roots", path, info)
                elif not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)) or info.st_mode & 0o022:
                    note("entry-kind-writable", path, info)
    return categories


def main() -> None:
    owned = OwnedMac("daybook-root-python")
    failure: BaseException | None = None
    try:
        provenance(owned)
        actor = pwd.getpwnam("runner")
        uv = shutil.which("uv")
        assert uv
        owned.report["fixture_uv_version"] = command(uv, "--version").stdout.strip()
        base = owned.root / "Daybook"
        checkout = base / "voice-memo-inbox/daybook"
        checkout.mkdir(parents=True)
        tree = base / "python"
        tree.mkdir(mode=0o755)
        cache = owned.root / "fixture-uv-cache"
        (checkout / "pyproject.toml").write_text(
            '[project]\nname="owned-inbox-python"\nversion="0.0.0"\nrequires-python=">=3.14.7"\ndependencies=[]\n'
        )
        (checkout / ".python-version").write_text("3.14.7\n")
        environment = {
            **{
                k: v for k, v in os.environ.items() if k not in {"UV_PYTHON", "VIRTUAL_ENV", "PYTHONHOME", "PYTHONPATH"}
            },
            "HOME": "/var/root",
            "UV_NO_PROGRESS": "1",
            "UV_PYTHON_INSTALL_DIR": str(tree),
            "UV_PYTHON_PREFERENCE": "only-managed",
            "UV_CACHE_DIR": str(cache),
        }
        # Explicit managed disposable setup, matching the ORIGINAL root tree,
        # selector, regular-copy boundary and fixed patch; no real app checkout.
        command(uv, "python", "install", "--no-bin", "3.14.7", env=environment)
        environment["UV_PYTHON_DOWNLOADS"] = "never"
        found = command(uv, "python", "find", "--no-project", "3.14.7", env=environment).stdout.strip()
        source = Path(found)
        assert source.is_relative_to(tree)
        assert source.is_file()
        assert not source.is_symlink()
        assert source.stat().st_uid == 0
        command(uv, "--directory", str(checkout), "lock", "--offline", "--python", "3.14.7", env=environment)
        command(uv, "--directory", str(checkout), "sync", "--frozen", "--no-dev", "--python", "3.14.7", env=environment)
        copied = checkout / ".venv/bin/python"
        assert copied.is_symlink()  # original explicit managed materialization follows
        script = importlib.resources.files("ops_deploy.services.daybook_operations_runtime").joinpath(
            "files/runtime_state.py"
        )
        module = runpy.run_path(str(script), run_name="owned_root_runtime_observer")
        data = {
            "user": actor.pw_name,
            "owner": "root",
            "python": str(copied),
            "python_version": "3.14.7",
            "uv_bin": uv,
            "checkout": str(checkout),
        }
        calls = []
        diagnostics = []

        class Probes(module["NativeProbes"]):
            def run(self, argv: list[str], user: bool = False, extra: Any = None) -> Any:
                category = (
                    "stdlib-interpreter"
                    if argv[0] == str(copied)
                    else ("root-uv-find" if argv[1:3] == ["python", "find"] else "root-uv-lock-check")
                )
                calls.append({"probe": category, "as_gui": user, "root_selector": extra == self.root_python_env()})
                result = super().run(argv, user=user, extra=extra)
                diagnostics.append(
                    {"probe": category, "returncode": result.returncode, "stderr_present": bool(result.stderr)}
                )
                return result

        probes = Probes(data)
        assert probes.root_python_tree() == tree
        assert probes.runtime_current() is False
        owned.report["initial_symlink_probe_history"] = list(calls)
        owned.report["initial_metadata_diagnostic"] = metadata_diagnostic(owned, checkout, tree)
        # A symlink may already be rejected by the earlier metadata tree guard.
        # Neither path may execute the copied interpreter or root lock query.
        assert [row["probe"] for row in calls] in ([], ["root-uv-find"])

        def materialize() -> None:
            temporary = copied.with_name("python.managed")
            assert not temporary.exists()
            shutil.copyfile(source, temporary)
            os.chown(temporary, 0, 0)
            temporary.chmod(0o755)
            os.replace(temporary, copied)

        materialize()
        assert copied.is_file()
        assert not copied.is_symlink()
        assert copied.stat().st_uid == 0
        assert copied.stat().st_nlink == 1
        calls.clear()
        owned.report["copied_metadata_diagnostic"] = metadata_diagnostic(owned, checkout, tree)
        current = probes.runtime_current()
        owned.report["copied_probe_history"] = list(calls)
        owned.report["probe_diagnostics"] = diagnostics
        assert current is True
        assert calls == [
            {"probe": "root-uv-find", "as_gui": False, "root_selector": True},
            {"probe": "stdlib-interpreter", "as_gui": True, "root_selector": False},
            {"probe": "root-uv-lock-check", "as_gui": False, "root_selector": True},
        ]
        uv_locks = [checkout / ".venv/.lock", tree / ".lock"]
        for path in uv_locks:
            info = path.lstat()
            assert stat.S_ISREG(info.st_mode)
            assert (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink) == (0, 0, 0o666, 1)
            # Explicit synthetic fixture content only. UV uses the lock inode,
            # never executes/imports its content; observer reads metadata only.
            path.write_bytes(b"INERT-OWNED-LOCK-CONTENT")
        assert probes.runtime_current() is True
        owned.report["actual_uv_bookkeeping_locks"] = [
            {
                "path": str(path.relative_to(owned.root)),
                "uid": path.stat().st_uid,
                "gid": path.stat().st_gid,
                "mode": oct(stat.S_IMODE(path.stat().st_mode)),
                "nlink": path.stat().st_nlink,
            }
            for path in uv_locks
        ]
        before = metadata([checkout, tree])
        for _ in range(2):
            assert probes.runtime_current() is True
            assert metadata([checkout, tree]) == before

        faults = []

        def refuse_before_execution(name: str, *, root_find: bool = True) -> None:
            calls.clear()
            assert probes.runtime_current() is False
            expected = [{"probe": "root-uv-find", "as_gui": False, "root_selector": True}] if root_find else []
            assert calls == expected
            faults.append({"name": name, "root_uv_find_reached": root_find})

        lock = uv_locks[0]
        lock.chmod(0o777)
        try:
            refuse_before_execution("uv-lock-executable", root_find=False)
        finally:
            lock.chmod(0o666)
        assert probes.runtime_current() is True
        os.chown(lock, actor.pw_uid, actor.pw_gid)
        try:
            refuse_before_execution("uv-lock-wrong-owner", root_find=False)
        finally:
            os.chown(lock, 0, 0)
        assert probes.runtime_current() is True
        alias = owned.root / "uv-lock-hardlink"
        os.link(lock, alias)
        try:
            refuse_before_execution("uv-lock-multiple-links", root_find=False)
        finally:
            alias.unlink()
        assert probes.runtime_current() is True
        lock.unlink()
        lock.symlink_to(uv_locks[1])
        try:
            refuse_before_execution("uv-lock-symlink", root_find=False)
        finally:
            lock.unlink()
            lock.write_bytes(b"INERT-OWNED-LOCK-CONTENT")
            lock.chmod(0o666)
        assert probes.runtime_current() is True
        lock.unlink()
        lock.mkdir()
        try:
            refuse_before_execution("uv-lock-is-directory", root_find=False)
        finally:
            lock.rmdir()
            lock.write_bytes(b"INERT-OWNED-LOCK-CONTENT")
            lock.chmod(0o666)
        assert probes.runtime_current() is True
        unexpected = checkout / ".venv/unexpected.lock"
        unexpected.write_bytes(b"INERT-UNAPPROVED-OWNED-LOCK")
        unexpected.chmod(0o666)
        try:
            refuse_before_execution("unrecognized-writable-lock", root_find=False)
        finally:
            unexpected.unlink()
        assert probes.runtime_current() is True
        copied.chmod(0o775)
        refuse_before_execution("copied-group-writable", root_find=False)
        copied.chmod(0o755)
        assert probes.runtime_current() is True
        os.chown(copied, actor.pw_uid, actor.pw_gid)
        refuse_before_execution("copied-wrong-owner", root_find=False)
        os.chown(copied, 0, 0)
        assert probes.runtime_current() is True
        hardlink = owned.root / "copied-hardlink"
        os.link(copied, hardlink)
        refuse_before_execution("copied-multiple-links")
        hardlink.unlink()
        assert probes.runtime_current() is True
        copied.unlink()
        copied.symlink_to(source)
        refuse_before_execution("copied-is-symlink")
        copied.unlink()
        materialize()
        assert probes.runtime_current() is True
        marker = owned.root / "substituted-interpreter-executed"
        copied.write_text("#!/bin/sh\n/usr/bin/touch '" + str(marker) + "'\nexit 0\n")
        copied.chmod(0o755)
        refuse_before_execution("copied-hash-mismatch")
        assert not marker.exists()
        materialize()
        assert probes.runtime_current() is True
        source_mode = source.stat().st_mode & 0o777
        source.chmod(0o775)
        try:
            refuse_before_execution("pinned-source-group-writable", root_find=False)
        finally:
            source.chmod(source_mode)
        assert probes.runtime_current() is True
        copied.parent.chmod(0o775)
        try:
            refuse_before_execution("venv-bin-writable", root_find=False)
        finally:
            copied.parent.chmod(0o755)
        assert probes.runtime_current() is True
        home_cfg = checkout / ".venv/pyvenv.cfg"
        cfg_mode = home_cfg.stat().st_mode & 0o777
        home_cfg.chmod(0o666)
        try:
            refuse_before_execution("pyvenv-config-writable", root_find=False)
        finally:
            home_cfg.chmod(cfg_mode)
        assert probes.runtime_current() is True
        original_home = home_cfg.read_bytes()
        home_cfg.write_text("home = /wrong\n")
        try:
            refuse_before_execution("wrong-pyvenv-home")
        finally:
            home_cfg.write_bytes(original_home)
        assert probes.runtime_current() is True
        final = metadata([checkout, tree])
        assert probes.runtime_current() is True
        assert metadata([checkout, tree]) == final
        owned.report["root_python"] = {
            "python_version": "3.14.7",
            "original_root_tree_shape": True,
            "initial_symlink_refused_before_execution": True,
            "root_source_copy_owner_mode_singlelink_hash_verified": True,
            "actual_gui_stdlib_version_and_base_prefix": True,
            "actual_root_uv_selector_and_offline_lock_check": True,
            "first_and_final_two_repeat_metadata_exact": True,
            "genuine_preexecution_faults": faults,
            "substituted_interpreter_never_executed": not marker.exists(),
            "setup": (
                "Explicit managed toy source/lock, root uv Python install/sync and regular binary copy "
                "under owned root; "
                "no app import or source activation."
            ),
            "scope": "original Inbox root interpreter mechanism; original user-owned component proofs remain separate",
        }
        owned.report["limitations"].append(
            "uv --check/uv-find may perform native cache/temporary IO; "
            "service source/interpreter metadata is compared. "
            "Workflow/controller caches are disposable setup outside fixture root cleanup."
        )
        owned.report["status"] = "passed"
    except BaseException as error:
        failure = error
    failure = owned.finish(failure)
    if failure is not None:
        raise failure


if __name__ == "__main__":
    main()
