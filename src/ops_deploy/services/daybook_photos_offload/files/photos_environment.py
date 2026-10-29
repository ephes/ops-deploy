"""Original root-created, GUI-user managed Photos environment contract.

Only stdlib interpreter metadata and UV's dry dependency check are facts. Root
never executes or walks user-writable environment code. Sync is managed work
under the original login transition and exact configured Python selector.
"""

import grp
import os
import pathlib
import shutil
import stat

from ops_photos_filesystem import ensure_directory
from ops_photos_source import PhotosSourceError, no_links


class PhotosEnvironmentError(RuntimeError):
    pass


def interpreter_current(data, probes):
    python = pathlib.Path(data["checkout"]) / ".venv/bin/python"
    if not python.is_file():
        return False
    # -S excludes user .pth/import hooks for this pure stdlib version probe.
    predicate = (
        "import sys;v='%d.%d.%d'%sys.version_info[:3];"
        "raise SystemExit(0 if v==sys.argv[1] and '/uv/python/cpython-'+v+'-' in sys.base_prefix else 1)"
    )
    try:
        result = probes.run([str(python), "-I", "-B", "-S", "-c", predicate, data["python_version"]], user=True)
    except PhotosSourceError:
        return False  # Original non-starting interpreter selects managed rebuild.
    return result.returncode == 0


def environment_current(data, probes):
    environment = pathlib.Path(data["checkout"]) / ".venv"
    no_links(environment)
    try:
        info = environment.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISDIR(info.st_mode):
        raise PhotosEnvironmentError("photos_environment_substituted")
    if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (
        data["uid"],
        grp.getgrnam(data["group"]).gr_gid,
        0o700,
    ):
        return False
    if not interpreter_current(data, probes):
        return False
    # Qualified UV --check planning semantics: no build/install/backend/app call.
    checked = probes.run(
        [
            data["uv_bin"],
            "--directory",
            data["checkout"],
            "sync",
            "--check",
            "--frozen",
            "--no-config",
            "--no-dev",
            "--no-install-project",
            "--offline",
            "--no-python-downloads",
            "--no-cache",
            "--python",
            data["python_version"],
        ],
        user=True,
        extra={"UV_PROJECT_ENVIRONMENT": ".venv", "UV_PYTHON_PREFERENCE": "only-managed"},
    )
    return checked.returncode == 0


def converge_environment(data, probes, controls):
    if os.geteuid() != 0:
        raise PhotosEnvironmentError("photos_environment_original_root_preparation_required")
    controls.require_quiescent()
    # Before any root removal, distinguish an unavailable GUI transition from a
    # genuine missing/broken/wrong-version executable in the declared .venv.
    identity = probes.run(["/usr/bin/id", "-u"], user=True)
    if identity.returncode or identity.stdout.decode().strip() != str(data["uid"]):
        raise PhotosEnvironmentError("photos_environment_gui_context_unavailable")
    environment = pathlib.Path(data["checkout"]) / ".venv"
    no_links(environment)
    if environment.exists() and not environment.is_dir():
        raise PhotosEnvironmentError("photos_environment_substituted")
    spec = {"path": str(environment), "owner": data["user"], "group": data["group"], "mode": 0o700}
    ensure_directory(spec)  # Root parent stays protected; no recursive walk/chown.
    python = environment / "bin/python"
    if os.path.lexists(python) and not interpreter_current(data, probes):
        # Original task: root can unlink the environment entry in its protected
        # parent; the GUI user cannot. This is state-free .venv replacement only.
        shutil.rmtree(environment)
        ensure_directory(spec)
    outcome = probes.managed_user(
        [
            data["uv_bin"],
            "sync",
            "--frozen",
            "--no-config",
            "--no-dev",
            "--no-install-project",
            "--python",
            data["python_version"],
        ],
        cwd=data["checkout"],
        extra={"UV_PROJECT_ENVIRONMENT": ".venv", "UV_PYTHON_PREFERENCE": "only-managed"},
    )
    if outcome.returncode:
        raise PhotosEnvironmentError("photos_environment_frozen_sync_failed")
    if not environment_current(data, probes):
        raise PhotosEnvironmentError("photos_environment_not_current_after_sync")
