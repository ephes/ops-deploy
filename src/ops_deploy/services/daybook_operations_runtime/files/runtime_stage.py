"""Disabled-first runtime staging; no source replacement, signals or activation.

Stdin contains declared resources (including credential), never argv/environment.
Original installed-client validation is managed work, not pure observation.
"""

import contextlib
import grp
import json
import os
import pathlib
import stat
import subprocess
import sys
import secrets
import types

from ops_daybook_guards import JournalEvidence, RuntimeGuardError, require_profile_transition
from ops_daybook_observer import (
    MAX_INPUT, NativeProbes, ObservationError, code_current, resource_current, safe_file,
)


class StageError(RuntimeError):
    pass


def directory_current(path, user, group):
    import pwd
    import stat

    if not path.is_absolute() or ".." in path.parts or path == pathlib.Path("/"):
        raise StageError("runtime_stage_directory_invalid")
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise StageError("runtime_stage_linked_directory")
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISDIR(info.st_mode):
        raise StageError("runtime_stage_directory_invalid")
    return (info.st_uid == pwd.getpwnam(user).pw_uid and info.st_gid == grp.getgrnam(group).gr_gid
            and stat.S_IMODE(info.st_mode) == 0o700)


def journal_evidence(previous):
    schema = previous["schema"]
    paths = ([b["journal"] for b in previous["bindings"]]
             if schema < 3 and "bindings" in previous else [previous["journal"]])
    result = []
    for name in paths:
        root = pathlib.Path(name)
        if not root.is_absolute() or ".." in root.parts or root == pathlib.Path("/"):
            raise StageError("runtime_stage_old_store_invalid")
        # Metadata/slot reads only for explicitly managed original replacement.
        # No record/slot body or derived identifier is emitted.
        for path in (root, *root.parents):
            if path.is_symlink():
                raise StageError("runtime_stage_old_store_linked")
        evidence = dict(path=name, directory_exists=root.is_dir())
        if schema >= 3:
            children = [root / "deliveries", root / "halts"]
            if any(path.is_symlink() for path in children):
                raise StageError("runtime_stage_old_store_linked")
            evidence.update(deliveries_directory_exists=children[0].is_dir(),
                            halts_directory_exists=children[1].is_dir())
            evidence["json_entries"] = sum(
                entry.name.endswith(".json") for path in children if path.is_dir()
                for entry in path.iterdir()
            )
        else:
            slot = safe_file(root / "delivery.json")
            evidence.update(slot_exists=slot is not None,
                            slot_idle=slot is not None and json.loads(slot[1]).get("phase") == "idle",
                            lock_exists=os.path.lexists(root / "runtime.lock"),
                            halt_exists=os.path.lexists(root / "halted.json"))
        result.append(JournalEvidence(**evidence))
    return result


def prepare(data, probes, *, managed=False):
    if data["action"] not in {"install", "replace"} or (data["action"] == "replace" and not data["confirmed"]):
        raise StageError("runtime_stage_action_invalid")
    if not code_current(data, probes):
        raise StageError("runtime_stage_source_not_current")
    previous_file = safe_file(data["policy"])
    previous = json.loads(previous_file[1]) if previous_file is not None else None
    label = "gui/" + str(probes.account.pw_uid) + "/" + data["label"]
    loaded = probes.run(["/bin/launchctl", "print", label])
    serving = probes.run(["/usr/bin/pgrep", "-u", data["user"], "-f", "[o]perations serve"])
    if loaded.returncode not in {0, 113} or serving.returncode not in {0, 1}:
        raise StageError("runtime_stage_process_probe_failed")
    cfg = types.SimpleNamespace(**{**data, "kinds": [types.SimpleNamespace(**kind) for kind in data["kinds"]]})
    state = dict(closed_out=pathlib.Path(data["closeout_marker"]).exists(),
                 label_loaded=loaded.returncode == 0, serving=serving.returncode == 0)
    require_profile_transition(cfg, previous, **state, check_journals=False)
    legacy = previous is not None and data["action"] == "replace" and previous["schema"] < 3
    if data["action"] == "replace" and previous is not None and (managed or not legacy):
        require_profile_transition(cfg, previous, **state, journals=journal_evidence(previous))
    # Original install/replace stage no live LaunchAgent: only cutover installs it.
    resources = [r for r in data["resources"] if r["path"] != data["plist"]]
    directories = [pathlib.Path(data["journal"]), pathlib.Path(data["journal"]) / "deliveries",
                   pathlib.Path(data["journal"]) / "halts", pathlib.Path(data["credential"]).parent]
    directory_matches = [directory_current(p, data["user"], data["group"]) for p in directories]
    resource_matches = [resource_current(r) for r in resources]
    for resource in resources:
        parent = pathlib.Path(resource["path"]).parent
        if parent not in directories:
            with directory_fd(parent):
                pass
    # A legacy slot is read only by managed apply, never a dry-run/status fact.
    current = all(directory_matches) and all(resource_matches) and not legacy
    return current, directories, resources


@contextlib.contextmanager
def directory_fd(path):
    if not path.is_absolute() or ".." in path.parts:
        raise StageError("runtime_stage_directory_invalid")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for name in path.parts[1:]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def make_directory(path, uid, gid):
    if not path.is_absolute() or ".." in path.parts or path == pathlib.Path("/"):
        raise StageError("runtime_stage_directory_invalid")
    # Descriptor-relative traversal cannot be redirected by an ancestor link.
    # Missing ancestors are explicit owner-private preparation; existing parents
    # are left unchanged. Only the declared leaf gets ownership/mode convergence.
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for number, name in enumerate(path.parts[1:], 1):
            created = False
            try:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                os.mkdir(name, 0o700, dir_fd=fd)
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                created = True
            os.close(fd)
            fd = child
            if created or number == len(path.parts) - 1:
                info = os.fstat(fd)
                if stat.S_IMODE(info.st_mode) != 0o700:
                    os.fchmod(fd, 0o700)
                if (info.st_uid, info.st_gid) != (uid, gid):
                    os.fchown(fd, uid, gid)
    finally:
        os.close(fd)


def put(resource):
    if resource_current(resource):
        return
    import pwd

    path = pathlib.Path(resource["path"])
    with directory_fd(path.parent) as parent:
        temporary = ".daybook-stage-" + secrets.token_hex(16)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(resource["content"].encode())
                stream.flush()
                os.fsync(stream.fileno())
                os.fchmod(stream.fileno(), resource["mode"])
                os.fchown(stream.fileno(), pwd.getpwnam(resource["owner"]).pw_uid,
                          grp.getgrnam(resource["group"]).gr_gid)
            os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        finally:
            try:
                os.unlink(temporary, dir_fd=parent)
            except FileNotFoundError:
                pass


def validate_client(data, probes, *, pure=False):
    # Original installed-client profile parsing is retained after staging.
    argv = [data["python"], "-I", "-B", "-c",
            "import sys;from daybook.operations_runtime import Config;Config.load(sys.argv[1],sys.argv[2])",
            data["policy"], data["owner"]]
    if pure:
        # New constructor-only verification: no profiles, app CLI, Journal or
        # Client.call. Explicit account/env/cwd and ordinary metadata bound.
        checked = probes.run(argv, user=True)
    else:
        if os.geteuid() != probes.account.pw_uid:
            argv = ["/usr/bin/sudo", "-H", "-S", "-n", "-i", "-u", data["user"], "--", *argv]
        checked = subprocess.run(argv, capture_output=True, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    if checked.returncode:
        raise StageError("runtime_stage_client_rejected_profile")


def stage(data, action, probes=None):
    probes = probes or NativeProbes(data)
    current, directories, resources = prepare(data, probes, managed=action == "apply")
    if action == "status":
        return "current" if current else "change"
    if action == "verify":
        if not current:
            raise StageError("runtime_stage_not_current")
        validate_client(data, probes, pure=True)
        return "current"
    if action != "apply":
        raise StageError("runtime_stage_operation_invalid")
    if not current:
        for path in directories:
            make_directory(path, probes.account.pw_uid, grp.getgrnam(data["group"]).gr_gid)
        for resource in resources:
            put(resource)
    validate_client(data, probes)
    if not prepare(data, probes)[0]:
        raise StageError("runtime_stage_not_current")
    return "changed" if not current else "current"


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise StageError("runtime_stage_request_too_large")
        print(stage(json.loads(raw), sys.argv[1]))
    except (RuntimeGuardError, ObservationError, StageError, ValueError, KeyError, TypeError, OSError, AttributeError, RecursionError) as error:
        message = str(error) if isinstance(error, (RuntimeGuardError, ObservationError, StageError)) else "runtime_stage_failed"
        print(message, file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
