"""Original Sessions control-object guards, without application/data access.

All names and error output remain fixed or internal. Metadata guards never read
auth, browser, state or log bodies. Only identity_gate reads the declared private
seed/root-proof metadata and captures the bound verifier in remote memory.
"""

import hmac
import base64
import json
import os
import pathlib
import pwd
import re
import stat
import subprocess

from ops_sessions_resources import ResourceError, directory_fd, resource_path


def metadata(name):
    path = resource_path(name)
    try:
        with directory_fd(path.parent) as parent:
            return os.stat(path.name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return None


def private_object(name, uid, *, directory=False, required=False):
    info = metadata(name)
    if info is None:
        if required:
            raise ResourceError("sessions_private_control_missing")
        return False
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (not kind(info.st_mode) or info.st_uid != uid
            or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)
            or (not directory and info.st_nlink != 1)):
        raise ResourceError("sessions_private_control_unsafe")
    return True


def names(name):
    try:
        with directory_fd(resource_path(name)) as parent:
            return set(os.listdir(parent))
    except FileNotFoundError:
        return set()


def browser_guard(cfg, uid):
    if not cfg["daybook_archive_quote_classifier_enabled"]:
        return
    base = resource_path(cfg["daybook_sessions_service_home"] + "/.daybook")
    profile = resource_path(cfg["daybook_archive_browser_user_data_dir"])
    if profile.parent != base:
        raise ResourceError("sessions_browser_profile_not_dedicated")
    executable = metadata(cfg["daybook_archive_browser_executable"])
    if executable is None or not stat.S_ISREG(executable.st_mode):
        raise ResourceError("sessions_browser_executable_invalid")
    for path in (base, profile):
        info = metadata(str(path))
        if info is not None and (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid):
            raise ResourceError("sessions_browser_profile_unsafe")
    marker = ".daybook-archive-browser-profile"
    lock = ".daybook-archive-browser.lock"
    for name in (marker, lock):
        info = metadata(str(profile / name))
        if info is not None and (not stat.S_ISREG(info.st_mode) or info.st_uid != uid):
            raise ResourceError("sessions_browser_control_unsafe")
    if names(str(profile)) - {marker, lock} and metadata(str(profile / marker)) is None:
        raise ResourceError("sessions_browser_profile_unmarked")


def weeknotes_guard(cfg, uid):
    if not cfg["daybook_weeknotes_reconcile_enabled"]:
        return
    home = resource_path(cfg["daybook_sessions_service_home"])
    # Exact, descriptor-walked paths prevent linked ancestors and ~/.pi reuse.
    with directory_fd(home):
        pass
    root = resource_path(cfg["daybook_weeknotes_reconcile_pi_auth_source_root"])
    source = resource_path(cfg["daybook_weeknotes_reconcile_pi_auth_source"])
    runtime = resource_path(cfg["daybook_weeknotes_reconcile_runtime_dir"])
    agent = resource_path(cfg["daybook_weeknotes_reconcile_pi_agent_dir"])
    legacy = home / ".pi"
    if (source != root / "auth.json" or root == legacy or legacy in root.parents
            or agent != runtime / "pi-agent" or source == agent / "auth.json"):
        raise ResourceError("sessions_auth_path_invalid")
    private_object(str(root), uid, directory=True, required=True)
    private_object(str(source), uid, required=True)
    for path in (runtime, agent):
        private_object(str(path), uid, directory=True)
    for path in (runtime / "state.json", runtime / ".state.json.lock", agent / "auth.json"):
        private_object(str(path), uid)
    if names(str(agent)) - {"auth.json"}:
        raise ResourceError("sessions_auth_directory_not_isolated")


def browser_access(cfg):
    if not cfg["daybook_archive_quote_classifier_enabled"]:
        return
    try:
        gui_command(cfg, ["/bin/test", "-x", cfg["daybook_archive_browser_executable"]])
        for flag in ("-r", "-w", "-x"):
            gui_command(cfg, ["/bin/test", flag, cfg["daybook_archive_browser_user_data_dir"]])
    except ResourceError:
        raise ResourceError("sessions_browser_access_denied") from None


def preflight(data):
    cfg = data["config"]
    uid = pwd.getpwnam(cfg["daybook_sessions_service_user"]).pw_uid
    browser_guard(cfg, uid)
    weeknotes_guard(cfg, uid)
    return uid


def seed_auth(data, launchd):
    cfg = data["config"]
    if not cfg["daybook_weeknotes_reconcile_enabled"]:
        return
    from ops_sessions_resources import ensure_log, put_bytes
    uid = preflight(data)
    rotate = cfg["daybook_weeknotes_reconcile_pi_auth_rotate"]
    if rotate:
        state = launchd.state(cfg["daybook_weeknotes_reconcile_launchd_label"])
        if state["loaded"] or not state["disabled"]:
            raise ResourceError("sessions_auth_rotation_requires_quiescence")
    dest = cfg["daybook_weeknotes_reconcile_pi_agent_dir"] + "/auth.json"
    spec = {"path": dest, "owner": cfg["daybook_sessions_service_user"],
            "group": cfg["daybook_sessions_service_group"], "mode": 0o600}
    if private_object(dest, uid) and not rotate:
        ensure_log(spec)  # metadata only, never read/reseed refreshed auth
        return  # preserve existing OAuth refresh bytes without reading them
    path = resource_path(cfg["daybook_weeknotes_reconcile_pi_auth_source"])
    with directory_fd(path.parent) as parent:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != uid
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 8 * 1024 * 1024):
            raise ResourceError("sessions_auth_source_unsafe")
        chunks, remaining = [], 8 * 1024 * 1024 + 1
        while remaining:
            piece = os.read(fd, min(remaining, 65536))
            if not piece:
                break
            chunks.append(piece)
            remaining -= len(piece)
        body = b"".join(chunks)
        if len(body) > 8 * 1024 * 1024:
            raise ResourceError("sessions_auth_source_unsafe")
    finally:
        os.close(fd)
    put_bytes(spec, body, replace=rotate)
    weeknotes_guard(cfg, uid)
    ensure_log(spec)
    if names(cfg["daybook_weeknotes_reconcile_pi_agent_dir"]) != {"auth.json"}:
        raise ResourceError("sessions_auth_provisioning_failed")


def read_private_json(name, uid):
    private_object(name, uid, required=True)
    path = resource_path(name)
    with directory_fd(path.parent) as parent:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != uid
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 1024 * 1024):
            raise ResourceError("sessions_identity_metadata_unsafe")
        chunks, remaining = [], 1024 * 1024 + 1
        while remaining:
            piece = os.read(fd, min(remaining, 65536))
            if not piece:
                break
            chunks.append(piece)
            remaining -= len(piece)
        body = b"".join(chunks)
        if len(body) > 1024 * 1024:
            raise ResourceError("sessions_identity_metadata_unsafe")
        return json.loads(body)
    finally:
        os.close(fd)


def gui_command(cfg, argv, *, payload=None):
    account = pwd.getpwnam(cfg["daybook_sessions_service_user"])
    environment = {"HOME": account.pw_dir, "PATH": cfg["daybook_sessions_launchd_path"],
                   "PYTHONDONTWRITEBYTECODE": "1", "GIT_OPTIONAL_LOCKS": "0",
                   "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"}
    if os.geteuid() != account.pw_uid:
        # Same direct metadata context as existing NativeProbes: no login profile
        # execution or output, independent of connecting user's private cwd.
        argv = ["/usr/bin/sudo", "-n", "-H", "-u", account.pw_name, "--", "/usr/bin/env",
                *[key + "=" + value for key, value in environment.items()], *argv]
    # No app stderr/body forwarding or invented whole-command deadline. Managed
    # source/Brew/model calls retain their separate original login context.
    checked = subprocess.run(argv, input=payload, capture_output=True, cwd="/", env=environment)
    if checked.returncode:
        raise ResourceError("sessions_identity_verification_failed")
    return checked.stdout


def identity_source_ready(data):
    if not data["config"]["daybook_weeknotes_reconcile_enabled"]:
        return True
    cfg = data["config"]
    checkout = resource_path(cfg["daybook_sessions_checkout_path"])
    info = metadata(str(checkout))
    if info is None:
        return False
    if not stat.S_ISDIR(info.st_mode):
        raise ResourceError("sessions_identity_checkout_invalid")
    prefix = ["/usr/bin/git", "--no-optional-locks", "-c", "core.hooksPath=/dev/null",
              "-c", "core.fsmonitor=false", "-C", str(checkout)]
    revision = gui_command(cfg, [*prefix, "rev-parse", "HEAD"]).decode().strip()
    return revision == cfg["daybook_sessions_repo_ref"]


def checkout_git(cfg, *args):
    return gui_command(cfg, ["/usr/bin/git", "--no-optional-locks", "-c", "core.hooksPath=/dev/null",
                            "-c", "core.fsmonitor=false", "-C", cfg["daybook_sessions_checkout_path"], *args])


def require_bound_checkout(cfg):
    checkout = cfg["daybook_sessions_checkout_path"]
    if (checkout_git(cfg, "rev-parse", "HEAD").decode().strip() != cfg["daybook_sessions_repo_ref"]
            or resource_path(checkout_git(cfg, "rev-parse", "--show-toplevel").decode().strip()) != resource_path(checkout)
            or checkout_git(cfg, "status", "--porcelain=v1", "--untracked-files=all").strip()):
        raise ResourceError("sessions_identity_checkout_invalid")


def bound_loader(cfg, loader, request):
    # Keep public loader source one-line and exact; private request stays stdin.
    encoded = base64.b64encode(loader.encode()).decode()
    program = "import base64;exec(compile(base64.b64decode('" + encoded + "'),'<bound-identity>','exec'))"
    return gui_command(cfg, [cfg["daybook_sessions_checkout_path"] + "/.venv/bin/python", "-I", "-B", "-S", "-c", program],
                       payload=json.dumps(request).encode())


def policy_gate(data, loader):
    cfg, binding = data["config"], data["identity"]
    if not cfg["daybook_weeknotes_reconcile_enabled"]:
        return
    require_bound_checkout(cfg)
    request = {"action": "policy", "python_version": cfg["daybook_sessions_python_version"],
               "checkout": str(resource_path(cfg["daybook_sessions_checkout_path"])),
               "module_hashes": binding["module_hashes"], "policy_environment": binding["policy_environment"]}
    try:
        raw = bound_loader(cfg, loader, request)
    except ResourceError:
        raise ResourceError("sessions_public_repository_policy_invalid") from None
    try:
        result = json.loads(raw)
        if (not isinstance(result, dict) or type(result.get("schema_version")) is not int
                or result != {"schema_version": 1, "policy_verified": True}
                or result["policy_verified"] is not True):
            raise ValueError
    except (ValueError, TypeError, KeyError):
        raise ResourceError("sessions_public_repository_policy_invalid") from None


def identity_gate(data, loader):
    if not data["identity"]["required"]:
        return {"schema_version": 1, "identity_verified": False}
    cfg, binding = data["config"], data["identity"]
    uid = preflight(data)
    paths = [cfg["daybook_weeknotes_identity_" + field + "_path"]
             for field in ("seed", "plan", "attestation")]
    for path in paths:
        private_object(path, uid, required=True)
    def identities():
        rows = [metadata(path) for path in paths]
        if any(i is None for i in rows):
            raise ResourceError("sessions_identity_metadata_changed")
        return [(i.st_dev, i.st_ino, i.st_uid, i.st_mode, i.st_nlink, i.st_size, i.st_mtime_ns, i.st_ctime_ns) for i in rows]
    initial = identities()
    seed = read_private_json(paths[0], uid)
    if seed != binding["seed_intent"]:
        raise ResourceError("sessions_identity_intent_mismatch")
    proof = read_private_json(cfg["daybook_weeknotes_identity_activation_proof_path"], 0)
    # Both original root-controlled rails must match before calling any app code.
    from ops_sessions_resources import file_matches
    for field in ("helper", "launcher"):
        path = cfg["daybook_weeknotes_identity_" + field + "_path"]
        rows = [row for row in data["resources"] if row["path"] == path]
        if len(rows) != 1 or rows[0]["owner"] != "root" or rows[0]["mode"] != 0o755:
            raise ResourceError("sessions_identity_rail_invalid")
        if not file_matches(rows[0], content=True, strict=True):
            raise ResourceError("sessions_identity_rail_invalid")
    checkout = cfg["daybook_sessions_checkout_path"]
    require_bound_checkout(cfg)
    request = {"python_version": cfg["daybook_sessions_python_version"], "checkout": str(resource_path(checkout)),
               "helper": str(resource_path(cfg["daybook_weeknotes_identity_helper_path"])),
               "helper_sha256": binding["helper_sha256"], "module_hashes": binding["module_hashes"],
               "paths": [str(resource_path(path)) for path in paths]}
    raw = bound_loader(cfg, loader, request)
    if identities() != initial:
        raise ResourceError("sessions_identity_metadata_changed")
    try:
        result = json.loads(raw)
        plan_hash = result["plan_hash"]
        valid = (set(result) == {"schema_version", "status", "plan_hash"}
                 and type(result["schema_version"]) is int and result["schema_version"] == 1
                 and result["status"] == "attestation_verified" and isinstance(plan_hash, str)
                 and re.fullmatch(r"[0-9a-f]{64}", plan_hash))
        ref = proof.get("daybook_repo_ref", "")
        valid = (valid and isinstance(ref, str) and re.fullmatch(r"[0-9a-f]{40}", ref)
                 and type(proof.get("schema_version")) is int
                 and proof == {"schema_version": 1, "identity_epoch": "monday-after-v1",
                               "plan_hash": plan_hash, "daybook_repo_ref": ref})
        if not valid or not hmac.compare_digest(proof["plan_hash"], plan_hash):
            raise ValueError
    except (ValueError, TypeError, KeyError, AttributeError):
        raise ResourceError("sessions_identity_root_proof_invalid") from None
    checkout_git(cfg, "merge-base", "--is-ancestor", ref, "HEAD")
    return {"schema_version": 1, "identity_verified": True}
