# Run on the OpenClaw host as root: ``python3 -I -c <this file> STEP MODE``
# with the step's JSON request on stdin. STEP is one of the role's steps
# that depend on what the host holds at run time (openclaw_deploy, ops-library):
#
#   config      tasks/config.yml on an existing openclaw.json: the v2026.9.1
#               legacy-key migration, the merged runtime patch, the Telegram
#               streaming alias normalization (the scripts are the role's).
#   doctor      tasks/doctor_activation.yml: Doctor repair with the target
#               image when the gateway container runs another one.
#   plugins     tasks/plugins.yml: the pinned official Codex plugin.
#   migrations  tasks/upgrade_migrations.yml, then config.yml again when it ran.
#   audio       tasks/audio_transcription.yml: the SecretRef plan apply.
#   cron        the reminder cron registration of tasks/weeknotes.yml.
#   health      tasks/health.yml (port, container, gateway RPC, Telegram).
#   session     the session-binding reset of tasks/session_state.yml.
#
# MODE ``check`` changes nothing and prints ``current`` or ``pending`` (the
# deploy decides with it while planning); ``apply`` does what the role does.
# No request carries a secret: CLI containers read the deployed .env file.
import fnmatch
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

LEGACY_SETUP = (
    "{w}/openclaw-workspace-state.json",
    "{w}/openclaw-workspace-state.json.doctor-importing",
    "{w}/.openclaw/workspace-state.json",
    "{w}/.openclaw/workspace-state.json.doctor-importing",
    "{w}.attested",
    "{w}.attested.doctor-importing",
)
ATTESTATION_PATTERNS = ("*.attested", "*.attested.doctor-importing")
MISSING = object()


class StepError(Exception):
    pass


def run(argv, **kwargs):
    return subprocess.run(argv, capture_output=True, text=True, **kwargs)


# -- config.yml -----------------------------------------------------------------------------


def migrate_v2026_9_1(data):
    """The role's "Migrate legacy settings removed in OpenClaw 2026.9.1" (in memory)."""
    changed = False
    agents = data.get("agents")
    defaults = agents.get("defaults") if isinstance(agents, dict) else None
    legacy_memory_search = defaults.pop("memorySearch", MISSING) if isinstance(defaults, dict) else MISSING
    if legacy_memory_search is not MISSING:
        memory = data.setdefault("memory", {})
        if not isinstance(memory, dict):
            raise TypeError("memory must be an object before migrating memorySearch")
        memory.setdefault("search", legacy_memory_search)
        changed = True
    meta = data.get("meta")
    if isinstance(meta, dict) and "lastTouchedAt" in meta:
        meta.pop("lastTouchedAt")
        changed = True
    return changed


def write_preserving(path, data):
    """The migration's atomic rewrite: same owner and mode, two-space JSON."""
    original_stat = path.stat()
    temporary_fd, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(temporary_fd, "w", encoding="utf-8") as handle:
            os.fchown(handle.fileno(), original_stat.st_uid, original_stat.st_gid)
            os.fchmod(handle.fileno(), original_stat.st_mode & 0o7777)
            handle.write(json.dumps(data, indent=2) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def combine(left, right):
    result = dict(left)
    for key, value in right.items():
        current = result.get(key)
        result[key] = combine(current, value) if isinstance(current, dict) and isinstance(value, dict) else value
    return result


def unique(values):
    seen, result = [], []
    for value in values:
        key = value.lower() if isinstance(value, str) else value
        if key not in seen:
            seen.append(key)
            result.append(value)
    return result


def clean(values):
    return unique(item for item in (str(value).strip() for value in values) if item != "")


def attr(value, key):
    """Jinja's ``value.key`` on a decoded JSON value: MISSING when undefined."""
    return value[key] if isinstance(value, dict) and key in value else MISSING


def default(value, fallback):
    return fallback if value is MISSING else value


def runtime_patch(request, existing):
    """``_openclaw_runtime_patch`` of config.yml for ``existing`` (the parsed openclaw.json)."""
    patch = request["base"]
    plugins = default(attr(existing, "plugins"), {})
    if request["plugin_allow"]:
        allow = default(attr(plugins, "allow"), []) if isinstance(plugins, dict) else []
        patch = combine(patch, {"plugins": {"allow": clean(allow + request["plugin_allow"])}})
    patch = combine(patch, request["control_ui"])
    if request["plugin_load_paths"]:
        load = default(attr(plugins, "load"), {})
        paths = default(attr(load, "paths"), []) if isinstance(plugins, dict) and isinstance(load, dict) else []
        patch = combine(patch, {"plugins": {"load": {"paths": clean(paths + request["plugin_load_paths"])}}})
    patch = combine(patch, request["model_policy"])
    primary = request["model_primary"]
    models = existing.get("agents", {}).get("defaults", {}).get("models", {})
    if primary and len(models) > 0:
        patch = combine(patch, {"agents": {"defaults": {"models": {primary: {}}}}})
    patch = combine(patch, request["reasoning"])
    patch = combine(patch, request["auth_order"])
    if request["audio_managed"]:
        patch = combine(patch, audio_runtime_patch(request, existing))
    return patch


def audio_runtime_patch(request, existing):
    enabled = request["audio_enabled"]
    tools = default(attr(existing, "tools"), {})
    media = default(attr(tools, "media"), {})
    preserved = []
    for item in default(attr(media, "models"), []):
        if not isinstance(item, dict):
            continue
        capabilities = item.get("capabilities", MISSING)
        if enabled:
            keep = (
                capabilities is not MISSING
                and isinstance(capabilities, (list, dict))
                and "audio" not in capabilities
            )
        else:
            keep = item.get("profile", "") != request["audio_profile_id"]
        if keep:
            preserved.append(item)
    patch = request["audio_config_patch"]
    models = default(attr(existing, "models"), {})
    providers = default(attr(models, "providers"), {}) if isinstance(models, dict) else {}
    if not enabled and request["audio_provider"] in providers:
        patch = combine(patch, {"models": {"providers": {request["audio_provider"]: {"request": {"allowPrivateNetwork": False}}}}})
    selected = [request["audio_model_entry"]] if enabled else []
    return combine(patch, {"tools": {"media": {"models": selected + preserved}}})


def to_nice_json(value):
    return json.dumps(value, indent=4, sort_keys=True, separators=(",", ": "))


def write_owned(path, text, mode):
    """Ansible's copy: an atomic replace owned by 1000:1000 with ``mode``."""
    temporary_fd, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(temporary_fd, "w", encoding="utf-8") as handle:
            os.fchown(handle.fileno(), 1000, 1000)
            os.fchmod(handle.fileno(), mode)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def resolve_mode(value):
    if value is True:
        return "partial"
    if value is False:
        return "off"
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"off", "partial", "block", "progress"}:
            return normalized
    return "partial"


def ensure_dict(value):
    return value if isinstance(value, dict) else {}


def normalize_entry(entry):
    """The role's "Normalize legacy Telegram streaming aliases" for one entry."""
    entry_changed = False
    if not isinstance(entry, dict):
        return False
    raw_streaming = entry.get("streaming")
    raw_stream_mode = entry.get("streamMode")
    streaming = ensure_dict(raw_streaming).copy()
    if raw_stream_mode is not None and "mode" not in streaming:
        streaming["mode"] = resolve_mode(raw_stream_mode)
        entry_changed = True
    elif raw_streaming is not None and not isinstance(raw_streaming, dict):
        streaming["mode"] = resolve_mode(raw_streaming)
        entry_changed = True
    if "streamMode" in entry:
        entry.pop("streamMode", None)
        entry_changed = True
    if "chunkMode" in entry and "chunkMode" not in streaming:
        streaming["chunkMode"] = entry.pop("chunkMode")
        entry_changed = True
    block = ensure_dict(streaming.get("block")).copy()
    if "blockStreaming" in entry and "enabled" not in block:
        block["enabled"] = entry.pop("blockStreaming")
        entry_changed = True
    if "blockStreamingCoalesce" in entry and "coalesce" not in block:
        block["coalesce"] = entry.pop("blockStreamingCoalesce")
        entry_changed = True
    if block:
        streaming["block"] = block
    preview = ensure_dict(streaming.get("preview")).copy()
    if "draftChunk" in entry and "chunk" not in preview:
        preview["chunk"] = entry.pop("draftChunk")
        entry_changed = True
    if preview:
        streaming["preview"] = preview
    if entry_changed:
        entry["streaming"] = streaming
    return entry_changed


def normalize(data):
    telegram = ensure_dict(ensure_dict(data.get("channels")).get("telegram"))
    changed = normalize_entry(telegram)
    for account in ensure_dict(telegram.get("accounts")).values():
        changed = normalize_entry(account) or changed
    return changed


def config(request, apply):
    """config.yml on an existing file, in the role's order; returns whether anything changed."""
    path = Path(request["path"])
    mode = int(request["mode"], 8)
    if not path.exists():
        # The deploy seeds the file from the controller first.
        return False
    # ``force`` marks a fresh seed: only the Telegram alias normalization applies.
    patching = not request["force"]
    changed = False
    data = json.loads(path.read_text(encoding="utf-8"))
    if patching and request["migrate_v2026_9_1"] and migrate_v2026_9_1(data):
        changed = True
        if apply:
            write_preserving(path, data)
    if patching:
        patched = combine(data, runtime_patch(request["runtime"], data))
        if patched != data:
            changed = True
            text = to_nice_json(patched) + "\n"
            # The normalization reads the file back: sorted keys, as written.
            data = json.loads(text)
            if apply:
                write_owned(path, text, mode)
    if normalize(data):
        changed = True
        if apply:
            path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            os.chmod(path, mode)
    return changed


# -- the gateway container and the CLI ------------------------------------------------------


def container_image(name):
    result = run(["docker", "inspect", "--format", "{{.Config.Image}}", name])
    return result.stdout.strip() if result.returncode == 0 else None


def unit_known(unit):
    """Whether systemd knows ``unit`` (the role's ``in ansible_facts.services``)."""
    result = run(["systemctl", "show", "--property=LoadState", "--value", unit])
    return result.returncode == 0 and result.stdout.strip() not in {"", "not-found"}


def stop_service(request):
    unit = request["service"] + ".service"
    if unit_known(unit):
        result = run(["systemctl", "stop", unit])
        if result.returncode != 0:
            raise StepError(f"systemctl stop {unit} failed: {result.stderr.strip()}")


def image_present(image):
    return run(["docker", "image", "inspect", image]).returncode == 0


def cli_argv(request):
    """cli_context.yml: the CLI container, sharing the gateway's PID namespace while it runs."""
    name, image = request["container"], request["image"]
    result = run(["docker", "inspect", "--format", "{{.State.Running}} {{.Config.Image}}", name])
    state = result.stdout.strip()
    if result.returncode == 0 and not re.search(r"^(true|false) [^ ]+$", state):
        raise StepError(
            "Docker inspection returned an unexpected state/image format. Refusing "
            "to select an offline CLI while the gateway may still be running."
        )
    running = result.returncode == 0 and state.startswith("true ")
    if running and state != "true " + image:
        raise StepError(
            "The running OpenClaw gateway uses a different image. Stop it before "
            "running target-version CLI tasks. Doctor activation does this for "
            "targets v2026.9.7+ when enabled; older targets or activation-disabled "
            "deploys require a manual stop."
        )
    argv = ["docker", "run", "--rm", "--network", "host"]
    if running:
        argv += ["--pid", "container:" + name]
    argv += ["--user", "1000:1000", "--env-file", request["site_dir"] + "/.env"]
    argv += ["--volume", request["data_dir"] + ":/home/node/.openclaw", "--entrypoint", "node", image, "dist/index.js"]
    return argv


def cli_ready(request):
    """Whether the CLI can run now (check mode): the image exists and no other image runs."""
    if not image_present(request["image"]):
        return False
    current = container_image(request["container"])
    running = run(["docker", "inspect", "--format", "{{.State.Running}}", request["container"]]).stdout.strip()
    return not (running == "true" and current != request["image"])


def doctor_argv(request, entry, *extra):
    return [
        "docker", "run", "--rm", "--network", "host", "--user", "1000:1000",
        "--env-file", request["site_dir"] + "/.env",
        "--volume", request["data_dir"] + ":/home/node/.openclaw",
        "--entrypoint", "node", request["image"], entry, "doctor", "--fix", "--non-interactive", *extra,
    ]  # fmt: skip


def doctor(request, apply):
    if container_image(request["container"]) == request["image"]:
        return False
    if not apply:
        return True
    stop_service(request)
    result = run(doctor_argv(request, "openclaw.mjs"))
    if result.returncode != 0:
        lines = result.stdout.splitlines()
        raise StepError(
            f"OpenClaw Doctor failed while activating {request['image']}. The gateway stays "
            "stopped because its state may be partially migrated and the previous "
            "release cannot open newer databases. Inspect the Doctor output, then "
            "either fix the reported problem and redeploy, or redeploy the previous "
            "version and restore the pre-upgrade backup. " + (lines[-1] if lines else "")
        )
    return True


def plugin_inspect(request, argv):
    result = run(argv + ["plugins", "inspect", request["plugin_id"], "--json"])
    if result.returncode == 0 and result.stdout.strip():
        return json.loads(result.stdout)
    return {}


def plugin_identity(request, inspected):
    install = inspected.get("install", {})
    return (
        inspected.get("plugin", {}).get("id", "") == request["plugin_id"]
        and install.get("resolvedName", "") == request["plugin_package"]
        and install.get("version", "") == request["plugin_version"].strip()
    )


def plugins(request, apply):
    if not apply and not cli_ready(request):
        return True
    argv = cli_argv(request)
    inspected = plugin_inspect(request, argv)
    if inspected.get("install", {}).get("version", "").strip() == request["plugin_version"].strip():
        if not apply:
            # The role verifies the identity on every run; a mismatch runs the step (and fails there).
            return not plugin_identity(request, inspected)
        changed = False
    else:
        if not apply:
            return True
        result = run(argv + ["plugins", "install", "--force", "--pin", request["plugin_package"] + "@" + request["plugin_version"]])
        if result.returncode != 0:
            raise StepError(f"Installing {request['plugin_package']} failed: {result.stderr.strip()[-400:]}")
        changed = True
    verify = run(argv + ["plugins", "inspect", request["plugin_id"], "--json"])
    if verify.returncode != 0:
        raise StepError(f"Codex plugin inspection failed: {verify.stderr.strip()[-400:]}")
    if not verify.stdout.strip() or not re.search(r"^\{", verify.stdout.strip()):
        raise StepError("Codex plugin inspection did not return a JSON object on stdout.")
    if not plugin_identity(request, json.loads(verify.stdout)):
        raise StepError(
            f"Installed {request['plugin_package']} identity or version does not "
            "match the configured Codex plugin settings."
        )
    return changed


def legacy_state(request):
    workspace = request["workspace_dir"]
    paths = [pattern.format(w=workspace) for pattern in LEGACY_SETUP]
    found = [path for path in paths if os.path.lexists(path)]
    attestations = Path(request["data_dir"]) / "workspace-attestations"
    if attestations.is_dir():
        for entry in os.listdir(attestations):
            if any(fnmatch.fnmatch(entry, pattern) for pattern in ATTESTATION_PATTERNS):
                found.append(str(attestations / entry))
    return found


def migrations(request, apply):
    if not legacy_state(request):
        return False
    if not apply:
        return True
    stop_service(request)
    if run(doctor_argv(request, "dist/index.js", "--yes")).returncode != 0:
        raise StepError("OpenClaw Doctor repair of the legacy workspace state failed")
    if legacy_state(request):
        raise StepError(
            "OpenClaw Doctor returned without removing all runtime-blocking legacy "
            "workspace state. Keep the gateway stopped and inspect Doctor output."
        )
    # main.yml: "Reconcile config after upstream upgrade migrations".
    config(request["config"], True)
    return True


def audio(request, apply):
    if not apply and (not cli_ready(request) or not os.path.exists(request["plan_host_path"])):
        return True
    argv = cli_argv(request)
    plan = ["secrets", "apply", "--from", request["plan_path"]]
    dry = run(argv + plan + ["--dry-run", "--json"])
    if dry.returncode != 0:
        raise StepError("OpenClaw secrets apply --dry-run failed")
    if not json.loads(dry.stdout)["changed"]:
        return False
    if not apply:
        return True
    if run(argv + plan + ["--json"]).returncode != 0:
        raise StepError("OpenClaw secrets apply failed")
    return True


# -- weeknotes cron --------------------------------------------------------------------------


def compose_cli(request, *args):
    return ["docker", "compose", "-f", request["site_dir"] + "/docker-compose.yml", "run", "--rm", "openclaw-cli", *args]


def retried(argv, attempts, delay):
    for attempt in range(attempts):
        result = run(argv)
        if result.returncode == 0:
            return result
        if attempt + 1 < attempts:
            time.sleep(delay)
    return result


def cron_jobs(request):
    result = retried(compose_cli(request, "cron", "list", "--json"), 4, 3)
    if result.returncode != 0 or not result.stdout.strip():
        return None
    jobs = json.loads(result.stdout).get("jobs", [])
    return [job for job in jobs if job.get("name") == "weeknotes-reminder"]


def cron_drifted(request, jobs):
    if len(jobs) > 1:
        return True
    if not jobs:
        return False
    job = jobs[0]
    schedule, payload = job.get("schedule", {}), job.get("payload", {})
    return (
        schedule.get("kind", "") != "cron"
        or schedule.get("expr", "") != request["cron"]
        or job.get("sessionTarget", "") != "main"
        or payload.get("kind", "") != "systemEvent"
        or payload.get("text", "") != request["command"]
    )


def cron_add(request):
    argv = compose_cli(
        request, "cron", "add", "--name", "weeknotes-reminder", "--cron", request["cron"],
        "--session", "main", "--wake", "now", "--system-event", request["command"], "--json",
    )  # fmt: skip
    return retried(argv, 6, 3).returncode == 0


def cron(request, apply):
    jobs = cron_jobs(request)
    if jobs and not cron_drifted(request, jobs):
        return False
    if not apply:
        return True
    if jobs is None:
        ok = False
    elif not jobs:
        ok = cron_add(request)
    else:
        # Every job is removed first; the job is added again only when all removals worked.
        removed = [run(compose_cli(request, "cron", "rm", str(job.get("id", "")), "--json")).returncode == 0 for job in jobs]
        ok = all(removed) and cron_add(request)
    if not ok:
        # The role warns and carries on.
        sys.stderr.write(
            "WARNING: Weeknotes reminder cron registration did not complete successfully. "
            "Inspect gateway health and rerun the OpenClaw deploy.\n"
        )
    return True


# -- health.yml ------------------------------------------------------------------------------


def wait_port(host, port, delay, timeout):
    time.sleep(delay)
    deadline = time.monotonic() + timeout
    while True:
        try:
            with socket.create_connection((host, port), timeout=1):
                return
        except OSError:
            if time.monotonic() >= deadline:
                raise StepError(f"Timeout when waiting for {host}:{port}") from None
            time.sleep(1)


def container_running(name):
    return run(["docker", "inspect", "--format", "{{.State.Running}}", name]).stdout.strip() == "true"


def gateway_health(name, telegram):
    result = run(["docker", "exec", name, "openclaw", "health", "--json"])
    if result.returncode != 0:
        return None
    try:
        health = json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError):
        return None
    ready = isinstance(health, dict) and health.get("ok") is True
    if ready and telegram:
        channels = health.get("channels")
        state = channels.get("telegram") if isinstance(channels, dict) else None
        ready = (
            isinstance(state, dict)
            and state.get("configured") is True
            and state.get("running") is True
            and state.get("connected") is True
            and state.get("lastError") is None
        )
    return health if ready else None


def health(request, apply):
    if not apply:
        return False
    name = request["container"]
    wait_port(request["bind_host"], request["port"], 2, request["startup_timeout"])
    if not container_running(name):
        raise StepError(f"{name} is not running")
    time.sleep(5)
    if not container_running(name):
        raise StepError(f"{name} stopped after starting (crash loop?)")
    for attempt in range(request["retries"] + 1):
        if gateway_health(name, request["telegram"]) is not None:
            return False
        if attempt < request["retries"]:
            time.sleep(request["delay"])
    if request["telegram"]:
        raise StepError(
            "OpenClaw gateway is reachable, but the configured Telegram channel is not "
            "running and connected. Inspect gateway logs for migration or crash-loop "
            "suppression errors."
        )
    raise StepError("OpenClaw or its configured Telegram channel is not ready")


# -- session_state.yml -----------------------------------------------------------------------


def session(request, apply):
    path = Path(request["path"])
    if not apply or not path.exists():
        return False
    data = json.loads(path.read_text(encoding="utf-8"))
    updated_entries = 0
    for _key, entry in list(data.items()):
        if not isinstance(entry, dict):
            continue
        changed = False
        for field in ("skillsSnapshot", "systemPromptReport", "sessionId", "sessionFile"):
            if field in entry:
                entry.pop(field, None)
                changed = True
        if changed:
            entry["systemSent"] = False
            entry["abortedLastRun"] = False
            entry["updatedAt"] = 0
            updated_entries += 1
    if updated_entries > 0:
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return updated_entries > 0


STEPS = {
    "config": config,
    "doctor": doctor,
    "plugins": plugins,
    "migrations": migrations,
    "audio": audio,
    "cron": cron,
    "health": health,
    "session": session,
}


def main(argv):
    step, mode = argv
    if step not in STEPS or mode not in {"check", "apply"}:
        sys.stderr.write("usage: openclaw_host.py STEP check|apply\n")
        return 2
    try:
        result = STEPS[step](json.load(sys.stdin), mode == "apply")
    except (StepError, ValueError, KeyError, OSError) as error:
        sys.stderr.write(f"openclaw {step}: {type(error).__name__}: {error}\n")
        return 1
    print("pending" if result else "current") if mode == "check" else print("changed" if result else "unchanged")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
