# Read-only: what the MinIO bootstrap still has to do for each bucket, through
# root's admin alias. Arguments: mc, the admin alias, a JSON list of
# {"name", "versioning", "anonymous"} (anonymous: the permission ``mc anonymous
# get`` reports for the wanted policy, or null to leave it alone).
#
# Prints one JSON object {bucket: [step, ...]} with the steps "mb", "version"
# and "anonymous" a bucket still needs; ``{}`` when nothing is left. Any mc
# failure (MinIO unreachable, the alias missing, an unexpected answer) exits
# non-zero, so the deploy's strict probe reports it. Nothing secret is read or
# printed.
import json
import subprocess
import sys

mc, alias, spec = sys.argv[1:]


def mc_json(*args):
    """mc's JSON lines for ``args``; exits on any failure."""

    result = subprocess.run([mc, "--json", *args], capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit(f"mc {' '.join(args[:2])} exited {result.returncode}")
    try:
        found = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    except ValueError:
        sys.exit(f"mc {' '.join(args[:2])} printed no JSON")
    if any(not isinstance(item, dict) or item.get("status") != "success" for item in found):
        sys.exit(f"mc {' '.join(args[:2])} reported an error")
    return found


existing = {str(item.get("key", "")).rstrip("/") for item in mc_json("ls", f"{alias}/")}
needed = {}
for bucket in json.loads(spec):
    name = bucket["name"]
    if name not in existing:
        steps = ["mb"]
        if bucket["versioning"]:
            steps.append("version")
        if bucket["anonymous"] is not None:
            steps.append("anonymous")
        needed[name] = steps
        continue
    steps = []
    if bucket["versioning"]:
        [info] = mc_json("version", "info", f"{alias}/{name}")
        if (info.get("versioning") or {}).get("status") != "Enabled":
            steps.append("version")
    if bucket["anonymous"] is not None:
        [info] = mc_json("anonymous", "get", f"{alias}/{name}")
        if info.get("permission") != bucket["anonymous"]:
            steps.append("anonymous")
    if steps:
        needed[name] = steps
print(json.dumps(needed, sort_keys=True))
