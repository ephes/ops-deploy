# Keeps one entry in a user's crontab exactly as Ansible's ``cron`` module does,
# so the two tools never add a second copy of a job: a ``#Ansible: <name>``
# header line followed by the job line. Argument: a JSON object with ``user``,
# ``name``, ``state`` (present or absent), ``minute``, ``hour``, ``job`` and
# ``apply``. Without ``apply`` it only prints ``unchanged`` or ``pending``.
import json
import subprocess
import sys

params = json.loads(sys.argv[1])
header = "#Ansible: " + params["name"]
line = f"{params['minute']} {params['hour']} * * * {params['job']}"

listing = subprocess.run(["crontab", "-l", "-u", params["user"]], capture_output=True, text=True)
if listing.returncode == 0:
    original = listing.stdout.splitlines()
elif "no crontab" in listing.stderr:
    original = []
else:
    sys.exit(f"crontab -l failed: {listing.stderr.strip()}")

wanted = list(original)
# Ansible finds the job by its header, else adopts an identical job line.
at = next((i for i in range(len(wanted) - 1) if wanted[i] == header), None)
if at is None and line in wanted:
    found = wanted.index(line)
    if found == 0 or not wanted[found - 1].startswith("#Ansible: "):
        wanted.insert(found, header)
        at = found
if params["state"] == "present":
    if at is None:
        wanted += [header, line]
    else:
        wanted[at + 1] = line
elif at is not None:
    del wanted[at : at + 2]

if wanted == original:
    print("unchanged")
elif not params["apply"]:
    print("pending")
else:
    text = "\n".join(wanted).rstrip("\r\n") + "\n" if wanted else ""
    subprocess.run(["crontab", "-u", params["user"], "-"], input=text, text=True, check=True)
    print("updated")
