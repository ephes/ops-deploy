"""tasks/coding_tools.yml's npm steps, run on the host as root (``python3 -I -c``).

argv: ``check|apply USER HOME PATH PREFIX TOOL...``.

1. ``npm list -g --depth=0 --json`` as root; every tool in that list is
   uninstalled system-wide (``npm uninstall -g -- TOOL``), so the per-user
   copy is the one on PATH.
2. ``npm list -g`` and ``npm outdated -g`` (both ``--json``) as USER; a tool
   is installed (``npm install -g -- TOOL`` as USER) when it is missing from
   the first or listed in the second. Both lists are read before the first
   install, as in the role.

Exit status 1 or 0 of the listings is accepted (npm reports problems or
outdated packages with 1), anything else fails, as the role's
``failed_when``. Unlike the role, a per-user PREFIX without ``lib`` (no tool
installed there yet) counts as empty instead of failing the listing (npm 10
exits 254 there, which stops the role on a first run). ``check`` prints the steps ``apply`` would run, one per
line (``uninstall-system TOOL``, ``install TOOL``) and changes nothing;
``apply`` prints each step before running it. Commands as USER run through
``sudo -H -n -u USER`` like the role's ``become_user`` (sudo's environment,
HOME and PAM umask); root's run with HOME=/root and sudo's secure_path.
The source holds no backslash: it travels on a command line that the
host's login shell may read (ops-deploy's fish rule).
"""

import json
import os
import subprocess
import sys


def main():
    mode, user, _home, path, prefix = sys.argv[1:6]
    tools = sys.argv[6:]
    if mode not in ("check", "apply"):
        raise SystemExit("mode must be check or apply")
    root_env = ["HOME=/root", "PATH=" + path]

    def command(argv, as_user):
        if as_user:
            return ["sudo", "-H", "-n", "-u", user, "--", *argv]
        return ["env", *root_env, *argv]

    def listing(argv, as_user):
        done = subprocess.run(command(argv, as_user), capture_output=True, text=True)
        if done.returncode not in (0, 1):
            sys.stderr.write(done.stderr)
            raise SystemExit(" ".join(argv) + " failed with exit status " + str(done.returncode))
        return json.loads(done.stdout)

    def step(argv, as_user, label):
        print(label)
        if mode == "apply":
            sys.stdout.flush()
            subprocess.run(command(argv, as_user), check=True)

    system = listing(["npm", "list", "-g", "--depth=0", "--json"], False).get("dependencies", {})
    for tool in tools:
        if tool in system:
            step(["npm", "uninstall", "-g", "--", tool], False, "uninstall-system " + tool)
    if os.path.isdir(os.path.join(prefix, "lib")):
        installed = listing(["npm", "list", "-g", "--depth=0", "--json"], True).get("dependencies", {})
        outdated = listing(["npm", "outdated", "-g", "--json"], True)
    else:
        # A prefix nothing was installed into yet: npm 10 fails both listings
        # (ENOENT, exit 254) and the role stops there; nothing is installed.
        installed, outdated = {}, {}
    for tool in tools:
        if tool not in installed or tool in outdated:
            step(["npm", "install", "-g", "--", tool], True, "install " + tool)


main()
