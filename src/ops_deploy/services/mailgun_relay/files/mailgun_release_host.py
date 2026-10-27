"""Pinned relay releases; standalone host script, no secret arguments or output.

Candidate validation creates a transient systemd unit, reads the production
configuration and binds/sends nothing. Existing versions are never replaced.
"""

import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

VERSION = re.compile(r"^[0-9]+[.][0-9]+[.][0-9]+(-[0-9A-Za-z.-]+)?$")


def command(argv):
    return subprocess.run(argv, cwd="/", capture_output=True, text=True, check=True).stdout.strip()


def validate(cfg):
    binary = str(pathlib.Path(cfg["root"]) / cfg["version"] / "mailgun-relay")
    version = command(["runuser", "-u", cfg["user"], "--", binary, "--version"])
    if version.split()[:2] != ["mailgun-relay", cfg["version"]]:
        raise ValueError("candidate does not report the pinned version")
    command([
        "systemd-run", "--wait", "--pipe", "--collect", "--quiet",
        "--property=User=" + cfg["user"], "--property=Group=" + cfg["group"],
        "--property=EnvironmentFile=" + cfg["env"], "--property=NoNewPrivileges=yes",
        "--property=ProtectSystem=strict", "--property=ProtectHome=yes",
        "--property=PrivateTmp=yes", "--property=PrivateDevices=yes", binary, "--check-config",
    ])


def remove(path):
    if path.is_symlink():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)


def candidate(cfg):
    root = pathlib.Path(cfg["root"])
    dest = root / cfg["version"]
    try:
        if cfg.get("archive_refused") or root.is_symlink() or dest.is_symlink():
            raise ValueError("candidate archive/path refused")
        if not dest.is_dir() or (dest / ".archive-sha256").read_text().strip() != cfg["sha256"]:
            raise ValueError("installed archive differs; replacing it is refused")
        validate(cfg)
    except Exception:
        if cfg.get("fresh"):
            remove(dest)
        # Config-parser stderr can contain secrets. Only a fixed diagnostic and
        # an outcome marker reach the controller, including soft Python rollback.
        if cfg["impl"] == "python":
            print("WARNING: pinned Rust candidate rejected; Python rollback continues, no pruning")
            print("failed candidate configuration validation")
        else:
            raise ValueError("Rust candidate validation failed; selection unchanged") from None


def live(cfg):
    if command(["systemctl", "is-active", cfg["unit"]]) != "active":
        raise ValueError("relay unit is not active")
    pid = int(command(["systemctl", "show", "--property=MainPID", "--value", cfg["unit"]]))
    if pid < 1:
        raise ValueError("relay has no live main process")
    exe = os.readlink("/proc/%s/exe" % pid)
    if cfg["impl"] == "rust":
        if exe != str(pathlib.Path(cfg["root"]) / cfg["version"] / "mailgun-relay"):
            raise ValueError("live executable is not the selected Rust release")
    else:
        args = pathlib.Path("/proc/%s/cmdline" % pid).read_bytes().rstrip(b"\0").split(b"\0")
        expected = [cfg["python"].encode(), b"-m", b"mailgun_relay"]
        if args != expected or exe.startswith(cfg["root"] + "/"):
            raise ValueError("live argv is not the selected Python rollback")
    return exe


def prunable(cfg, projected=False):
    root = pathlib.Path(cfg["root"])
    if not root.is_dir():
        return []
    previous = (root / ".previous-version").read_text().strip() if (root / ".previous-version").is_file() else ""
    loaded = subprocess.run(
        ["systemctl", "show", "--property=MainPID", "--value", cfg["unit"]],
        capture_output=True, text=True, check=False,
    )
    # A not-yet-installed unit has no MainPID on first deployment.
    pid = int(loaded.stdout.strip() or "0")
    exe = os.readlink("/proc/%s/exe" % pid) if pid > 0 else ""
    active = exe.removeprefix(str(root) + "/").split("/")[0] if exe.startswith(str(root) + "/") else ""
    versions = sorted(
        (p for p in root.iterdir() if p.is_dir() and not p.is_symlink() and VERSION.fullmatch(p.name)),
        key=lambda p: (p.stat().st_mtime_ns, p.name), reverse=True,
    )
    newest = [p.name for p in versions]
    if projected:
        dropin = pathlib.Path(cfg["dropin"])
        before = dropin.read_text() if dropin.is_file() else ""
        match = re.search(r"(?m)^ExecStart=" + re.escape(str(root)) + r"/([^/ ]+)/mailgun-relay(?: |$)", before)
        old = match[1] if match else ""
        if old and old != (cfg["version"] if cfg["impl"] == "rust" else "") and (root / old).is_dir():
            previous = old
        if cfg["version"] not in newest:
            newest.insert(0, cfg["version"])
    keep = {cfg["version"], previous, active} | set(newest[:cfg["keep"]])
    return [p for p in versions if p.name not in keep]


def main(mode, cfg):
    if mode == "candidate":
        candidate(cfg)
    elif mode == "live":
        live(cfg)
    elif mode == "prune-plan":
        print(json.dumps([str(p) for p in prunable(cfg, projected=True)]))
    elif mode == "prune":
        live(cfg)
        try:
            validate(cfg)
        except Exception:
            if cfg["impl"] == "python":
                print("WARNING: rejected Rust candidate; skipping pruning")
                return
            raise ValueError("refusing pruning after candidate validation failure") from None
        for p in prunable(cfg):
            remove(p)
    else:
        raise ValueError("unknown relay lifecycle operation")


if __name__ == "__main__":
    try:
        main(sys.argv[1], json.loads(sys.argv[2]))
    except Exception:
        print("mailgun-relay lifecycle check failed (secret details withheld)", file=sys.stderr)
        sys.exit(1)
