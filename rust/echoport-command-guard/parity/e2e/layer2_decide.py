#!/usr/bin/env python3
"""Layer 2, decision part (PLAN.md 7.5): the Python guard's ``check()`` with
the real ``os.path.realpath``, ``os.lstat``, ``pwd`` and euid against the Rust
guard's ``--decide`` on the same real trees, inside the distribution
containers (Ubuntu 24.04 with Python 3.12, Debian 13 with Python 3.13).

Runs as root inside ``parity/e2e/Dockerfile`` (target ``layer2``) with the
Python guard mounted at ``--guard`` and the binary at ``--binary``. For every
path-taking shape of the allowlist under the fixture policies (and the
``test_scp_against_a_real_tree`` tree with its own policy) it materialises
each relevant state of the paths the command names, as real files:

- the target file: absent, regular (owned by root, postgres, the root's
  owner or nobody), a hard link, a symlink inside or outside the root, a
  dangling link, a loop, a fifo, a socket, a device, a directory;
- a directory the guard requires private: ``0700`` root's, ``0750``,
  ``0777``, someone else's, a symlink to a private directory, absent, a file;
- a parent component: a directory, a symlink inside the root, outside it,
  to ``../..``, to the root by its absolute path, a loop, a dangling link, a
  file (``ENOTDIR`` below);

plus seeded random trees under the roots with random commands into them,
and a few commands run as ``nobody`` (both guards then run without root, so
``EACCES`` and the euid checks are real).

The rule is PLAN.md 4/4.4: when Rust allows, Python allows with an
identical decision; when Rust refuses, Python refuses with the same reason,
except for the stricter realpath refusals of PLAN.md 4.2 (``path not
checkable: <path>: <strerror>`` for a loop, which an independent resolver
must confirm, more than 40 links, ``ENAMETOOLONG``, ``EACCES`` and a link
target that is not UTF-8) and for a ``check()`` crash of Python, which Rust
refuses as ``unparsable command: <Python's error>``.

Usage (``parity/e2e/run-layer2.sh`` does this)::

    python3 -I layer2_decide.py --guard /e2e/guard.py --binary /usr/local/bin/echoport-command-guard \
        --policies /e2e/policies [--random 200] [--seed 1]

Exits 1 on any other difference. Stdlib only.
"""

from __future__ import annotations

import argparse
import ast
import errno
import importlib.util
import json
import os
import pwd
import random
import re
import socket
import stat
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any, Callable

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from layer2_realpath import MAX_LINKS, reset  # noqa: E402

GTS = "/var/lib/gotosocial"
SITE = "/home/marina/site"
DATA = "/home/villakunterbunt/data"
MEDIA_PARENT = "/home/python-podcast/site"
MEDIA = f"{MEDIA_PARENT}/private_media"
TREE = "/srv/echoport-l2-tree/site"
OUTSIDE = "/srv/echoport-l2-outside"
ROOT_OWNERS = {GTS: "gotosocial", SITE: "marina", DATA: "villakunterbunt", MEDIA: "python-podcast", TREE: "marina"}
PRIVATE_MEDIA_TMP = "/tmp/echoport-pp-private-media.L2abcd12"
SNAPSHOT_TMP = "/var/tmp/gotosocial-echoport.L2abc1"
DJANGO_TMP = "/var/tmp/django-chat-db-restore.L2abcd12"
# The file names the templates use; link targets hold all of them.
NAMES = ["sqlite.db", "sqlite.db-wal", "sqlite.db-shm", "sqlite.db.tmp", "a", "a.tmp", "b", "x", "f",
         "db.sqlite3", "db.sqlite3.tmp", "plain.tmp", "new.tmp"]
# PLAN.md 4.2: the realpath errors Rust refuses and Python resolves past.
P3_STRERRORS = {"Too many levels of symbolic links", "File name too long", "Permission denied",
                "link target is not valid UTF-8"}
NOT_CHECKABLE = re.compile(r"^path not checkable: (.*): ([^:]*)$")


def uid(user: str) -> int:
    return pwd.getpwnam(user).pw_uid


def load_guard(path: str) -> Any:
    spec = importlib.util.spec_from_file_location("echoport_remote_command_guard_l2", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


# --- the two guards ----------------------------------------------------------


def encode_redirect(redirect: Any) -> dict[str, Any] | None:
    if redirect is None:
        return None
    return {"directory": redirect.directory, "name": redirect.name, "owners": list(redirect.owners)}


def python_decide(guard: Any, policy_path: str, command: str) -> dict[str, Any]:
    """main()'s view of check(): the decision, the refusal (Refused or an
    OSError), or a crash (no exec, a traceback)."""
    policy = guard.load_policy(policy_path)
    try:
        decision = guard.check(command, policy)
    except (guard.Refused, OSError) as exc:
        return {"verdict": "refused", "reason": str(exc)}
    except Exception as exc:  # noqa: BLE001 - the Python guard crashes
        return {"verdict": "error", "error_type": type(exc).__name__, "message": str(exc)}
    mutation = decision.mutation
    return {"verdict": "allowed", "argv": list(decision.argv), "umask": decision.umask,
            "stdin": encode_redirect(decision.stdin), "stdout": encode_redirect(decision.stdout),
            "mutation": None if mutation is None else {
                "op": mutation.op, "paths": list(mutation.paths), "mode": mutation.mode, "owner": mutation.owner,
                "recursive": mutation.recursive, "private": mutation.private, "replace": mutation.replace,
                "user": mutation.user}}


def rust_decide(binary: str, policy_path: str, command: str, user: str | None = None) -> dict[str, Any]:
    argv = [binary, "--decide", policy_path]
    if user is not None:
        argv = ["runuser", "-u", user, "--", *argv]
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "SSH_ORIGINAL_COMMAND": command,
           "SSH_CLIENT": "192.0.2.10 50000 22"}
    result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=30)
    if result.returncode not in (0, 1) or result.stderr:
        raise RuntimeError(f"--decide {command!r}: exit {result.returncode}, stderr {result.stderr!r}")
    return json.loads(result.stdout)


PY_AS_USER = r"""
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("g", sys.argv[1])
guard = importlib.util.module_from_spec(spec)
sys.modules["g"] = guard
spec.loader.exec_module(guard)
sys.path.insert(0, sys.argv[2])
from layer2_decide import python_decide
for line in sys.stdin:
    request = json.loads(line)
    print(json.dumps(python_decide(guard, request["policy"], request["command"])), flush=True)
"""


def python_decide_as(user: str, guard_path: str, policy_path: str, command: str) -> dict[str, Any]:
    here = os.path.dirname(os.path.abspath(__file__))
    result = subprocess.run(["runuser", "-u", user, "--", sys.executable, "-I", "-c", PY_AS_USER, guard_path, here],
                            input=json.dumps({"policy": policy_path, "command": command}) + "\n",
                            capture_output=True, text=True, check=True, timeout=30)
    return json.loads(result.stdout)


# --- comparison --------------------------------------------------------------


def realpath_error(path: str) -> str | None:
    """The error a component-by-component resolution of ``path`` meets, as
    the stricter Rust resolver reports it (PLAN.md 4.2), found independently
    of both guards: an ``lstat`` error other than ``ENOENT``/``ENOTDIR``, a
    ``readlink`` error, a link target that is not UTF-8, or more than 40
    symlink traversals (a loop never ends; every traversal counts, as in the
    kernel, without Python's ``seen`` map), whichever comes first.
    ``None`` when there is none."""
    stack = path.split("/")[::-1]
    resolved = "/"
    links = 0
    while stack:
        name = stack.pop()
        if not name or name == ".":
            continue
        if name == "..":
            resolved = resolved[: resolved.rindex("/")] or "/"
            continue
        newpath = resolved + name if resolved == "/" else resolved + "/" + name
        try:
            is_link = stat.S_ISLNK(os.lstat(newpath).st_mode)
        except OSError as exc:
            if exc.errno in (errno.ENOENT, errno.ENOTDIR):
                resolved = newpath
                continue
            return exc.strerror
        if not is_link:
            resolved = newpath
            continue
        links += 1
        if links > MAX_LINKS:
            return "Too many levels of symbolic links"
        try:
            raw = os.readlink(os.fsencode(newpath))
        except OSError as exc:
            return exc.strerror
        try:
            target = raw.decode("utf-8")
        except UnicodeDecodeError:
            return "link target is not valid UTF-8"
        if target.startswith("/"):
            resolved = "/"
        stack.extend(target.split("/")[::-1])
    return None


def realpath_error_as(user: str | None, path: str) -> str | None:
    if user is None:
        return realpath_error(path)
    here = os.path.dirname(os.path.abspath(__file__))
    code = ("import json, sys; sys.path.insert(0, sys.argv[1]); from layer2_decide import realpath_error; "
            "print(json.dumps(realpath_error(sys.argv[2])))")
    result = subprocess.run(["runuser", "-u", user, "--", sys.executable, "-I", "-c", code, here, path],
                            capture_output=True, text=True, check=True, timeout=30)
    return json.loads(result.stdout)


@dataclass
class Report:
    allowed_equal: int = 0
    refused_equal: int = 0
    python_error: int = 0
    p3_realpath: dict[str, int] = field(default_factory=dict)
    # shape -> [allowed, refused] by the Rust guard
    shapes: dict[str, list[int]] = field(default_factory=dict)
    failures: list[str] = field(default_factory=list)

    def compare(self, label: str, command: str, python: dict[str, Any], rust: dict[str, Any],
                user: str | None = None) -> None:
        verdict = rust.get("verdict")
        counts = self.shapes.setdefault(label.split(" ", 1)[0], [0, 0])
        counts[0 if verdict == "allowed" else 1] += 1
        if verdict == "allowed":
            if python == rust:
                self.allowed_equal += 1
                return
        elif verdict == "refused":
            reason = rust["reason"]
            if python.get("verdict") == "refused" and python.get("reason") == reason:
                self.refused_equal += 1
                return
            if python.get("verdict") == "error" and reason == f"unparsable command: {python.get('message')}":
                self.python_error += 1
                return
            match = NOT_CHECKABLE.match(reason)
            if match and match.group(2) in P3_STRERRORS:
                # Only when the error is real: an independent resolution of
                # the path, as the same user, must meet it (a loop: without
                # Python's `seen` map, and more than 40 links).
                path = ast.literal_eval(match.group(1))
                if realpath_error_as(user, path) == match.group(2):
                    self.p3_realpath[match.group(2)] = self.p3_realpath.get(match.group(2), 0) + 1
                    return
        self.failures.append(f"{label}: {command!r}: Rust {rust}, Python {python}")


# --- states ------------------------------------------------------------------


def chown(path: str, user: str) -> None:
    entry = pwd.getpwnam(user)
    os.lchown(path, entry.pw_uid, entry.pw_gid)


def write_file(path: str, user: str = "root", mode: int = 0o600) -> None:
    with open(path, "w") as handle:
        handle.write("x")
    os.chmod(path, mode)
    chown(path, user)


def make_outside() -> None:
    reset(OUTSIDE)
    os.makedirs(f"{OUTSIDE}/private", mode=0o700)
    for name in NAMES:
        write_file(f"{OUTSIDE}/{name}")


def make_roots() -> None:
    for root, user in ROOT_OWNERS.items():
        reset(root)
        os.makedirs(root, mode=0o755)
        chown(root, user)
        os.makedirs(f"{root}/inner")
        chown(f"{root}/inner", user)
        for name in NAMES:
            write_file(f"{root}/inner/{name}", user)
    os.makedirs("/etc/gotosocial", exist_ok=True)
    reset("/etc/gotosocial/config.yaml")
    write_file("/etc/gotosocial/config.yaml", "root", 0o644)


# A file state: how to make the path (the parent exists).
FILE_STATES: dict[str, Callable[[str, str], None]] = {
    "absent": lambda path, owner: None,
    "reg-root": lambda path, owner: write_file(path, "root"),
    "reg-postgres": lambda path, owner: write_file(path, "postgres"),
    "reg-owner": lambda path, owner: write_file(path, owner),
    "reg-nobody": lambda path, owner: write_file(path, "nobody"),
    "hardlink": lambda path, owner: (write_file(f"{path}.orig", owner), os.link(f"{path}.orig", path)),
    "symlink-in": lambda path, owner: os.symlink("x", path),
    "symlink-out": lambda path, owner: os.symlink(f"{OUTSIDE}/x", path),
    "dangling": lambda path, owner: os.symlink("/nonexistent/x", path),
    "loop": lambda path, owner: os.symlink(os.path.basename(path), path),
    "fifo": lambda path, owner: os.mkfifo(path),
    "socket": lambda path, owner: socket.socket(socket.AF_UNIX).bind(path),
    "device": lambda path, owner: os.mknod(path, 0o600 | stat.S_IFCHR, os.makedev(1, 3)),
    "dir": lambda path, owner: os.mkdir(path),
}

# A directory the guard requires private (a fresh mktemp -d of root).
DIR_STATES: dict[str, Callable[[str], None]] = {
    "private": lambda path: os.mkdir(path, 0o700),
    "mode-0750": lambda path: (os.mkdir(path), os.chmod(path, 0o750)),
    "mode-0777": lambda path: (os.mkdir(path), os.chmod(path, 0o777)),
    "foreign": lambda path: (os.mkdir(path, 0o700), chown(path, "nobody")),
    "service-user": lambda path: (os.mkdir(path, 0o700), chown(path, "gotosocial")),
    "symlink": lambda path: os.symlink(f"{OUTSIDE}/private", path),
    "absent": lambda path: None,
    "file": lambda path: write_file(path),
}

# A parent component below a root.
PARENT_STATES: dict[str, Callable[[str, str], None]] = {
    "dir": lambda path, root: os.mkdir(path),
    "link-in": lambda path, root: os.symlink("inner", path),
    "link-out": lambda path, root: os.symlink(OUTSIDE, path),
    "link-dotdot": lambda path, root: os.symlink("../..", path),
    "link-root": lambda path, root: os.symlink(f"{root}/inner", path),
    "link-dotdot-in": lambda path, root: os.symlink(f"{root}/inner/../inner", path),
    "loop": lambda path, root: os.symlink("sub", path),
    "dangling": lambda path, root: os.symlink("missing/deeper", path),
    "file": lambda path, root: write_file(path),
    "absent": lambda path, root: None,
}


@dataclass
class Template:
    """A command with up to one slot of each kind; `{P}` is `<root>/sub`."""

    label: str
    policy: str
    command: str
    root: str | None = None
    files: list[str] = field(default_factory=list)  # paths (with {P}) that get FILE_STATES
    default_file: str = "absent"
    private_dir: str | None = None
    default_dir: str = "private"


def templates() -> list[Template]:
    dump = "/tmp/echoport_pp_dump_L2.dump"
    restore = "/tmp/echoport_pp_restore_L2.dump"
    archive = f"{PRIVATE_MEDIA_TMP}/private_media.tar.gz"
    sender = "rsync --server --sender -logDtpre.iLsfxCIvu --safe-links ."
    receiver = "rsync --server -logtpre.iLsfxCIvu"
    out = [
        Template("scp-f-dump", "production", f"scp -f {dump}", files=[dump], default_file="reg-postgres"),
        Template("scp-f-archive", "production", f"scp -f {archive}", files=[archive], default_file="reg-root",
                 private_dir=PRIVATE_MEDIA_TMP),
        Template("scp-f-read-file", "production", "scp -f /etc/gotosocial/config.yaml",
                 files=["/etc/gotosocial/config.yaml"], default_file="reg-root"),
        Template("scp-t-restore", "production", f"scp -t {restore}", files=[restore]),
        Template("tar", "production",
                 f"umask 077 && tar -C {MEDIA_PARENT} -czf {archive} -- private_media",
                 files=[archive], private_dir=PRIVATE_MEDIA_TMP),
        Template("chown-snapshot", "production", f"chown gotosocial:gotosocial {SNAPSHOT_TMP}",
                 private_dir=SNAPSHOT_TMP),
        Template("cat-snapshot", "production", f"cat {SNAPSHOT_TMP}/sqlite.db"),
        Template("sha256sum", "staging", f"sha256sum {DJANGO_TMP}/db.dump", files=[f"{DJANGO_TMP}/db.dump"],
                 default_file="reg-root", private_dir=DJANGO_TMP),
        Template("cat-to-file", "staging", f"umask 077 && cat > {DJANGO_TMP}/db.dump"),
        Template("pg_restore-stdin", "staging",
                 "runuser -u postgres -- pg_restore --no-owner --no-privileges --exit-on-error "
                 f"--dbname=django_chat_restore_7 < {DJANGO_TMP}/db.dump"),
    ]
    for policy, root in (("production", GTS), ("staging", SITE), ("staging", DATA)):
        p = f"{root}/sub"
        out += [
            Template("scp-f-root", policy, f"scp -f {p}/sqlite.db", root, [f"{p}/sqlite.db"], "reg-owner"),
            Template("scp-t-root", policy, f"scp -t {p}/sqlite.db.tmp", root, [f"{p}/sqlite.db.tmp"]),
            Template("rsync-sender", policy, f"{sender} {p}/", root),
            Template("rsync-receiver", policy, f"{receiver} . {p}/", root),
            Template("rsync-delete", policy, f"{receiver} --delete . {p}/", root),
            Template("rm-wal-shm", policy, f"rm -f {p}/sqlite.db-wal {p}/sqlite.db-shm", root,
                     [f"{p}/sqlite.db-wal", f"{p}/sqlite.db-shm"], "reg-owner"),
            Template("chown-R", policy, f"chown -R {ROOT_OWNERS[root]}:{ROOT_OWNERS[root]} {p}", root),
            Template("chown", policy, f"chown {ROOT_OWNERS[root]}:{ROOT_OWNERS[root]} {p}/f", root, [f"{p}/f"]),
            Template("readlink", policy, f"readlink -f {p}/x", root, [f"{p}/x"]),
            Template("test-e", policy, f"test -e {p}/x", root, [f"{p}/x"]),
            Template("test-d", policy, f"test -d {p}", root),
            Template("mv-into-place", policy, f"mv {p}/a.tmp {p}/a", root, [f"{p}/a"], "reg-owner"),
            Template("mv-rename", policy, f"mv {p}/a {p}/b", root, [f"{p}/b"]),
            Template("mkdir", policy, f"mkdir -p {p}/new", root, [f"{p}/new"]),
            Template("chmod", policy, f"chmod 0600 {p}/f", root, [f"{p}/f"], "reg-owner"),
        ]
    out.append(Template("mv-across-roots", "staging", f"mv {SITE}/sub/a {DATA}/a", SITE))
    return out


def reset_world() -> None:
    for path in (PRIVATE_MEDIA_TMP, SNAPSHOT_TMP, DJANGO_TMP, "/tmp/echoport_pp_dump_L2.dump",
                 "/tmp/echoport_pp_restore_L2.dump"):
        reset(path)
    make_roots()


def materialise(template: Template, parent: str, file_state: str, dir_state: str) -> None:
    reset_world()
    if template.private_dir is not None:
        DIR_STATES[dir_state](template.private_dir)
    if template.root is not None:
        PARENT_STATES[parent](f"{template.root}/sub", template.root)
        if parent == "dir":
            for name in NAMES:
                write_file(f"{template.root}/sub/{name}", ROOT_OWNERS[template.root])
    owner = ROOT_OWNERS.get(template.root or "", "postgres")
    for path in template.files:
        directory = os.path.dirname(path)
        if not os.path.isdir(directory) or os.path.realpath(directory) != directory:
            continue  # through a link or below a non-directory: leave the target as it is
        reset(path)
        FILE_STATES[file_state](path, owner)


def run_templates(guard: Any, args: argparse.Namespace, report: Report) -> None:
    label_python = f"Python {sys.version.split()[0]}"
    for template in templates():
        policy = os.path.join(args.policies, f"{template.policy}.json")
        variants: list[tuple[str, str, str]] = [("dir", template.default_file, template.default_dir)]
        if template.root is not None:
            variants += [(parent, template.default_file, template.default_dir) for parent in PARENT_STATES]
        if template.files:
            variants += [("dir", state, template.default_dir) for state in FILE_STATES]
        if template.private_dir is not None:
            variants += [("dir", template.default_file, state) for state in DIR_STATES]
        for parent, file_state, dir_state in dict.fromkeys(variants):
            materialise(template, parent, file_state, dir_state)
            command = template.command
            label = f"{template.label} parent={parent} file={file_state} dir={dir_state} ({label_python})"
            report.compare(label, command, python_decide(guard, policy, command),
                           rust_decide(args.binary, policy, command))


def run_real_tree(guard: Any, args: argparse.Namespace, report: Report) -> None:
    """``GuardRefusals.test_scp_against_a_real_tree`` on a real tree."""
    base = os.path.dirname(TREE)
    reset(base)
    os.makedirs(TREE)
    write_file(f"{base}/outside.txt")
    write_file(f"{TREE}/plain.tmp")
    os.symlink(f"{base}/outside.txt", f"{TREE}/link.tmp")
    os.symlink(base, f"{TREE}/dirlink")
    os.link(f"{base}/outside.txt", f"{TREE}/hard.tmp")
    os.mkfifo(f"{TREE}/fifo.tmp")
    policy = os.path.join(args.scratch, "tree.json")
    with open(policy, "w") as handle:
        json.dump({"path_roots": [{"path": TREE, "owner": "marina:marina"}]}, handle)
    expected = {"plain.tmp": "allowed", "new.tmp": "allowed", "link.tmp": "refused", "hard.tmp": "refused",
                "fifo.tmp": "refused", "dirlink/outside.tmp": "refused"}
    for name, verdict in expected.items():
        command = f"scp -t {TREE}/{name}"
        python = python_decide(guard, policy, command)
        rust = rust_decide(args.binary, policy, command)
        report.compare(f"real-tree {name}", command, python, rust)
        if rust["verdict"] != verdict:
            report.failures.append(f"real-tree {name}: expected {verdict}, Rust {rust}")
    reset(base)


def run_as_nobody(guard: Any, args: argparse.Namespace, report: Report) -> None:
    """A few shapes without root: real EACCES below a closed directory, and
    the euid in the private-directory checks."""
    reset_world()
    os.makedirs(f"{SITE}/closed/inner/x", exist_ok=True)
    os.chmod(f"{SITE}/closed", 0o700)
    os.makedirs(PRIVATE_MEDIA_TMP, mode=0o700)
    chown(PRIVATE_MEDIA_TMP, "nobody")
    policy_staging = os.path.join(args.policies, "staging.json")
    policy_production = os.path.join(args.policies, "production.json")
    for policy, command in (
        (policy_staging, f"test -e {SITE}/closed/inner/x"),
        (policy_staging, f"scp -f {SITE}/closed/inner/x/f"),
        (policy_staging, f"mv {SITE}/closed/a {SITE}/closed/b"),
        (policy_staging, f"scp -t {SITE}/closed/f.tmp"),
        (policy_staging, f"mkdir -p {SITE}/inner/new"),
        (policy_production, f"scp -f {PRIVATE_MEDIA_TMP}/private_media.tar.gz"),
        (policy_production, f"umask 077 && tar -C {MEDIA_PARENT} -czf {PRIVATE_MEDIA_TMP}/private_media.tar.gz "
                            "-- private_media"),
    ):
        python = python_decide_as("nobody", args.guard, policy, command)
        rust = rust_decide(args.binary, policy, command, user="nobody")
        report.compare("as-nobody", command, python, rust, user="nobody")


def random_tree(rng: random.Random, root: str, index: int) -> str:
    """A random tree at <root>/rt<index>: directories, files of several
    owners, links with relative or absolute targets inside and outside."""
    base = f"{root}/rt{index}"
    reset(base)
    os.makedirs(base)
    chown(base, ROOT_OWNERS[root])
    level = [base]
    made = {base}
    for _ in range(3):
        level = [f"{parent}/{name}" for parent in level for name in ("a", "b", "c")]
        for path in level:
            if os.path.dirname(path) not in made:
                continue
            roll = rng.random()
            if roll < 0.25:
                continue
            if roll < 0.5:
                os.mkdir(path)
                made.add(path)
            elif roll < 0.65:
                write_file(path, rng.choice([ROOT_OWNERS[root], "root", "postgres"]))
            elif roll < 0.7:
                os.mkfifo(path)
            else:
                parts = [rng.choice(["a", "b", "c", "..", ".", "", "inner"]) for _ in range(rng.randrange(0, 5))]
                target = "/".join(parts) or "."
                roll = rng.random()
                if roll < 0.2:
                    target = f"{base}/{target}"
                elif roll < 0.3:
                    target = f"{OUTSIDE}/{target}"
                os.symlink(target, path)
    return base


RANDOM_SHAPES = [
    "scp -f {p}", "scp -t {p}.tmp", "test -e {p}", "readlink -f {p}", "chmod 0700 {p}", "mkdir -p {p}",
    "rsync --server -logtpre.iLsfxCIvu . {p}/", "rsync --server --sender -logDtpre.iLsfxCIvu --safe-links . {p}/",
    "mv {p} {q}", "mv {p}.tmp {p}", "rm -f {p}-wal {p}-shm", "chown -R {owner}:{owner} {p}",
]


def run_random(guard: Any, args: argparse.Namespace, report: Report) -> None:
    rng = random.Random(args.seed)
    make_outside()
    reset_world()
    for index in range(args.random):
        policy_name, root = rng.choice([("production", GTS), ("staging", SITE), ("staging", DATA)])
        policy = os.path.join(args.policies, f"{policy_name}.json")
        base = random_tree(rng, root, index)
        for _ in range(5):
            def probe() -> str:
                return "/".join([base, *(rng.choice("abc") for _ in range(rng.randrange(0, 4)))])
            command = rng.choice(RANDOM_SHAPES).format(p=probe(), q=probe(), owner=ROOT_OWNERS[root])
            report.compare(f"random {index}", command, python_decide(guard, policy, command),
                           rust_decide(args.binary, policy, command))
        reset(base)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--guard", required=True, help="the Python guard (echoport-remote-command-guard.py)")
    parser.add_argument("--binary", required=True, help="the Rust guard binary")
    parser.add_argument("--policies", required=True, help="directory with production.json and staging.json")
    parser.add_argument("--scratch", default="/tmp", help="where to write the real-tree policy")
    parser.add_argument("--random", type=int, default=200, help="random trees (default 200)")
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print("layer2_decide.py runs as root inside the e2e container", file=sys.stderr)
        return 2
    guard = load_guard(args.guard)
    report = Report()
    make_outside()
    run_templates(guard, args, report)
    run_real_tree(guard, args, report)
    run_as_nobody(guard, args, report)
    run_random(guard, args, report)
    summary = {"python": sys.version.split()[0], "allowed_equal": report.allowed_equal,
               "refused_equal": report.refused_equal, "python_error": report.python_error,
               "p3_realpath": report.p3_realpath, "shapes": report.shapes, "failures": len(report.failures)}
    print(json.dumps(summary))
    for failure in report.failures[:50]:
        print("FAIL", failure)
    return 1 if report.failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
