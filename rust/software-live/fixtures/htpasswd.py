#!/usr/bin/env python3
"""Record fixtures/htpasswd.json with the real ``htpasswd -vi`` (PLAN.md 4.2 item 1).

The Python endpoint verifies every request with ``htpasswd -vi <file> <user>``
(password on stdin, ``software_live.py:732-739``); the Rust endpoint verifies
in process (``src/htpasswd.rs``). This script creates bcrypt entries with
``htpasswd -niB`` (the role's command, default cost) and the other formats
``htpasswd`` knows, builds htpasswd files around them (prefix swaps,
non-canonical characters, long and broken lines, duplicates, NUL bytes) and
records the exit status of ``htpasswd -vi`` for every case in a
``debian:13`` and an ``ubuntu:24.04`` container (the hosts' distributions,
apache2-utils from their archives). Both must agree.

It needs Docker and network access for the images and packages, so it is not
part of the stdlib fixture check (``generate.py``); bcrypt salts are random,
so a new run gives new hashes with the same verdicts. Run it from a worktree::

    python3 -I rust/software-live/fixtures/htpasswd.py

Every password here is a test value, never a credential.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

FIXTURES_DIR = Path(__file__).resolve().parent
OUTPUT = FIXTURES_DIR / "htpasswd.json"
IMAGES = ["debian:13", "ubuntu:24.04"]
CONTAINER_PREFIX = "software-live-s4-htpasswd"

# Runs inside the container (python3 from the distribution): creates entries
# or verifies cases, reading its job as JSON on stdin.
INNER = r"""
import json, os, subprocess, sys, tempfile
job = json.load(sys.stdin)
out = {"versions": {}}
for package in ("apache2-utils", "libaprutil1t64", "libapr1t64", "libcrypt1"):
    result = subprocess.run(["dpkg-query", "-W", "-f", "${Version}", package],
                            capture_output=True, text=True)
    out["versions"][package] = result.stdout if result.returncode == 0 else None
out["arch"] = subprocess.run(["dpkg", "--print-architecture"], capture_output=True,
                             text=True).stdout.strip()
if job["mode"] == "create":
    lines = {}
    for name, user, password_hex, flags in job["entries"]:
        result = subprocess.run(["htpasswd", "-ni", *flags, user],
                                input=bytes.fromhex(password_hex), capture_output=True)
        assert result.returncode == 0, (name, result.stderr)
        lines[name] = result.stdout.decode("ascii").strip()
    out["lines"] = lines
else:
    directory = tempfile.mkdtemp()
    paths = {}
    for name, text in job["files"].items():
        path = os.path.join(directory, name)
        with open(path, "wb") as stream:
            stream.write(text.encode("latin-1"))
        paths[name] = path
    paths["missing"] = os.path.join(directory, "missing")
    exits = {}
    for case in job["cases"]:
        user = bytes.fromhex(case["user_hex"])
        result = subprocess.run([b"htpasswd", b"-vi", paths[case["file"]].encode(), user],
                                input=bytes.fromhex(case["password_hex"]),
                                capture_output=True, timeout=60)
        exits[case["id"]] = result.returncode
    out["exits"] = exits
json.dump(out, sys.stdout)
"""

CORRECT = "correct horse battery staple"
UTF8 = "pässwörd-☃"

# (name, user, password, htpasswd flags after -ni)
ENTRIES: list[tuple[str, str, bytes, list[str]]] = [
    ("nyxmon", "nyxmon", CORRECT.encode(), ["-B"]),
    ("empty", "empty", b"", ["-B"]),
    ("long", "long", b"a" * 72 + b"TAIL", ["-B"]),
    ("max", "max", b"b" * 255, ["-B"]),
    ("utf8", "utf8", UTF8.encode(), ["-B"]),
    ("cr", "cr", b"pw\r", ["-B"]),
    ("nul", "nul", b"a", ["-B"]),
    ("colon", "colon", b"pa:ss", ["-B"]),
    ("cost4", "cost4", b"cost-four", ["-B", "-C", "4"]),
    ("cost12", "cost12", b"cost-twelve", ["-B", "-C", "12"]),
    ("md5", "md5", b"md5-password", ["-m"]),
    ("sha", "sha", b"sha-password", ["-s"]),
    ("crypt", "crypt", b"cryptpw", ["-d"]),
    ("dupbad1", "dupbad", b"first", ["-B"]),
    ("dupbad2", "dupbad", b"second", ["-B"]),
]

BCRYPT64 = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def bump(char: str) -> str:
    """The next character of bcrypt's alphabet (a non-canonical last character)."""
    return BCRYPT64[(BCRYPT64.index(char) + 1) % 64]


def docker(*args: str, stdin: bytes | None = None) -> bytes:
    result = subprocess.run(["docker", *args], input=stdin, capture_output=True, check=False)
    if result.returncode != 0:
        raise SystemExit(f"docker {args[0]} failed: {result.stderr.decode(errors='replace')}")
    return result.stdout


class Container:
    def __init__(self, image: str) -> None:
        self.name = f"{CONTAINER_PREFIX}-{image.replace(':', '').replace('.', '')}"
        subprocess.run(["docker", "rm", "-f", self.name], capture_output=True, check=False)
        docker("run", "-d", "--name", self.name, image, "sleep", "1800")
        docker("exec", "-e", "DEBIAN_FRONTEND=noninteractive", self.name, "sh", "-c",
               "apt-get update -qq && apt-get install -y -qq --no-install-recommends "
               "apache2-utils python3 >/dev/null")

    def run(self, job: dict[str, Any]) -> dict[str, Any]:
        output = docker("exec", "-i", self.name, "python3", "-c", INNER,
                        stdin=json.dumps(job).encode())
        return json.loads(output)

    def close(self) -> None:
        subprocess.run(["docker", "rm", "-f", self.name], capture_output=True, check=False)


def build(lines: dict[str, str]) -> tuple[dict[str, str], list[dict[str, Any]]]:
    hashes = {name: line.split(":", 1)[1] for name, line in lines.items()}
    ny = hashes["nyxmon"]
    utf8 = hashes["utf8"]
    swapped = {
        "nyxmon2a": "$2a$" + ny[4:], "nyxmon2b": "$2b$" + ny[4:], "nyxmon2x": "$2x$" + ny[4:],
        "utf82a": "$2a$" + utf8[4:], "utf82b": "$2b$" + utf8[4:],
        "saltnc": ny[:28] + bump(ny[28]) + ny[29:],
        "hashnc": ny[:-1] + bump(ny[-1]),
        "garbage": ny + "x",
        "short": ny[:-1],
        "cost31": ny[:4] + "31" + ny[6:],
        "cost03": ny[:4] + "03" + ny[6:],
        "upper": ny.upper(),
    }
    main = [
        "# Test-only htpasswd file of the software-live fixtures; never a credential.",
        "",
        "   \t",
        *[f"{entry[1]}:{hashes[entry[0]]}" for entry in ENTRIES if not entry[0].startswith("dupbad")],
        *[f"{name}:{value}" for name, value in swapped.items()],
        f" \tspaced:{ny}",
        f"\x0b\x0cvtff:{ny}",
        f":{ny}",
        f"dup:{ny}",
        f"dup:{ny}",
        f"dupbad:{hashes['dupbad1']}",
        f"dupbad:{hashes['dupbad2']}",
        "emptyhash:",
        f"#commented:{ny}",
        f"crlf:{ny}\r",
        f"tabhash:{ny}\tx",
    ]
    files = {
        "main": "\n".join(main) + "\n",
        "nocolon_after": f"nyxmon:{ny}\njunk\n",
        "nocolon_before": f"junk\nnyxmon:{ny}\n",
        "long_comment": "#" + "c" * 300 + f"\nnyxmon:{ny}\n",
        "long_other": "other:" + "h" * 300 + f"\nnyxmon:{ny}\n",
        "line255": "u" * 194 + f":{ny}\n",
        "line256": "u" * 195 + f":{ny}\n",
        "nul_line": f"nyxmon:{ny}\nn\x00x:junk\n",
        "nul_in_hash": f"nyxmon:{ny}\x00junk\n",
        "no_final_newline": f"nyxmon:{ny}",
        "empty_file": "",
        "only_comments": "# nothing\n\n",
        "emptyhash_file": f"emptyhash:\nnyxmon:{ny}\n",
        "cr_lines": f"\r\nnyxmon:{ny}\r\n",
    }
    a72 = b"a" * 72
    cases: list[tuple[str, str, bytes, bytes]] = [
        ("correct", "main", b"nyxmon", CORRECT.encode()),
        ("wrong", "main", b"nyxmon", b"wrong"),
        ("case_differs", "main", b"nyxmon", b"Correct horse battery staple"),
        ("prefix_only", "main", b"nyxmon", CORRECT.encode()[:-1]),
        ("trailing_cr", "main", b"nyxmon", CORRECT.encode() + b"\r"),
        ("trailing_lf", "main", b"nyxmon", CORRECT.encode() + b"\n"),
        ("trailing_crlf", "main", b"nyxmon", CORRECT.encode() + b"\r\n"),
        ("trailing_two_lf", "main", b"nyxmon", CORRECT.encode() + b"\n\n"),
        ("leading_lf", "main", b"nyxmon", b"\n" + CORRECT.encode()),
        ("nul_tail", "main", b"nyxmon", CORRECT.encode() + b"\x00garbage"),
        ("empty_correct", "main", b"empty", b""),
        ("empty_nul_tail", "main", b"empty", b"\x00x"),
        ("empty_lf", "main", b"empty", b"\n"),
        ("empty_wrong", "main", b"empty", b"x"),
        ("long_72", "main", b"long", a72),
        ("long_created", "main", b"long", a72 + b"TAIL"),
        ("long_other_tail", "main", b"long", a72 + b"x"),
        ("long_71", "main", b"long", b"a" * 71),
        ("long_71_b", "main", b"long", b"a" * 71 + b"b"),
        ("max_255", "main", b"max", b"b" * 255),
        ("max_256", "main", b"max", b"b" * 256),
        ("max_254_lf", "main", b"max", b"b" * 254 + b"\n"),
        ("max_255_lf", "main", b"max", b"b" * 255 + b"\n"),
        ("max_72", "main", b"max", b"b" * 72),
        ("long_password_short_hash", "main", b"nyxmon", CORRECT.encode() + b"\x00" + b"z" * 250),
        ("utf8_correct", "main", b"utf8", UTF8.encode()),
        ("utf8_nfd", "main", b"utf8", "pässwörd-☃".encode()),
        ("utf8_as_latin1", "main", b"utf8", UTF8[:8].encode("latin-1") + "-☃".encode()),
        ("cr_correct", "main", b"cr", b"pw\r"),
        ("cr_without", "main", b"cr", b"pw"),
        ("cr_crlf", "main", b"cr", b"pw\r\n"),
        ("cr_cr_crlf", "main", b"cr", b"pw\r\r\n"),
        ("nul_correct", "main", b"nul", b"a"),
        ("nul_after", "main", b"nul", b"a\x00b"),
        ("nul_before", "main", b"nul", b"\x00a"),
        ("colon_password", "main", b"colon", b"pa:ss"),
        ("cost4", "main", b"cost4", b"cost-four"),
        ("cost12", "main", b"cost12", b"cost-twelve"),
        ("md5_correct", "main", b"md5", b"md5-password"),
        ("md5_wrong", "main", b"md5", b"wrong"),
        ("sha_correct", "main", b"sha", b"sha-password"),
        ("sha_wrong", "main", b"sha", b"wrong"),
        ("crypt_correct", "main", b"crypt", b"cryptpw"),
        ("crypt_wrong", "main", b"crypt", b"wrong"),
        ("prefix_2a", "main", b"nyxmon2a", CORRECT.encode()),
        ("prefix_2a_wrong", "main", b"nyxmon2a", b"wrong"),
        ("prefix_2b", "main", b"nyxmon2b", CORRECT.encode()),
        ("prefix_2b_wrong", "main", b"nyxmon2b", b"wrong"),
        ("prefix_2x", "main", b"nyxmon2x", CORRECT.encode()),
        ("prefix_2a_utf8", "main", b"utf82a", UTF8.encode()),
        ("prefix_2b_utf8", "main", b"utf82b", UTF8.encode()),
        ("salt_non_canonical", "main", b"saltnc", CORRECT.encode()),
        ("hash_non_canonical", "main", b"hashnc", CORRECT.encode()),
        ("hash_trailing_text", "main", b"garbage", CORRECT.encode()),
        ("hash_short", "main", b"short", CORRECT.encode()),
        ("cost_31_text", "main", b"cost31", CORRECT.encode()),
        ("cost_03_text", "main", b"cost03", CORRECT.encode()),
        ("hash_upper", "main", b"upper", CORRECT.encode()),
        ("leading_whitespace_entry", "main", b"spaced", CORRECT.encode()),
        ("vt_ff_entry", "main", b"vtff", CORRECT.encode()),
        ("empty_user_entry", "main", b"", CORRECT.encode()),
        ("duplicates_equal", "main", b"dup", CORRECT.encode()),
        ("duplicates_differ_first", "main", b"dupbad", b"first"),
        ("duplicates_differ_second", "main", b"dupbad", b"second"),
        ("empty_hash", "main", b"emptyhash", b""),
        ("commented_entry", "main", b"#commented", CORRECT.encode()),
        ("crlf_entry", "main", b"crlf", CORRECT.encode()),
        ("tab_after_hash", "main", b"tabhash", CORRECT.encode()),
        ("unknown_user", "main", b"nobody", CORRECT.encode()),
        ("user_case", "main", b"Nyxmon", CORRECT.encode()),
        ("user_leading_space", "main", b" nyxmon", CORRECT.encode()),
        ("user_trailing_space", "main", b"nyxmon ", CORRECT.encode()),
        ("user_255", "main", b"u" * 255, CORRECT.encode()),
        ("user_256", "main", b"u" * 256, CORRECT.encode()),
        ("nocolon_after", "nocolon_after", b"nyxmon", CORRECT.encode()),
        ("nocolon_before", "nocolon_before", b"nyxmon", CORRECT.encode()),
        ("long_comment", "long_comment", b"nyxmon", CORRECT.encode()),
        ("long_other_line", "long_other", b"nyxmon", CORRECT.encode()),
        ("line_255", "line255", b"u" * 194, CORRECT.encode()),
        ("line_256", "line256", b"u" * 195, CORRECT.encode()),
        ("nul_line", "nul_line", b"nyxmon", CORRECT.encode()),
        ("nul_in_hash_line", "nul_in_hash", b"nyxmon", CORRECT.encode()),
        ("no_final_newline", "no_final_newline", b"nyxmon", CORRECT.encode()),
        ("empty_file", "empty_file", b"nyxmon", CORRECT.encode()),
        ("only_comments", "only_comments", b"nyxmon", CORRECT.encode()),
        ("emptyhash_other_user", "emptyhash_file", b"nyxmon", CORRECT.encode()),
        ("emptyhash_own_user", "emptyhash_file", b"emptyhash", b""),
        ("cr_lines", "cr_lines", b"nyxmon", CORRECT.encode()),
        ("missing_file", "missing", b"nyxmon", CORRECT.encode()),
    ]
    return files, [
        {"id": case_id, "file": file, "user_hex": user.hex(), "password_hex": password.hex()}
        for case_id, file, user, password in cases
    ]


# The cases where this port refuses what htpasswd accepts (PLAN.md 4.2 item 1).
P3 = {
    "md5_correct": "non-bcrypt",
    "sha_correct": "non-bcrypt",
    "crypt_correct": "non-bcrypt",
    "prefix_2x": "non-bcrypt",
    "prefix_2a_utf8": "2a-non-ascii",
}


def main() -> int:
    entries = [[name, user, password.hex(), flags] for name, user, password, flags in ENTRIES]
    images: dict[str, Any] = {}
    exits: dict[str, dict[str, int]] = {}
    files: dict[str, str] = {}
    cases: list[dict[str, Any]] = []
    for index, image in enumerate(IMAGES):
        container = Container(image)
        try:
            if index == 0:
                created = container.run({"mode": "create", "entries": entries})
                files, cases = build(created["lines"])
            result = container.run({"mode": "verify", "files": files, "cases": cases})
        finally:
            container.close()
        images[image] = {"arch": result["arch"], **{k: v for k, v in result["versions"].items() if v}}
        exits[image] = result["exits"]
    out_cases = []
    for case in cases:
        codes = {image: exits[image][case["id"]] for image in IMAGES}
        verdicts = {code == 0 for code in codes.values()}
        if len(verdicts) != 1:
            raise SystemExit(f"the distributions disagree on {case['id']}: {codes}")
        apache = verdicts.pop()
        # A refused format is a divergence only where htpasswd accepts it.
        p3 = P3.get(case["id"]) if apache else None
        out_cases.append({**case, "exit": codes, "apache": apache,
                          "rust": apache if p3 is None else False, **({"p3": p3} if p3 else {})})
    for name, text in files.items():
        assert text.isascii(), name
    data = {"images": images, "files": files, "cases": out_cases}
    OUTPUT.write_text(json.dumps(data, indent=1, sort_keys=True, ensure_ascii=True) + "\n",
                      encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
