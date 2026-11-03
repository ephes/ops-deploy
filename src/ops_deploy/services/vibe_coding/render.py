"""Files and edits of the ``vibe_coding_deploy`` role, computed on the controller.

The role's templates are shipped unchanged (headers included) and rendered
like Ansible's ``template`` module (``trim_blocks``, trailing newline kept),
so every file is byte-identical to the role's. :func:`blockinfile` and
:func:`known_hosts` reproduce ``ansible.builtin.blockinfile`` and
``ansible.builtin.known_hosts`` (state ``present``) for the role's arguments.
"""

from __future__ import annotations

import re
from functools import cache
from typing import Any

import jinja2

from ops_deploy.services.vibe_coding.config import VibeCodingConfig

TEMPLATE_PACKAGE = "ops_deploy.services.vibe_coding"
# tasks/sshd.yml
SSHD_MARKER = "# {mark} ANSIBLE MANAGED — vibe_coding_deploy"
# tasks/chezmoi.yml: the key both known_hosts tasks add for github.com.
GITHUB_HOST = "github.com"
GITHUB_KEY = "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"


@cache
def _environment() -> jinja2.Environment:
    return jinja2.Environment(
        loader=jinja2.PackageLoader(TEMPLATE_PACKAGE, "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )


def role_vars(cfg: VibeCodingConfig, *, github_username: str = "", github_token: str = "") -> dict[str, Any]:
    return {
        "vibe_coding_user_home": str(cfg.home),
        "vibe_coding_ssh_authorized_keys": list(cfg.ssh_authorized_keys),
        "vibe_coding_npm_prefix": str(cfg.npm_prefix_path),
        "vibe_coding_github_username": github_username,
        "vibe_coding_github_token": github_token,
    }


def render(template: str, cfg: VibeCodingConfig, **secrets: str) -> str:
    return _environment().get_template(template).render(**role_vars(cfg, **secrets))


def sshd_block(user: str) -> str:
    """The ``block:`` of tasks/sshd.yml (a YAML literal block: one trailing newline)."""

    return (
        f"Match User {user}\n"
        "    PasswordAuthentication no\n"
        "    PermitEmptyPasswords no\n"
        "    AllowAgentForwarding yes\n"
        "    PermitUserRC yes\n"
        "    X11Forwarding no\n"
        "    AllowTcpForwarding no\n"
    )


def blockinfile(original: str, block: str, marker: str) -> str:
    """``ansible.builtin.blockinfile`` with ``state: present`` and ``insertafter: EOF`` (the default).

    ``original`` is the file's text, read without newline translation. An
    existing marked block is replaced in place, else the block goes to the
    end, after a line separator if the last line has none.
    """

    lines = original.splitlines(True)
    marker0 = marker.replace("{mark}", "BEGIN") + "\n"
    marker1 = marker.replace("{mark}", "END") + "\n"
    if block and not block.endswith("\n"):
        block += "\n"
    blocklines = [marker0, *block.splitlines(True), marker1] if block else []
    n0 = n1 = None
    for i, line in enumerate(lines):
        if line == marker0:
            n0 = i
        if line == marker1:
            n1 = i
    if n0 is None or n1 is None:
        n0 = len(lines)
    elif n0 < n1:
        lines[n0 : n1 + 1] = []
    else:
        lines[n1 : n0 + 1] = []
        n0 = n1
    if n0 > 0 and not lines[n0 - 1].endswith("\n"):
        lines[n0 - 1] += "\n"
    lines[n0:n0] = blocklines
    return "".join(lines)


def _normalized(line: str) -> dict[str, str]:
    fields = line.strip().split()
    if fields[0].startswith("@"):
        return {"options": fields[0], "host": fields[1], "type": fields[2], "key": fields[3]}
    return {"host": fields[0], "type": fields[1], "key": fields[2]}


def known_hosts(current: str | None, lookup: str, key: str = GITHUB_KEY) -> str | None:
    """New content of a known_hosts file after ``known_hosts: state=present``, or None when unchanged.

    ``current`` is the file's text (None: no file); ``lookup`` the output of
    ``ssh-keygen -F <host> -f <file>``, which Ansible reads the same way:
    a matching entry (also a hashed one) leaves the file alone, an entry of
    the same key type with another key or host field is replaced in place,
    anything else appends the key.
    """

    key_line = key if key.endswith("\n") else key + "\n"
    if current is None:
        return key_line
    found, replace, found_line = False, False, None
    if lookup != "":
        found = True
        wanted = _normalized(key_line)
        replace = True
        for line in lookup.split("\n"):
            if line == "":
                continue
            if line.startswith("#"):
                match = re.search(r"found: line (\d+)", line)
                found_line = int(match.group(1)) if match else found_line
                continue
            entry = _normalized(line)
            if entry.get("options", "")[:15] == "@cert-authority" or entry.get("options", "")[:7] == "@revoke":
                if wanted == entry:
                    replace = False
                    break
                continue
            # Like Ansible, the adopted hashed host field stays for later entries.
            if wanted["host"][:3] == "|1|" and entry["host"][:3] == "|1|":
                wanted["host"] = entry["host"]
            if wanted == entry:
                replace = False
                break
            if wanted["type"] == entry["type"]:
                break
        else:
            found_line = None
    if found and not replace:
        return None
    kept = [
        line for number, line in enumerate(current.splitlines(True), start=1) if not (replace and found_line == number)
    ]
    return "".join(kept) + key_line
