"""Probes and commands the vibe_coding deploy runs on the host.

Every command is plain ``sh`` (``bash`` where noted) without backslash pairs,
so root's fish login shell passes it on unchanged. Probes are read-only.
"""

from __future__ import annotations

import base64
import hashlib
import re
import shlex
from dataclasses import dataclass
from pathlib import PurePosixPath

from pyinfra.api import DeployError

from ops_deploy.services.vibe_coding.config import Dotfiles, VibeCodingConfig

# sudo's secure_path on Ubuntu: the PATH the role's become (sudo -H) commands see.
SECURE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
# Ansible's create of the user: ``password: "!"`` with ``password_lock``.
LOCKED_PASSWORD = "!!"
# The root account sshd -T compares before and after the Match block changes.
ROOT_MATCH = "user=root,host=localhost,addr=127.0.0.1"


def q(value: object) -> str:
    return shlex.quote(str(value))


def secure(command: str) -> str:
    """``command`` with sudo's secure_path, where the role's (root) command module looks binaries up."""

    return f"env PATH={SECURE_PATH} {command}"


def search(pattern: str, text: str) -> bool:
    """Jinja's ``is search`` test."""

    return re.search(pattern, text) is not None


def regex_escape(text: str) -> str:
    """Ansible's ``regex_escape`` filter (python re)."""

    return re.escape(text)


def as_user(cfg: VibeCodingConfig, script: str) -> str:
    """``script`` in bash as the vibe user, switched the way the role's ``become_user`` is: ``sudo -H -n``.

    sudo's PAM session and reset environment are the role's: HOME from the
    passwd entry (also the role's ``environment: HOME``), secure_path, the
    locale from /etc/default/locale and pam_umask's 0002 for a user with its
    own group, which decides the modes chezmoi and npm give new files.

    The command starts in ``/``: sudo keeps root's working directory (usually
    ``/root``, which the user cannot read) and chezmoi stats ``.`` first
    (``chezmoi: stat .: permission denied``). Ansible's become runs its
    modules from a temporary directory the user can read.
    """

    return "cd / && " + shlex.join(["sudo", "-H", "-n", "-u", cfg.user, "--", "bash", "-c", script])


def read_probe(path: str, *, follow: bool = False) -> str:
    """``present`` and the base64 of ``path`` (``readlink -f`` first with ``follow``), or ``absent``."""

    target = f"$(readlink -f {q(path)})" if follow else q(path)
    return f'p={target}; if [ -e "$p" ]; then echo present; base64 -w0 "$p"; else echo absent; fi'


def read_text(answer: str) -> str | None:
    """:func:`read_probe`'s answer as text (None: no file); anything else fails the deploy."""

    status, _, data = answer.partition("\n")
    if status == "absent":
        return None
    if status != "present":
        raise DeployError("vibe_coding: could not read a file on the host")
    return base64.b64decode(data.strip()).decode("utf-8", "surrogateescape")


# -- user ---------------------------------------------------------------------


@dataclass(frozen=True)
class UserState:
    group_exists: bool
    group_gid: str
    user_exists: bool
    gid: str = ""
    home: str = ""
    shell: str = ""
    # The shadow field starts with "!" / is only "!"s (never the field itself).
    locked: bool = False
    password_matches: bool = False
    # Groups that list the user as a member (Ansible's user_group_membership).
    members: tuple[str, ...] = ()


def user_probe(user: str, group: str) -> str:
    return (
        f"u={q(user)}; g={q(group)}; "
        'if gr=$(getent group "$g"); then echo group=yes; echo "groupgid=$(echo "$gr" | cut -d: -f3)"; '
        "else echo group=no; fi; "
        'pw=$(getent passwd "$u") || { echo user=no; exit 0; }; echo user=yes; echo "passwd=$pw"; '
        'h=$(getent shadow "$u" | cut -d: -f2); '
        "case \"$h\" in '!'*) echo locked=yes;; *) echo locked=no;; esac; "
        'if [ -z "$(printf %s "$h" | sed \'s/^!*//\')" ]; then echo pwmatch=yes; else echo pwmatch=no; fi; '
        'echo "members=$(getent group | awk -F: -v u="$u" '
        '\'{n=split($4,m,","); for(i=1;i<=n;i++) if(m[i]==u) print $1}\' | paste -sd, -)"'
    )


def parse_user(answer: str) -> UserState:
    values = dict(line.split("=", 1) for line in answer.splitlines() if "=" in line)
    if values.get("group") not in ("yes", "no") or values.get("user") not in ("yes", "no"):
        raise DeployError("vibe_coding: could not read the user and group")
    if values["user"] == "no":
        return UserState(values["group"] == "yes", values.get("groupgid", ""), False)
    fields = values.get("passwd", "").split(":")
    if len(fields) != 7:
        raise DeployError("vibe_coding: could not parse the passwd entry")
    return UserState(
        group_exists=values["group"] == "yes",
        group_gid=values.get("groupgid", ""),
        user_exists=True,
        gid=fields[3],
        home=fields[5],
        shell=fields[6],
        locked=values.get("locked") == "yes",
        password_matches=values.get("pwmatch") == "yes",
        members=tuple(name for name in values.get("members", "").split(",") if name),
    )


def user_command(cfg: VibeCodingConfig, state: UserState) -> str | None:
    """``useradd``/``usermod`` as Ansible's ``user`` module runs them for tasks/user.yml, or None."""

    if not state.user_exists:
        parent = q(cfg.home.parent)
        create = ["useradd", "-g", cfg.group, "-d", str(cfg.home), "-s", cfg.shell, "-p", LOCKED_PASSWORD, "-m"]
        return f"{{ [ -d {parent} ] || mkdir -p {parent}; }} && {shlex.join([*create, cfg.user])}"
    args: list[str] = []
    if not state.group_exists or state.gid != state.group_gid:
        args += ["-g", cfg.group]
    if state.members:  # groups: [] with append: false
        args += ["-G", ""]
    if state.home != str(cfg.home):
        args += ["-d", str(cfg.home)]
    if state.shell != cfg.shell:
        args += ["-s", cfg.shell]
    if not state.locked:
        args += ["-L"]
    if not state.password_matches:
        args = [arg for arg in args if arg != "-L"] + ["-p", LOCKED_PASSWORD]
    return shlex.join(["usermod", *args, cfg.user]) if args else None


# -- ~/.ssh -------------------------------------------------------------------


def private_keys_probe(ssh_dir: PurePosixPath) -> str:
    # find(1) like the role's find: top level, regular files, id_* but not *.pub.
    return f"find {q(ssh_dir)} -mindepth 1 -maxdepth 1 -type f -name 'id_*' ! -name '*.pub' -printf '%f\\n'"


def private_keys(answer: str) -> list[str]:
    return sorted(name for name in answer.splitlines() if name and "/" not in name)


# -- dotfiles checkout ----------------------------------------------------------


@dataclass(frozen=True)
class Checkout:
    is_git: bool
    origin: str = ""
    head: str = ""
    modified: bool = False


def _git(source: PurePosixPath) -> str:
    # Runs as the user (see checkout_probe/checkout_command): root never runs
    # git in the user's checkout, whose config (core.fsmonitor, hooks) the
    # user controls. safe.directory only for a top the user does not own.
    return f'g() {{ git -c safe.directory={q(source)} -C {q(source)} "$@"; }}; '


def checkout_probe(cfg: VibeCodingConfig, source: PurePosixPath) -> str:
    """As the user: whether ``source`` is a checkout, its origin, HEAD and tracked changes."""

    script = (
        f"[ -e {q(source)}/.git ] || {{ echo git=no; exit 0; }}; echo git=yes; {_git(source)}"
        'echo "origin=$(g remote get-url origin 2>/dev/null)"; '
        'echo "head=$(g rev-parse --verify -q HEAD 2>/dev/null)"; '
        # --no-optional-locks: a read, no index refresh.
        "if g --no-optional-locks status --porcelain 2>/dev/null | grep -v '^??' | grep -q .; "
        "then echo mods=yes; else echo mods=no; fi"
    )
    return as_user(cfg, script)


def parse_checkout(answer: str) -> Checkout:
    values = dict(line.split("=", 1) for line in answer.splitlines() if "=" in line)
    if values.get("git") != "yes":
        return Checkout(False)
    return Checkout(True, values.get("origin", ""), values.get("head", ""), values.get("mods") == "yes")


def checkout_command(
    cfg: VibeCodingConfig, source: PurePosixPath, bundle: str, dotfiles: Dotfiles, *, mode: str
) -> str:
    """Bring the checkout to ``dotfiles.commit`` from the bundle, as Ansible's ``git`` module does from the remote.

    ``clone``: the role's "remove chezmoi source without correct origin"
    and a fresh clone; ``update``: fetch, ``checkout --force`` and ``reset
    --hard`` on the default branch (refused with local modifications,
    ``force=no``). Both check the planned state again first. ``auto``
    decides here, for a checkout planning could not read (its owner was
    being repaired). ``origin`` ends up as the repository URL. Root only
    reads the bundle (removed whatever happens) into the stdin of the
    user's part; every git command, the removal and the clone run as the
    user.
    """

    if mode not in ("clone", "update", "auto"):
        raise ValueError("mode must be clone, update or auto")
    clone = (
        'rm -rf -- "$S"; mkdir -p -- "$(dirname -- "$S")"; '
        'git clone --quiet --branch "$BR" -- "$B" "$S"; g remote set-url origin "$R"; '
    )
    update = (
        "if g status --porcelain | grep -v '^??' | grep -q .; then "
        'echo "Local modifications exist in the destination: $S (force=no)." >&2; exit 1; fi; '
        'g fetch --quiet --force --tags "$B" "+refs/heads/*:refs/remotes/origin/*"; '
        'g checkout --quiet --force "$BR"; g reset --quiet --hard "origin/$BR" --; '
    )
    on_origin = '[ -e "$S/.git" ] && [ "$origin" = "$R" ]'
    script = (
        f"set -e; S={q(source)}; R={q(dotfiles.repo)}; BR={q(dotfiles.branch)}; C={q(dotfiles.commit)}; "
        'd=$(mktemp -d); trap \'rm -rf "$d"\' EXIT; B="$d/dotfiles.bundle"; cat > "$B"; '
        f"{_git(source)}"
        'origin=""; if [ -e "$S/.git" ]; then origin=$(g remote get-url origin 2>/dev/null || true); fi; '
    )
    if mode == "clone":
        script += (
            f"if {on_origin}; then "
            'echo "$S is a checkout of $R now; planned a fresh clone; nothing changed" >&2; exit 1; fi; ' + clone
        )
    elif mode == "update":
        script += (
            f'{on_origin} || {{ echo "$S is no longer a checkout of $R; nothing changed" >&2; exit 1; }}; ' + update
        )
    else:
        script += f"if {on_origin}; then {update}else {clone}fi; "
    script += '[ "$(g rev-parse HEAD)" = "$C" ] || { echo "$S is not at $C after the update" >&2; exit 1; }'
    return f"trap 'rm -f {q(bundle)}' EXIT; {as_user(cfg, script)} < {q(bundle)}"


def own_tree_command(path: PurePosixPath, user: str, group: str, source: str) -> str:
    """``files/own_tree.py``: the owner of the tree, as root, following no symlink (not even a parent)."""

    return shlex.join(["python3", "-I", "-c", source, str(path), user, group])


def own_dir_command(path: PurePosixPath, user: str, group: str, source: str) -> str:
    """The same for ``path`` itself only (not what is below it)."""

    return shlex.join(["python3", "-I", "-c", source, str(path), user, group, "--top"])


def foreign_owner_probe(path: PurePosixPath, user: str, group: str) -> str:
    """First path below ``path`` (itself included) not owned by user and group; symlinks are not followed."""

    return (
        f"[ -e {q(path)} ] || exit 0; "
        f"find {q(path)} ! -user {q(user)} -print -quit; find {q(path)} ! -group {q(group)} -print -quit"
    )


# -- chezmoi --------------------------------------------------------------------

CHEZMOI = "/usr/local/bin/chezmoi"
# chezmoi's config template formats (``.chezmoi.<format>.tmpl``).
CONFIG_FORMATS = ("json", "jsonc", "toml", "yaml")
# Status and apply skip chezmoi externals (``.chezmoiexternal.*``), as the
# role does: the dotfiles pull agent-stuff as a git-repo external over SSH and
# the user has no GitHub key and no forwarded agent during a deploy. The next
# interactive ``chezmoi update`` as the user fetches them.
EXCLUDE_EXTERNALS = "--exclude=externals"


def chezmoi_probe(source: PurePosixPath) -> str:
    """bash, as the user: ``current`` when init and apply would change nothing, else ``pending``.

    ``chezmoi init --force`` regenerates the config from the source's config
    template: unchanged when ``execute-template --init`` of that template is
    byte-identical to the config file. ``chezmoi apply`` does nothing when
    ``chezmoi status`` prints nothing (always-run scripts are listed there).
    Both leave chezmoi externals out (:data:`EXCLUDE_EXTERNALS`).
    """

    formats = " ".join(CONFIG_FORMATS)
    return (
        f"set -o pipefail; C={CHEZMOI}; S={q(source)}; "
        '{ [ -x "$C" ] && [ -d "$S" ]; } || { echo pending; exit 0; }; '
        'root="$S"; if [ -f "$S/.chezmoiroot" ]; then root="$S/$(head -n 1 "$S/.chezmoiroot")"; fi; '
        f"for fmt in {formats}; do "
        't="$root/.chezmoi.$fmt.tmpl"; [ -f "$t" ] || continue; '
        'f="$HOME/.config/chezmoi/chezmoi.$fmt"; [ -f "$f" ] || { echo pending; exit 0; }; '
        '"$C" execute-template --init --source "$S" --file "$t" </dev/null | cmp -s - "$f" '
        "|| { echo pending; exit 0; }; done; "
        f'st=$("$C" status {EXCLUDE_EXTERNALS} --source "$S" </dev/null) || exit 1; '
        '[ -z "$st" ] || { echo pending; exit 0; }; echo current'
    )


def chezmoi_apply(source: PurePosixPath) -> str:
    """bash, as the user: the role's init, status and apply, in its order."""

    return (
        f"set -e; C={CHEZMOI}; S={q(source)}; "
        '"$C" init --force --source "$S" </dev/null; '
        f'"$C" status {EXCLUDE_EXTERNALS} --source "$S" </dev/null; '
        f'"$C" apply --force {EXCLUDE_EXTERNALS} --source "$S" </dev/null'
    )


# -- toolchain ------------------------------------------------------------------


def _download(url: str, sha256: str, dest: str) -> str:
    return f"curl -fsSL --max-time 300 -o {dest} {q(url)}; echo {q(sha256)}'  '{dest} | sha256sum -c --quiet -; "


_TMP = "set -e; tmp=$(mktemp -d); trap 'rm -rf \"$tmp\"' EXIT; "


def nodesource_key_command(url: str, keyring: str) -> str:
    """Download and dearmor NodeSource's key into ``keyring`` (unverified, as the role's get_url)."""

    return (
        _TMP
        + f'curl -fsSL --max-time 120 -o "$tmp/nodesource-repo.gpg.key" {q(url)}; '
        + f'gpg --batch --dearmor -o {q(keyring)} "$tmp/nodesource-repo.gpg.key"'
    )


def extract_command(url: str, sha256: str, dest: str) -> str:
    """Download ``url``, check ``sha256`` and unpack the whole archive into ``dest`` (Neovim into /opt)."""

    return _TMP + _download(url, sha256, '"$tmp/release.tar.gz"') + f'tar -xzf "$tmp/release.tar.gz" -C {q(dest)}'


def rustup_command(url: str, sha256: str) -> str:
    """bash, as the user: the pinned rustup-init, checked, run once with the role's flags."""

    return (
        "set -e; tmp=$(mktemp -d -t rustup_XXXXXX); trap 'rm -rf \"$tmp\"' EXIT; "
        + _download(url, sha256, '"$tmp/rustup-init"')
        + 'chmod 0755 "$tmp/rustup-init"; "$tmp/rustup-init" -y --no-modify-path'
    )


def zellij_command(url: str, sha256: str, binary_sha256: str) -> str:
    """The archive's and then the binary's published SHA-256 before anything is installed."""

    staged = "/usr/local/bin/.zellij.ops-deploy-new"
    return (
        _TMP
        + _download(url, sha256, '"$tmp/release.tar.gz"')
        + 'tar -xzf "$tmp/release.tar.gz" -C "$tmp" zellij; '
        + '{ [ -f "$tmp/zellij" ] && [ ! -L "$tmp/zellij" ]; } || '
        + "{ echo 'zellij archive has no regular zellij file; nothing was installed' >&2; exit 1; }; "
        + f"echo {q(binary_sha256)}'  '\"$tmp/zellij\" | sha256sum -c --quiet - || "
        + "{ echo 'zellij binary does not match the published SHA-256; nothing was installed' >&2; exit 1; }; "
        + f'install -o root -g root -m 0755 "$tmp/zellij" {staged}; mv -f {staged} /usr/local/bin/zellij'
    )


def npm_tools_command(mode: str, cfg: VibeCodingConfig, source: str) -> str:
    argv = [mode, cfg.user, str(cfg.home), SECURE_PATH, str(cfg.npm_prefix_path), *cfg.npm_tools]
    return shlex.join(["python3", "-I", "-c", source, *argv])


# -- sshd -------------------------------------------------------------------------


def sshd_install_command(staged: str, planned: str, reload: str) -> str:
    """Replace sshd_config with ``staged`` only if it is still ``planned``, sshd accepts the new file and
    root's effective settings stay the same; reload ssh, and on any failure after the
    replacement restore the old file and reload again."""

    digest = hashlib.sha256(planned.encode("utf-8", "surrogateescape")).hexdigest()
    return (
        f"set -u; cfg=$(readlink -f /etc/ssh/sshd_config); new={q(staged)}; "
        'bak="$cfg.ops-deploy-vibe-coding.bak"; '
        'fail() { rm -f "$new"; echo "$1" >&2; exit 1; }; '
        f'[ "$(sha256sum < "$cfg" | cut -d \' \' -f 1)" = {digest} ] '
        '|| fail "$cfg changed since planning; nothing changed"; '
        '{ chown --reference="$cfg" "$new" && chmod --reference="$cfg" "$new"; } '
        '|| fail "could not copy the owner and mode of $cfg; nothing changed"; '
        'sshd -t -f "$new" || fail "sshd -t rejects the new configuration; nothing changed"; '
        f'before=$(sshd -T -C {ROOT_MATCH} -f "$cfg") '
        '|| fail "sshd -T fails for the current configuration; nothing changed"; '
        f'after=$(sshd -T -C {ROOT_MATCH} -f "$new") '
        '|| fail "sshd -T fails for the new configuration; nothing changed"; '
        '[ "$before" = "$after" ] '
        '|| fail "the new configuration would change the effective sshd settings of root; nothing changed"; '
        'cp -p "$cfg" "$bak" || fail "could not back up $cfg; nothing changed"; '
        'mv -f "$new" "$cfg" || { rm -f "$bak"; fail "could not replace $cfg; nothing changed"; }; '
        f'if sshd -t -f "$cfg" && {{ {reload}; }}; then rm -f "$bak"; exit 0; fi; '
        'cp -p "$bak" "$cfg" && rm -f "$bak"; '
        f"{{ {reload}; }} || true; "
        'echo "sshd rejected the new configuration after the replacement; restored the previous $cfg" >&2; exit 1'
    )
