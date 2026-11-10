"""Host access of one runner: its object-store account and ``mc`` alias, work dir and SSH known host.

Ports of the ops-control includes every register playbook shares:

- :func:`minio_access`: ``playbooks/common/backup_minio_account.yml`` (with
  ``minio_deploy``'s ``backup_account`` and ``echoport_backup``'s
  ``minio_alias``). Which account, alias, store and secret a target gets is
  decided in ops-control from ``playbooks/vars/backup_minio_accounts.yml``;
  :class:`MinioAccess` carries the result. The registry's own refusals (an
  unmanaged entry, retiring the shared alias while a target still needs it)
  stay with that resolution.
- :func:`work_dir`: ``playbooks/common/backup_work_dir.yml``.
- :func:`known_host`: ``playbooks/common/deploy_known_host_ed25519.yml``.

Credentials reach the host on stdin only, never in an argument, a fact
command or the environment.
"""

from __future__ import annotations

import base64
import hashlib
import json
import posixpath
import re
import shlex
import subprocess
from collections.abc import Callable, Mapping, Sequence
from io import StringIO
from pathlib import PurePosixPath
from typing import Annotated, Any, Literal

from pydantic import Field, model_validator
from pyinfra import host
from pyinfra.api import DeployError
from pyinfra.facts.files import File
from pyinfra.operations import files, server

from ops_deploy.base._common import RoleConfig, output
from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.probes import probe, verify_probe, when_present
from ops_deploy.helpers.python import _as_user
from ops_deploy.ops import secret_stdin
from ops_deploy.services.echoport.deploy import MC_ALIAS_PROBE, McAdminProvisioner, MinioAccount
from ops_deploy.services.echoport.deploy import _templates as _policy_templates
from ops_deploy.services.vibe_coding.render import known_hosts

_ALIAS = r"^[A-Za-z][A-Za-z0-9_-]*$"
Alias = Annotated[str, Field(pattern=_ALIAS)]
Url = Annotated[str, Field(pattern=r"^https?://[^\s'\"$`\\]+$")]
Prefix = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*(/[A-Za-z0-9][A-Za-z0-9_-]*)*$")]
User = Annotated[str, Field(pattern=r"^[a-z_][a-z0-9_-]{0,31}$")]
PlainPath = Annotated[str, Field(pattern=r"^/[A-Za-z0-9._/-]*$")]


# -- MinIO account and mc alias ---------------------------------------------------


class RunnerAccount(MinioAccount):
    """``minio_deploy``'s ``backup_account`` as the include calls it: read, write and list ``<bucket>/<prefix>/``.

    ``name`` is the target, the user ``bk-<sha256(name)[:17]>`` (the registry's
    ``backup_minio_account_user``), the policy ``backup-<name>``.
    """

    name: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$")]
    allow_put: bool = True
    allow_delete: bool = False
    # The entry's ``prefixes``; empty: the target's own name.
    prefixes: tuple[Prefix, ...] = ()

    @property
    def key_prefixes(self) -> tuple[str, ...]:
        return self.prefixes or (self.name,)


class MinioAccess(RoleConfig):
    """One target's object-store access, as ops-control resolves it from the registry.

    ``scoped``: the target has a secret in ``minio-backup-accounts.yml`` (its
    own account; else the shared alias with the MinIO root credentials).
    ``store``: where the runner writes; ``rustfs`` needs a scoped target whose
    entry declares ``rustfs_account: true`` (the RustFS deploy creates that
    account; this include only proves it). ``os_user`` ``none``: a runner that
    reads its credentials from its own file (rclone) and gets no alias.
    """

    target: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$")]
    os_user: Literal["none"] | User
    alias: Alias
    url: Url
    scoped: bool
    store: Literal["minio", "rustfs"] = "minio"
    rustfs_account: bool = False
    retired_aliases: tuple[Alias, ...] = ()
    bucket: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9.-]{2,62}$")] = "backups"
    prefixes: tuple[Prefix, ...] = ()
    mc: PlainPath = "/usr/local/bin/mc"
    admin_alias: Alias = "local"
    policy_dir: PlainPath = "/etc/minio/policies"
    # The home ``mc`` runs with for ``os_user`` (default ``/root`` or ``/home/<user>``).
    home: PlainPath | None = None

    @model_validator(mode="after")
    def _store_and_aliases(self) -> MinioAccess:
        if self.store == "rustfs" and not (self.scoped and self.rustfs_account):
            raise ValueError("store rustfs needs a secret and rustfs_account: true (then just deploy-one rustfs) first")
        if self.alias in self.retired_aliases:
            raise ValueError("the alias must not be retired in the same run")
        return self

    @property
    def user_home(self) -> PurePosixPath:
        if self.home is not None:
            return PurePosixPath(self.home)
        return PurePosixPath("/root" if self.os_user == "root" else f"/home/{self.os_user}")

    @property
    def account(self) -> RunnerAccount:
        return RunnerAccount(
            name=self.target,
            bucket=self.bucket,
            prefixes=self.prefixes,
            admin_alias=self.admin_alias,
            policy_dir=PurePosixPath(self.policy_dir),
        )


def render_account_policy(account: RunnerAccount) -> str:
    """``backup-account-policy.json.j2`` of ``minio_deploy`` for the account's prefixes."""

    return (
        _policy_templates()
        .get_template("backup-account-policy.json.j2")
        .render(
            minio_backup_account_bucket=account.bucket,
            minio_backup_account_prefixes=list(account.key_prefixes),
            minio_backup_account_whole_bucket=False,
            minio_backup_account_allow_put=account.allow_put,
            minio_backup_account_allow_delete=account.allow_delete,
        )
    )


def _mc(cfg: MinioAccess, *args: str) -> str:
    return _as_user(cfg.os_user, cfg.user_home, {}, [cfg.mc, *args])


def alias_check(cfg: MinioAccess, alias: str) -> str:
    """Strict probe: a digest of ``alias`` in ``os_user``'s mc configuration, or ``none``."""

    listing = (
        f"out=$( {_mc(cfg, '--json', 'alias', 'list', alias)} ); rc=$?; "
        f'printf \'%s\\n\' "$out" | python3 -I -c {shlex.quote(MC_ALIAS_PROBE)} "$rc"'
    )
    return when_present([cfg.user_home], listing, otherwise="none")


def alias_digest(url: str, access_key: str, secret_key: str) -> str:
    """What :func:`alias_check` prints for an alias holding these values."""

    return hashlib.sha256("\n".join((url, access_key, secret_key)).encode()).hexdigest()


def _account(cfg: MinioAccess, secret_key: str) -> None:
    """``minio_deploy``'s ``backup_account`` through root's MinIO admin alias (as the echoport deploy ports it).

    The policy is created and the user upserted only when the probe finds them
    missing or different; the secret counts as current when the runner's alias
    already holds it and lists the target's prefix with it. A runner without an alias (``os_user`` ``none``) gives no
    such proof, so its user is upserted on every run, as the role does.
    """

    # The role's input check; the value is never printed.
    if not (32 <= len(secret_key) <= 40 and secret_key != "CHANGEME"):
        raise DeployError("a backup account secret must have 32 to 40 characters and not be CHANGEME")
    account = cfg.account
    admin = McAdminProvisioner(PurePosixPath(cfg.mc), account.admin_alias)
    document = render_account_policy(account)
    state = probe(admin.state("probe", account, document), name=f"MinIO account {account.name}")
    found = dict(part.partition("=")[::2] for part in (state or "").split())
    stored = login = ""
    if cfg.os_user != "none":
        stored = (probe(alias_check(cfg, cfg.alias), name=f"mc alias {cfg.alias} of {cfg.os_user}") or "").strip()
        # The server must accept the secret too (a user re-added by hand or restored keeps another one).
        listing = f"{_mc(cfg, 'ls', f'{cfg.alias}/{account.bucket}/{account.key_prefixes[0]}/')} >/dev/null && echo ok"
        login = output(when_present([cfg.user_home], listing, otherwise="no")).strip()
    exists = found.get("user") in ("attached", "unattached")
    current = exists and stored == alias_digest(cfg.url, account.user, secret_key) and login == "ok"

    mark_read_only(server.shell(name=f"Require {admin.admin}", commands=[admin.require_admin()]))
    files.directory(
        name="Create MinIO policy directory", path=str(account.policy_dir), user="root", group="root", mode="0750"
    )
    policy_file = files.put(
        name=f"Install MinIO policy {account.policy}",
        src=StringIO(document),
        dest=str(account.policy_path),
        user="root",
        group="root",
        mode="0640",
        create_remote_dir=False,
    )
    server.shell(
        name=f"Create or update MinIO policy {account.policy}",
        commands=[admin.create_policy(account)],
        _if=lambda: policy_file.did_change() or found.get("policy") != "ok",
    )
    secret_stdin(
        name=f"Create or update MinIO user of {account.name}",
        command=admin.add_user(account),
        content=SecretContent(f"{account.user}\n{secret_key}\n"),
        _if=lambda: not current,
    )
    server.shell(
        name=f"Attach MinIO policy {account.policy}",
        commands=[admin.attach_policy(account)],
        _if=lambda: found.get("user") != "attached",
    )
    mark_read_only(
        server.shell(name=f"Verify MinIO account {account.name}", commands=[admin.state("verify", account, document)])
    )


def _alias(cfg: MinioAccess, access_key: str, secret_key: str) -> None:
    """``echoport_backup``'s ``minio_alias`` for ``os_user``: import when it differs, remove the retired ones."""

    check = alias_check(cfg, cfg.alias)
    found = probe(check, name=f"mc alias {cfg.alias} of {cfg.os_user}")
    wanted = {"url": cfg.url, "accessKey": access_key, "secretKey": secret_key, "api": "s3v4", "path": "auto"}
    # ``alias import`` opens its file itself and the user cannot reopen root's
    # stdin pipe, so the JSON goes through a private file in a root-owned 0711
    # directory (nothing in it can be swapped for a link), removed right after.
    script = (
        "set -e; d=$(mktemp -d); trap 'rm -rf \"$d\"' EXIT; "
        'chmod 0711 "$d"; umask 077; '
        f'cat > "$d/alias.json"; chown {cfg.os_user} "$d/alias.json"; '
        + f'{_mc(cfg, "alias", "import", cfg.alias)} "$d/alias.json" >/dev/null 2>&1 '
        + "|| { echo 'mc alias import failed; mc output is withheld (it can quote the credentials)' >&2; exit 1; }"
    )
    secret_stdin(
        name=f"Configure mc alias {cfg.alias} of {cfg.os_user}",
        command=script,
        content=SecretContent(json.dumps(wanted)),
        _if=lambda: (found or "").strip() != alias_digest(cfg.url, access_key, secret_key),
    )
    if found is None:
        verify_probe(check, name=f"mc alias {cfg.alias} of {cfg.os_user}")
    for retired in cfg.retired_aliases:
        present = (probe(alias_check(cfg, retired), name=f"retired mc alias {retired} of {cfg.os_user}") or "").strip()
        if present == "none":
            continue
        # ``mc alias remove`` prints no credentials; a missing alias is fine.
        remove = _mc(cfg, "alias", "remove", retired)
        server.shell(
            name=f"Remove retired mc alias {retired} of {cfg.os_user}",
            commands=[
                f'out=$( {remove} 2>&1 ) || case "$out" in *"No such alias"*) ;; *) echo "$out" >&2; exit 1;; esac'
            ],
        )


def require_mc(cfg: MinioAccess) -> None:
    """The playbooks' "Ensure mc is installed" (register-echoport-backup.yml installs it): refuse while planning."""

    mc = shlex.quote(cfg.mc)
    if (probe(f"test -x {mc} && echo present || echo missing", name=f"mc at {cfg.mc}") or "").strip() != "present":
        raise DeployError(f"mc (MinIO client) not found at {cfg.mc}; register echoport-backup first to install it")


def minio_access(cfg: MinioAccess, *, access_key: str, secret_key: str) -> None:
    """``backup_minio_account.yml`` for one target (call inside a deploy, on the store's host).

    ``access_key``/``secret_key``: the scoped account's user and secret, or the
    MinIO root credentials for a target that is not switched yet.
    """

    if not access_key or not secret_key:
        raise DeployError(f"{cfg.target}: the MinIO access key and secret key are required (values withheld)")
    if cfg.scoped and access_key != cfg.account.user:
        raise DeployError(f"{cfg.target}: a scoped target's access key must be its account user {cfg.account.user}")
    if cfg.os_user == "none" and not (cfg.scoped and cfg.store == "minio"):
        return
    require_mc(cfg)
    if cfg.scoped and cfg.store == "minio":
        _account(cfg, secret_key)
    if cfg.os_user == "none":
        return
    _alias(cfg, access_key, secret_key)
    if cfg.store == "rustfs":
        # The RustFS deploy created the account: prove the alias reaches the target's own prefix.
        mark_read_only(
            server.shell(
                name=f"Prove the RustFS account of {cfg.target} through the runner's alias",
                commands=[f"{_mc(cfg, 'ls', f'{cfg.alias}/{cfg.bucket}/{cfg.target}/')} >/dev/null"],
            )
        )


# -- work dir ---------------------------------------------------------------------


class WorkDir(RoleConfig):
    """``backup_work_dir.yml``'s inputs: a non-root runner's work dir strictly below the mount."""

    path: PlainPath
    owner: User
    mount: PlainPath = "/mnt/cryptdata"

    @model_validator(mode="after")
    def _below_mount(self) -> WorkDir:
        # The include's assert, condition by condition.
        relative = posixpath.relpath(self.path, self.mount)
        if (
            re.search(r"(^|/)\.\.?(/|$)|//|/$", self.path)
            or self.mount == "/"
            or re.match(r"\.\.?(/|$)", relative)
            or self.owner == "root"
        ):
            raise ValueError(
                "the work dir must be a normalized absolute path below the mount, owned by a non-root user"
            )
        return self

    @property
    def parents(self) -> list[str]:
        """The directories between the mount and the work dir, top down."""

        current, parents = self.mount, []
        for part in posixpath.relpath(self.path, self.mount).split("/")[:-1]:
            current = f"{current}/{part}"
            parents.append(current)
        return parents


def _kinds(paths: list[str]) -> list[str]:
    checks = [
        f"if [ -L {p} ]; then echo link; elif [ -d {p} ]; then echo dir; elif [ -e {p} ]; then echo other; "
        "else echo missing; fi"
        for p in map(shlex.quote, paths)
    ]
    found = probe("; ".join(checks), name="work dir paths") if paths else ""
    kinds = (found or "").splitlines()
    if found is None or len(kinds) != len(paths):
        raise DeployError("could not inspect the runner's work dir paths")
    return kinds


def _acl_check(path: str, owner: str) -> str:
    # The named user's entry is exactly ``--x`` (no header, no "#effective" comments, no link followed).
    return f"getfacl -cpEP -- {shlex.quote(path)} | grep -qx 'user:{owner}:--x' && echo ok || echo missing"


def work_dir(cfg: WorkDir) -> None:
    """``backup_work_dir.yml`` (call inside a deploy); refuses while planning before any write.

    Missing parents are created ``root:root 0700``; existing ones keep owner
    and mode (``chmod`` would reset the ACL mask). Every parent gets the ACL
    entry ``user:<owner>:--x``; the work dir itself is ``<owner>:<owner> 0700``.
    """

    mounted = probe(
        f"mountpoint -q {shlex.quote(cfg.mount)} && echo mounted || echo missing", name=f"mount {cfg.mount}"
    )
    if (mounted or "").strip() != "mounted":
        raise DeployError(f"{cfg.mount} is not mounted; nothing is created on the root filesystem")
    parents = cfg.parents
    kinds = _kinds([*parents, cfg.path])
    for path, kind in zip([*parents, cfg.path], kinds, strict=True):
        if kind not in ("dir", "missing"):
            raise DeployError(f"{path} is not a plain directory")
    for path, kind in zip(parents, kinds, strict=False):
        if kind == "missing":
            files.directory(name=f"Create work dir parent {path}", path=path, user="root", group="root", mode="0700")
    for path, kind in zip(parents, kinds, strict=False):
        if kind == "dir" and (probe(_acl_check(path, cfg.owner), name=f"ACL of {path}") or "").strip() == "ok":
            continue
        server.shell(
            name=f"Let {cfg.owner} traverse {path} (ACL --x)",
            commands=[shlex.join(["setfacl", "-P", "-m", f"user:{cfg.owner}:--x", path])],
        )
    files.directory(name=f"Ensure the work dir {cfg.path}", path=cfg.path, user=cfg.owner, group=cfg.owner, mode="0700")


# -- known host -------------------------------------------------------------------

# The controller's ``ssh-keyscan`` waits 5 s per address itself; this bounds a hung resolver too.
KEYSCAN_TIMEOUT = 60
ED25519 = re.compile(r"^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI[A-P][A-Za-z0-9+/]{42}$")
_HOSTNAME = r"^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$"


class KnownHost(RoleConfig):
    """``deploy_known_host_ed25519.yml``'s inputs.

    ``pin``: the inventory host's ``deploy_backup_ssh_host_ed25519_key``, used
    only when that host's ``ansible_host`` (``pin_address``) is ``name``.
    Without a pin the controller scans the name (trust on first use).
    """

    name: Annotated[str, Field(pattern=_HOSTNAME)]
    pin: str | None = None
    pin_address: str | None = None
    path: PlainPath = "/home/deploy/.ssh/known_hosts"


def controller_keyscan(name: str) -> str:
    """``ssh-keyscan -q -t ed25519 <name>`` on the controller, as the include's ``pipe`` lookup runs it."""

    try:
        result = subprocess.run(
            ["ssh-keyscan", "-q", "-t", "ed25519", name],
            capture_output=True,
            text=True,
            timeout=KEYSCAN_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise DeployError(
            f"ssh-keyscan of {name} gave no answer within {KEYSCAN_TIMEOUT} s; nothing was written."
        ) from None
    except OSError as error:
        raise DeployError(
            f"ssh-keyscan could not run on the controller ({error.strerror}); nothing was written."
        ) from None
    return result.stdout


def host_keys(cfg: KnownHost, keyscan: Callable[[str], str] = controller_keyscan) -> list[str]:
    """The include's key resolution: the pin, or the scanned ``<name> ssh-ed25519 ...`` lines (unique)."""

    if cfg.pin is not None:
        return [cfg.pin]
    line = re.compile(re.escape(cfg.name) + r" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI[A-P][A-Za-z0-9+/]{42}$")
    keys: list[str] = []
    for raw in keyscan(cfg.name).splitlines():
        entry = raw.strip()
        if line.match(entry):
            key = entry.split(" ", 1)[1]
            if key not in keys:
                keys.append(key)
    return keys


def _read(path: str) -> str | None:
    quoted = shlex.quote(path)
    answer = probe(f"if [ -e {quoted} ]; then echo present; base64 -w0 {quoted}; else echo absent; fi", name=path)
    status, _, data = (answer or "").partition("\n")
    if status == "absent":
        return None
    if status != "present":
        raise DeployError(f"could not read {path}")
    return base64.b64decode(data.strip()).decode("utf-8", "surrogateescape")


def _resolved_key(cfg: KnownHost, keyscan: Callable[[str], str]) -> str:
    """The include's resolution and assert for one name: exactly one well-formed key, or a refusal."""

    keys = host_keys(cfg, keyscan)
    source = "pinned" if cfg.pin is not None else "ssh-keyscan"
    if len(keys) != 1 or not ED25519.match(keys[0]) or (source == "pinned" and cfg.pin_address != cfg.name):
        raise DeployError(
            f"Expected exactly one ed25519 host key for {cfg.name} from {source}, got {len(keys)} "
            "(a pin must come from the inventory host whose ansible_host is that name). "
            f"Nothing was written to {cfg.path}."
        )
    return keys[0]


_FOUND = re.compile(r"^# Host (?P<host>\S+) found: line (?P<line>\d+)(?P<rest>.*)$")


def _without_line(lookup: str, number: int) -> str:
    """``ssh-keygen -F`` output after line ``number`` of the file was removed (later lines move up)."""

    kept: list[str] = []
    skip = False
    for line in lookup.split("\n"):
        found = _FOUND.match(line)
        if found:
            at = int(found["line"])
            skip = at == number
            if not skip:
                kept.append(f"# Host {found['host']} found: line {at - 1 if at > number else at}{found['rest']}")
            continue
        if not skip:
            kept.append(line)
        skip = False
    return "\n".join(kept)


def _replaced_line(before: str, after: str) -> int | None:
    """The line ``known_hosts`` removed from ``before`` (it appends its line to the rest), if any."""

    old, new = before.splitlines(True), after.splitlines(True)[:-1]
    if len(new) == len(old):
        return None
    for number, (line, kept) in enumerate(zip(old, [*new, None], strict=True), start=1):
        if line != kept:
            return number
    return None


_BANNER = re.compile(r"^# (?P<host>\S+):\d+ SSH-")


def _deduplicated(content: str, wanted: Sequence[str]) -> str:
    """``content`` with one copy of each ``wanted`` key line and none of those hosts' keyscan banners.

    Until 2026-10-22 every register run appended the controller's
    ``ssh-keyscan`` output again: a ``# <host>:22 SSH-2.0-...`` banner
    comment and another copy of the same key line. Later identical copies
    of a wanted ``<host> <key>`` line (whitespace-normalized) and the
    banner comments of those hosts are dropped; the first copy keeps its
    place and every other line (other hosts, hashed or multi-host entries,
    other keys of the same host) is left as it is.
    """

    lines = set(wanted)
    hosts = {line.split(" ", 1)[0] for line in wanted}
    seen: set[str] = set()
    kept: list[str] = []
    for line in content.splitlines(True):
        banner = _BANNER.match(line)
        if banner and banner["host"] in hosts:
            continue
        normalized = " ".join(line.split())
        if normalized in lines:
            if normalized in seen:
                continue
            seen.add(normalized)
        kept.append(line)
    return "".join(kept)


def known_hosts_entries(cfgs: Sequence[KnownHost], keyscan: Callable[[str], str] = controller_keyscan) -> None:
    """The include, once per name in ``cfgs`` and in that order, on one known_hosts file.

    Every name's key is resolved before the file is touched (anything other
    than exactly one well-formed key refuses while planning). The names are
    then applied one after the other as ``known_hosts`` ``state: present``
    applies them, each to the file the previous one left (the host's
    ``ssh-keygen -F`` answers are read once and moved past a replaced line),
    and the result is written in one upload. The file keeps its owner and mode.
    Beyond the include, the result keeps a single copy of each name's key
    line and none of the names' ``ssh-keyscan`` banner comments, which the
    register playbooks appended on every run until 2026-10-22
    (:func:`_deduplicated`); a converged file stays unchanged.
    """

    if not cfgs:
        return
    path = cfgs[0].path
    if any(cfg.path != path for cfg in cfgs) or len({cfg.name for cfg in cfgs}) != len(cfgs):
        raise DeployError("the known hosts of one run must be distinct names in one known_hosts file")
    keys = [_resolved_key(cfg, keyscan) for cfg in cfgs]
    current = _read(path)
    lookups = [
        output(f"ssh-keygen -F {shlex.quote(cfg.name)} -f {shlex.quote(path)}") if current is not None else ""
        for cfg in cfgs
    ]
    content = current
    for index, (cfg, key) in enumerate(zip(cfgs, keys, strict=True)):
        changed = known_hosts(content, lookups[index], f"{cfg.name} {key}")
        if changed is None:
            continue
        removed = _replaced_line(content, changed) if content is not None else None
        if removed is not None:
            lookups[index + 1 :] = [_without_line(lookup, removed) for lookup in lookups[index + 1 :]]
        content = changed
    if content is not None:
        content = _deduplicated(content, [f"{cfg.name} {key}" for cfg, key in zip(cfgs, keys, strict=True)])
    if content == current:
        return
    if len(cfgs) > 1 and current and not current.endswith("\n"):
        # known_hosts appends to the last line then; consecutive tasks leave a
        # file the answers read once do not describe.
        raise DeployError(f"{path} does not end with a newline; fix it by hand. Nothing was written.")
    found = host.get_fact(File, path=path)
    info: Mapping[str, Any] = found or {}
    names = ", ".join(cfg.name for cfg in cfgs)
    files.put(
        name=f"Add the ed25519 host key{'s' if len(cfgs) > 1 else ''} of {names} to {path}",
        src=StringIO(content or ""),
        dest=path,
        user=str(info.get("user", "root")),
        group=str(info.get("group", "root")),
        mode=str(info.get("mode", 644)),
        create_remote_dir=False,
    )


def known_host(cfg: KnownHost, keyscan: Callable[[str], str] = controller_keyscan) -> None:
    """Write exactly one ed25519 key line for ``cfg.name`` (``known_hosts`` ``state: present``).

    Anything other than exactly one well-formed key refuses while planning,
    before the file is touched.
    """

    known_hosts_entries([cfg], keyscan)


__all__ = [
    "KnownHost",
    "MinioAccess",
    "RunnerAccount",
    "WorkDir",
    "alias_check",
    "alias_digest",
    "controller_keyscan",
    "host_keys",
    "known_host",
    "known_hosts_entries",
    "minio_access",
    "render_account_policy",
    "require_mc",
    "work_dir",
]
