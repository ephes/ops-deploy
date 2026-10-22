"""OS lifecycle: a read-only status report per host, how it reaches Nyxmon, and the Nyxmon checks.

Every host gets the status script (``files/os_lifecycle_status.py``), its
policy (``/etc/os-lifecycle/policy.json``) and an hourly collector timer that
writes ``/var/lib/os-lifecycle/state.json``. How the report leaves the host
depends on ``exposure``:

- ``endpoint`` (hosts on the monitoring network): an authenticated HTTP
  endpoint serves the file, metrics-httpd's ``json-file`` mode through the
  shared switch (:mod:`ops_deploy.services._metrics_httpd`, reused unchanged)
  or the Python fallback ``files/os_lifecycle_httpd.py`` with the same
  command line. Optionally (``remote``) the host also pulls the reports of
  ``ssh`` hosts and serves the combined file on a second endpoint.
- ``ssh`` (hosts that must not join that network): no listener. A system
  account whose ``authorized_keys`` (owned by root) holds only the collector's
  public key, restricted to ``restrict,command="<status script> show"``: the
  key can print the cached report and nothing else.

Unit names and the configuration directory are fixed, so a later deploy
finds whatever an earlier one created: a host that keeps units or secrets of
a mode its configuration leaves (``ssh`` after ``endpoint``, an endpoint
without ``remote`` after one with it) is refused before any change.

:func:`deploy_os_lifecycle_checks` upserts the Nyxmon checks (see
:mod:`ops_deploy.services.os_lifecycle.checks`) on the Nyxmon host. Secrets:
the endpoint password (``endpoint_password``, also the checks' login) and,
for ``remote``, the collector's private key (``collector_ssh_private_key``),
written only with ``secret_file``.
"""

from __future__ import annotations

import ipaddress
import json
import re
import shlex
from collections.abc import Sequence
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import Annotated, ClassVar, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    field_validator,
    model_validator,
)
from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import FileContents
from pyinfra.facts.server import Users
from pyinfra.operations import apt, files, server, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers import service_rollout, systemd_unit
from ops_deploy.helpers.probes import probe
from ops_deploy.helpers.systemd import UNIT_DIR
from ops_deploy.helpers.traefik import hash_password
from ops_deploy.ops import secret_file
from ops_deploy.services import _metrics_httpd as metrics_httpd
from ops_deploy.services._nyxmon_json_metrics import JsonMetricsCheck, upsert_json_metrics_check
from ops_deploy.services.nyxmon_site_checks.deploy import _HOSTNAME, PlainPath
from ops_deploy.services.os_lifecycle.checks import HostKey
from ops_deploy.services.thermal_monitoring.deploy import credentials_verify

FILES = Path(__file__).parent / "files"
STATUS_SCRIPT = (FILES / "os_lifecycle_status.py").read_text()
PULL_SCRIPT = (FILES / "os_lifecycle_pull.py").read_text()
HTTPD_SCRIPT = (FILES / "os_lifecycle_httpd.py").read_text()
PASSWORD_KEY = "endpoint_password"
PRIVATE_KEY_KEY = "collector_ssh_private_key"
TAILSCALE: Literal["tailscale"] = "tailscale"
REALM = "os-lifecycle"
SERVER_NAME = "os-lifecycle-httpd/1"
PYTHON = "/usr/bin/python3"
# Fixed names: no configuration can move a unit or a secret where a later deploy does not look.
ENDPOINT_UNIT = "os-lifecycle-endpoint"
REMOTE_UNIT = "os-lifecycle-remote-endpoint"
COLLECTOR_UNIT = "os-lifecycle-collector"
PULL_UNIT = "os-lifecycle-pull"
CONFIG_DIR = PurePosixPath("/etc/os-lifecycle")
HTPASSWD_PATH = CONFIG_DIR / "htpasswd"
IDENTITY_PATH = CONFIG_DIR / "collector_ed25519"
# What the remote pull leaves on a host, and what the endpoint exposure leaves (both servers, the pull, the secrets).
REMOTE_UNITS = (f"{REMOTE_UNIT}.service", f"{PULL_UNIT}.service", f"{PULL_UNIT}.timer")
ENDPOINT_UNITS = (f"{ENDPOINT_UNIT}.service", *REMOTE_UNITS)
# A unit is gone when systemd answers these (and its unit file is absent).
KEYS = ("LoadState", "ActiveState")
GONE = ("not-found", "inactive")
_DATE = r"^\d{4}-\d{2}-\d{2}$"
_PUBLIC_KEY = re.compile(r"^(ssh-ed25519|ecdsa-sha2-nistp(256|384|521)|ssh-rsa) [A-Za-z0-9+/]+={0,3}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_PRIVATE_KEY = re.compile(
    r"\A-----BEGIN OPENSSH PRIVATE KEY-----\n[A-Za-z0-9+/=\n]+-----END OPENSSH PRIVATE KEY-----\n\Z"
)

Port = Annotated[StrictInt, Field(ge=1, le=65535)]
UrlPath = Annotated[str, Field(pattern=r"^/[A-Za-z0-9._~/-]*$")]
AuthUser = Annotated[str, Field(pattern=r"^[A-Za-z0-9._@-]{1,64}$")]
Days = Annotated[StrictInt, Field(ge=1, le=3650)]
Text = Annotated[str, Field(pattern=r"^[A-Za-z0-9 ._:/()+-]{0,80}$")]
DateText = Annotated[str, Field(pattern=_DATE)]


class _Part(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, validate_default=True, hide_input_in_errors=True)


def _public_key(value: str) -> str:
    if not _PUBLIC_KEY.fullmatch(value):
        raise ValueError("must be '<type> <base64>' of an SSH public key, without options or comment")
    return value


PublicKey = Annotated[str, Field(max_length=2000), AfterValidator(_public_key)]


class EolCycle(_Part):
    """One endoflife.date cycle, the fields the status script reads (dates as text, or false)."""

    cycle: Annotated[str, Field(pattern=r"^[0-9][0-9.]{0,15}$")]
    codename: Text = ""
    # endoflife.date's field name.
    releaseDate: DateText
    support: DateText | StrictBool = False
    eol: DateText | StrictBool = False
    lts: StrictBool = False


class EolSnapshot(_Part):
    """endoflife.date data the controller embeds (``/api/debian.json``, ``/api/ubuntu.json``)."""

    fetched_at: DateText
    debian: tuple[EolCycle, ...] = ()
    ubuntu: tuple[EolCycle, ...] = ()


class SshReport(_Part):
    """``exposure: ssh``: the collector's public key and optional ``from=`` sources."""

    public_key: PublicKey
    from_sources: tuple[Annotated[str, Field(pattern=r"^[0-9A-Fa-f.:/*?]{1,64}$")], ...] = ()
    home: PlainPath = PurePosixPath("/var/lib/os-lifecycle-ssh")
    key_comment: Annotated[str, Field(pattern=r"^[A-Za-z0-9._@-]{1,64}$")] = "os-lifecycle-collector"


class RemoteHost(_Part):
    """A host whose report the monitoring host pulls over SSH."""

    name: HostKey
    address: Annotated[str, Field(max_length=253)]
    port: Port = 22
    user: UnixUser = "os-lifecycle"
    # The host's SSH host keys ("<type> <base64>"); the pull trusts nothing else.
    host_keys: tuple[PublicKey, ...] = Field(min_length=1)

    @field_validator("address")
    @classmethod
    def _address(cls, value: str) -> str:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            if not _HOSTNAME.fullmatch(value):
                raise ValueError("address must be a host name or an IP address") from None
        return value


class RemotePull(_Part):
    """``remote``: pull ``hosts`` hourly (``os-lifecycle-pull.timer``) and serve the combined file on a second endpoint.

    The second endpoint is ``os-lifecycle-remote-endpoint.service``.
    """

    hosts: tuple[RemoteHost, ...] = Field(min_length=1)
    port: Port = 9114
    path: UrlPath = "/.well-known/os-lifecycle-remote"
    timeout: Annotated[StrictInt, Field(ge=5, le=600)] = 60

    @model_validator(mode="after")
    def _unique(self) -> RemotePull:
        names = [entry.name for entry in self.hosts]
        if len(set(names)) != len(names):
            raise ValueError("remote host names must be unique")
        return self


class OsLifecycleConfig(BaseServiceConfig, metrics_httpd.HttpdSwitchFields):
    """One host's report, its exposure and (on the monitoring host) the remote pull.

    ``service_name`` is the endpoint's unit, fixed like every unit name of
    this service; ``user`` the account that reads the report (the endpoint's
    user, or the SSH account for ``ssh``), ``site_path`` the state directory.
    ``host_label`` is the report's ``host`` (what the pull and the checks
    expect).
    """

    service_name: Literal["os-lifecycle-endpoint"] = "os-lifecycle-endpoint"
    user: UnixUser = "metrics"
    group: UnixUser | None = None
    site_path: PlainPath = PurePosixPath("/var/lib/os-lifecycle")
    host_label: HostKey
    exposure: Literal["endpoint", "ssh"]
    reboot_class: Literal["A", "B", "C"]
    upgrade_horizon_days: Days = 365
    lifecycle_tolerance_days: Annotated[StrictInt, Field(ge=0, le=365)] = 31
    endoflife: EolSnapshot
    script_dir: PlainPath = PurePosixPath("/usr/local/lib/os-lifecycle")
    packages: tuple[Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9+.-]*$")], ...] = ("python3", "distro-info-data")
    # exposure endpoint
    bind: Literal["tailscale"] | ipaddress.IPv4Address = TAILSCALE
    port: Port = 9113
    path: UrlPath = "/.well-known/os-lifecycle"
    auth_user: AuthUser | None = None
    remote: RemotePull | None = None
    # exposure ssh
    ssh: SshReport | None = None

    required_secret_keys: ClassVar[tuple[str, ...]] = ()

    @model_validator(mode="after")
    def _exposure(self) -> OsLifecycleConfig:
        if self.exposure == "endpoint":
            if self.ssh is not None:
                raise ValueError("ssh is only for exposure ssh")
            if self.auth_user is None or self.secrets is None:
                raise ValueError("exposure endpoint needs auth_user and a secrets file (endpoint_password)")
            if self.remote is not None and self.remote.port == self.port:
                raise ValueError("remote.port must differ from port")
        else:
            if self.ssh is None:
                raise ValueError("exposure ssh needs ssh (the collector's public key)")
            if self.remote is not None or self.auth_user is not None:
                raise ValueError("exposure ssh has no endpoint: drop remote and auth_user")
            if self.user == "root":
                raise ValueError("the SSH account must not be root")
        return self

    @property
    def group_name(self) -> str:
        return self.group or self.user

    @property
    def state_path(self) -> PurePosixPath:
        return self.site_path / "state.json"

    @property
    def remote_path(self) -> PurePosixPath:
        return self.site_path / "remote.json"

    @property
    def status_script(self) -> PurePosixPath:
        return self.script_dir / "os_lifecycle_status.py"


class OsLifecycleChecksConfig(BaseServiceConfig):
    """The Nyxmon checks of every host, upserted on the Nyxmon host."""

    required_secret_keys: ClassVar[tuple[str, ...]] = (PASSWORD_KEY,)

    service_name: ServiceName = "os-lifecycle-checks"
    user: UnixUser = "nyxmon"
    site_path: PurePosixPath = PurePosixPath("/home/nyxmon/site")
    checks: tuple[JsonMetricsCheck, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _unique(self) -> OsLifecycleChecksConfig:
        keys = [(check.service_name, check.name) for check in self.checks]
        if len(set(keys)) != len(keys):
            raise ValueError("check names must be unique per Nyxmon service")
        return self


# -- rendered files ------------------------------------------------------------------------


def render_policy(cfg: OsLifecycleConfig) -> str:
    """``policy.json``: what the status script reads besides the host itself."""

    policy = {
        "host": cfg.host_label,
        "reboot_class": cfg.reboot_class,
        "upgrade_horizon_days": cfg.upgrade_horizon_days,
        "lifecycle_tolerance_days": cfg.lifecycle_tolerance_days,
        "state_group": cfg.group_name,
        "endoflife": cfg.endoflife.model_dump(),
    }
    return json.dumps(policy, indent=2, sort_keys=True) + "\n"


def collect_command(cfg: OsLifecycleConfig) -> str:
    return shlex.join(
        [PYTHON, "-I", str(cfg.status_script), "collect", "--policy", str(CONFIG_DIR / "policy.json"),
         "--state-dir", str(cfg.site_path)]
    )  # fmt: skip


def show_command(cfg: OsLifecycleConfig) -> str:
    """The forced command of the collector key (no quotes or backslashes: it sits in ``command="..."``)."""

    return shlex.join([PYTHON, "-I", str(cfg.status_script), "show", "--state-dir", str(cfg.site_path)])


def _oneshot(description: str, command: str, state_dir: PurePosixPath, *extra: str) -> str:
    lines = [
        "[Unit]",
        f"Description={description}",
        "After=network-online.target",
        "Wants=network-online.target",
        "",
        "[Service]",
        "Type=oneshot",
        "User=root",
        "Group=root",
        f"ExecStart={command}",
        "TimeoutStartSec=900",
        "Nice=10",
        "IOSchedulingClass=idle",
        "NoNewPrivileges=yes",
        "PrivateTmp=yes",
        "ProtectHome=yes",
        "ProtectSystem=strict",
        f"ReadWritePaths={state_dir}",
        *extra,
        "",
    ]
    return "\n".join(lines)


def render_collector_service(cfg: OsLifecycleConfig) -> str:
    return _oneshot("Write the OS lifecycle report", collect_command(cfg), cfg.site_path)


def render_timer(description: str) -> str:
    return (
        f"[Unit]\nDescription={description}\n\n"
        "[Timer]\nOnBootSec=5min\nOnCalendar=hourly\nRandomizedDelaySec=600\nPersistent=true\n\n"
        "[Install]\nWantedBy=timers.target\n"
    )


def endpoint_argv(cfg: OsLifecycleConfig, bind: str, *, remote: bool = False) -> tuple[str, ...]:
    """The metrics-httpd ``json-file`` command line (also the Python fallback's)."""

    port, path, json_path = (
        (cfg.remote.port, cfg.remote.path, cfg.remote_path)
        if remote and cfg.remote
        else (cfg.port, cfg.path, cfg.state_path)
    )
    return (
        *("json-file", "--bind", bind, "--port", str(port), "--path", path),
        *("--json-path", str(json_path), "--htpasswd-file", str(HTPASSWD_PATH)),
        *("--realm", REALM, "--server-name", SERVER_NAME),
    )


SANDBOX = ("NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes")
ALLOW = ("localhost", "100.64.0.0/10")


def render_endpoint_unit(cfg: OsLifecycleConfig, bind: str, *, remote: bool = False) -> str:
    argv = " ".join(endpoint_argv(cfg, bind, remote=remote)[1:])
    lines = [
        "[Unit]",
        f"Description=OS lifecycle {'remote reports' if remote else 'report'} endpoint",
        "After=network-online.target",
        "Wants=network-online.target",
        "",
        "[Service]",
        "Type=exec",
        f"User={cfg.user}",
        f"Group={cfg.group_name}",
        f"ExecStart={PYTHON} -I {cfg.script_dir / 'os_lifecycle_httpd.py'} {argv}",
        "Restart=always",
        "RestartSec=5",
        *SANDBOX,
        "ProtectControlGroups=yes",
        "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes",
        "ProtectHostname=yes",
        "RestrictRealtime=yes",
        "LockPersonality=yes",
        "IPAddressDeny=any",
        *(f"IPAddressAllow={entry}" for entry in ALLOW),
        f"ReadOnlyPaths={cfg.site_path}",
        "",
        "[Install]",
        "WantedBy=multi-user.target",
        "",
    ]
    return "\n".join(lines)


def httpd_endpoint(cfg: OsLifecycleConfig, bind: str, *, remote: bool = False) -> metrics_httpd.Endpoint:
    pull = cfg.remote
    return metrics_httpd.Endpoint(
        service_name=REMOTE_UNIT if remote and pull else ENDPOINT_UNIT,
        argv=endpoint_argv(cfg, bind, remote=remote),
        user=cfg.user,
        group=cfg.group_name,
        sandbox=(*SANDBOX, f"ReadOnlyPaths={cfg.site_path}"),
        python_script=str(cfg.script_dir / "os_lifecycle_httpd.py"),
        probe_bind=bind,
        probe_port=pull.port if remote and pull else cfg.port,
        probe_path=pull.path if remote and pull else cfg.path,
        probe_realm=REALM,
        ip_address_allow=ALLOW,
    )


def render_authorized_keys(cfg: OsLifecycleConfig) -> str:
    assert cfg.ssh is not None
    sources = f'from="{",".join(cfg.ssh.from_sources)}",' if cfg.ssh.from_sources else ""
    return (
        "# Managed by ops-deploy services.os_lifecycle: the collector key may only print the report.\n"
        f'{sources}restrict,command="{show_command(cfg)}" {cfg.ssh.public_key} {cfg.ssh.key_comment}\n'
    )


def render_pull_config(cfg: OsLifecycleConfig) -> str:
    assert cfg.remote is not None
    config = {
        "identity_file": str(IDENTITY_PATH),
        "known_hosts": str(CONFIG_DIR / "known_hosts"),
        "state_group": cfg.group_name,
        "timeout": cfg.remote.timeout,
        "hosts": [entry.model_dump(include={"name", "address", "port", "user"}) for entry in cfg.remote.hosts],
    }
    return json.dumps(config, indent=2, sort_keys=True) + "\n"


def render_known_hosts(cfg: OsLifecycleConfig) -> str:
    assert cfg.remote is not None
    return "".join(f"os-lifecycle-{entry.name} {key}\n" for entry in cfg.remote.hosts for key in entry.host_keys)


def render_pull_service(cfg: OsLifecycleConfig) -> str:
    command = shlex.join(
        [PYTHON, "-I", str(cfg.script_dir / "os_lifecycle_pull.py"), "--config",
         str(CONFIG_DIR / "remote-hosts.json"), "--out", str(cfg.remote_path)]
    )  # fmt: skip
    return _oneshot("Pull the OS lifecycle reports of remote hosts", command, cfg.site_path, "PrivateDevices=yes")


# -- the deploy ----------------------------------------------------------------------------------


def _password(secrets: SecretValues) -> str:
    password = secrets.get(PASSWORD_KEY, "")
    if not password or password == "CHANGE_ME":
        raise DeployError(f"os_lifecycle: the secret {PASSWORD_KEY} is missing, empty or CHANGE_ME")
    # htpasswd reads one line and bcrypt uses 72 bytes: anything else checks another password.
    if _CONTROL.search(password) or len(password.encode()) > 72:
        raise DeployError(f"os_lifecycle: {PASSWORD_KEY} must be at most 72 bytes without control characters")
    return password


def _htpasswd(cfg: OsLifecycleConfig, password: str) -> list[OperationMeta]:
    """Verify, then write only when the password does not verify (bcrypt salts differ per write)."""

    path, user = HTPASSWD_PATH, str(cfg.auth_user)
    if credentials_verify(host.get_fact(FileContents, path=str(path)), user, password):
        files.file(name=f"Ensure owner and mode of {path}", path=str(path), user="root", group=cfg.group_name,
                   mode="0640")  # fmt: skip
        return []
    content = SecretContent(f"{user}:{hash_password(password)}\n")
    return [secret_file(name=f"Write {path}", path=path, content=content, user="root", group=cfg.group_name,
                        mode="0640")]  # fmt: skip


def _bind(cfg: OsLifecycleConfig) -> str:
    if cfg.bind != TAILSCALE:
        return str(cfg.bind)
    words = (probe("tailscale ip --4", name="Tailscale IPv4 address") or "").split()
    try:
        return str(ipaddress.IPv4Address(words[0])) if len(words) == 1 else ""
    except ValueError:
        return ""


def _account(cfg: OsLifecycleConfig) -> None:
    """The reader's group and system account: no login for the endpoint, ``/bin/sh`` for the SSH account.

    sshd runs a forced command through the account's shell, so an existing
    SSH account with a non-login shell is refused instead of silently broken.
    """

    group = cfg.group_name
    server.group(name=f"Ensure group {group}", group=group, system=True)
    ssh = cfg.exposure == "ssh"
    shell = "/bin/sh" if ssh else "/usr/sbin/nologin"
    home = str(cfg.ssh.home) if cfg.ssh else f"/home/{cfg.user}"
    existing = host.get_fact(Users).get(cfg.user)
    if existing is None:
        server.user(
            name=f"Ensure user {cfg.user}",
            user=cfg.user,
            group=group,
            home=home,
            shell=shell,
            system=True,
            ensure_home=False,
            create_home=False,
        )
        return
    if existing.get("group") != group:
        raise DeployError(f"os_lifecycle: existing user {cfg.user} is not in group {group}; refusing to change it")
    if ssh and (existing.get("shell") != shell or existing.get("home") != home):
        raise DeployError(f"os_lifecycle: existing user {cfg.user} lacks shell {shell} or home {home}")


def _scripts(cfg: OsLifecycleConfig, *names: str) -> list[OperationMeta]:
    sources = {"os_lifecycle_status.py": STATUS_SCRIPT, "os_lifecycle_pull.py": PULL_SCRIPT,
               "os_lifecycle_httpd.py": HTTPD_SCRIPT}  # fmt: skip
    return [
        files.put(
            name=f"Install {cfg.script_dir / name}",
            src=StringIO(sources[name]),
            dest=str(cfg.script_dir / name),
            user="root",
            group="root",
            mode="0644",
        )
        for name in names
    ]


def _put(path: PurePosixPath, content: str, mode: str = "0644") -> OperationMeta:
    return files.put(name=f"Write {path}", src=StringIO(content), dest=str(path), user="root", group="root", mode=mode)


def _first_run(path: PurePosixPath, service: str, changed: list[OperationMeta]) -> None:
    """Run the oneshot ``service`` while its output is missing or its inputs changed."""

    quoted = shlex.quote(str(path))
    state = probe(f"if test -e {quoted}; then echo present; else echo absent; fi", name=f"{path}")
    missing = (state or "").strip() != "present"
    server.shell(
        name=f"Run {service} once",
        commands=[shlex.join(["systemctl", "start", service])],
        _if=lambda: missing or any(meta.did_change() for meta in changed),
    )


def _endpoint(cfg: OsLifecycleConfig, bind: str, *, remote: bool, inputs: list[OperationMeta]) -> None:
    endpoint = httpd_endpoint(cfg, bind, remote=remote)
    unit = systemd_unit(endpoint.service_name, render_endpoint_unit(cfg, bind, remote=remote))
    # A pinned release is only installed when Rust is selected: os_lifecycle
    # never stages metrics-httpd ahead of the fleet's own rollout.
    switch = metrics_httpd.HttpdSwitchFields(
        httpd_impl=cfg.httpd_impl,
        httpd_rust_version=cfg.httpd_rust_version if cfg.httpd_impl == "rust" else "",
        httpd_rust_sha256=cfg.httpd_rust_sha256 if cfg.httpd_impl == "rust" else "",
    )
    selection = metrics_httpd.select(endpoint, switch)
    systemd.daemon_reload(name=f"Reload systemd for {endpoint.service_name}", _if=any_changed(unit, selection.dropin))
    service_rollout(endpoint.service_name, restart_when=[unit, selection.dropin, *inputs])
    metrics_httpd.verify(selection)


def _collector(cfg: OsLifecycleConfig, inputs: list[OperationMeta]) -> None:
    service = systemd_unit(f"{COLLECTOR_UNIT}.service", render_collector_service(cfg))
    timer = systemd_unit(f"{COLLECTOR_UNIT}.timer", render_timer("Write the OS lifecycle report hourly"))
    systemd.daemon_reload(name="Reload systemd for the OS lifecycle collector", _if=any_changed(service, timer))
    _first_run(cfg.state_path, f"{COLLECTOR_UNIT}.service", [service, *inputs])
    service_rollout(f"{COLLECTOR_UNIT}.timer", restart_when=[timer])


def _remote(cfg: OsLifecycleConfig, secrets: SecretValues, bind: str, httpd: list[OperationMeta]) -> None:
    pull = cfg.remote
    assert pull is not None
    key = secrets.get(PRIVATE_KEY_KEY, "")
    if not _PRIVATE_KEY.fullmatch(key):
        raise DeployError(f"os_lifecycle: the secret {PRIVATE_KEY_KEY} is missing or not an OpenSSH private key")
    inputs = [
        secret_file(name=f"Write {IDENTITY_PATH}", path=IDENTITY_PATH, content=SecretContent(key),
                    user="root", group="root", mode="0600"),
        _put(CONFIG_DIR / "remote-hosts.json", render_pull_config(cfg)),
        _put(CONFIG_DIR / "known_hosts", render_known_hosts(cfg)),
        *_scripts(cfg, "os_lifecycle_pull.py"),
    ]  # fmt: skip
    service = systemd_unit(f"{PULL_UNIT}.service", render_pull_service(cfg))
    timer = systemd_unit(f"{PULL_UNIT}.timer", render_timer("Pull the OS lifecycle reports of remote hosts"))
    systemd.daemon_reload(name="Reload systemd for the OS lifecycle pull", _if=any_changed(service, timer))
    _first_run(cfg.remote_path, f"{PULL_UNIT}.service", [service, *inputs])
    service_rollout(f"{PULL_UNIT}.timer", restart_when=[timer])
    _endpoint(cfg, bind, remote=True, inputs=httpd)


def _present(path: PurePosixPath) -> str:
    """Shell setting ``file`` to ``present`` if ``path`` exists (a dangling symlink too), else ``absent``."""

    return f'f={shlex.quote(str(path))}; if test -e "$f" || test -L "$f"; then file=present; else file=absent; fi'


def leftover_command(units: Sequence[str], paths: Sequence[PurePosixPath], unit_dir: PurePosixPath = UNIT_DIR) -> str:
    """Probe: per unit ``unit <name> <LoadState> <ActiveState> <present|absent>``, per path ``file <path> <...>``.

    systemd answers for the unit whatever its file or process (running with
    its file gone, masked, failed); ``present`` is the unit file in
    ``unit_dir``, in case systemd has not loaded it yet. ``systemctl`` failing
    fails the probe.
    """

    if any(len(str(item).split()) != 1 for item in (*units, *paths, unit_dir)):
        raise ValueError("leftover_command: unit names and paths must not contain whitespace")
    parts = []
    for unit in units:
        load, active = (shlex.join(["systemctl", "show", f"--property={key}", "--value", unit]) for key in KEYS)
        parts.append(
            f"load=$({load}) || exit 1; active=$({active}) || exit 1; {_present(unit_dir / unit)}; "
            f'echo unit {shlex.quote(unit)} "$load" "$active" "$file"'
        )
    parts += [f'{_present(path)}; echo file {shlex.quote(str(path))} "$file"' for path in paths]
    return "; ".join(parts)


def leftovers(answer: str | None, units: Sequence[str], paths: Sequence[PurePosixPath]) -> list[str] | None:
    """What of ``units`` and ``paths`` :func:`leftover_command` found; ``None`` unless it answered for each."""

    if answer is None:
        return None
    lines = [line.split() for line in answer.splitlines() if line.strip()]
    expected = [["unit", unit] for unit in units] + [["file", str(path)] for path in paths]
    if len(lines) != len(expected):
        return None
    found: list[str] = []
    for words, (kind, name) in zip(lines, expected, strict=True):
        if words[:2] != [kind, name] or len(words) != (5 if kind == "unit" else 3):
            return None
        if words[-1] not in ("present", "absent"):
            return None
        if kind == "file" and words[-1] == "present":
            found.append(name)
        elif kind == "unit" and (tuple(words[2:4]) != GONE or words[-1] == "present"):
            found.append(f"{name} ({words[2]}, {words[3]}, unit file {words[4]})")
    return found


def _refuse_leftovers(cfg: OsLifecycleConfig) -> None:
    """Refuse a host that keeps units or secrets of a mode ``cfg`` leaves, before any change.

    ``ssh`` promises no listener: none of the endpoint exposure's units (both
    servers, the pull) and neither the password hash nor the collector key may
    stay. An endpoint without ``remote``: none of the pull's units and no
    collector key. A unit counts while systemd knows it in any state but
    ``not-found``/``inactive`` or its unit file exists; an incomplete answer
    refuses as well.
    """

    units: tuple[str, ...]
    paths: tuple[PurePosixPath, ...]
    if cfg.exposure == "ssh":
        units, paths, mode = ENDPOINT_UNITS, (HTPASSWD_PATH, IDENTITY_PATH), "exposure ssh"
    elif cfg.remote is None:
        units, paths, mode = REMOTE_UNITS, (IDENTITY_PATH,), "an endpoint without remote"
    else:
        return
    found = leftovers(probe(leftover_command(units, paths), name=f"what {mode} must not keep"), units, paths)
    if found is None or found:
        what = ", ".join(found) if found else "unknown (no complete answer)"
        raise DeployError(
            f"os_lifecycle: {mode}, but the host keeps units or secrets of the other mode: {what}; stop and disable "
            "those units, remove their unit files and those files first (nothing of it may stay behind)"
        )


@deploy("OS lifecycle")
def deploy_os_lifecycle(cfg: OsLifecycleConfig, secrets: SecretValues | None) -> None:
    password = bind = ""
    _refuse_leftovers(cfg)
    if cfg.exposure == "endpoint":
        if secrets is None:
            raise DeployError("os_lifecycle: exposure endpoint needs the secrets (endpoint_password)")
        password = _password(secrets)
        bind = _bind(cfg)
        if not bind:
            raise DeployError("os_lifecycle: `tailscale ip --4` printed no single IPv4 address; is Tailscale up?")
    if cfg.remote is not None and secrets is None:
        raise DeployError(f"os_lifecycle: remote needs the secrets ({PRIVATE_KEY_KEY})")

    packages = [*cfg.packages, *(["apache2-utils"] if cfg.exposure == "endpoint" else [])]
    apt.packages(name="Install the OS lifecycle packages", packages=packages)
    _account(cfg)
    group = cfg.group_name
    files.directory(name=f"Ensure {CONFIG_DIR}", path=str(CONFIG_DIR), user="root", group=group, mode="0750")
    files.directory(name=f"Ensure {cfg.site_path}", path=str(cfg.site_path), user="root", group=group, mode="0750")
    files.directory(name=f"Ensure {cfg.script_dir}", path=str(cfg.script_dir), user="root", group="root", mode="0755")
    inputs = [*_scripts(cfg, "os_lifecycle_status.py"), _put(CONFIG_DIR / "policy.json", render_policy(cfg))]
    _collector(cfg, inputs)

    if cfg.exposure == "ssh":
        assert cfg.ssh is not None
        ssh_dir = cfg.ssh.home / ".ssh"
        for directory in (cfg.ssh.home, ssh_dir):
            files.directory(name=f"Ensure {directory}", path=str(directory), user="root", group="root", mode="0755")
        _put(ssh_dir / "authorized_keys", render_authorized_keys(cfg))
        return

    assert secrets is not None
    httpd = [*_scripts(cfg, "os_lifecycle_httpd.py"), *_htpasswd(cfg, password)]
    _endpoint(cfg, bind, remote=False, inputs=httpd)
    if cfg.remote is not None:
        _remote(cfg, secrets, bind, httpd)


@deploy("OS lifecycle Nyxmon checks")
def deploy_os_lifecycle_checks(cfg: OsLifecycleChecksConfig, secrets: SecretValues) -> None:
    password = _password(secrets)
    for check in cfg.checks:
        upsert_json_metrics_check(check, password if check.auth_username is not None else None)


__all__ = [
    "PASSWORD_KEY",
    "PRIVATE_KEY_KEY",
    "EolSnapshot",
    "OsLifecycleChecksConfig",
    "OsLifecycleConfig",
    "RemoteHost",
    "RemotePull",
    "SshReport",
    "deploy_os_lifecycle",
    "deploy_os_lifecycle_checks",
]
