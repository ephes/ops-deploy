"""Certbot DNS-01 certificate lineage (the ``certbot_dns_deploy`` role).

Installs certbot with the DNS plugin, writes the provider credentials, keeps
one lineage (apex and wildcard by default) and its deploy hook, switches the
lineage's authenticator when the provider changed, removes the other
provider's unused credentials file and listed stray certbot trees, and keeps
``certbot.timer`` running. The credentials and the hook are byte-identical to
the role's templates, so a host the role set up shows no change.

The role runs ``certbot certonly --keep-until-expiring`` on every run and lets
certbot decide; that contacts the ACME server each time. Here a read-only
probe (``files/certbot_dns_host.py probe``: the lineage's renewal
configuration, live links, archive and the certificate's dates and names via
``openssl``) decides while planning whether certbot would act: ``certonly``
(the role's argv, byte for byte) runs only for a missing lineage, other names,
another key type, a pending deployment or a certificate inside its renewal
window. A converged host therefore gets no certbot command and no mutating
operation. Steps whose need depends on what an earlier step of the same run
did (``reconfigure`` after ``certonly``, the cleanup after ``reconfigure``,
the stray guard) check again on the host when they run, as the role's later
tasks do.

The provider secret (Gandi API key or TSIG key) is a deploy argument, written
with :func:`~ops_deploy.ops.secret_file` and never put on a command line.
"""

from __future__ import annotations

import ipaddress
import json
import re
import shlex
from dataclasses import dataclass
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal

from pydantic import BeforeValidator, Field, SecretStr, StrictBool, field_validator, model_validator
from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.server import Which
from pyinfra.operations import apt, files, server, systemd

from ops_deploy.base._common import AbsolutePath, RoleConfig, require_linux, require_systemd
from ops_deploy.core.secrets import SecretContent
from ops_deploy.helpers import mark_read_only
from ops_deploy.helpers.probes import probe, verify_probe
from ops_deploy.infra._common import directory
from ops_deploy.ops import secret_file

FILES = Path(__file__).parent / "files"
HOST_SCRIPT = (FILES / "certbot_dns_host.py").read_text()
# Vendored byte for byte from the role (tests/test_ops_library_drift.py).
STRAY_GUARD = (FILES / "certbot_stray_guard.py").read_text()

Provider = Literal["gandi", "rfc2136"]
PROVIDERS: tuple[Provider, ...] = ("gandi", "rfc2136")
PLUGINS = {"gandi": "python3-certbot-dns-gandi", "rfc2136": "python3-certbot-dns-rfc2136"}
KINDS = ("cert", "chain", "fullchain", "privkey")
# certbot's defaults the stray guard protects besides the config dir (tasks/stray.yml).
CERTBOT_DIRS = ("/etc/letsencrypt", "/var/lib/letsencrypt", "/var/log/letsencrypt")
DAY = 86400
# certbot's ``renew_before_expiry`` default.
DEFAULT_WINDOW = 30 * DAY

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN = re.compile(rf"(?=.{{1,253}}\Z){_LABEL}(?:\.{_LABEL})+\Z")
_EMAIL = re.compile(r"[^@\s\x00-\x1f\x7f]+@[^@\s\x00-\x1f\x7f]+\Z")
_KEY_NAME = re.compile(r"[A-Za-z0-9._-]+\Z")
_UNIT = re.compile(r"[A-Za-z0-9_.:@][A-Za-z0-9_.:@-]*\Z")
# The role's stray-dir format checks (tasks/stray.yml).
_STRAY = re.compile(r"/[A-Za-z0-9._/-]+\Z")
_DOT_SEGMENT = re.compile(r"(^|/)\.\.?(/|$)")
# ``renew_before_expiry`` forms read exactly (a bare number is days, as in certbot).
_WINDOW = re.compile(r"\s*(\d+)\s*(d|days?|w|weeks?)?\s*\Z")
_VERSIONED = re.compile(r"(cert|chain|fullchain|privkey)([0-9]+)\.pem\Z")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _domain(value: str) -> str:
    if not _DOMAIN.match(value):
        raise ValueError(f"not a lowercase DNS name: {value!r}")
    return value


def _san(value: str) -> str:
    return "*." + _domain(value[2:]) if value.startswith("*.") else _domain(value)


def _upper(value: object) -> object:
    return value.upper() if isinstance(value, str) else value


Domain = Annotated[str, BeforeValidator(_domain)]
San = Annotated[str, BeforeValidator(_san)]


def _overlaps(a: str, b: str) -> bool:
    # The guard's ``overlaps``: equal, or one contains the other.
    return a == b or a.startswith(b + "/") or b.startswith(a + "/")


class CertbotDnsConfig(RoleConfig):
    """The role's ``certbot_dns_*`` variables without the prefix.

    ``domain`` and ``email`` have no defaults here (the role's are one site's
    values). ``single_lineage`` and ``consumer_units`` are read-only checks at
    the end of the deploy, not role variables.
    """

    provider: Provider = "gandi"
    domain: Domain
    email: str
    rfc2136_server: str | None = None
    rfc2136_port: int = Field(default=53, ge=1, le=65535)
    rfc2136_key_name: str | None = None
    rfc2136_key_algorithm: Annotated[Literal["HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512"], BeforeValidator(_upper)] = (
        "HMAC-SHA256"
    )
    wildcard: StrictBool = True
    include_base: StrictBool = True
    additional_domains: tuple[San, ...] = ()
    key_type: Literal["rsa", "ecdsa"] = "ecdsa"
    staging: StrictBool = False
    propagation_seconds: int = Field(default=120, ge=0)
    # Neither the role's certbot commands nor certbot itself take another
    # directory (no --config-dir), so only the default is accepted.
    config_dir: Literal["/etc/letsencrypt"] = "/etc/letsencrypt"
    credentials_file: AbsolutePath = "/etc/letsencrypt/dns-credentials.ini"
    rfc2136_credentials_file: AbsolutePath = "/etc/letsencrypt/dns-rfc2136-credentials.ini"
    renewal_hook_path: AbsolutePath = "/etc/letsencrypt/renewal-hooks/deploy/reload-services.sh"
    renewal_hooks: tuple[str, ...] = ()
    reconfigure_on_provider_change: StrictBool = True
    remove_unused_credentials: StrictBool = True
    stray_config_dirs: tuple[str, ...] = ()
    package_state: Literal["present", "latest"] = "present"
    # The renewal directory must hold exactly this lineage's configuration
    # (a host-wide deploy hook is only safe for one lineage).
    single_lineage: StrictBool = False
    # Units that read the certificate; each must be loaded and active.
    consumer_units: tuple[str, ...] = ()

    @field_validator("email")
    @classmethod
    def _email(cls, value: str) -> str:
        if not _EMAIL.match(value):
            raise ValueError("email must be a single address")
        return value

    @field_validator("rfc2136_server")
    @classmethod
    def _server_is_an_address(cls, value: str | None) -> str | None:
        # The plugin hands it to dnspython, which needs an address, not a name.
        if value is not None:
            try:
                ipaddress.ip_address(value)
            except ValueError:
                raise ValueError("rfc2136_server must be an IP address") from None
        return value

    @field_validator("rfc2136_key_name")
    @classmethod
    def _key_name(cls, value: str | None) -> str | None:
        if value is not None and (not _KEY_NAME.match(value) or value == "CHANGEME"):
            raise ValueError("rfc2136_key_name must be a TSIG key name (letters, digits, '.', '_', '-')")
        return value

    @field_validator("renewal_hooks")
    @classmethod
    def _hooks(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any("\x00" in hook for hook in value):
            raise ValueError("renewal_hooks must not contain NUL characters")
        return value

    @field_validator("consumer_units")
    @classmethod
    def _units(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for unit in value:
            if not _UNIT.match(unit):
                raise ValueError(f"not a systemd unit name: {unit!r}")
        return value

    @field_validator("stray_config_dirs")
    @classmethod
    def _stray_format(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for path in value:
            if (
                not _STRAY.match(path)
                or path.startswith("//")
                or "//" in path
                or path.endswith("/")
                or _DOT_SEGMENT.search(path)
            ):
                raise ValueError(
                    f"Refusing stray certbot dir {path}: only absolute, normalized paths of letters, digits, "
                    "'.', '_', '-' and '/' without '.'/'..' segments or a trailing slash are accepted."
                )
        return value

    @model_validator(mode="after")
    def _consistent(self) -> CertbotDnsConfig:
        if self.provider == "rfc2136" and (self.rfc2136_server is None or self.rfc2136_key_name is None):
            raise ValueError("rfc2136: set rfc2136_server (an IP address) and rfc2136_key_name")
        if not self.domains:
            raise ValueError("No domains requested for certificate")
        for path in self.stray_config_dirs:
            # The guard refuses these on the host too; the given paths are known now.
            if any(_overlaps(path, protected) for protected in self.protected_dirs):
                raise ValueError(f"Refusing stray certbot dir {path}: it overlaps a live certbot dir")
        return self

    @property
    def domains(self) -> tuple[str, ...]:
        """The role's domain list: base, wildcard, extras, first occurrence kept."""

        names = [self.domain] if self.include_base else []
        names += [f"*.{self.domain}"] if self.wildcard else []
        return tuple(dict.fromkeys([*names, *self.additional_domains]))

    @property
    def active_credentials_file(self) -> str:
        return self.rfc2136_credentials_file if self.provider == "rfc2136" else self.credentials_file

    @property
    def inactive_credentials_files(self) -> tuple[str, ...]:
        both = dict.fromkeys([self.credentials_file, self.rfc2136_credentials_file])
        return tuple(path for path in both if path != self.active_credentials_file)

    @property
    def renewal_conf(self) -> str:
        return f"{self.config_dir}/renewal/{self.domain}.conf"

    @property
    def protected_dirs(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys([self.config_dir, *CERTBOT_DIRS]))


def render_credentials(cfg: CertbotDnsConfig, secret: SecretStr) -> str:
    """``dns-credentials.ini.j2`` from the role, byte for byte."""

    head = "# DNS provider credentials for Certbot (managed by Ansible)\n\n"
    value = secret.get_secret_value()
    if cfg.provider == "gandi":
        return f"{head}# Gandi LiveDNS API key\ndns_gandi_api_key = {value}\n"
    return (
        f"{head}# RFC 2136 DNS UPDATE, authenticated with TSIG\n"
        f"dns_rfc2136_server = {cfg.rfc2136_server}\n"
        f"dns_rfc2136_port = {cfg.rfc2136_port}\n"
        f"dns_rfc2136_name = {cfg.rfc2136_key_name}\n"
        f"dns_rfc2136_secret = {value}\n"
        f"dns_rfc2136_algorithm = {cfg.rfc2136_key_algorithm}\n"
    )


def render_hook(cfg: CertbotDnsConfig) -> str:
    """``renewal-hooks.sh.j2`` from the role, byte for byte."""

    text = "#!/bin/bash\nset -uo pipefail\n\n# Managed by Ansible - commands run after certificate renewal\n\n"
    if not cfg.renewal_hooks:
        return text + "exit 0\n"
    text += "hook_status=0\n"
    for index, hook in enumerate(cfg.renewal_hooks, start=1):
        text += (
            f"(\n  set -e\n{hook}\n)\nhook_rc=$?\n"
            'if [ "$hook_rc" -ne 0 ]; then\n'
            f"  printf 'Certbot renewal hook item {index} failed (rc=%s) lineage=%s\\n' \\\n"
            '    "$hook_rc" "${RENEWED_LINEAGE:-unknown}" >&2\n'
            "  hook_status=1\nfi\n"
        )
    return text + 'exit "$hook_status"\n'


def certonly_argv(cfg: CertbotDnsConfig) -> list[str]:
    """The role's ``certbot certonly`` argv (each domain as one ``-d <name>`` word, as there)."""

    plugin = f"dns-{cfg.provider}"
    return [
        "certbot",
        "certonly",
        "--non-interactive",
        "--agree-tos",
        "--email",
        cfg.email,
        "--authenticator",
        plugin,
        f"--{plugin}-credentials",
        cfg.active_credentials_file,
        f"--{plugin}-propagation-seconds",
        str(cfg.propagation_seconds),
        "--cert-name",
        cfg.domain,
        "--key-type",
        cfg.key_type,
        "--keep-until-expiring",
        "--expand",
        *(["--staging"] if cfg.staging else []),
        *(f"-d {name}" for name in cfg.domains),
    ]


def reconfigure_argv(cfg: CertbotDnsConfig) -> list[str]:
    plugin = f"dns-{cfg.provider}"
    return [
        "certbot",
        "reconfigure",
        "--non-interactive",
        "--cert-name",
        cfg.domain,
        "--authenticator",
        plugin,
        f"--{plugin}-credentials",
        cfg.active_credentials_file,
        f"--{plugin}-propagation-seconds",
        str(cfg.propagation_seconds),
    ]


def host_command(*args: str, env: dict[str, str] | None = None) -> str:
    """``files/certbot_dns_host.py`` with ``args``, isolated from the host's Python setup."""

    assignments = [f"{key}={value}" for key, value in (env or {}).items()]
    return shlex.join([*(["env", *assignments] if assignments else []), "python3", "-I", "-c", HOST_SCRIPT, *args])


def probe_command(cfg: CertbotDnsConfig) -> str:
    inactive = json.dumps(list(cfg.inactive_credentials_files) if cfg.remove_unused_credentials else [])
    return host_command("probe", cfg.config_dir, cfg.domain, inactive, json.dumps(list(cfg.stray_config_dirs)))


def guard_input(cfg: CertbotDnsConfig) -> str:
    return json.dumps(
        {"stray": list(cfg.stray_config_dirs), "protected": list(cfg.protected_dirs), "config_dir": cfg.config_dir}
    )


def guard_command(cfg: CertbotDnsConfig) -> str:
    return shlex.join(["env", f"CERTBOT_STRAY_INPUT={guard_input(cfg)}", "python3", "-I", "-c", STRAY_GUARD])


@dataclass(frozen=True)
class Lineage:
    """What the probe saw (``None`` fields: not there)."""

    config_dir: str
    now: int
    conf: dict[str, Any] | None
    cert: dict[str, Any] | None
    links: dict[str, dict[str, Any]]
    archive: tuple[str, ...]
    inactive: dict[str, dict[str, Any]]
    stray: dict[str, bool]

    @classmethod
    def parse(cls, output: str | None) -> Lineage | None:
        if output is None:
            return None
        try:
            data = json.loads(output)
            return cls(
                config_dir=str(data["config_dir"]),
                now=int(data["now"]),
                conf=data["conf"],
                cert=data["cert"],
                links=dict(data["links"]),
                archive=tuple(data["archive"]),
                inactive=dict(data["inactive"]),
                stray={str(k): bool(v) for k, v in data["stray"].items()},
            )
        except (ValueError, KeyError, TypeError):
            return None

    @property
    def authenticator(self) -> str:
        return str(self.conf["authenticator"]) if self.conf else ""


def _window(value: str | None, cert: dict[str, Any]) -> int | None:
    """Seconds before expiry certbot renews; ``None`` if ``value`` is not understood."""

    if value is None:
        # certbot 2.x renews 30 days before expiry; newer releases at a third
        # of the lifetime left. The longer of the two (the earlier date) wins.
        return max(DEFAULT_WINDOW, (int(cert["not_after"]) - int(cert["not_before"])) // 3)
    match = _WINDOW.match(value)
    if not match:
        return None
    count, unit = int(match.group(1)), match.group(2) or "d"
    return count * DAY * (7 if unit.startswith("w") else 1)


def _latest_common(archive: tuple[str, ...]) -> int:
    versions: dict[str, set[int]] = {kind: set() for kind in KINDS}
    for name in archive:
        match = _VERSIONED.match(name)
        if match:
            versions[match.group(1)].add(int(match.group(2)))
    return max(set.intersection(*versions.values()), default=0)


def renewal_due(cfg: CertbotDnsConfig, state: Lineage | None) -> str | None:
    """Why ``certonly`` must run (certbot would issue, renew or relink), or ``None``.

    Mirrors certbot's ``certonly --keep-until-expiring --expand --cert-name``:
    a missing lineage or other names mean a new certificate; another key type
    a renewal; live links that are not on the latest archive version a
    redeployment; otherwise renewal when the certificate is inside its renewal
    window (unless the lineage turned automatic renewal off). Anything the
    probe cannot read exactly counts as due: ``certonly`` then decides, as in
    the role.
    """

    if state is None:
        return "the lineage probe failed"
    if state.conf is None:
        return "no lineage yet"
    if state.conf.get("malformed", True):
        return "the renewal configuration is not plain configobj certbot would read"
    values = state.conf.get("values") or {}
    base = state.config_dir
    expected = {
        "archive_dir": f"{base}/archive/{cfg.domain}",
        **{kind: f"{base}/live/{cfg.domain}/{kind}.pem" for kind in KINDS},
    }
    if any(values.get(key) != path for key, path in expected.items()):
        return "the renewal configuration does not use the standard paths"
    if state.cert is None:
        return "the live certificate is missing"
    names = {str(name).lower() for name in state.cert["names"]}
    if names != {name.lower() for name in cfg.domains}:
        return "the certificate names differ"
    # With --key-type and --cert-name given, another key type renews at once.
    if str(state.cert.get("key_type", "")).upper() != cfg.key_type.upper():
        return "the key type changes"
    latest = _latest_common(state.archive)
    for kind in KINDS:
        link = state.links.get(kind) or {}
        target = link.get("target")
        match = _VERSIONED.match(PurePosixPath(str(target)).name) if target and link.get("exists") else None
        if not match or match.group(1) != kind or int(match.group(2)) < latest:
            return "the live links are not on the latest certificate"
    autorenew = state.conf.get("autorenew")
    if autorenew is not None:
        if str(autorenew).lower() in ("false", "no", "off", "0"):
            return None
        if str(autorenew).lower() not in ("true", "yes", "on", "1"):
            return "autorenew is not understood"
    window = _window(values.get("renew_before_expiry"), state.cert)
    if window is None:
        return "renew_before_expiry is not understood"
    if int(state.cert["not_after"]) < state.now + window:
        return "the certificate is inside its renewal window"
    return None


def _check_secret(cfg: CertbotDnsConfig, secret: SecretStr) -> None:
    value = secret.get_secret_value()
    what = "Gandi API token" if cfg.provider == "gandi" else "TSIG key secret"
    if not value or value == "CHANGEME":
        raise DeployError(f"certbot_dns: set the {what} (not CHANGEME)")
    if _CONTROL.search(value):
        # One line of the credentials file; a newline would add settings.
        raise DeployError(f"certbot_dns: the {what} must not contain control characters")


def _stray_decision(cfg: CertbotDnsConfig, state: Lineage) -> bool:
    """Whether a stray dir will be removed; refuses what the role refuses.

    With the lineage in place the guard runs now (read-only), so a refusal
    fails the deploy before any change. Without it (a first run, where
    ``certonly`` creates the renewal configuration the guard requires) the
    removal step runs when a listed dir exists, and its own guard run decides.
    """

    if state.conf is None:
        return any(state.stray.get(path) for path in cfg.stray_config_dirs)
    output = probe(guard_command(cfg), name="certbot stray guard")
    if output is None:
        raise DeployError("certbot_dns: the stray certbot dir guard failed")
    try:
        decision = json.loads(output)
        refused, remove, skipped = decision["refused"], decision["remove"], decision["skipped"]
    except (ValueError, KeyError, TypeError):
        raise DeployError("certbot_dns: the stray certbot dir guard printed something unexpected") from None
    if refused or sorted(remove + skipped) != sorted(cfg.stray_config_dirs):
        raise DeployError(f"Refusing stray certbot dirs, nothing removed: {json.dumps(refused)}")
    return bool(remove)


def _check(name: str, test: str, message: str) -> None:
    mark_read_only(server.shell(name=name, commands=[f"{test} || {{ echo {shlex.quote(message)} >&2; exit 1; }}"]))


def _final_checks(cfg: CertbotDnsConfig) -> None:
    hook = shlex.quote(cfg.renewal_hook_path)
    _check(
        "Check the renewal hook",
        f'test -f {hook} && test ! -L {hook} && [ "$(stat -c %a {hook})" = 755 ]',
        f"{cfg.renewal_hook_path} must be a regular executable file with mode 0755",
    )
    if cfg.single_lineage:
        renewal = shlex.quote(f"{cfg.config_dir}/renewal")
        # Every entry certbot's ``renewal/*.conf`` glob finds, symlinks included.
        found = f"found=$(find {renewal} -mindepth 1 -maxdepth 1 -name '*.conf' ! -name '.*' | LC_ALL=C sort)"
        _check(
            "Check the lineage is the only one",
            f'{found} && [ "$found" = {shlex.quote(cfg.renewal_conf)} ]',
            f"{cfg.config_dir}/renewal must hold only {cfg.domain}.conf (the deploy hook serves one lineage)",
        )
    for unit in cfg.consumer_units:
        show = shlex.join(["systemctl", "show", "--property=LoadState", "--property=ActiveState", unit])
        _check(
            f"Check {unit} is loaded and active",
            f"s=$({show}) && printf '%s\\n' \"$s\" | grep -qxF LoadState=loaded "
            f"&& printf '%s\\n' \"$s\" | grep -qxF ActiveState=active",
            f"Certificate consumer {unit} is not both loaded and active",
        )


@deploy("certbot DNS")
def deploy_certbot_dns(cfg: CertbotDnsConfig, secret: SecretStr) -> None:
    """Install certbot, keep the lineage, its hook and the timer; see the module docstring."""

    require_linux("certbot_dns")
    if not host.get_fact(Which, command="apt-get"):
        raise DeployError("certbot_dns needs a Debian-family host")
    require_systemd("certbot_dns")
    _check_secret(cfg, secret)

    command = probe_command(cfg)
    output = probe(command, name="certbot lineage")
    state = Lineage.parse(output)
    if output is not None and state is None:
        raise DeployError("certbot_dns: the lineage probe printed something unexpected")
    remove_stray = bool(cfg.stray_config_dirs) and (state is None or _stray_decision(cfg, state))

    apt.packages(
        name="Install certbot and the DNS plugin",
        packages=["certbot", PLUGINS[cfg.provider]],
        present=True,
        latest=cfg.package_state == "latest",
    )
    directory(cfg.config_dir, user="root", group="root", mode="0755")
    secret_file(
        name=f"Write {cfg.active_credentials_file}",
        path=cfg.active_credentials_file,
        content=SecretContent(render_credentials(cfg, secret)),
        user="root",
        group="root",
        mode="0600",
    )

    target = f"dns-{cfg.provider}"
    certonly = renewal_due(cfg, state) is not None
    if certonly:
        server.shell(name="Request or renew the certificate", commands=[shlex.join(certonly_argv(cfg))])

    # The role reads the authenticator after certonly (which may have renewed
    # with the configured one), so the step checks again when it runs.
    reconfigure = cfg.reconfigure_on_provider_change and (state is None or state.authenticator not in ("", target))
    if reconfigure:
        current = host_command("authenticator", cfg.renewal_conf)
        server.shell(
            name=f"Switch the lineage to {target}",
            commands=[
                f"cur=$({current}) || exit 1; "
                f'if [ -n "$cur" ] && [ "$cur" != {target} ]; then {shlex.join(reconfigure_argv(cfg))}; fi'
            ],
        )

    if cfg.remove_unused_credentials:
        others = state is None or any(p != cfg.provider for p in (state.conf or {}).get("settings", ()))
        drop = others and (state is None or state.authenticator == target or reconfigure)
        if drop:
            server.shell(
                name="Drop the other providers' settings from the lineage",
                commands=[host_command("drop-settings", cfg.renewal_conf, cfg.provider)],
            )
        for path in cfg.inactive_credentials_files:
            found = (state.inactive.get(path) or {}) if state else {}
            kind = found.get("kind", "file") if state else "file"
            if kind == "missing":
                continue
            if kind == "other":
                raise DeployError(f"certbot_dns: {path} is not a regular file or symlink")
            # Only an unused file goes (grep exit 1); 0 (in use) and 2 (scan error)
            # keep it, unless an earlier step of this run can still change that.
            if state is not None and found.get("rc") in (0, 2) and not (certonly or reconfigure or drop):
                continue
            scan = shlex.join(["sh", "-c", 'exec grep -l -F -e "$1" -- "$2"/*.conf', "sh", path])
            server.shell(
                name=f"Remove {path} once no lineage uses it",
                commands=[
                    f"{scan} {shlex.quote(cfg.config_dir + '/renewal')} >/dev/null 2>&1; rc=$?; "
                    f"case $rc in 1) rm -f -- {shlex.quote(path)} ;; 0|2) ;; *) exit $rc ;; esac"
                ],
            )

    if remove_stray:
        # The guard again, now that the lineage exists; only its decision is applied.
        apply = host_command("remove-stray", env={"CERTBOT_STRAY_INPUT": guard_input(cfg)})
        server.shell(
            name="Remove listed stray certbot dirs",
            commands=[f'out=$({guard_command(cfg)}) || exit 1; printf %s "$out" | {apply}'],
        )

    hook_dir = str(PurePosixPath(cfg.renewal_hook_path).parent)
    directory(hook_dir, user="root", group="root", mode="0755")
    files.put(
        name=f"Write {cfg.renewal_hook_path}",
        src=StringIO(render_hook(cfg)),
        dest=cfg.renewal_hook_path,
        user="root",
        group="root",
        mode="0755",
    )
    systemd.service(name="Ensure certbot.timer", service="certbot.timer", running=True, enabled=True)

    if output is None:
        verify_probe(command, name="certbot lineage")
    _final_checks(cfg)
