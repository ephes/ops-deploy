"""Typed configuration of one Docker Compose app (the parts, then :class:`ComposeAppConfig`).

ops-control supplies data only; everything a deploy writes is derived from it
here and in :mod:`.render`. Unknown keys fail, every value that lands in the
compose file, a unit or a shell line is checked against a narrow pattern, and
the keys of the app's secrets follow from its :class:`Secret` references
(:attr:`ComposeAppConfig.required_secret_keys`).

Values are literals or references, resolved as late as possible:

- :class:`Secret`: a key of the app's decrypted SOPS mapping (controller, in memory);
- :class:`HostId`: the uid of a user or the gid of a group on the target (on the host);
- :class:`HostSecret`: a secret created once on the host and never read back
  to the controller; an existing file is adopted unchanged (on the host).

A tuple of pieces is their concatenation (a JSON value that carries a host key).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator
from pathlib import PurePosixPath
from typing import Annotated, Any, Literal, Self

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, field_validator, model_validator

from ops_deploy.core.config import BaseServiceConfig, ServiceName, UnixUser
from ops_deploy.helpers.traefik import DEFAULT_INTERNAL_IP_RANGES, Hostname
from ops_deploy.infra.docker_install import DockerInstallConfig

ComposeProject = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,62}$")]
ServiceKey = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_-]{0,62}$")]
UnitName = Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{0,62}$")]
NetworkName = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,62}$")]
FileName = Annotated[str, Field(pattern=r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$")]
EnvKey = Annotated[str, Field(pattern=r"^[A-Z_][A-Z0-9_]*$")]
SecretKey = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$")]
# A systemd ``Description=`` and YAML comments: one plain line.
Label = Annotated[str, Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9 .,:;()/_+-]+$")]
# ``repo[:tag]@sha256:<digest>``: the tag is for people, the digest makes it immutable.
ImageRef = Annotated[
    str,
    Field(
        pattern=r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
        r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@sha256:[0-9a-f]{64}$"
    ),
]
Mode = Annotated[str, Field(pattern=r"^0?[0-7]{3,4}$")]
# A user or group by name, or a numeric id (a container's user without a name on the host).
Owner = Annotated[str, Field(pattern=r"^([a-z_][a-z0-9_-]{0,31}|[0-9]{1,10})$")]
Duration = Annotated[str, Field(pattern=r"^[0-9]+(ms|s|m|h)$")]
# argv words of a command, a healthcheck or an entrypoint: no line breaks.
Word = Annotated[str, Field(min_length=1, pattern=r"^[^\r\n\x00]+$")]

STATE_ROOT = PurePosixPath("/var/lib/ops-deploy")


def plain_path(value: PurePosixPath) -> PurePosixPath:
    """An absolute path below ``/`` that templates and shell lines can carry unquoted."""

    if not re.fullmatch(r"(/[A-Za-z0-9_.-]+)+", str(value)) or ".." in value.parts:
        raise ValueError("must be an absolute path of letters, digits and _ . -")
    return value


PlainPath = Annotated[PurePosixPath, AfterValidator(plain_path)]


class Part(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


# -- values -------------------------------------------------------------------


class Secret(Part):
    """A value of the app's secrets by key.

    ``form``: ``int`` (digits; a number in JSON), or ``first_ipv4``: the first
    IPv4 entry of a comma-separated address list (WireGuard ``Address =``
    lines carry IPv4 and IPv6 addresses).
    """

    secret: SecretKey
    form: Literal["text", "int", "first_ipv4"] = "text"


class HostSecret(Part):
    """A secret file on the host, created once (``secrets.token_urlsafe(bytes)``, root ``0600``)."""

    host_secret: PlainPath
    bytes: int = Field(default=24, ge=16, le=64)


class HostId(Part):
    """The uid of ``user`` or the gid of ``group`` on the target (``PUID``, ``PGID``)."""

    user: UnixUser | None = None
    group: UnixUser | None = None

    @model_validator(mode="after")
    def _one(self) -> Self:
        if (self.user is None) == (self.group is None):
            raise ValueError("a HostId names exactly one of user or group")
        return self

    @property
    def ref(self) -> tuple[str, str]:
        return ("user", self.user) if self.user is not None else ("group", self.group or "")


Piece = Annotated[str | Secret | HostSecret | HostId, Field(union_mode="left_to_right")]
EnvValue = Annotated[str | Secret | HostSecret | HostId | tuple[Piece, ...], Field(union_mode="left_to_right")]


def pieces(value: EnvValue) -> tuple[str | Secret | HostSecret | HostId, ...]:
    return value if isinstance(value, tuple) else (value,)


class EnvEntry(Part):
    key: EnvKey
    value: EnvValue


class EnvFile(Part):
    """``<dir>/<name>``: one ``KEY='value'`` line per entry, read by the services that list it."""

    name: FileName
    mode: Mode = "0600"
    entries: tuple[EnvEntry, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _unique_keys(self) -> Self:
        keys = [entry.key for entry in self.entries]
        repeated = sorted({key for key in keys if keys.count(key) > 1})
        if repeated:
            raise ValueError(f"env file {self.name} repeats {', '.join(repeated)}")
        return self

    @property
    def host_rendered(self) -> bool:
        """Whether a value needs the host (a :class:`HostSecret` or :class:`HostId`)."""

        return any(isinstance(p, (HostSecret, HostId)) for e in self.entries for p in pieces(e.value))


class EnvRef(Part):
    """A YAML ``!env_var NAME`` leaf: the app reads the value from its environment (Recyclarr).

    Lets a config file name a value that only its env file carries, such as
    another app's :class:`HostSecret` API key, without the file holding it.
    """

    env_var: EnvKey


class ConfigFile(Part):
    """A file a service reads through a bind mount, rendered from data (``Secret`` leaves allowed).

    YAML files may also carry :class:`EnvRef` leaves (``{"env_var": "NAME"}``).

    Compose does not see a change in a mounted file, so the services in
    ``restarts`` are restarted when it changes.
    """

    path: PlainPath
    format: Literal["yaml", "json"]
    data: dict[str, Any]
    mode: Mode = "0644"
    owner: Owner = "root"
    group: Owner = "root"
    restarts: tuple[ServiceKey, ...] = ()

    @field_validator("data", mode="before")
    @classmethod
    def _secret_leaves(cls, value: Any) -> Any:
        return _config_value(value)

    @model_validator(mode="after")
    def _env_refs_in_yaml(self) -> Self:
        if self.format != "yaml" and any(isinstance(leaf, EnvRef) for leaf in _leaves(self.data)):
            raise ValueError(f"config file {self.path}: env_var references need format yaml")
        return self


def _config_value(value: Any) -> Any:
    """Plain JSON data, with ``{"secret": key[, "form": ...]}`` mappings read as :class:`Secret`."""

    if isinstance(value, (Secret, EnvRef, str, bool, int, float)) or value is None:
        return value
    if isinstance(value, dict):
        if "secret" in value:
            return Secret.model_validate(value)
        if "env_var" in value:
            return EnvRef.model_validate(value)
        if not all(isinstance(key, str) for key in value):
            raise ValueError("config file keys must be strings")
        return {key: _config_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_config_value(item) for item in value]
    raise ValueError("config file data must be JSON values or secrets")


# -- compose services -------------------------------------------------------------


class PublishedPort(Part):
    """A port published on the host; loopback unless ``exposure_reason`` says why not."""

    published: int = Field(ge=1, le=65535)
    target: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    host_ip: str = "127.0.0.1"
    exposure_reason: Label | None = None

    @field_validator("host_ip")
    @classmethod
    def _address(cls, value: str) -> str:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise ValueError("host_ip must be an IP address") from None
        return value

    @model_validator(mode="after")
    def _loopback(self) -> Self:
        if not ipaddress.ip_address(self.host_ip).is_loopback and self.exposure_reason is None:
            raise ValueError(f"port {self.published} binds {self.host_ip}: an exposure_reason is required")
        return self


class Bind(Part):
    """A bind mount; ``target`` defaults to ``source`` (the same path inside and outside)."""

    source: PlainPath
    target: PlainPath | None = None
    read_only: bool = False

    @property
    def container_path(self) -> PurePosixPath:
        return self.target or self.source


class Healthcheck(Part):
    test: tuple[Word, ...] = Field(min_length=2)
    interval: Duration = "30s"
    timeout: Duration = "10s"
    retries: int = Field(default=3, ge=1, le=100)
    start_period: Duration = "0s"

    @field_validator("test")
    @classmethod
    def _form(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value[0] not in ("CMD", "CMD-SHELL"):
            raise ValueError("healthcheck test starts with CMD or CMD-SHELL")
        return value


class DependsOn(Part):
    service: ServiceKey
    condition: Literal["service_started", "service_healthy"] = "service_started"


class Sysctl(Part):
    key: Annotated[str, Field(pattern=r"^[a-z0-9_]+(\.[a-z0-9_]+)+$")]
    value: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]+$")]


class ComposeService(Part):
    """One compose service; the keys the apps on the fleet use, nothing passed through."""

    name: ServiceKey
    image: ImageRef
    container_name: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,62}$")] | None = None
    command: tuple[Word, ...] | None = None
    entrypoint: tuple[Word, ...] | None = None
    user: Annotated[str, Field(pattern=r"^[0-9]+(:[0-9]+)?$")] | None = None
    profiles: tuple[Annotated[str, Field(pattern=r"^[a-z][a-z0-9_-]*$")], ...] = ()
    # "host", or "service:<name>" (a service of this app whose network namespace it joins).
    network_mode: Annotated[str, Field(pattern=r"^(host|service:[a-z][a-z0-9_-]{0,62})$")] | None = None
    host_network_reason: Label | None = None
    # The app's external networks this service joins (besides the project network).
    networks: tuple[NetworkName, ...] = ()
    ports: tuple[PublishedPort, ...] = ()
    env_files: tuple[FileName, ...] = ()
    # Non-secret literals only; secrets go through an env file.
    environment: tuple[EnvEntry, ...] = ()
    binds: tuple[Bind, ...] = ()
    # The privileges a service may ask for; anything else is a public change.
    cap_add: tuple[Literal["NET_ADMIN", "SYS_ADMIN"], ...] = ()
    devices: tuple[Literal["/dev/net/tun"], ...] = ()
    sysctls: tuple[Sysctl, ...] = ()
    shm_size: Annotated[str, Field(pattern=r"^[0-9]+[bkmg]?$")] | None = None
    mem_limit: Annotated[str, Field(pattern=r"^[0-9]+[bkmg]?$")] | None = None
    cpus: Annotated[str, Field(pattern=r"^[0-9]+(\.[0-9]+)?$")] | None = None
    pids_limit: int | None = Field(default=None, ge=1)
    restart: Literal["unless-stopped", "always", "on-failure", "no"] = "unless-stopped"
    depends_on: tuple[DependsOn, ...] = ()
    healthcheck: Healthcheck | None = None

    @field_validator("environment")
    @classmethod
    def _literal_environment(cls, value: tuple[EnvEntry, ...]) -> tuple[EnvEntry, ...]:
        if any(not isinstance(entry.value, str) for entry in value):
            raise ValueError("environment takes literals only; put secrets and host values in an env file")
        return value

    @model_validator(mode="after")
    def _network(self) -> Self:
        if self.network_mode == "host" and self.host_network_reason is None:
            raise ValueError(f"service {self.name}: network_mode host needs a host_network_reason")
        if self.network_mode is not None and (self.ports or self.networks):
            raise ValueError(
                f"service {self.name}: a service with a network_mode publishes no ports and joins no networks"
            )
        return self

    @property
    def provider(self) -> str | None:
        """The service whose network namespace this one joins (``network_mode: service:X``)."""

        if self.network_mode and self.network_mode.startswith("service:"):
            return self.network_mode.removeprefix("service:")
        return None


# -- users and directories -------------------------------------------------------


class AppUser(Part):
    """A nologin system user; an existing one only gets the missing ``groups`` appended."""

    name: UnixUser
    # Primary group; default: a group named like the user.
    group: UnixUser | None = None
    groups: tuple[UnixUser, ...] = ()
    home: PlainPath
    shell: Literal["/usr/sbin/nologin", "/bin/false"] = "/usr/sbin/nologin"

    @property
    def primary_group(self) -> str:
        return self.group or self.name


class Directory(Part):
    """A directory with its owner, group and mode (``"2775"`` keeps setgid).

    Owner and group are both names or both numeric ids.
    """

    path: PlainPath
    owner: Owner = "root"
    group: Owner = "root"
    mode: Mode = "0755"

    @model_validator(mode="after")
    def _same_kind(self) -> Self:
        if self.owner.isdigit() != self.group.isdigit():
            raise ValueError(f"directory {self.path}: owner and group are both names or both numeric ids")
        return self


class RequiredPath(Part):
    """A path the app needs and does not create; the deploy stops before any change without it."""

    path: PlainPath
    hint: Label


# -- route, steps and checks -------------------------------------------------------


class Route(Part):
    """``/etc/traefik/dynamic/<name>.yml`` (the shared helper's route); Traefik is never restarted.

    ``access``: ``internal`` (LAN and tailnet only), ``internal_or_basic_auth``
    (internal without auth, everyone else with Basic Auth), or ``public``
    (with a ``public_reason``).
    """

    name: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,62}$")] | None = None
    host: Hostname
    # A host port the app publishes on loopback.
    port: int = Field(ge=1, le=65535)
    access: Literal["internal", "internal_or_basic_auth", "public"]
    basic_auth_user: Annotated[str | Secret, Field(union_mode="left_to_right")] | None = None
    basic_auth_password: Secret | None = None
    public_reason: Label | None = None
    internal_ip_ranges: tuple[str, ...] = DEFAULT_INTERNAL_IP_RANGES
    frame_options: Literal["DENY", "SAMEORIGIN"] = "DENY"

    @model_validator(mode="after")
    def _access(self) -> Self:
        auth = self.basic_auth_user is not None or self.basic_auth_password is not None
        if self.access == "internal_or_basic_auth":
            if self.basic_auth_user is None or self.basic_auth_password is None:
                raise ValueError("internal_or_basic_auth needs basic_auth_user and basic_auth_password")
        elif auth:
            raise ValueError(f"access {self.access} takes no basic auth")
        if (self.access == "public") != (self.public_reason is not None):
            raise ValueError("public_reason is required for access public, and only there")
        return self


PrefValue = Annotated[Secret | bool | int | float | str, Field(union_mode="left_to_right")]


class QbittorrentPreferences(Part):
    """qBittorrent's WebUI credentials and a subset of its preferences, reconciled by drift.

    ``service`` is the compose service whose log holds the temporary password
    qBittorrent prints on a first start (the credentials bootstrap).
    """

    kind: Literal["qbittorrent_preferences"] = "qbittorrent_preferences"
    service: ServiceKey
    port: int = Field(ge=1, le=65535)
    username: Annotated[str | Secret, Field(union_mode="left_to_right")]
    password: Secret
    preferences: dict[Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$")], PrefValue] = Field(min_length=1)
    wait_seconds: int = Field(default=60, ge=1, le=600)


class JsonKeyCopy(Part):
    """Copy a key an app generates (a JSON file on the host) into another app's JSON config.

    Waits until ``source`` holds one of ``keys``; ``dest`` is ``template``
    with every ``"{value}"`` string replaced by it (JSON, 4-space indent).
    """

    kind: Literal["json_key_copy"] = "json_key_copy"
    name: Label
    source: PlainPath
    keys: tuple[Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")], ...] = Field(min_length=1)
    dest: PlainPath
    template: dict[str, Any]
    owner: Owner = "root"
    group: Owner = "root"
    mode: Mode = "0640"
    wait_seconds: int = Field(default=120, ge=1, le=600)

    @field_validator("template")
    @classmethod
    def _placeholder(cls, value: dict[str, Any]) -> dict[str, Any]:
        if "{value}" not in _strings(value):
            raise ValueError('template needs a "{value}" string')
        return value


# An API path below the app's prefix: no query, no spaces, no dot segments.
ApiPath = Annotated[str, Field(pattern=r"^(/[A-Za-z0-9_-]+)+$")]
# A key of a JSON object, or ``fields.<name>`` for a Servarr field.
JsonKey = Annotated[str, Field(pattern=r"^(fields\.)?[A-Za-z_][A-Za-z0-9_]*$")]


def _api_value(value: Any) -> Any:
    """JSON data with ``{"secret": ...}`` read as :class:`Secret`, ``{"host_secret": ...}`` as :class:`HostSecret`."""

    if isinstance(value, (Secret, HostSecret, str, bool, int, float)) or value is None:
        return value
    if isinstance(value, dict):
        if "secret" in value:
            return Secret.model_validate(value)
        if "host_secret" in value:
            return HostSecret.model_validate(value)
        if not all(isinstance(key, str) for key in value):
            raise ValueError("API data keys must be strings")
        return {key: _api_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_api_value(item) for item in value]
    raise ValueError("API data must be JSON values, secrets or host secrets")


class ApiAuth(Part):
    """A header carrying the app's API key (Servarr: ``X-Api-Key``)."""

    header: Annotated[str, Field(pattern=r"^[A-Za-z][A-Za-z0-9-]{0,62}$")] = "X-Api-Key"
    value: Annotated[Secret | HostSecret, Field(union_mode="left_to_right")]


class _HttpJson(Part):
    """Common fields of the JSON API kinds: the app's loopback port, API prefix and auth."""

    name: Label
    port: int = Field(ge=1, le=65535)
    prefix: Annotated[str, Field(pattern=r"^(/[A-Za-z0-9_-]+)*$")] = ""
    path: ApiPath
    auth: ApiAuth
    # Keys the API masks on reads (passwords, API keys): not compared, tracked by digest.
    write_only: tuple[JsonKey, ...] = ()
    # Directory paths the API returns with a trailing slash: one is ignored when comparing.
    path_keys: tuple[JsonKey, ...] = ()
    wait_seconds: int = Field(default=120, ge=1, le=600)


class HttpJsonSettings(_HttpJson):
    """One settings object: ``GET <path>``, ``PUT <path>/<id>`` with ``desired`` merged in.

    Servarr: ``/api/v3/config/host``, ``/config/naming``, ``/config/mediamanagement``.
    """

    kind: Literal["http_json_settings"] = "http_json_settings"
    desired: dict[str, Any] = Field(min_length=1)

    @field_validator("desired", mode="before")
    @classmethod
    def _values(cls, value: Any) -> Any:
        return _api_value(value)


class SchemaRef(Part):
    """Where new items start: the entry of ``path`` whose ``key`` equals the item's (Servarr ``implementation``)."""

    path: ApiPath
    key: Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")] = "implementation"


class HttpJsonItems(_HttpJson):
    """Listed items of a collection exist with the desired fields; nothing else is touched or deleted.

    Matched by ``match``; created with ``POST <path>`` (from the ``schema``
    entry, when given), corrected with ``PUT <path>/<id>``. ``fields`` is a
    mapping written into Servarr's ``[{"name", "value"}]`` list; ``tags``
    given as labels are mapped to ids through ``tags_path`` (created there
    when missing). ``force_save`` adds ``?forceSave=true`` (Servarr skips its
    connection test).
    """

    kind: Literal["http_json_items"] = "http_json_items"
    match: Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")] = "name"
    items: tuple[dict[str, Any], ...] = Field(min_length=1)
    schema_ref: SchemaRef | None = Field(default=None, alias="schema")
    tags_path: ApiPath | None = None
    force_save: bool = False

    @field_validator("items", mode="before")
    @classmethod
    def _values(cls, value: Any) -> Any:
        return tuple(_api_value(item) for item in value)

    @model_validator(mode="after")
    def _matched(self) -> Self:
        keys = []
        for item in self.items:
            key = item.get(self.match)
            if not isinstance(key, (str, int)) or isinstance(key, bool):
                raise ValueError(f"step {self.name}: every item needs a literal {self.match}")
            keys.append(str(key))
        _unique(f"step {self.name} items", keys)
        return self


Step = Annotated[QbittorrentPreferences | JsonKeyCopy | HttpJsonSettings | HttpJsonItems, Field(discriminator="kind")]


class HttpCheck(Part):
    url: Annotated[str, Field(pattern=r"^https?://[^\s'\"$`\\]+$")]
    statuses: tuple[int, ...] = (200,)
    host_header: Hostname | None = None


class Checks(Part):
    """Read-only checks after the rollout (2.9 of the design)."""

    # Seconds to wait for every service to run (and be healthy, with a healthcheck).
    timeout: int = Field(default=180, ge=1, le=1800)
    http: tuple[HttpCheck, ...] = ()


# The prefixes Echoport accepts for a target's paths (its default
# ``ECHOPORT_ALLOWED_PATH_PREFIXES``); checked here so a wrong path fails before any operation.
ECHOPORT_PATH_PREFIXES = ("/home/", "/opt/", "/var/lib/", "/mnt/cryptdata/")


class Echoport(Part):
    """The app's Echoport backup target (generic paths), upserted at the end of the run.

    Echoport copies ``db_path`` with SQLite's online backup and the
    ``backup_files`` (files or whole directories) as they are, while the app
    runs; a restore stops ``service_name``, puts every path back and chowns it
    to ``restore_owner``. Each path is a declared directory of the app, below
    one, or one of its :class:`HostSecret` files (put back to root ``0600`` by
    the next deploy). Basenames must differ: the archive is flat.
    """

    name: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,62}$")]
    description: Label
    icon: Annotated[str, Field(pattern=r"^[a-z0-9-]{1,50}$")] = "archive"
    db_path: PlainPath | None = None
    backup_files: tuple[PlainPath, ...] = ()
    # Default: the app's unit.
    service_name: Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{0,62}\.service$")] | None = None
    # ``user:group``; default: the app's user and its primary group.
    restore_owner: Annotated[str, Field(pattern=r"^[a-z_][a-z0-9_-]{0,31}:[a-z_][a-z0-9_-]{0,31}$")] | None = None
    schedule: Annotated[str, Field(pattern=r"^[0-9*/,-]+( [0-9*/,-]+){4}$")]
    # A schedule changed in the Echoport UI is kept unless this is set.
    update_schedule: bool = False

    @model_validator(mode="after")
    def _paths(self) -> Self:
        paths = self.paths
        if not paths:
            raise ValueError("an echoport target needs a db_path or backup_files")
        _unique("echoport paths", [str(p) for p in paths])
        _unique("echoport basenames", [p.name for p in paths])
        for path in paths:
            # A directory around another path (the database above all) copies it raw and restores it twice.
            outer = next((o for o in paths if o != path and path.is_relative_to(o)), None)
            if outer is not None:
                raise ValueError(f"echoport: {path} is inside {outer}")
        if self.db_path is not None:
            sidecars = {self.db_path.with_name(self.db_path.name + s) for s in ("-wal", "-shm", "-journal")}
            if sidecars & set(self.backup_files):
                raise ValueError("echoport: the database's -wal/-shm/-journal files come from the online backup")
        for path in paths:
            if path.name == "manifest.json":
                raise ValueError("echoport: manifest.json is the archive's own file")
            if not any(str(path).startswith(prefix) for prefix in ECHOPORT_PATH_PREFIXES):
                raise ValueError(f"echoport: {path} is outside {', '.join(ECHOPORT_PATH_PREFIXES)}")
        return self

    @property
    def paths(self) -> tuple[PurePosixPath, ...]:
        return ((self.db_path,) if self.db_path is not None else ()) + self.backup_files


# -- the app -------------------------------------------------------------------------


class ComposeAppConfig(BaseServiceConfig):
    """One Compose app: its project, files, services, route, steps and checks.

    ``site_path`` is the directory of the compose and env files; ``user`` the
    app's main user (one of ``users``).
    """

    service_name: ServiceName
    title: Label
    unit: UnitName | None = None
    project: ComposeProject
    compose_file: FileName = "compose.yml"
    stop: Literal["down", "stop"] = "down"
    groups: tuple[UnixUser, ...] = ()
    users: tuple[AppUser, ...] = ()
    mounts_required: tuple[PlainPath, ...] = ()
    paths_required: tuple[RequiredPath, ...] = ()
    directories: tuple[Directory, ...] = ()
    external_networks: tuple[NetworkName, ...] = ()
    env_files: tuple[EnvFile, ...] = ()
    config_files: tuple[ConfigFile, ...] = ()
    services: tuple[ComposeService, ...] = Field(min_length=1)
    # Docker Engine and Compose, installed (or checked) like the docker_install role does.
    docker: DockerInstallConfig = DockerInstallConfig()
    route: Route | None = None
    steps: tuple[Step, ...] = ()
    checks: Checks = Checks()
    echoport: Echoport | None = None
    # Removed after a successful run when empty; a non-empty one is kept and reported.
    legacy_dirs: tuple[PlainPath, ...] = ()
    # Removed before the apply (the compose project reads its directory's ``.env``).
    legacy_files: tuple[PlainPath, ...] = ()

    @field_validator("site_path")
    @classmethod
    def _plain_site_path(cls, value: PurePosixPath) -> PurePosixPath:
        return plain_path(value)

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        names = [s.name for s in self.services]
        _unique("services", names)
        _unique("env files", [f.name for f in self.env_files])
        _unique("config files", [str(f.path) for f in self.config_files])
        _unique("directories", [str(d.path) for d in self.directories])
        if self.user not in {u.name for u in self.users}:
            raise ValueError(f"user {self.user} must be one of users")
        env_names = {f.name for f in self.env_files}
        published: set[tuple[int, str]] = set()
        for service in self.services:
            missing = sorted(set(service.env_files) - env_names)
            if missing:
                raise ValueError(f"service {service.name} reads undeclared env files {', '.join(missing)}")
            unknown = sorted(set(service.networks) - set(self.external_networks))
            if unknown:
                raise ValueError(f"service {service.name} joins undeclared networks {', '.join(unknown)}")
            provider = service.provider
            if provider is not None:
                target = next((s for s in self.services if s.name == provider), None)
                if target is None or target.provider is not None or provider == service.name:
                    raise ValueError(f"service {service.name}: network_mode names no namespace provider of this app")
                if target.healthcheck is None:
                    raise ValueError(f"service {provider} provides a network namespace and needs a healthcheck")
                if any(dep.service == provider for dep in service.depends_on):
                    raise ValueError(f"service {service.name}: the depends_on on {provider} is implied")
            for dep in service.depends_on:
                if dep.service not in names or dep.service == service.name:
                    raise ValueError(f"service {service.name} depends on an unknown service")
            for port in service.ports:
                key = (port.published, port.protocol)
                if key in published:
                    raise ValueError(f"port {port.published}/{port.protocol} is published twice")
                published.add(key)
            for bind in service.binds:
                if not self._declared(bind.source):
                    raise ValueError(f"service {service.name}: bind source {bind.source} is not declared")
        for config in self.config_files:
            # A provider's restart would replace the namespace under running dependents.
            providers = sorted(set(config.restarts) & set(self.providers))
            if providers:
                raise ValueError(f"config file {config.path} restarts namespace provider {', '.join(providers)}")
            unknown = sorted(set(config.restarts) - set(names))
            if unknown:
                raise ValueError(f"config file {config.path} restarts unknown services {', '.join(unknown)}")
            if any(isinstance(p, (HostSecret, HostId)) for p in _leaves(config.data)):
                raise ValueError(f"config file {config.path}: host values are not supported in config files")
        if self.route is not None and (self.route.port, "tcp") not in published:
            raise ValueError(f"route port {self.route.port} is not a published port of the app")
        for step in self.steps:
            if isinstance(step, QbittorrentPreferences):
                if step.service not in names:
                    raise ValueError(f"step qbittorrent_preferences names an unknown service {step.service}")
                if (step.port, "tcp") not in published:
                    raise ValueError(f"step qbittorrent_preferences port {step.port} is not published")
            if isinstance(step, (HttpJsonSettings, HttpJsonItems)) and (step.port, "tcp") not in published:
                raise ValueError(f"step {step.name}: port {step.port} is not published")
        _unique("step names", [s.name for s in self.steps if isinstance(s, (HttpJsonSettings, HttpJsonItems))])
        if self.echoport is not None:
            secrets = set(self.host_secret_paths)
            for path in self.echoport.paths:
                if path not in secrets and not self._declared(path):
                    raise ValueError(f"echoport: {path} is neither a declared directory of the app nor its host secret")
        return self

    def _declared(self, source: PurePosixPath) -> bool:
        """A bind source the app declares: a directory, a config file, its dir, or below one of them."""

        if source == self.site_path or any(source == f.path for f in self.config_files):
            return True
        roots = [d.path for d in self.directories] + [r.path for r in self.paths_required]
        return any(_within(source, root) for root in roots)

    # -- derived names and paths ------------------------------------------

    @property
    def unit_name(self) -> str:
        return self.unit or self.service_name.replace("_", "-")

    @property
    def compose_path(self) -> PurePosixPath:
        return self.site_path / self.compose_file

    @property
    def state_dir(self) -> PurePosixPath:
        return STATE_ROOT / self.service_name

    def env_path(self, env: EnvFile) -> PurePosixPath:
        return self.site_path / env.name

    def service(self, name: str) -> ComposeService:
        return next(s for s in self.services if s.name == name)

    @property
    def running_services(self) -> tuple[ComposeService, ...]:
        """The services ``up`` starts (no profile)."""

        return tuple(s for s in self.services if not s.profiles)

    @property
    def providers(self) -> tuple[str, ...]:
        """Services others join with ``network_mode: service:X``."""

        return tuple(dict.fromkeys(s.provider for s in self.services if s.provider))

    def dependents(self, provider: str) -> tuple[str, ...]:
        return tuple(s.name for s in self.services if s.provider == provider)

    @property
    def published_ports(self) -> tuple[PublishedPort, ...]:
        return tuple(port for service in self.services for port in service.ports)

    @property
    def images(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(s.image for s in self.services))

    @property
    def host_secret_paths(self) -> tuple[PurePosixPath, ...]:
        """The files of every :class:`HostSecret` the config refers to, in order of first use."""

        return tuple(dict.fromkeys(ref.host_secret for ref in _parts(self, HostSecret)))

    @property
    def echoport_secret_paths(self) -> tuple[PurePosixPath, ...]:
        """The app's host secrets an Echoport restore puts back: listed, or inside a listed directory."""

        assert self.echoport is not None
        roots = self.echoport.paths
        return tuple(p for p in self.host_secret_paths if any(_within(p, root) for root in roots))

    @property
    def echoport_service(self) -> str:
        assert self.echoport is not None
        return self.echoport.service_name or f"{self.unit_name}.service"

    @property
    def echoport_owner(self) -> str:
        assert self.echoport is not None
        if self.echoport.restore_owner is not None:
            return self.echoport.restore_owner
        user = next(u for u in self.users if u.name == self.user)
        return f"{user.name}:{user.primary_group}"

    @property
    def required_secret_keys(self) -> tuple[str, ...]:  # type: ignore[override]
        """Every secret key the config refers to, in order of first use."""

        return tuple(dict.fromkeys(secret.secret for secret in _secrets(self)))


def _unique(what: str, values: list[str]) -> None:
    repeated = sorted({v for v in values if values.count(v) > 1})
    if repeated:
        raise ValueError(f"{what} repeat {', '.join(repeated)}")


def _within(path: PurePosixPath, root: PurePosixPath) -> bool:
    return path == root or path.is_relative_to(root)


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


def _leaves(value: Any) -> Iterator[Any]:
    if isinstance(value, dict):
        for item in value.values():
            yield from _leaves(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _leaves(item)
    else:
        yield value


def _parts[T: BaseModel](value: Any, kind: type[T]) -> Iterator[T]:
    if isinstance(value, kind):
        yield value
    elif isinstance(value, BaseModel):
        for name in type(value).model_fields:
            yield from _parts(getattr(value, name), kind)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _parts(item, kind)
    elif isinstance(value, (tuple, list)):
        for item in value:
            yield from _parts(item, kind)


def _secrets(value: Any) -> Iterator[Secret]:
    if isinstance(value, Secret):
        yield value
    elif isinstance(value, BaseModel):
        for name in type(value).model_fields:
            yield from _secrets(getattr(value, name))
    elif isinstance(value, dict):
        for item in value.values():
            yield from _secrets(item)
    elif isinstance(value, (tuple, list)):
        for item in value:
            yield from _secrets(item)
