"""The ``bind_authoritative_deploy`` role's variables as a typed config.

Field names are the role's ``bind_*`` variables without the prefix, with the
role's defaults. TSIG key material is not a field: :class:`TsigKey` names a key
and its algorithm, the secrets are deploy arguments (``tsig_secrets``).

Stricter than the role, on purpose (each value is rendered verbatim into
``named.conf*``): no control characters in any rendered string, zone names and
key names from a fixed character set, zone files a single path component below
their directory, known zone types and HMAC algorithms only.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Annotated, Literal

from pydantic import AfterValidator, Field, StrictBool, model_validator

from ops_deploy.base._common import AbsolutePath, RoleConfig

ZoneType = Literal[
    "master", "primary", "slave", "secondary", "hint", "stub", "static-stub", "forward", "redirect", "mirror"
]
Algorithm = Literal["hmac-md5", "hmac-sha1", "hmac-sha224", "hmac-sha256", "hmac-sha384", "hmac-sha512"]

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_ZONE_NAME = re.compile(r"\.|[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*\.?")
_FILE_NAME = re.compile(r"[A-Za-z0-9_+@=-][A-Za-z0-9._+@=-]*")
_KEY_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_OWNER = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*")
_MODE = re.compile(r"0[0-7]{3}")
_DNSSEC = re.compile(r"auto|yes|no")
_ADDRESS = re.compile(r"[0-9A-Fa-f.:]+")


def _line(value: str) -> str:
    if _CONTROL.search(value):
        raise ValueError("must not contain control characters (newlines, tabs, NUL)")
    return value


def _lines(value: str | tuple[str, ...]) -> str | tuple[str, ...]:
    for item in (value,) if isinstance(value, str) else value:
        _line(item)
    return value


def _match(pattern: re.Pattern[str], what: str) -> AfterValidator:
    def check(value: str) -> str:
        if not pattern.fullmatch(value):
            raise ValueError(f"not a {what}: {value!r}")
        return value

    return AfterValidator(check)


Line = Annotated[str, AfterValidator(_line)]
# The role's ``acl_list`` macro takes a string (rendered as is) or a list (joined with "; ").
AclList = Annotated[str | tuple[Line, ...], AfterValidator(_lines)]
Owner = Annotated[str, _match(_OWNER, "user or group name")]
Mode = Annotated[str, _match(_MODE, "four-digit octal mode")]


def _non_empty(value: str | tuple[str, ...] | None) -> bool:
    return value is not None and len(value) > 0


class TsigKey(RoleConfig):
    """One ``bind_tsig_keys`` entry without its ``secret`` (a deploy argument)."""

    name: Annotated[str, _match(_KEY_NAME, "TSIG key name")]
    algorithm: Algorithm = "hmac-sha256"


class BindZone(RoleConfig):
    """One ``bind_zones`` entry; unset fields are left out of the template input, as in the role."""

    name: Annotated[str, _match(_ZONE_NAME, "zone name")]
    # Below config_dir (static), dynamic_zone_dir (dynamic) or working_dir (transfer-backed).
    # An absolute path only for transfer-backed zones (no controller file).
    file: Annotated[str, AfterValidator(_line)]
    type: ZoneType | None = None
    dynamic: StrictBool | None = None
    primaries: AclList | None = None
    update_policy: AclList | None = None
    allow_transfer: AclList | None = None
    extra_config: tuple[Line, ...] | None = None


class BindConfig(RoleConfig):
    """The role's ``bind_*`` variables (see the module docstring for what is stricter)."""

    enabled: StrictBool = True
    packages: tuple[Annotated[str, _match(re.compile(r"[a-z0-9][a-z0-9.+-]*"), "package name")], ...] = (
        "bind9",
        "bind9-utils",
        "dnsutils",
    )
    service_name: Annotated[str, _match(re.compile(r"[A-Za-z0-9@_.-]+"), "unit name")] = "named"
    config_dir: AbsolutePath = "/etc/bind"
    working_dir: AbsolutePath = "/var/cache/bind"
    # None: the role's choice from the host's distribution (named.conf.root-hints on
    # Debian 13 and later, named.conf.default-zones elsewhere).
    builtin_zones_file: AbsolutePath | None = None
    # Controller directory holding the zone files (the role's ``bind_zone_files_dir``).
    zone_files_dir: str
    config_owner: Owner = "root"
    config_group: Owner = "bind"
    config_mode: Mode = "0644"
    service_user: Owner = "bind"
    zone_default_type: ZoneType = "master"
    zone_transfer_backed_types: tuple[ZoneType, ...] = ("slave", "secondary")
    zones: tuple[BindZone, ...] = Field(min_length=1)
    dynamic_zone_dir: AbsolutePath = "/var/lib/bind"
    recursion: StrictBool = True
    recursion_acl: tuple[Line, ...] = ("localhost", "localnets")
    allow_query: AclList = ("any",)
    # None: recursion_acl, as the role's default.
    allow_query_cache: AclList | None = None
    allow_transfer: AclList = ("none",)
    dnssec_validation: Annotated[str, _match(_DNSSEC, "dnssec-validation value")] = "auto"
    verify_enabled: StrictBool = True
    verify_server: Annotated[str, _match(_ADDRESS, "IP address")] = "127.0.0.1"
    verify_zone_types: tuple[ZoneType, ...] = ("master", "primary", "slave", "secondary")
    verify_retries: int = Field(default=12, ge=1)
    verify_delay: int = Field(default=5, ge=0)
    firewall_check_enabled: StrictBool = True
    listen_on: AclList = ()
    listen_on_v6: AclList = ("any",)
    extra_options: tuple[Line, ...] = ()
    tsig_keys: tuple[TsigKey, ...] = ()
    # None: <config_dir>/named.conf.keys, as the role's default.
    tsig_keys_file: AbsolutePath | None = None
    tsig_keys_mode: Mode = "0640"

    @model_validator(mode="after")
    def _consistent(self) -> BindConfig:
        # tasks/validate.yml
        names = [zone.name for zone in self.zones]
        if len(set(names)) != len(names):
            raise ValueError("bind zones: each zone name may appear once")
        for zone in self.zones:
            backed = self.transfer_backed(zone)
            if backed and not _non_empty(zone.primaries):
                raise ValueError(
                    f"Zone {zone.name} has type {self.zone_type(zone)} and must define a non-empty primaries list "
                    "(or a single address string)."
                )
            if zone.dynamic and (
                self.zone_type(zone) not in ("master", "primary") or not _non_empty(zone.update_policy)
            ):
                raise ValueError(
                    f"Zone {zone.name} is dynamic: it must be type master/primary and define a non-empty update_policy."
                )
            if zone.file.startswith("/"):
                if not backed or ".." in zone.file.split("/") or "//" in zone.file:
                    raise ValueError(
                        f"Zone {zone.name}: an absolute file is only supported for transfer-backed zones (normalized)"
                    )
            elif not _FILE_NAME.fullmatch(zone.file):
                raise ValueError(f"Zone {zone.name}: file must be one file name below its directory: {zone.file!r}")
        if not _non_empty(self.allow_transfer):
            raise ValueError(
                "bind_allow_transfer must include at least one ACL entry (use 'none' to disable transfers)."
            )
        keys = [key.name for key in self.tsig_keys]
        if len(set(keys)) != len(keys):
            raise ValueError("bind tsig keys: each key name may appear once")
        # Static zones may share a file (named reads it once per zone); a file named
        # writes (dynamic, transfer-backed) belongs to one zone only.
        written = [self.zone_path(zone) for zone in self.zones if self.dynamic(zone) or self.transfer_backed(zone)]
        others = {self.zone_path(zone) for zone in self.static_zones()}
        if len(set(written)) != len(written) or others & set(written):
            raise ValueError("bind zones: a dynamic or transfer-backed zone shares its file with another zone")
        return self

    # -- the role's derived values ------------------------------------------------

    def zone_type(self, zone: BindZone) -> str:
        return zone.type or self.zone_default_type

    def transfer_backed(self, zone: BindZone) -> bool:
        return self.zone_type(zone) in self.zone_transfer_backed_types

    def dynamic(self, zone: BindZone) -> bool:
        return bool(zone.dynamic)

    def zone_path(self, zone: BindZone) -> str:
        """The ``file`` named.conf.local names (``named.conf.local.j2``)."""

        if zone.file.startswith("/"):
            return zone.file
        if self.transfer_backed(zone):
            base = self.working_dir
        elif self.dynamic(zone):
            base = self.dynamic_zone_dir
        else:
            base = self.config_dir
        return f"{base}/{zone.file}"

    def static_zones(self) -> Iterable[BindZone]:
        """Zones whose file the deploy installs on every run (``Install zone files``)."""

        return (zone for zone in self.zones if not self.transfer_backed(zone) and not self.dynamic(zone))

    def dynamic_zones(self) -> Iterable[BindZone]:
        """Zones whose file is only seeded (``Seed dynamic zone files``)."""

        return (zone for zone in self.zones if self.dynamic(zone))

    @property
    def keys_file(self) -> str:
        return self.tsig_keys_file or f"{self.config_dir}/named.conf.keys"

    @property
    def query_cache_acl(self) -> str | tuple[str, ...]:
        return self.recursion_acl if self.allow_query_cache is None else self.allow_query_cache

    @property
    def needs_working_dir(self) -> bool:
        return any(self.transfer_backed(zone) for zone in self.zones)

    @property
    def needs_dynamic_dir(self) -> bool:
        return any(self.dynamic(zone) for zone in self.zones)
