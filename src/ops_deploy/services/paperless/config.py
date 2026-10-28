"""Paperless configuration for the prepared deployment and recovery API."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Annotated, Any, Literal, Self

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, SecretStr, StrictBool, StrictInt, model_validator

from ops_deploy.base._common import RoleConfig, Sha256, Version
from ops_deploy.base.uv_install import UvInstallConfig
from ops_deploy.core.config import UnixUser
from ops_deploy.helpers.traefik import Hostname

RELEASE_SHA256 = "7391e75706d9dafe84dd2235df12c932c0034a4f453725437d07918eee7a35b8"


def canonical_path(value: str) -> str:
    if not re.fullmatch(r"(?:/[A-Za-z0-9_.+-]+)+", value) or any(part in {".", ".."} for part in value.split("/")[1:]):
        raise ValueError("expected a canonical absolute path")
    return value


CanonicalPath = Annotated[str, AfterValidator(canonical_path)]
OneLine = Annotated[str, Field(pattern=r"^[^\x00-\x1f\x7f\r\n]*$")]
Positive = Annotated[StrictInt, Field(ge=1, le=65535)]


class PaperlessUvConfig(UvInstallConfig):
    """Original Paperless uv dependency defaults, without changing other callers."""

    version: Version = "0.13.5"
    checksums: dict[str, Sha256] = Field(
        default_factory=lambda: {
            "x86_64-unknown-linux-gnu": "f68d291c75783122dad58ab77def0e13f3233f358731db5d6d7e8715603b928f",
            "aarch64-unknown-linux-gnu": "4bb69cf95ed13f23713bb7bc09f241896ea0c75b7c557e615a20604b82f9c403",
            "x86_64-apple-darwin": "b0f52b0e3945b4107d89024ea38e625683011fbfc05a0d98f9fa2d6dcee28c66",
            "aarch64-apple-darwin": "743f85035a1996ecb350659e01cd9faea9709829be09b1b4b03c73eaf3c9cd73",
        }
    )
    create_symlinks: StrictBool = False
    symlink_dir: CanonicalPath = "/usr/local/bin"

    @model_validator(mode="after")
    def original_linux_contract(self) -> Self:
        if self.darwin:
            raise ValueError("Paperless requires the Linux uv dependency")
        return self


class PaperlessConfig(RoleConfig):
    """Current role settings used by the prepared runtime and index contract.

    Secrets live in PaperlessCredentials. Public defaults are synthetic; the
    private adapter retains actual deployment values. Native application and
    inventory qualification remain pending; lifecycle migration is separate.
    """

    username: UnixUser = "paperless"
    group: UnixUser = "paperless"
    service_name: UnixUser = "paperless"
    home_path: CanonicalPath = "/home/paperless"
    site_root: CanonicalPath = "/home/paperless/site"
    external_storage_root: CanonicalPath = "/mnt/cryptdata/paperless"
    version: Literal["3.2.1"] = "3.2.1"
    python_version: Literal["3.14"] = "3.14"
    uv_install_dir: CanonicalPath = "/usr/local/bin"
    uv_binary: CanonicalPath = "/usr/local/bin/uv"
    force_reinstall: StrictBool = False
    force_reindex: StrictBool = False
    python_security_floor_enabled: StrictBool = True
    app_port: Positive = 10030
    bind_address: Annotated[str, Field(pattern=r"^(127\.0\.0\.1|0\.0\.0\.0)$")] = "0.0.0.0"
    traefik_domain: Hostname
    traefik_enabled: StrictBool = True
    traefik_entrypoint: Annotated[str, Field(pattern=r"^[A-Za-z][A-Za-z0-9_-]*$")] = "web-secure"
    traefik_cert_resolver: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]*$")] = ""
    time_zone: Annotated[str, Field(pattern=r"^(?:UTC|[A-Za-z_]+(?:/[A-Za-z_+-]+)+)$")] = "Europe/Berlin"
    language: Annotated[str, Field(pattern=r"^[A-Za-z-]+$")] = "en-us"
    ocr_language: Annotated[str, Field(pattern=r"^[A-Za-z_]+(?:\+[A-Za-z_]+)*$")] = "eng+deu"
    ocr_mode: Literal["auto", "force", "redo"] = "auto"
    ocr_threads: Positive = 2
    filename_format: OneLine = "{{ created_year }}/{{ correspondent }}/{{ title }}"
    filename_date_order: Literal["DMY", "MDY", "YMD"] = "YMD"
    date_order: Literal["DMY", "MDY", "YMD"] = "DMY"
    ignore_dates: tuple[OneLine, ...] = ()
    consumer_recursive: StrictBool = True
    consumer_subdirs_as_tags: StrictBool = True
    task_workers: Positive = 2
    threads_per_worker: Positive = 2
    manage_superuser: StrictBool = True
    admin_user: UnixUser = "admin"
    admin_email: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.+-]+@[A-Za-z0-9.-]+$")] = "admin@example.com"
    existing_superusers: tuple[UnixUser, ...] = ()
    existing_superusers_strict: StrictBool = False
    postgres_database: UnixUser = "paperless"
    postgres_user: UnixUser = "paperless"
    postgres_host: Literal["localhost", "127.0.0.1"] = "localhost"
    postgres_port: Positive = 5432
    postgres_sslmode: Literal["disable", "allow", "prefer", "require", "verify-ca", "verify-full"] = "prefer"
    redis_host: Literal["localhost", "127.0.0.1"] = "localhost"
    redis_port: Positive = 6379
    redis_database: Annotated[StrictInt, Field(ge=0, le=15)] = 0
    redis_requirepass_enabled: StrictBool = False
    scanner_enabled: StrictBool = True
    scanner_username: UnixUser = "scanner"
    scanner_group: UnixUser = "scanner"
    sftp_chroot_dir: CanonicalPath = "/srv/sftp-scanner"
    scanner_acl_enabled: StrictBool = True
    scanner_bind_mount_enabled: StrictBool = True
    verify_storage_mount: StrictBool = True
    manage_symlinks: StrictBool = True
    manage_tmpdir: StrictBool = True
    configure_scanner_acl: StrictBool = True
    create_venv_symlink: StrictBool = True
    patch_ocrmypdf_missing_check: StrictBool = True
    install_nltk_data: StrictBool = True
    nltk_data_path: CanonicalPath = "/usr/share/nltk_data"
    temp_dir: CanonicalPath = "/tmp/paperless"

    @model_validator(mode="before")
    @classmethod
    def dependent_defaults(cls, values: Any) -> Any:
        if not isinstance(values, dict):
            return values
        result = dict(values)
        username = result.get("username", "paperless")
        result.setdefault("group", username)
        home = result.setdefault("home_path", f"/home/{username}")
        result.setdefault("site_root", f"{home}/site")
        result.setdefault("uv_binary", result.get("uv_install_dir", "/usr/local/bin") + "/uv")
        return result

    @model_validator(mode="after")
    def relationships(self) -> Self:
        if self.username == self.scanner_username or self.username == "root" or self.scanner_username == "root":
            raise ValueError("Paperless and scanner require distinct non-root identities")
        app, data = PurePosixPath(self.site_root), PurePosixPath(self.external_storage_root)
        if app == data or app in data.parents or data in app.parents:
            raise ValueError("application and external storage roots must not overlap")
        chroot = PurePosixPath(self.sftp_chroot_dir)
        if self.scanner_enabled and (chroot == data or chroot in data.parents or data in chroot.parents):
            raise ValueError("scanner chroot and external storage roots must not overlap")
        if self.date_order != "YMD" and any(re.fullmatch(r"\s*\d{4}-\d{2}-\d{2}\s*", d) for d in self.ignore_dates):
            raise ValueError("ignored dates must match the configured date order")
        if any(not re.fullmatch(r"[A-Za-z0-9_.+-]+", d) for d in self.ignore_dates):
            raise ValueError("ignored date entries must be literal nonempty environment words")
        # The original environment quotes this string with double quotes. Do not
        # change its interpretation through shell/environment delimiters.
        if any(char in self.filename_format for char in '\\"$`'):
            raise ValueError("filename format contains unsupported environment delimiters")
        return self

    @property
    def units(self) -> tuple[str, ...]:
        return tuple(self.service_name + suffix for suffix in ("", "-worker", "-scheduler", "-consumer"))


class PaperlessCredentials(BaseModel):
    """No secret participates in configuration repr or validation error input."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    secret_key: SecretStr
    postgres_password: SecretStr
    admin_password: SecretStr
    scanner_password: SecretStr = SecretStr("")
    redis_password: SecretStr = SecretStr("")

    @model_validator(mode="after")
    def environment_values(self) -> Self:
        for name in type(self).model_fields:
            value = getattr(self, name).get_secret_value()
            if name in {"secret_key", "postgres_password", "admin_password"} and (not value or value == "CHANGEME"):
                raise ValueError("Paperless requires configured credentials")
            if name == "secret_key" and len(value) < 50:
                raise ValueError("Paperless application key requires at least50 characters")
            # .env is read both by systemd and the original Bash-managed command.
            # Refuse values whose literal meaning differs across those readers.
            if name in {"scanner_password", "redis_password"}:
                # Scanner uses protected chpasswd stdin; Redis is URL-encoded
                # in this environment. Neither is emitted as a raw shell word.
                if any(char in value for char in "\r\n\0"):
                    raise ValueError("credential contains an unsupported control character")
                continue
            if value and not re.fullmatch(r"[A-Za-z0-9_.:@%+=,/?~-]+", value):
                raise ValueError("credential cannot be represented literally in the Paperless environment")
            if value.startswith("~") or ":~" in value:
                raise ValueError("credential cannot be represented literally in the Paperless environment")
        return self


def validate_credentials(cfg: PaperlessConfig, credentials: PaperlessCredentials) -> None:
    if cfg.scanner_enabled and credentials.scanner_password.get_secret_value() == "CHANGEME":
        raise ValueError("enabled scanner requires configured credentials")
    if cfg.redis_requirepass_enabled and not credentials.redis_password.get_secret_value():
        raise ValueError("authenticated Redis requires configured credentials")
