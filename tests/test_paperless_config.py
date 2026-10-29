"""Prepared Paperless config boundaries, without any deployment connection."""

import pytest
from pydantic import SecretStr, ValidationError

from ops_deploy.services.paperless.config import PaperlessConfig, PaperlessCredentials, validate_credentials


def credentials(**updates: str) -> PaperlessCredentials:
    values = {
        "secret_key": "synthetic-key-" * 5,
        "postgres_password": "synthetic-db",
        "admin_password": "synthetic-admin",
        "scanner_password": "synthetic-scanner",
    }
    values.update(updates)
    return PaperlessCredentials(**{key: SecretStr(value) for key, value in values.items()})


def test_four_original_units_and_fixed_release() -> None:
    cfg = PaperlessConfig(traefik_domain="home.example.test")
    assert cfg.units == ("paperless", "paperless-worker", "paperless-scheduler", "paperless-consumer")
    assert (cfg.version, cfg.python_version, cfg.app_port) == ("3.2.1", "3.14", 10030)
    assert cfg.external_storage_root == "/mnt/cryptdata/paperless"
    assert not cfg.force_reindex


@pytest.mark.parametrize("path", ["relative", "/tmp/../etc", "/tmp//data", "/tmp/data/", "/"])
def test_storage_path_is_canonical(path: str) -> None:
    with pytest.raises(ValidationError, match="canonical"):
        PaperlessConfig(traefik_domain="home.example.test", external_storage_root=path)


def test_storage_and_application_must_not_overlap() -> None:
    with pytest.raises(ValidationError, match="overlap"):
        PaperlessConfig(traefik_domain="home.example.test", external_storage_root="/home/paperless/site/data")


def test_original_ignored_date_guard_remains_effective() -> None:
    with pytest.raises(ValidationError, match="date order"):
        PaperlessConfig(traefik_domain="home.example.test", ignore_dates=("1970-02-01",))
    assert PaperlessConfig(traefik_domain="home.example.test", date_order="YMD", ignore_dates=("1970-02-01",))


@pytest.mark.parametrize(
    "value",
    [
        "synthetic;touch/x",
        "synthetic&cmd",
        "synthetic|cmd",
        "synthetic$(id)",
        "synthetic\nNEXT=1",
        "synthetic'quote",
        "synthetic`id`",
        "synthetic\\backslash",
        "~",
        "synthetic:~",
    ],
)
def test_secret_cannot_change_env_or_shell_grammar(value: str) -> None:
    with pytest.raises(ValidationError, match="represented literally") as error:
        credentials(postgres_password=value)
    assert value not in str(error.value)


def test_secret_reprs_are_masked_and_placeholder_refused() -> None:
    value = credentials()
    assert "synthetic" not in repr(value)
    with pytest.raises(ValueError, match="configured credentials"):
        validate_credentials(
            PaperlessConfig(traefik_domain="home.example.test"), credentials(scanner_password="CHANGEME")
        )
    with pytest.raises(ValidationError, match="at least50"):
        credentials(secret_key="short")


def test_disabled_scanner_does_not_require_its_password() -> None:
    cfg = PaperlessConfig(traefik_domain="home.example.test", scanner_enabled=False)
    validate_credentials(cfg, credentials(scanner_password=""))


def test_empty_scanner_password_preserves_original_no_password_change_semantics() -> None:
    validate_credentials(PaperlessConfig(traefik_domain="home.example.test"), credentials(scanner_password=""))


@pytest.mark.parametrize("date", ["01.02.1970;id", "01 February 1970", "$(id)", "01.02.1970,02.02.1970"])
def test_ignored_dates_cannot_change_shell_environment(date: str) -> None:
    with pytest.raises(ValidationError, match="literal"):
        PaperlessConfig(traefik_domain="home.example.test", ignore_dates=(date,))


def test_account_dependent_paths_match_role_defaults() -> None:
    cfg = PaperlessConfig(traefik_domain="home.example.test", username="archivist")
    assert cfg.group == "archivist"
    assert cfg.home_path == "/home/archivist"
    assert cfg.site_root == "/home/archivist/site"
