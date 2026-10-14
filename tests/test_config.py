from pathlib import PurePosixPath
from typing import ClassVar

import pytest
from pydantic import BaseModel, Field, SecretStr, ValidationError

from ops_deploy.core import BaseServiceConfig, SecretRef, ServiceName, UnixUser


class Route(BaseModel):
    host: str
    aliases: list[str] = Field(default_factory=list)


class ExampleConfig(BaseServiceConfig):
    service_name: ServiceName = "example"
    user: UnixUser = "example"
    site_path: PurePosixPath = PurePosixPath("/home/example/site")
    greeting: str = "hi"
    route: Route | None = None
    env: dict[str, str] = Field(default_factory=dict)
    password: SecretStr | None = None


class NeedsSecrets(ExampleConfig):
    required_secret_keys: ClassVar[tuple[str, ...]] = ("django_secret_key",)


def test_defaults_validate() -> None:
    cfg = ExampleConfig()
    assert cfg.site_path == PurePosixPath("/home/example/site")
    assert cfg.secrets is None


def test_unknown_keys_are_rejected() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ExampleConfig(sevice_name="typo")  # type: ignore[call-arg]


def test_config_is_frozen() -> None:
    cfg = ExampleConfig()
    with pytest.raises(ValidationError, match="frozen"):
        cfg.user = "other"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("kwargs", "location"),
    [
        ({"greeting": "CHANGEME"}, "greeting"),
        ({"route": {"host": "app.example.org", "aliases": ["ok", "CHANGEME.example.org"]}}, r"route\.aliases\[1\]"),
        ({"env": {"API_TOKEN": "prefix-CHANGEME"}}, r"env\.API_TOKEN"),
        ({"env": {"CHANGEME": "value"}}, r"env\.CHANGEME"),
        ({"password": "CHANGEME"}, "password"),
        ({"site_path": "/srv/CHANGEME"}, "site_path"),
        ({"secrets": "secrets/prod/CHANGEME.yml"}, r"secrets\.path"),
    ],
)
def test_placeholders_are_rejected_everywhere(kwargs: dict[str, object], location: str) -> None:
    with pytest.raises(ValidationError, match=f"{location} still contains the placeholder"):
        ExampleConfig(**kwargs)


@pytest.mark.parametrize("password", ["hunter2-CHANGEME", SecretStr("hunter2-CHANGEME")])
def test_placeholder_error_does_not_echo_secret_value(password: str | SecretStr) -> None:
    with pytest.raises(ValidationError) as excinfo:
        ExampleConfig(password=password)
    assert "hunter2" not in str(excinfo.value)
    assert "hunter2" not in repr(excinfo.value)


def test_field_errors_do_not_echo_input() -> None:
    with pytest.raises(ValidationError, match="site_path") as excinfo:
        ExampleConfig(site_path=PurePosixPath("relative-s3cret"))
    assert "s3cret" not in str(excinfo.value)


@pytest.mark.parametrize("site_path", ["relative/site", "/", "/home/../etc"])
def test_site_path_must_be_safe_absolute(site_path: str) -> None:
    with pytest.raises(ValidationError, match="site_path"):
        ExampleConfig(site_path=PurePosixPath(site_path))


@pytest.mark.parametrize(("field", "value"), [("service_name", "Bad Name"), ("user", "root;rm")])
def test_names_are_constrained(field: str, value: str) -> None:
    with pytest.raises(ValidationError, match=field):
        ExampleConfig(**{field: value})


def test_overriding_field_with_annotated_type_keeps_constraint() -> None:
    with pytest.raises(ValidationError, match="service_name"):
        ExampleConfig(service_name="UPPER")


def test_required_secret_keys_need_a_secret_ref() -> None:
    with pytest.raises(ValidationError, match="requires a secrets file providing django_secret_key"):
        NeedsSecrets()
    cfg = NeedsSecrets(secrets=SecretRef("secrets/prod/example.yml"))
    assert str(cfg.secrets) == "secrets/prod/example.yml"
