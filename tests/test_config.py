from pathlib import PurePosixPath
from typing import ClassVar

import pytest
from pydantic import BaseModel, Field, SecretStr
from pydantic import ValidationError as PydanticValidationError

from ops_deploy.core import BaseServiceConfig, ConfigValidationError, SecretRef, ServiceName, UnixUser


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
    with pytest.raises(ConfigValidationError, match="extra_forbidden"):
        ExampleConfig(sevice_name="typo")  # type: ignore[call-arg]


def test_config_is_frozen() -> None:
    cfg = ExampleConfig()
    with pytest.raises(PydanticValidationError, match="frozen"):
        cfg.user = "other"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("kwargs", "location"),
    [
        ({"greeting": "CHANGEME"}, "greeting"),
        ({"route": {"host": "app.example.org", "aliases": ["ok", "CHANGEME.example.org"]}}, r"route\.aliases\[1\]"),
        ({"env": {"API_TOKEN": "prefix-CHANGEME"}}, r"env\.API_TOKEN"),
        ({"env": {"CHANGEME": "value"}}, r"env\[<key>\]"),
        ({"password": "CHANGEME"}, "password"),
        ({"site_path": "/srv/CHANGEME"}, "site_path"),
        ({"secrets": "secrets/prod/CHANGEME.yml"}, "secrets"),
        ({"secrets": SecretRef("secrets/prod/CHANGEME.yml")}, r"secrets\.path"),
    ],
)
def test_placeholders_are_rejected_everywhere(kwargs: dict[str, object], location: str) -> None:
    with pytest.raises(ConfigValidationError, match=f"{location} still contains the placeholder"):
        ExampleConfig(**kwargs)


@pytest.mark.parametrize("password", ["hunter2-CHANGEME", SecretStr("hunter2-CHANGEME")])
def test_placeholder_error_does_not_echo_secret_value(password: str | SecretStr) -> None:
    with pytest.raises(ConfigValidationError) as excinfo:
        ExampleConfig(password=password)
    assert "hunter2" not in str(excinfo.value)
    assert "hunter2" not in repr(excinfo.value)


@pytest.mark.parametrize("key", ["hunter2-CHANGEME", b"hunter2-CHANGEME"])
@pytest.mark.parametrize("value", ["value", None, 3])
def test_placeholder_mapping_key_is_not_echoed(key: str | bytes, value: object) -> None:
    with pytest.raises(ConfigValidationError, match=r"env\[<key>\] still contains the placeholder") as excinfo:
        ExampleConfig(env={key: value})
    assert "hunter2" not in str(excinfo.value)
    assert "hunter2" not in repr(excinfo.value)


def test_field_errors_do_not_echo_input() -> None:
    with pytest.raises(ConfigValidationError, match="site_path") as excinfo:
        ExampleConfig(site_path=PurePosixPath("relative-s3cret"))
    assert "s3cret" not in str(excinfo.value)


@pytest.mark.parametrize("site_path", ["relative/site", "/", "/home/../etc"])
def test_site_path_must_be_safe_absolute(site_path: str) -> None:
    with pytest.raises(ConfigValidationError, match="site_path"):
        ExampleConfig(site_path=PurePosixPath(site_path))


@pytest.mark.parametrize(("field", "value"), [("service_name", "Bad Name"), ("user", "root;rm")])
def test_names_are_constrained(field: str, value: str) -> None:
    with pytest.raises(ConfigValidationError, match=field):
        ExampleConfig(**{field: value})


def test_overriding_field_with_annotated_type_keeps_constraint() -> None:
    with pytest.raises(ConfigValidationError, match="service_name"):
        ExampleConfig(service_name="UPPER")


def test_required_secret_keys_need_a_secret_ref() -> None:
    with pytest.raises(ConfigValidationError, match="requires a secrets file providing django_secret_key"):
        NeedsSecrets()
    cfg = NeedsSecrets(secrets=SecretRef("secrets/prod/example.yml"))
    assert str(cfg.secrets) == "secrets/prod/example.yml"


@pytest.mark.parametrize(
    "default",
    [{"hunter2-CHANGEME": None}, {"ok": "CHANGEME"}, ["CHANGEME"]],
)
def test_placeholder_defaults_are_rejected_at_class_definition(default: object) -> None:
    with pytest.raises(TypeError, match="contains the placeholder") as excinfo:

        class Bad(ExampleConfig):
            extra_data: object = default

    assert "hunter2" not in str(excinfo.value)


def test_factory_default_using_validated_data_is_supported() -> None:
    class Derived(ExampleConfig):
        derived_user: str = Field(default_factory=lambda data: data["user"])

    assert Derived().derived_user == "example"


@pytest.mark.parametrize(
    "generated", [{"hunter2-CHANGEME": None}, {"hunter2-CHANGEME": "v"}, {"k": "hunter2-CHANGEME"}]
)
def test_factory_generated_placeholders_never_leak(generated: dict[str, object]) -> None:
    state: dict[str, object] = {}

    class Late(ExampleConfig):
        env: dict[str, str] = Field(default_factory=lambda: dict(state))  # type: ignore[arg-type]

    state.update(generated)
    with pytest.raises(ConfigValidationError) as excinfo:
        Late()
    assert "hunter2" not in str(excinfo.value)
    assert "hunter2" not in repr(excinfo.value)
    assert all("input" not in error for error in excinfo.value.errors)


@pytest.mark.parametrize("entry", ["model_validate", "model_validate_json", "model_validate_strings"])
def test_all_validation_entry_points_are_sanitized(entry: str) -> None:
    payload: object = {"env": {"hunter2-CHANGEME": "x"}, "site_path": "relative-s3cret"}
    if entry == "model_validate_json":
        import json

        payload = json.dumps(payload)
    elif entry == "model_validate_strings":
        payload = {"site_path": "relative-s3cret"}
    with pytest.raises(ConfigValidationError) as excinfo:
        getattr(ExampleConfig, entry)(payload)
    text = str(excinfo.value) + repr(excinfo.value) + repr(excinfo.value.errors)
    assert "hunter2" not in text
    assert "s3cret" not in text


def test_placeholder_default_scalar_rejected_at_class_definition() -> None:
    with pytest.raises(TypeError, match="default of greeting contains the placeholder"):

        class Bad(ExampleConfig):
            greeting: str = "CHANGEME"


class Port(BaseServiceConfig):
    service_name: ServiceName = "port"
    user: UnixUser = "port"
    site_path: PurePosixPath = PurePosixPath("/srv/port")
    port: int = 1


def test_strict_and_context_reach_validation() -> None:
    from pydantic import ValidationInfo, field_validator

    seen: list[object] = []

    class WithContext(Port):
        @field_validator("port")
        @classmethod
        def _record(cls, value: int, info: ValidationInfo) -> int:
            seen.append(info.context)
            return value

    with pytest.raises(ConfigValidationError, match="int_type"):
        Port.model_validate({"port": "123"}, strict=True)
    assert Port.model_validate({"port": "123"}).port == 123
    WithContext.model_validate({"port": 2}, context={"k": 1})
    WithContext.model_validate_json('{"port": 3, "site_path": "/srv/port"}', context={"k": 2})
    assert seen == [{"k": 1}, {"k": 2}]


def test_custom_and_builtin_error_types_are_reported() -> None:
    from pydantic import field_validator
    from pydantic_core import PydanticCustomError

    class Custom(Port):
        @field_validator("port")
        @classmethod
        def _odd(cls, value: int) -> int:
            raise PydanticCustomError("port_odd", "port {port} rejected", {"port": value})

    with pytest.raises(ConfigValidationError, match="site_path: path_type"):
        ExampleConfig(site_path=123)
    with pytest.raises(ConfigValidationError, match="port: port_odd") as excinfo:
        Custom(port=4711)
    assert "4711" not in str(excinfo.value)
    with pytest.raises(ConfigValidationError, match=r"secrets\.path: Value error, secret file path must be relative"):
        ExampleConfig(secrets={"path": "/abs.yml"})


def test_discriminated_union_tag_is_not_echoed() -> None:
    from typing import Literal

    class A(BaseModel):
        kind: Literal["a"] = "a"

    class B(BaseModel):
        kind: Literal["b"] = "b"

    class Tagged(Port):
        item: A | B = Field(discriminator="kind", default_factory=A)

    with pytest.raises(ConfigValidationError, match="union_tag_invalid") as excinfo:
        Tagged(item={"kind": "hunter2-x"})
    text = str(excinfo.value) + repr(excinfo.value.errors)
    assert "hunter2" not in text


def test_builtin_errors_report_type_only() -> None:
    with pytest.raises(ConfigValidationError, match=r"service_name: string_pattern_mismatch$"):
        ExampleConfig(service_name="Bad Name")


@pytest.mark.parametrize("entry", ["model_validate_json", "model_validate_strings"])
def test_text_entry_points_accept_path_defaults(entry: str) -> None:
    payload = "{}" if entry == "model_validate_json" else {}
    assert getattr(ExampleConfig, entry)(payload).site_path == PurePosixPath("/home/example/site")


@pytest.mark.parametrize("error_type", ["port_rejected", "string_pattern_mismatch", "value_error"])
def test_custom_error_context_is_dropped(error_type: str) -> None:
    from pydantic import field_validator
    from pydantic_core import PydanticCustomError

    class Custom(Port):
        @field_validator("port")
        @classmethod
        def _reject(cls, value: int) -> int:
            raise PydanticCustomError(error_type, "rejected {pattern}", {"pattern": f"s3cret-{value}"})

    with pytest.raises(ConfigValidationError) as excinfo:
        Custom(port=4711)
    assert "s3cret" not in str(excinfo.value) + repr(excinfo.value.errors)


@pytest.mark.parametrize("site_path", [None, PurePosixPath("/srv/strict")])
def test_strict_python_validation_accepts_paths(site_path: PurePosixPath | None) -> None:
    data = {} if site_path is None else {"site_path": site_path}
    cfg = ExampleConfig.model_validate(data, strict=True)
    assert cfg.site_path == (site_path or PurePosixPath("/home/example/site"))


def test_custom_value_error_with_forged_cause_uses_cause_text_only() -> None:
    from pydantic import field_validator
    from pydantic_core import PydanticCustomError

    class Forged(Port):
        @field_validator("port")
        @classmethod
        def _reject(cls, value: int) -> int:
            raise PydanticCustomError(
                "value_error", "rejected {pattern}", {"error": ValueError("invalid port"), "pattern": "s3cret-4711"}
            )

    with pytest.raises(ConfigValidationError, match="port: Value error, invalid port") as excinfo:
        Forged(port=1)
    assert "s3cret" not in str(excinfo.value) + repr(excinfo.value.errors)
