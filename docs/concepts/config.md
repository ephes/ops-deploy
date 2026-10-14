# Service configuration

Each service defines a config class that subclasses
`ops_deploy.core.BaseServiceConfig` (a pydantic model). Validation runs on the
controller before pyinfra opens any connection.

```python
from pathlib import PurePosixPath
from typing import ClassVar

from ops_deploy.core import BaseServiceConfig, SecretRef, ServiceName, UnixUser


class NyxmonConfig(BaseServiceConfig):
    required_secret_keys: ClassVar[tuple[str, ...]] = ("django_secret_key",)

    service_name: ServiceName = "nyxmon"
    user: UnixUser = "nyxmon"
    site_path: PurePosixPath = PurePosixPath("/home/nyxmon/site")
    app_port: int = 10017


cfg = NyxmonConfig(secrets=SecretRef("secrets/prod/nyxmon.yml"))
```

## Base fields

| Field | Type | Rule |
|---|---|---|
| `service_name` | `ServiceName` | `^[a-z][a-z0-9_-]{0,31}$` |
| `user` | `UnixUser` | `^[a-z_][a-z0-9_-]{0,31}$` |
| `site_path` | `PurePosixPath` | absolute, not `/`, no `..` |
| `secrets` | `SecretRef \| None` | required when `required_secret_keys` is non-empty |

## Behaviour

- **Unknown keys are errors** (`extra="forbid"`), so a typo fails loudly.
- **Configs are immutable** after validation (`frozen=True`).
- **`CHANGEME` is rejected anywhere**: in strings, paths, `SecretStr` values,
  dict keys and values, lists, and nested models. The error names the location
  (for example `route.aliases[1]`, or `env[<key>]` when a mapping key holds
  the marker) but never echoes the value.
- **Placeholder defaults fail at class definition**: a subclass whose literal
  field default contains `CHANGEME` raises `TypeError` on import. Default
  factories are not called there (they may take validated data); their output
  is checked at instantiation.
- **Errors are sanitized structurally**: constructing a config or calling
  `model_validate`, `model_validate_json` or `model_validate_strings` raises
  `ops_deploy.core.ConfigValidationError` (a `ValueError`), never pydantic's
  `ValidationError`. It carries no input values. Each entry in `.errors` has
  `loc` (segments containing `CHANGEME` become `<key>`) and `type`. `value_error`
  entries raised by a validator's `ValueError` also have `msg`, built from that
  exception's text. All other messages and all error context are
  dropped, because they can embed input (a custom error can reuse any type name). Caller options (`strict=`, `context=`) are honoured.
- **Validator messages must not include values**: `value_error` messages are
  shown verbatim, so validators in this package never put the
  value into their message. Subclass validators must follow the same rule
  (`raise ValueError("source_path is not a directory")`, not
  `f"{value} is not a directory"`), so a mistyped secret cannot leak through
  `str()`/`repr()` of the error.
- **`required_secret_keys`** lists the keys the secret file must provide. The
  config only checks that a `SecretRef` exists; key presence is checked after
  decryption with `SecretValues.require(cfg.required_secret_keys)`.

!!! warning "Overriding a base field"
    Redeclaring a pydantic field replaces its constraints. When a subclass gives
    `service_name` or `user` a default, annotate it with `ServiceName` /
    `UnixUser`, not `str`, or the pattern check is lost.
