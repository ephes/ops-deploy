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
  (for example `route.aliases[1]`) but never echoes the value.
- **Validation errors never include input values** (`hide_input_in_errors`), so
  a mistyped secret cannot leak through an error message.
- **`required_secret_keys`** lists the keys the secret file must provide. The
  config only checks that a `SecretRef` exists; key presence is checked after
  decryption with `SecretValues.require(cfg.required_secret_keys)`.

!!! warning "Overriding a base field"
    Redeclaring a pydantic field replaces its constraints. When a subclass gives
    `service_name` or `user` a default, annotate it with `ServiceName` /
    `UnixUser`, not `str`, or the pattern check is lost.
