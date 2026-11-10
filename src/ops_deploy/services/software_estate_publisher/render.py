"""The roles' content-addressed release, configuration and templates, byte for byte.

``templates/linux`` and ``templates/darwin`` are the roles' templates,
vendored unchanged (``tests/test_ops_library_drift.py``); ``files/`` holds the
five programs of ops-library's ``software_estate`` role as ``<name>.py.txt``
(installed as ``<name>.py``), so the package's Python scans do not take them
for host scripts of this package.
"""

from __future__ import annotations

import hashlib
import json
import shlex
from functools import cache
from importlib.resources import files
from typing import Any

import jinja2

from .config import LINUX_CONFIG_DIR, LINUX_STATE_DIR, SoftwareEstatePublisherConfig

PACKAGE = "ops_deploy.services.software_estate_publisher"
PROGRAMS = ("publish.py", "collect.py", "emit.py", "outbox.py", "send.py")


def program(name: str) -> str:
    """A file of ``files/``; the vendored programs carry a ``.txt`` suffix there."""

    stored = name + ".txt" if name in PROGRAMS else name
    return files(PACKAGE).joinpath("files", stored).read_text()


@cache
def release_id() -> str:
    """The roles' release directory name.

    ``lookup('file', ...)`` strips trailing whitespace from each program; the
    role hashes the five texts joined in this order.
    """

    return hashlib.sha256("".join(program(name).rstrip() for name in PROGRAMS).encode()).hexdigest()


def release_path(cfg: SoftwareEstatePublisherConfig) -> str:
    return f"{cfg.program}/{release_id()}"


def nice_json(value: Any) -> str:
    # ansible.builtin.to_nice_json: indent 4, sorted keys, ensure_ascii; copy adds "\n".
    return json.dumps(value, indent=4, sort_keys=True) + "\n"


def config_json(cfg: SoftwareEstatePublisherConfig) -> str:
    hostnames = list(cfg.hostnames)
    if cfg.platform == "linux":
        data = {
            "policy": cfg.policy,
            "hostnames": hostnames,
            "endpoint": cfg.endpoint,
            "directory": str(LINUX_STATE_DIR),
            "credential_file": str(LINUX_CONFIG_DIR / "writer"),
        }
    else:
        data = {
            "policy": cfg.policy,
            "hostnames": hostnames,
            "directory": str(cfg.directory),
            "endpoint": cfg.endpoint,
            "credential_file": str(cfg.credential_file),
        }
    return nice_json(data)


@cache
def _environment() -> jinja2.Environment:
    environment = jinja2.Environment(
        loader=jinja2.PackageLoader(PACKAGE, "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,
    )
    environment.filters["quote"] = lambda value: shlex.quote(str(value))
    return environment


def render(cfg: SoftwareEstatePublisherConfig, template: str) -> str:
    """``templates/<platform>/<template>`` with the role's variable names."""

    if cfg.platform == "linux":
        values: dict[str, Any] = {
            "software_estate_publisher_linux_python": str(cfg.python),
            "software_estate_publisher_linux_release": release_path(cfg),
            "software_estate_publisher_linux_minute": cfg.minute,
        }
    else:
        values = {
            "software_estate_publisher_label": cfg.label,
            "software_estate_publisher_python": str(cfg.python),
            "software_estate_publisher_release": release_path(cfg),
            "software_estate_publisher_config": str(cfg.config_path),
            "software_estate_publisher_minute": cfg.minute,
        }
    return _environment().get_template(f"{cfg.platform}/{template}").render(**values)
