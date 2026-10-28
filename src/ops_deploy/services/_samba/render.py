from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined


def role_render(role: str, resource: str, values: dict[str, Any]) -> str:
    env = Environment(
        loader=FileSystemLoader(Path(__file__).parent.parent / role / "templates"),
        undefined=StrictUndefined,
        keep_trailing_newline=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    return env.get_template(resource + ".j2").render(ansible_managed="Ansible managed", **values)
