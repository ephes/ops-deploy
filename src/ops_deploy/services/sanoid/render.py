"""Render the original role resources with their original whitespace."""

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from .config import SanoidConfig

ENV = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    undefined=StrictUndefined,
    keep_trailing_newline=True,
    trim_blocks=True,
    lstrip_blocks=True,
)


def render(cfg: SanoidConfig, resource: str) -> str:
    values = {"sanoid_" + key: value for key, value in cfg.model_dump().items()}
    return ENV.get_template(resource + ".j2").render(**values)
