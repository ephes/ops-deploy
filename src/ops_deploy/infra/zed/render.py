from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from .config import ZedConfig

ENV = Environment(
    loader=FileSystemLoader(Path(__file__).parent / "templates"),
    undefined=StrictUndefined,
    keep_trailing_newline=True,
    trim_blocks=True,
    lstrip_blocks=True,
)
ENV.filters["bool"] = bool


def render(cfg: ZedConfig, template: str) -> str:
    values = {"zed_" + key: value for key, value in cfg.model_dump().items()}
    values["zed_scrub_spindown_script_path"] = cfg.scrub_spindown_script_path or ""
    return ENV.get_template(template).render(**values)
