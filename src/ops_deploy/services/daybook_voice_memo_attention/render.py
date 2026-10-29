"""Credential-free original disabled launchd declaration."""

from importlib.resources import files

from jinja2 import Environment, StrictUndefined

from .config import PACKAGE, DaybookVoiceMemoAttentionConfig


def render_plist(cfg: DaybookVoiceMemoAttentionConfig) -> str:
    env = Environment(undefined=StrictUndefined, keep_trailing_newline=True)
    return env.from_string(files(PACKAGE).joinpath("templates/attention.launchd.plist.j2").read_text()).render(
        cfg.model_dump()
    )
