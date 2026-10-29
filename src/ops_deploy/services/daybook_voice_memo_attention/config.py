"""Original disabled attention wheel installation declaration."""

from __future__ import annotations

import json
import re
from importlib.resources import files
from pathlib import PurePosixPath
from typing import Any, Self

from jinja2 import StrictUndefined, UndefinedError
from jinja2.nativetypes import NativeEnvironment
from pydantic import Field, StrictBool, model_validator

from ops_deploy.base import RoleConfig

PACKAGE = "ops_deploy.services.daybook_voice_memo_attention"
DEFAULTS: dict[str, Any] = json.loads(files(PACKAGE).joinpath("defaults.json").read_text())


class DaybookVoiceMemoAttentionConfig(RoleConfig):
    daybook_voice_memo_attention_enabled: StrictBool = False
    daybook_voice_memo_attention_service_user: str = "CHANGEME"
    daybook_voice_memo_attention_service_home: str = ""
    daybook_voice_memo_attention_wheel_src: str = "CHANGEME"
    daybook_voice_memo_attention_install_root: str = ""
    daybook_voice_memo_attention_venv: str = ""
    daybook_voice_memo_attention_uv_bin: str = ""
    daybook_voice_memo_attention_python_version: str = ""
    daybook_voice_memo_attention_python_install_dir: str = ""
    daybook_voice_memo_attention_runtime_dir: str = ""
    daybook_voice_memo_attention_config_path: str = ""
    daybook_voice_memo_attention_config: dict[str, Any] = Field(default_factory=dict, repr=False)
    daybook_voice_memo_attention_launchd_label: str = ""
    daybook_voice_memo_attention_plist_path: str = ""

    @model_validator(mode="before")
    @classmethod
    def original_defaults(cls, supplied: Any) -> Any:
        if not isinstance(supplied, dict):
            return supplied
        values = {**DEFAULTS, **supplied}
        pending = set(DEFAULTS) - set(supplied)
        env = NativeEnvironment(undefined=StrictUndefined)
        for _ in range(len(DEFAULTS) + 1):
            remaining = set()
            for key in pending:
                try:
                    values[key] = (
                        env.from_string(DEFAULTS[key]).render(values)
                        if isinstance(DEFAULTS[key], str)
                        else DEFAULTS[key]
                    )
                    if any(marker in json.dumps(values[key]) for marker in ("{{", "{%", "{#")):
                        remaining.add(key)
                except UndefinedError:
                    remaining.add(key)
            if not remaining:
                return values
            pending = remaining
        raise ValueError("Attention defaults could not be resolved")

    @model_validator(mode="after")
    def disabled_original_layout(self) -> Self:
        prefix = "daybook_voice_memo_attention_"
        data = {key.removeprefix(prefix): value for key, value in self.model_dump().items()}
        user = data["service_user"]
        if data["enabled"] or user in {"root", "CHANGEME"} or not re.fullmatch(r"[a-z_][a-z0-9_-]*", user):
            raise ValueError("Attention supports disabled installation for its original non-root owner only")
        home = "/Users/" + user
        install = "/Library/Application Support/Daybook/voice-memo-attention"
        runtime = home + "/.local/state/daybook/voice-memo-attention"
        label = "de.wersdoerfer.daybook.voice-memo-attention"
        expected = {
            "service_home": home,
            "install_root": install,
            "venv": install + "/venv",
            "uv_bin": "/opt/homebrew/bin/uv",
            "python_install_dir": "/Library/Application Support/Daybook/python",
            "runtime_dir": runtime,
            "config_path": runtime + "/config.json",
            "launchd_label": label,
            "plist_path": home + "/Library/LaunchAgents/" + label + ".plist",
        }
        if any(data[key] != value for key, value in expected.items()):
            raise ValueError("Attention requires its original separate installation and runtime paths")
        wheel = PurePosixPath(data["wheel_src"])
        if (
            not wheel.is_absolute()
            or ".." in wheel.parts
            or any(char in str(wheel) for char in "\0\r\n")
            or not re.fullmatch(r"daybook-[A-Za-z0-9_.+-]+[.]whl", wheel.name)
            or not re.fullmatch(r"3\.14\.[0-9]+", data["python_version"])
        ):
            raise ValueError("Attention requires an absolute Daybook wheel and an exact Python 3.14 patch")
        config = data["config"]
        if (
            type(config.get("version")) is not int
            or config["version"] != 1
            or config.get("enabled") is not False
            or config.get("profile") not in {"synthetic", "production"}
            or config.get("state_path") != runtime + "/state.sqlite3"
            or not isinstance(config.get("source"), dict)
            or config["source"].get("kind") not in {"synthetic", "s3"}
        ):
            raise ValueError("Attention requires the original explicitly disabled private configuration")
        return self
