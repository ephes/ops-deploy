"""Exact diagnostic cafbe interpreter retained as the negative native control."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from types import ModuleType

SOURCE_SHA = "dc70d136298f9485e1c71479a818cec9abcfa02ba4a91fb473352031b205387d"
SOURCE_REF = "cafbe614f98ddea5f49a519fa44493002e74f031"


def load() -> ModuleType:
    name = "ops_deploy.services.homeassistant._owned_frozen_interpreter"
    if name not in sys.modules:
        path = Path(__file__).with_name("interpreter_cafbe.py.txt")
        source = path.read_bytes()
        if hashlib.sha256(source).hexdigest() != SOURCE_SHA:
            raise RuntimeError("owned frozen interpreter source mismatch")
        module = ModuleType(name)
        module.__file__ = str(path)
        module.__package__ = "ops_deploy.services.homeassistant"
        sys.modules[name] = module
        exec(compile(source, str(path), "exec"), module.__dict__)
    return sys.modules[name]
