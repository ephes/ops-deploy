"""``.env`` values read back by the real parsers: ``sh``, django-environ and python-dotenv.

Every value :func:`env_value_problem` accepts must come back unchanged from
all three; systemd's ``EnvironmentFile=`` takes single-quoted text as it is
(not testable here). Values it refuses are ones at least one parser would
change, or that cannot be a single-quoted line at all.
"""

from __future__ import annotations

import io
import itertools
import subprocess
from pathlib import Path

import environ
import pytest
from dotenv import dotenv_values

from ops_deploy.services.django_site import EnvEntry, EnvSpec
from ops_deploy.services.django_site.config import env_value_problem
from ops_deploy.services.django_site.render import render_env
from tests.django_site_fixtures import site_config, values
from tests.marina_fixtures import make_source

# Characters a quoting rule could trip over, plus ordinary ones.
ALPHABET = ["a", " ", "'", '"', "\\", "$", "{", "}", "#", ";", "`", "=", "!", "*"]


def parse_sh(path: Path) -> dict[str, str]:
    out = subprocess.run(
        ["env", "-i", "sh", "-c", f"set -a; . {path}; set +a; env -0"], capture_output=True, check=True
    ).stdout.decode()
    pairs = dict(item.split("=", 1) for item in out.split("\0") if "=" in item)
    return {k: v for k, v in pairs.items() if k.isupper() and k not in ("PWD", "SHLVL", "_")}


def parse_environ(path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    target: dict[str, str] = {}
    monkeypatch.setattr(environ.Env, "ENVIRON", target)
    environ.Env.read_env(str(path))
    return target


def parse_dotenv(text: str) -> dict[str, str]:
    return {k: v or "" for k, v in dotenv_values(stream=io.StringIO(text)).items()}


def candidates() -> list[str]:
    singles = ["".join(chars) for n in (1, 2, 3) for chars in itertools.product(ALPHABET, repeat=n)]
    return [*singles, "${HOME}", "a${X}b", "$HOME", '"x"', "x\\\\y", "ends\\", 'k$y with space; `x` \\ "q"']


def test_accepted_values_read_back_unchanged_everywhere(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    accepted = [v for v in candidates() if env_value_problem(v) is None]
    refused = [v for v in candidates() if env_value_problem(v) is not None]
    assert len(accepted) > 1000
    assert refused
    cfg = site_config(make_source(tmp_path))
    entries = tuple(EnvEntry(key=f"V{i}", value=v) for i, v in enumerate(accepted))
    site = cfg.model_copy(update={"env": EnvSpec(admin_url="marina_admin/", extra=entries)})
    text = render_env(site, values(site)).reveal().decode()
    path = tmp_path / "site.env"
    path.write_text(text)
    expected = {f"V{i}": v for i, v in enumerate(accepted)}

    for name, parsed in (
        ("sh", parse_sh(path)),
        ("django-environ", parse_environ(path, monkeypatch)),
        ("python-dotenv", parse_dotenv(text)),
    ):
        got = {k: parsed.get(k) for k in expected}
        wrong = {k: (expected[k], got[k]) for k in expected if got[k] != expected[k]}
        assert wrong == {}, name


@pytest.mark.parametrize("value", ["a${X}b", "x\\\\y", "ends\\", "$HOME", '"x"'])
def test_refused_values_are_ones_a_parser_would_change(value: str, monkeypatch: pytest.MonkeyPatch) -> None:
    line = f"K='{value}'\n"
    monkeypatch.setattr(environ.Env, "ENVIRON", {})
    environ.Env.read_env(io.StringIO(line))
    try:
        # What settings get: env("K") resolves a leading $ as another variable.
        from_environ: str | None = environ.Env().str("K")
    except Exception:
        from_environ = None

    assert env_value_problem(value) is not None
    assert parse_dotenv(line).get("K") != value or from_environ != value
