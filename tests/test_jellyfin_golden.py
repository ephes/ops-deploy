"""jellyfin's route and apt source stay byte for byte what hosts have today.

The goldens under ``tests/golden/jellyfin`` were recorded when the route
still equalled the retired jellyfin_deploy role's output; identical bytes
mean the next deploy rewrites neither the route nor the repository line
(see tests/goldens.py).
"""

from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import SecretStr

from ops_deploy.helpers import BasicAuth
from ops_deploy.services.jellyfin import JellyfinConfig
from ops_deploy.services.jellyfin.deploy import pick_ffmpeg, render_route, repository_line, traefik_config
from tests.goldens import assert_golden

GOLDEN = Path(__file__).parent / "golden" / "jellyfin"
REPO = {"repo_distro": "ubuntu", "repo_release": "noble", "repo_arch": "amd64"}
# A fixed bcrypt hash: hash_password salts randomly.
AUTH_HASH = "$2y$05$29Gfrp5dhiYLdDhT79roVeQM45oGC/gI9VBinrDYyO5ucrXoLooD6"  # pragma: allowlist secret
CASES: dict[str, dict[str, Any]] = {
    "defaults": {},
    "middlewares-port": {"traefik_middlewares": ("crowdsec@file", "ratelimit"), "http_port": 18096},
    "no-auth": {"basic_auth_enabled": False, "traefik_middlewares": ("extra",), "traefik_cert_resolver": "le"},
}


@pytest.mark.parametrize("case", sorted(CASES))
def test_route_is_golden(case: str) -> None:
    cfg = JellyfinConfig(**{**REPO, **CASES[case]})
    auth = BasicAuth(user="ops", password=SecretStr("fixture-password")) if cfg.basic_auth_enabled else None
    auth_hash = AUTH_HASH if auth else None

    ours = render_route(cfg, traefik_config(cfg, auth), auth_hash)

    assert_golden(GOLDEN / case / "jellyfin.yml", ours)
    route = yaml.safe_load(ours)
    if auth is not None:
        assert route["http"]["middlewares"]["jellyfin-auth"]["basicAuth"]["users"] == [f"ops:{auth_hash}"]
        assert (
            route["http"]["middlewares"]["jellyfin-auth"]["basicAuth"]["removeHeader"] is cfg.basic_auth_remove_header
        )
    else:
        assert "jellyfin-auth" not in route["http"]["middlewares"]


@pytest.mark.parametrize("repo", [REPO, {"repo_distro": "debian", "repo_release": "trixie", "repo_arch": "arm64"}])
def test_repository_line_is_golden(repo: dict[str, str]) -> None:
    assert_golden(GOLDEN / f"jellyfin-{repo['repo_distro']}.list", repository_line(JellyfinConfig(**repo)))


def test_route_path() -> None:
    cfg = JellyfinConfig(**REPO)

    assert str(traefik_config(cfg, None).path) == "/etc/traefik/dynamic/jellyfin.yml"


def test_ffmpeg_pick_takes_the_first_candidate_with_a_version() -> None:
    cfg = JellyfinConfig(**REPO)
    policies = {
        "jellyfin-ffmpeg6": "jellyfin-ffmpeg6:\n  Installed: (none)\n  Candidate: (none)",
        "jellyfin-ffmpeg5": "jellyfin-ffmpeg5:\n  Installed: (none)\n  Candidate: 5.1.4-3",
        "jellyfin-ffmpeg": "jellyfin-ffmpeg:\n  Installed: (none)\n  Candidate: 4.4.1-4",
    }

    assert pick_ffmpeg(cfg, policies) == "jellyfin-ffmpeg5"
    assert pick_ffmpeg(cfg, {}) is None
