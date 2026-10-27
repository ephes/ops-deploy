"""The ports follow ops-library's roles; these tests notice when a role moved on.

Template parity (``test_traefik_parity.test_vendored_templates_match_ops_library``)
only sees templates. A role can also change what it does (remove a file,
stop restarting Traefik, skip entries on restore) without touching a
template. With ``OPS_LIBRARY_PATH`` set to a checkout of ops-library's main
branch, the tests here fail when

- a role file vendored under ``services/*/files`` or ``infra/files`` (or
  another ops-library file, such as ``plugins/filter/rust_release.py``)
  differs from ops-library's or is gone, and
- a role a port mirrors changed since the port was last checked against it:
  ``tests/parity/ops_library_roles.json`` records a digest of each role's
  behaviour (tasks, handlers, defaults, vars, files, templates).

After a role change: port it (or record why not), then update the role's
digest (``python -m tests.test_ops_library_drift`` prints them all) and the
recorded ops-library commit.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

OPS_LIBRARY = os.environ.get("OPS_LIBRARY_PATH")
PACKAGE = Path(__file__).parents[1] / "src" / "ops_deploy"
MANIFEST = Path(__file__).parent / "parity" / "ops_library_roles.json"
# Below a role: what decides its behaviour (not README, meta or Molecule).
BEHAVIOUR = ("defaults", "files", "handlers", "tasks", "templates", "vars")
# ``<package dir>/files/<name>``: ``roles/<role>/files/<name>``, byte for byte.
VENDORED_FILES = {
    "services/dns/files/ddns_update.py": "dns_deploy",
    "services/dns/files/ddns_status_httpd.py": "dns_deploy",
    "infra/files/certbot_stray_guard.py": "certbot_dns_deploy",
    "infra/files/traefik_health_probe.py": "traefik_deploy",
    "services/delve/files/apple-storekit-root-certs.pem": "delve_deploy",
    "services/fastdeploy/files/ensure_token_user.py": "fastdeploy_deploy",
    "services/fastdeploy/files/sudoers_blanket_check.py": "fastdeploy_restore",
}
# ``<package path>``: a file of ops-library outside the roles, byte for byte.
VENDORED_LIBRARY_FILES = {
    "helpers/templates/rust_release.py.txt": "plugins/filter/rust_release.py",
    "services/_metrics_httpd/rules.py": "plugins/filter/metrics_httpd.py",
}

needs_ops_library = pytest.mark.skipif(not OPS_LIBRARY, reason="OPS_LIBRARY_PATH not set")


def role_digest(role: Path) -> str:
    """sha256 over the paths and contents of the role's behaviour files."""

    digest = hashlib.sha256()
    for part in BEHAVIOUR:
        for path in sorted((role / part).rglob("*")):
            relative = path.relative_to(role)
            if not path.is_file() or "__pycache__" in relative.parts or path.name.startswith("."):
                continue
            digest.update(f"\0{relative.as_posix()}\0".encode())
            digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def recorded() -> dict[str, str]:
    roles: dict[str, str] = json.loads(MANIFEST.read_text())["roles"]
    return roles


@needs_ops_library
@pytest.mark.parametrize("vendored", sorted(VENDORED_FILES), ids=str)
def test_vendored_role_files_match_ops_library(vendored: str) -> None:
    assert OPS_LIBRARY is not None
    source = Path(OPS_LIBRARY, "roles", VENDORED_FILES[vendored], "files", Path(vendored).name)

    assert source.is_file(), f"{source} is gone; the port still ships {vendored}"
    assert (PACKAGE / vendored).read_bytes() == source.read_bytes(), f"{source} changed; re-vendor and re-check"


@needs_ops_library
@pytest.mark.parametrize("vendored", sorted(VENDORED_LIBRARY_FILES), ids=str)
def test_vendored_library_files_match_ops_library(vendored: str) -> None:
    assert OPS_LIBRARY is not None
    source = Path(OPS_LIBRARY, VENDORED_LIBRARY_FILES[vendored])

    assert source.is_file(), f"{source} is gone; the port still ships {vendored}"
    assert (PACKAGE / vendored).read_bytes() == source.read_bytes(), f"{source} changed; re-vendor and re-check"


@needs_ops_library
@pytest.mark.parametrize("role", sorted(json.loads(MANIFEST.read_text())["roles"]))
def test_mirrored_roles_did_not_change(role: str) -> None:
    assert OPS_LIBRARY is not None
    path = Path(OPS_LIBRARY, "roles", role)

    assert path.is_dir(), f"role {role} is gone from ops-library; retire or re-check its port"
    assert role_digest(path) == recorded()[role], (
        f"role {role} changed since ops-library {json.loads(MANIFEST.read_text())['ops_library']}: "
        "port the change, then update tests/parity/ops_library_roles.json "
        "(or OPS_LIBRARY_PATH is not a checkout of ops-library main)"
    )


def test_manifest_digests_are_well_formed() -> None:
    manifest = json.loads(MANIFEST.read_text())

    assert len(manifest["ops_library"]) >= 8
    assert all(len(digest) == 64 for digest in manifest["roles"].values())


if __name__ == "__main__":  # print the current digests of the recorded roles
    library = Path(sys.argv[1] if len(sys.argv) > 1 else os.environ["OPS_LIBRARY_PATH"])
    print(json.dumps({role: role_digest(library / "roles" / role) for role in recorded()}, indent=2))
