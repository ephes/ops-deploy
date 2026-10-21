"""certifi/pip security floors: the controller-side lock check and the remote trust check."""

from __future__ import annotations

import shlex
import shutil
import subprocess
from importlib.resources import files
from pathlib import Path

import pytest

from ops_deploy.helpers.python_security import lock_floor_problems, project_locks, require_lock_floors
from ops_deploy.services.django_site import deploy_django_site
from ops_deploy.testing import RecordingRsyncRunner, run_deploy_fake
from tests import fakehost
from tests.django_site_fixtures import site_config, values
from tests.marina_fixtures import make_source

STALE = """version = 1
revision = 3
requires-python = ">=3.12"

[[package]]
name = "certifi"
version = "2026.7.22"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pip"
version = "26.2.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "django"
version = "5.2.18"
source = { registry = "https://pypi.org/simple" }
"""
CURRENT = STALE.replace('"2026.7.22"', '"2026.10.19"').replace('"26.2.1"', '"26.2.2"')
SCRIPT = files("ops_deploy.helpers").joinpath("templates/python_security_check.py.txt").read_text()
UV = shutil.which("uv")
# The same root with a non-canonical outer length (30 83 00 02 4e): OpenSSL
# still loads it, with the original fingerprint.
G3_TRUSTED_NONCANONICAL = """-----BEGIN TRUSTED CERTIFICATE-----
MIMAAk4wggHToAMCAQICCjz2B6locA7ai4QwCgYIKoZIzj0EAwMwazELMAkGA1UEBhMCSU4xEzAR
BgNVBAsTCmVtU2lnbiBQS0kxJTAjBgNVBAoTHGVNdWRocmEgVGVjaG5vbG9naWVzIExpbWl0ZWQx
IDAeBgNVBAMTF2VtU2lnbiBFQ0MgUm9vdCBDQSAtIEczMB4XDTE4MDIxODE4MzAwMFoXDTQzMDIx
ODE4MzAwMFowazELMAkGA1UEBhMCSU4xEzARBgNVBAsTCmVtU2lnbiBQS0kxJTAjBgNVBAoTHGVN
dWRocmEgVGVjaG5vbG9naWVzIExpbWl0ZWQxIDAeBgNVBAMTF2VtU2lnbiBFQ0MgUm9vdCBDQSAt
IEczMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEI6UMuC0S9SjzsbLd4gISgJ45X0lNn8klNFl07LsG
HOfAcq/ori/hQVSHFKhKsuh8guZbarXcs3XOiwbQhiO/RtWODz8E9Ncckn72pWPC9V+OLk+hGBkC
KzIKgmR9FpPRo0IwQDAdBgNVHQ4EFgQUfF0ChBPUzIqbgc4XHC4pHpxIY0IwDgYDVR0PAQH/BAQD
AgEGMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwMDaQAwZgIxAL7zYc8CEB1klQe4GG6IhQUv
gwgXkMofikzoDRt6sa3VgQlH7zusCAR8XJmx7UcH0gIxAJ26VfypSujt7eZ2AUJ7yPhg2Y1Ri1U7
+4x762UJw/iWzUeogvIWVXckfhIQlQQsozAMMAoGCCsGAQUFBwMB
-----END TRUSTED CERTIFICATE-----
"""
# emSign ECC Root CA - G3 (public root) as an OpenSSL TRUSTED CERTIFICATE block.
G3_TRUSTED = """-----BEGIN TRUSTED CERTIFICATE-----
MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG
EwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNo
bm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0g
RzMwHhcNMTgwMjE4MTgzMDAwWhcNNDMwMjE4MTgzMDAwWjBrMQswCQYDVQQGEwJJ
TjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNobm9s
b2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0gRzMw
djAQBgcqhkjOPQIBBgUrgQQAIgNiAAQjpQy4LRL1KPOxst3iAhKAnjlfSU2fySU0
WXTsuwYc58Byr+iuL+FBVIcUqEqy6HyC5ltqtdyzdc6LBtCGI79G1Y4PPwT01xyS
fvalY8L1X44uT6EYGQIrMgqCZH0Wk9GjQjBAMB0GA1UdDgQWBBR8XQKEE9TMipuB
zhccLikenEhjQjAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAKBggq
hkjOPQQDAwNpADBmAjEAvvNhzwIQHWSVB7gYboiFBS+DCBeQyh+KTOgNG3qxrdWB
CUfvO6wIBHxcmbHtRwfSAjEAnbpV/KlK6O3t5nYBQnvI+GDZjVGLVTv7jHvrZQnD
+JbNR6iC8hZVdyR+EhCVBCyjMAwwCgYIKwYBBQUHAwE=
-----END TRUSTED CERTIFICATE-----
"""


def test_stale_lock_reports_each_package_below_its_floor() -> None:
    assert lock_floor_problems(STALE) == [
        "certifi 2026.7.22 is locked; 2026.10.19 or later is required",
        "pip 26.2.1 is locked; 26.2.2 or later is required",
    ]


def test_current_lock_and_absent_packages_pass() -> None:
    assert lock_floor_problems(CURRENT) == []
    assert lock_floor_problems("version = 1\n") == []
    assert lock_floor_problems('version = 1\n[[package]]\nname = "django"\nversion = "5.2"\n') == []


def test_unrecognised_versions_and_malformed_locks_fail() -> None:
    assert lock_floor_problems('[[package]]\nname = "certifi"\nversion = "2026.10.19rc1"\n') == [
        "certifi 2026.10.19rc1: version not recognised"
    ]
    with pytest.raises(ValueError, match="malformed"):
        lock_floor_problems('package = "x"\n')
    with pytest.raises(ValueError, match="Invalid value"):
        lock_floor_problems("not = [toml")


def test_require_lock_floors_names_the_source_without_host_specific_advice(tmp_path: Path) -> None:
    lock = tmp_path / "uv.lock"
    lock.write_text(STALE)
    with pytest.raises(ValueError, match="site source") as error:
        require_lock_floors(tmp_path, "site source")
    message = str(error.value)
    assert message.startswith(
        "site source: uv.lock, a uv.lock about to be installed, is below the certifi/pip security floor "
        "(certifi 2026.7.22 is locked; 2026.10.19 or later is required; pip 26.2.1 is locked"
    )
    assert "Nothing was changed" in message
    assert "/Users/" not in message
    assert "DEPLOY_SOURCE" not in message
    lock.write_text(CURRENT)
    require_lock_floors(tmp_path, "site source")
    lock.unlink()
    require_lock_floors(tmp_path, "site source")


def test_a_workspace_root_lock_counts_for_a_member(tmp_path: Path) -> None:
    # uv installs a workspace member from the workspace root's lock.
    member = tmp_path / "packages" / "app"
    member.mkdir(parents=True)
    (member / "uv.lock").write_text(CURRENT)
    (tmp_path / "uv.lock").write_text(STALE)
    assert project_locks(member, tmp_path) == [member / "uv.lock", tmp_path / "uv.lock"]
    with pytest.raises(ValueError, match=r"^app source: uv\.lock, a uv\.lock about to be installed"):
        require_lock_floors(member, "app source", root=tmp_path)
    # Locks above the synced tree are not the deploy's.
    (tmp_path / "uv.lock").write_text(CURRENT)
    (tmp_path.parent / "uv.lock").write_text(STALE)
    try:
        require_lock_floors(member, "app source", root=tmp_path)
    finally:
        (tmp_path.parent / "uv.lock").unlink()
    with pytest.raises(ValueError, match="not inside"):
        project_locks(tmp_path.parent, tmp_path)


def site(tmp_path: Path, lock: str):  # type: ignore[no-untyped-def]
    source = make_source(tmp_path)
    (source / "uv.lock").write_text(lock)
    return site_config(source)


def test_django_site_refuses_a_stale_lock_before_any_operation(tmp_path: Path) -> None:
    cfg = site(tmp_path, STALE)
    rsync = RecordingRsyncRunner()
    with pytest.raises(ValueError, match=r"certifi 2026\.7\.22 is locked"):
        run_deploy_fake(deploy_django_site, cfg, values(cfg), rsync=rsync, responses={**fakehost.LINUX})
    # Raised while planning: nothing was synced to, or run on, the host.
    assert rsync.calls == []


def test_django_site_verifies_trust_after_the_sync_as_the_service_user(tmp_path: Path) -> None:
    cfg = site(tmp_path, CURRENT)
    run = run_deploy_fake(
        deploy_django_site, cfg, values(cfg), rsync=RecordingRsyncRunner(), responses={**fakehost.LINUX}
    )
    assert run.succeeded, run.error
    names = [op.name for op in run.ops]
    verify = "Deploy marina | Verify marina certifi/pip trust"
    assert names.index("Deploy marina | uv sync /home/marina/site") < names.index(verify)
    assert next(op for op in run.ops if op.name == verify).read_only
    command = next(c for c in run.executed_commands if " -I -c " in c)
    argv = shlex.split(command)
    assert argv[:4] == ["runuser", "-u", "marina", "--"]
    assert argv[-4:] == [str(cfg.venv_bin / "python"), "-I", "-c", SCRIPT]


@pytest.mark.skipif(UV is None, reason="uv is required")
class TestRemoteCheck:
    """The remote script against real environments."""

    def venv(self, tmp_path: Path, *packages: str, seed: bool = False) -> Path:
        path = tmp_path / "venv"
        assert UV is not None
        subprocess.run([UV, "venv", "-q", "--python", "3.12", *(["--seed"] if seed else []), str(path)], check=True)
        if packages:
            subprocess.run([UV, "pip", "install", "-q", "--python", str(path / "bin/python"), *packages], check=True)
        return path

    def check(self, venv: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(venv / "bin/python"), "-I", "-c", SCRIPT], capture_output=True, text=True, cwd=venv.parent
        )

    def test_current_certifi_without_pip_passes(self, tmp_path: Path) -> None:
        result = self.check(self.venv(tmp_path, "certifi==2026.10.19"))
        assert (result.returncode, result.stdout) == (0, "")

    def test_absent_certifi_and_pip_pass(self, tmp_path: Path) -> None:
        result = self.check(self.venv(tmp_path))
        assert (result.returncode, result.stdout) == (0, "")

    def test_old_certifi_fails_with_version_and_root(self, tmp_path: Path) -> None:
        result = self.check(self.venv(tmp_path, "certifi==2026.7.22"))
        assert result.returncode == 1
        lines = result.stdout.splitlines()
        assert lines[0] == "certifi 2026.7.22 is installed; 2026.10.19 or later is required"
        assert lines[1].endswith("contains distrusted root emSign ECC Root CA - G3")

    def test_version_is_read_without_importlib_metadata(self, tmp_path: Path) -> None:
        # Python < 3.8 has no importlib.metadata; the script must not need it.
        venv = self.venv(tmp_path, "certifi==2026.10.19")
        blocked = "import sys; sys.modules['importlib.metadata'] = None\n" + SCRIPT
        result = subprocess.run([str(venv / "bin/python"), "-I", "-c", blocked], capture_output=True, text=True)
        assert (result.returncode, result.stdout) == (0, "")

    def test_an_ambiguous_installed_version_fails_closed(self, tmp_path: Path) -> None:
        venv = self.venv(tmp_path, "certifi==2026.10.19")
        (info,) = (venv / "lib").glob("python3.12/site-packages/certifi-*.dist-info")
        shutil.copytree(info, info.with_name("certifi-2026.7.22.dist-info"))
        result = self.check(venv)
        assert result.returncode == 1
        assert result.stdout.splitlines()[0] == "certifi None: version not recognised"

    def bundle(self, venv: Path) -> Path:
        (path,) = (venv / "lib").glob("python3.12/site-packages/certifi/cacert.pem")
        return path

    def test_trusted_certificate_block_is_fingerprinted(self, tmp_path: Path) -> None:
        venv = self.venv(tmp_path, "certifi==2026.10.19")
        with self.bundle(venv).open("a") as handle:
            handle.write(G3_TRUSTED)
        result = self.check(venv)
        assert result.returncode == 1
        assert result.stdout.splitlines()[0].endswith("contains distrusted root emSign ECC Root CA - G3")

    def test_noncanonical_encoding_of_a_distrusted_root_is_still_matched(self, tmp_path: Path) -> None:
        venv = self.venv(tmp_path, "certifi==2026.10.19")
        with self.bundle(venv).open("a") as handle:
            handle.write(G3_TRUSTED_NONCANONICAL)
        result = self.check(venv)
        assert result.returncode == 1
        assert result.stdout.splitlines()[0].endswith("contains distrusted root emSign ECC Root CA - G3")

    def test_bundle_openssl_cannot_load_fails_closed(self, tmp_path: Path) -> None:
        venv = self.venv(tmp_path, "certifi==2026.10.19")
        self.bundle(venv).write_text("not a certificate\n")
        result = self.check(venv)
        assert result.returncode == 1
        assert "could not be read:" in result.stdout

    def test_old_pip_fails_with_its_vendored_bundle(self, tmp_path: Path) -> None:
        venv = self.venv(tmp_path, seed=True)
        subprocess.run(
            [str(venv / "bin/python"), "-m", "pip", "-q", "--disable-pip-version-check", "install", "pip==23.2.1"],
            check=True,
        )
        result = self.check(venv)
        assert result.returncode == 1
        lines = result.stdout.splitlines()
        assert lines[0] == "pip 23.2.1 is installed; 26.2.2 or later is required"
        assert sorted(line.rsplit("distrusted root ", 1)[1] for line in lines[1:]) == [
            "AAA Certificate Services",
            "emSign ECC Root CA - G3",
        ]


def test_django_site_refuses_a_stale_workspace_root_lock_above_the_app_dir(tmp_path: Path) -> None:
    from tests import django_site_split_fixtures as split

    source = split.make_source(tmp_path)
    (source / "django" / "uv.lock").write_text(CURRENT)
    (source / "uv.lock").write_text(STALE)
    cfg = split.split_config(source)
    rsync = RecordingRsyncRunner()
    with pytest.raises(ValueError, match=r"source: uv\.lock, a uv\.lock about to be installed"):
        run_deploy_fake(deploy_django_site, cfg, split.values(cfg), rsync=rsync, responses={**fakehost.LINUX})
    assert rsync.calls == []
