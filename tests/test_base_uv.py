"""uv_install: the canonical uv/uvx pair, its owner and mode, and approved compatibility links."""

from typing import Any

import pytest
from pydantic import ValidationError

from ops_deploy.base import UvAliasConfig, UvInstallConfig, deploy_uv_install
from ops_deploy.testing import run_deploy_fake
from tests import fakehost
from tests.fakehost import LINUX

X86 = {**LINUX, "uname -m": ["x86_64"], **fakehost.directory("/usr/local/bin")}
SHA_X86 = "f68d291c75783122dad58ab77def0e13f3233f358731db5d6d7e8715603b928f"
LEGACY = "legacy uv 0.13.4 bytes"


def installed(
    version: str | None = "0.13.5",
    *,
    uvx: str | None = "0.13.5",
    user: str = "root",
    mode: str = "-rwxr-xr-x",
) -> dict[str, Any]:
    responses: dict[str, Any] = {}
    for name, ver in (("uv", version), ("uvx", uvx)):
        if ver:
            responses.update(fakehost.file(f"/usr/local/bin/{name}", "binary", user=user, mode=mode))
            responses[f"/usr/local/bin/{name} --version"] = [f"{name} {ver} (x86_64-unknown-linux-gnu)"]
    return responses


def install_command(run: Any) -> str:
    assert run.succeeded, run.error
    (command,) = [c for c in run.executed_commands if "release.tar.gz" in c]
    return str(command)


def alias(path: str = "/usr/local/uv", binary: str = "uv", **extra: Any) -> UvAliasConfig:
    return UvAliasConfig(path=path, binary=binary, **extra)


def legacy_sha() -> str:
    import hashlib

    return hashlib.sha256(LEGACY.encode()).hexdigest()


def test_installs_verified_pair_when_missing() -> None:
    command = install_command(run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses=X86))

    assert "https://github.com/astral-sh/uv/releases/download/0.13.5/uv-x86_64-unknown-linux-gnu.tar.gz" in command
    assert f"echo {SHA_X86}'  '\"$tmp/release.tar.gz\" | sha256sum -c --quiet -" in command
    # Checksum first, then each binary staged and renamed into place, then both versions checked.
    assert command.index("sha256sum") < command.index("install -o root -g root -m 0755")
    for name in ("uv", "uvx"):
        assert f"&& mv -f /usr/local/bin/.{name}.ops-deploy-new /usr/local/bin/{name}" in command
        assert f'test "$(/usr/local/bin/{name} --version | cut -d " " -f 2)" = 0.13.5' in command


def test_same_pair_changes_nothing() -> None:
    run = run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses={**X86, **installed()})

    assert run.succeeded, run.error
    assert run.changed_ops == []


@pytest.mark.parametrize("uvx", [None, "0.9.0"])
def test_current_uv_with_missing_or_old_uvx_reinstalls_the_pair(uvx: str | None) -> None:
    assert install_command(
        run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses={**X86, **installed(uvx=uvx)})
    )


def test_current_uvx_with_old_uv_reinstalls_the_pair() -> None:
    responses = {**X86, **installed("0.9.0")}

    assert install_command(run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses=responses))


def test_other_version_is_replaced_unless_updates_are_off() -> None:
    responses = {**X86, **installed("0.9.0", uvx="0.9.0")}

    assert install_command(run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses=responses))
    kept = run_deploy_fake(deploy_uv_install, UvInstallConfig(update_existing=False), responses=responses)
    assert kept.succeeded, kept.error
    assert kept.changed_ops == []


@pytest.mark.parametrize("update_existing", [True, False])
def test_a_consistent_newer_pair_is_kept_not_downgraded(update_existing: bool) -> None:
    # metube pins 0.13.4 on a host whose shared uv is 0.13.5: keep the newer pair.
    responses = {**X86, **installed("0.13.6", uvx="0.13.6")}

    run = run_deploy_fake(deploy_uv_install, UvInstallConfig(update_existing=update_existing), responses=responses)

    assert run.succeeded, run.error
    assert run.changed_ops == []


@pytest.mark.parametrize(
    ("uv", "uvx", "force"),
    [("0.13.5", "0.13.6", False), ("0.13.6", None, False), ("0.13.6", "0.13.6", True)],
)
def test_refuses_a_reinstall_that_would_downgrade(uv: str, uvx: str | None, force: bool) -> None:
    run = run_deploy_fake(
        deploy_uv_install, UvInstallConfig(force_reinstall=force), responses={**X86, **installed(uv, uvx=uvx)}
    )

    assert "newer than the pinned 0.13.5 and the pair needs a reinstall; refusing to downgrade" in str(run.error)
    assert run.executed_commands == []


def test_owned_mode_drift_is_repaired_without_a_download() -> None:
    responses = {**X86, **installed(mode="-rwx------")}

    run = run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses=responses)

    assert run.succeeded, run.error
    assert not [c for c in run.executed_commands if "release.tar.gz" in c]
    assert any("chmod 755 /usr/local/bin/uv" in c for c in run.executed_commands)
    assert any("chmod 755 /usr/local/bin/uvx" in c for c in run.executed_commands)


@pytest.mark.parametrize(
    "fact",
    [
        {"user": "cast", "mode": "-rwxr-xr-x"},  # foreign owner
        {"user": "root", "mode": "-rwxrwxr-x"},  # group-writable
        {"user": "root", "mode": "-rw-r--r--"},  # not executable
    ],
)
def test_untrusted_canonical_file_is_never_run_and_gets_fresh_bytes(fact: dict[str, str]) -> None:
    responses = {**X86, **installed(**fact)}

    run = run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses=responses)

    assert install_command(run)
    assert not any(c.startswith("/usr/local/bin/uv --version") for c in run.executed_commands)


def test_symlinked_uv_is_replaced() -> None:
    responses = {**X86, **installed(None), **fakehost.symlink("/usr/local/bin/uv", "/root/.local/bin/uv")}

    assert install_command(run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses=responses))


def test_refuses_a_directory_at_the_canonical_path() -> None:
    responses = {**X86, **installed(None), **fakehost.directory("/usr/local/bin/uv")}

    run = run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses=responses)

    assert "/usr/local/bin/uv is not a regular file" in str(run.error)
    assert run.executed_commands == []


def test_force_reinstall() -> None:
    responses = {**X86, **installed()}

    assert install_command(
        run_deploy_fake(deploy_uv_install, UvInstallConfig(force_reinstall=True), responses=responses)
    )


def test_arm_host_uses_the_aarch64_archive() -> None:
    run = run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses={**X86, "uname -m": ["aarch64"]})

    assert "uv-aarch64-unknown-linux-gnu.tar.gz" in install_command(run)


def test_unpinned_architecture_fails_before_any_change() -> None:
    run = run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses={**X86, "uname -m": ["riscv64"]})

    assert "no pinned checksum for unsupported-unknown-linux-gnu" in str(run.error)
    assert run.executed_commands == []


def test_refuses_macos() -> None:
    run = run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses={"uname -s": ["Darwin"]})

    assert "Linux hosts only" in str(run.error)


@pytest.mark.parametrize(
    "overrides",
    [
        {"install_dir": "/"},
        {"install_dir": "relative"},
        {"version": "latest"},
        {"checksums": {"x": "nothex"}},
        {"aliases": [{"path": "/usr/local/bin/uv", "binary": "uv"}]},
        {"aliases": [{"path": "/usr/local/bin/.uvx.ops-deploy-new", "binary": "uvx"}]},
        {"aliases": [{"path": "/usr/local/uv", "binary": "uv"}, {"path": "/usr/local/uv", "binary": "uvx"}]},
        {"aliases": [{"path": "/usr/local/../uv", "binary": "uv"}]},
        {"aliases": [{"path": "/usr/local/uv", "binary": "uvw"}]},
        {"aliases": [{"path": "/usr/local/uv", "binary": "uv"}], "darwin": True},
    ],
)
def test_rejects_invalid_config(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        UvInstallConfig(**overrides)


def test_installs_curl_when_missing() -> None:
    responses = {**X86, "command -v curl": [], "command -v apt-get": ["/usr/bin/apt-get"]}

    run = run_deploy_fake(deploy_uv_install, UvInstallConfig(), responses=responses)

    assert run.succeeded, run.error
    assert any("apt-get" in c and "curl" in c for c in run.executed_commands)


# Approved compatibility links (``aliases``).

ALIAS_ROOT = {**X86, **installed(), **fakehost.directory("/usr/local")}


def test_missing_alias_becomes_a_root_link_to_the_canonical_binary() -> None:
    cfg = UvInstallConfig(aliases=(alias(), alias("/usr/local/uvx", "uvx")))

    run = run_deploy_fake(deploy_uv_install, cfg, responses=ALIAS_ROOT)

    assert run.succeeded, run.error
    assert any("ln -s /usr/local/bin/uv /usr/local/uv" in c for c in run.executed_commands)
    assert any("ln -s /usr/local/bin/uvx /usr/local/uvx" in c for c in run.executed_commands)


def test_correct_alias_link_changes_nothing() -> None:
    responses = {**ALIAS_ROOT, **fakehost.symlink("/usr/local/uv", "/usr/local/bin/uv")}

    run = run_deploy_fake(deploy_uv_install, UvInstallConfig(aliases=(alias(),)), responses=responses)

    assert run.succeeded, run.error
    assert run.changed_ops == []


def test_approved_legacy_copy_is_moved_aside_and_linked() -> None:
    responses = {**ALIAS_ROOT, **fakehost.file("/usr/local/uv", LEGACY, mode="-rwxr-xr-x")}
    cfg = UvInstallConfig(aliases=(alias(replace_sha256=legacy_sha()),))

    run = run_deploy_fake(deploy_uv_install, cfg, responses=responses)

    assert run.succeeded, run.error
    commands = "\n".join(run.executed_commands)
    # Moved to a timestamped backup, never deleted.
    assert "mv /usr/local/uv /usr/local/uv." in commands
    assert "rm -rf /usr/local/uv" not in commands
    assert "ln -s /usr/local/bin/uv /usr/local/uv" in commands


@pytest.mark.parametrize(
    ("extra", "file_user"),
    [
        ({}, "root"),  # no approval at all
        ({"replace_sha256": "0" * 64}, "root"),  # other bytes
        ({"replace_sha256": None}, "cast"),  # other owner, no approval
    ],
)
def test_unapproved_file_at_alias_fails_before_any_change(extra: dict[str, Any], file_user: str) -> None:
    responses = {**ALIAS_ROOT, **fakehost.file("/usr/local/uv", LEGACY, user=file_user, mode="-rwxr-xr-x")}

    run = run_deploy_fake(deploy_uv_install, UvInstallConfig(aliases=(alias(**extra),)), responses=responses)

    assert "is not the approved file" in str(run.error)
    assert run.executed_commands == []


def test_approved_bytes_with_another_owner_are_refused() -> None:
    responses = {**ALIAS_ROOT, **fakehost.file("/usr/local/uv", LEGACY, user="cast", mode="-rwxr-xr-x")}
    cfg = UvInstallConfig(aliases=(alias(replace_sha256=legacy_sha()),))

    run = run_deploy_fake(deploy_uv_install, cfg, responses=responses)

    assert "is not the approved file" in str(run.error)


@pytest.mark.parametrize(
    "existing",
    [
        fakehost.symlink("/usr/local/uv", "/opt/other/uv"),
        fakehost.symlink("/usr/local/uv", "/usr/local/bin/uv", user="cast"),
    ],
)
def test_unexpected_alias_link_is_refused(existing: dict[str, Any]) -> None:
    run = run_deploy_fake(deploy_uv_install, UvInstallConfig(aliases=(alias(),)), responses={**ALIAS_ROOT, **existing})

    assert "refusing unexpected symlink" in str(run.error)
    assert run.executed_commands == []


def test_directory_at_alias_is_refused() -> None:
    responses = {**ALIAS_ROOT, **fakehost.directory("/usr/local/uv")}

    run = run_deploy_fake(deploy_uv_install, UvInstallConfig(aliases=(alias(),)), responses=responses)

    assert "is not a regular file" in str(run.error)


@pytest.mark.parametrize(
    "parent",
    [
        {},
        fakehost.directory("/root/.local/bin", user="cast"),
        fakehost.directory("/root/.local/bin", mode="drwxrwxrwx"),
    ],
)
def test_alias_needs_an_existing_root_owned_unwritable_directory(parent: dict[str, Any]) -> None:
    cfg = UvInstallConfig(aliases=(alias("/root/.local/bin/uv"),))

    run = run_deploy_fake(deploy_uv_install, cfg, responses={**X86, **installed(), **parent})

    assert "alias directory /root/.local/bin must exist, be root-owned" in str(run.error)
    assert run.executed_commands == []


def test_aliases_follow_a_fresh_install() -> None:
    cfg = UvInstallConfig(aliases=(alias(),))

    run = run_deploy_fake(deploy_uv_install, cfg, responses={**X86, **fakehost.directory("/usr/local")})

    install = install_command(run)
    link = next(c for c in run.executed_commands if "ln -s /usr/local/bin/uv /usr/local/uv" in c)
    assert run.executed_commands.index(install) < run.executed_commands.index(link)
