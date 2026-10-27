"""encrypted_volume: the host admission/apply script and the deploy's plan against the fake connector."""

from __future__ import annotations

import base64
import importlib.util
import json
import stat as stat_module
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from pydantic import SecretStr, ValidationError

from ops_deploy.infra import EncryptedVolumeConfig, deploy_encrypted_volume
from ops_deploy.infra.encrypted_volume import host_command, host_payload
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost

SCRIPT = Path(__file__).parents[1] / "src/ops_deploy/infra/files/encrypted_volume_host.py"
UUID = "e301d851-3454-4b1b-a3a2-5e71f18af8d7"
FS_UUID = "169c4190-32ea-4ef1-b564-03da7eb18fea"
PASSPHRASE = "encrypted-volume-fixture-passphrase"  # pragma: allowlist secret
P = "Prepare encrypted volume | "
CRYPTTAB_LINE = "cryptdata /dev/sda /root/.luks-key-cryptdata luks"
FSTAB_LINE = f"UUID={FS_UUID} /mnt/cryptdata ext4 defaults,noatime 0 0"


def load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("encrypted_volume_host", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


host_script = load_script()


@pytest.fixture
def cfg() -> EncryptedVolumeConfig:
    return EncryptedVolumeConfig(device="/dev/sda", expected_luks_uuid=UUID)


# -- config ------------------------------------------------------------------------


def test_defaults_are_the_roles(cfg: EncryptedVolumeConfig) -> None:
    assert cfg.keyfile == "/root/.luks-key-cryptdata"
    assert cfg.mapper_path == "/dev/mapper/cryptdata"
    assert (cfg.mount_point, cfg.fs_type, cfg.mount_opts) == ("/mnt/cryptdata", "ext4", "defaults,noatime")
    assert (cfg.fstab_dump, cfg.fstab_passno, cfg.crypttab_options) == ("0", "0", "luks")
    assert (cfg.keyfile_owner, cfg.keyfile_group, cfg.keyfile_mode) == ("root", "root", "0400")
    assert (cfg.mount_owner, cfg.mount_group, cfg.mount_mode) == ("root", "root", "0755")
    assert cfg.packages == ("cryptsetup", "cryptsetup-initramfs")


@pytest.mark.parametrize(
    "fields",
    [
        {"expected_luks_uuid": "not-a-uuid"},
        {"mount_point": "/"},
        {"keyfile_path": "/mnt/cryptdata/key"},
        {"mount_opts": "defaults noatime"},
        {"mount_opts": "defaults#x"},
        {"mapper_name": "../x"},
        {"allow_format": True},
        {"device_by_id": "/dev/disk/by-id/x"},
        {"packages": ()},
    ],
)
def test_config_refuses(fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        EncryptedVolumeConfig.model_validate({"device": "/dev/sda", "expected_luks_uuid": UUID, **fields})


def test_host_command_carries_no_secret_and_is_fish_safe(cfg: EncryptedVolumeConfig) -> None:
    command = host_command(cfg, "check")
    assert "\\\\" not in command
    assert "\\'" not in command
    payload = host_payload(cfg)
    assert PASSPHRASE not in json.dumps(payload)
    encoded = command.rsplit(" ", 1)[1]
    assert json.loads(base64.b64decode(encoded)) == payload
    with pytest.raises(ValueError, match="unknown action"):
        host_command(cfg, "format")


# -- crypttab and fstab edits (lineinfile / ansible.posix.mount semantics) ----------------


def test_crypttab_identical_line_is_left_alone() -> None:
    text = f"# comment\nother /dev/sdb none luks\n{CRYPTTAB_LINE}\n"
    assert host_script.crypttab_update(text, CRYPTTAB_LINE, "cryptdata") is None


def test_crypttab_replaces_the_last_match_only() -> None:
    text = "cryptdata /dev/old a luks\nkeep me\ncryptdata\t/dev/older b luks\n"
    new = host_script.crypttab_update(text, CRYPTTAB_LINE, "cryptdata")
    assert new == f"cryptdata /dev/old a luks\nkeep me\n{CRYPTTAB_LINE}\n"


def test_crypttab_appends_and_creates() -> None:
    assert host_script.crypttab_update(None, CRYPTTAB_LINE, "cryptdata") == CRYPTTAB_LINE + "\n"
    assert host_script.crypttab_update("other x y z", CRYPTTAB_LINE, "cryptdata") == f"other x y z\n{CRYPTTAB_LINE}\n"
    # ``cryptdata2`` and comments do not match ``^cryptdata\s``.
    text = "cryptdata2 /dev/x none luks\n# cryptdata /dev/sda\n"
    assert host_script.crypttab_update(text, CRYPTTAB_LINE, "cryptdata") == text + CRYPTTAB_LINE + "\n"


def entry(**overrides: str) -> dict[str, str]:
    base = {
        "src": f"UUID={FS_UUID}",
        "name": "/mnt/cryptdata",
        "fstype": "ext4",
        "opts": "defaults,noatime",
        "dump": "0",
        "passno": "0",
    }
    return {**base, **overrides}


FSTAB = f"# /etc/fstab\nUUID=root / ext4 defaults 0 1\n\n{FSTAB_LINE}\n/mnt/cryptdata/x /srv/x none bind 0 0\n"


def test_fstab_identical_entry_is_left_alone_whatever_the_whitespace() -> None:
    assert host_script.fstab_update(FSTAB, entry()) == (None, 1)
    spaced = FSTAB.replace(FSTAB_LINE, FSTAB_LINE.replace(" ", "\t"))
    assert host_script.fstab_update(spaced, entry()) == (None, 1)


def test_fstab_differing_entry_is_rewritten_in_place() -> None:
    new, matches = host_script.fstab_update(FSTAB, entry(opts="defaults,noatime,nofail"))
    assert matches == 1
    assert new == FSTAB.replace(FSTAB_LINE, f"UUID={FS_UUID} /mnt/cryptdata ext4 defaults,noatime,nofail 0 0")


def test_fstab_missing_dump_and_passno_count_as_different() -> None:
    short = FSTAB.replace(FSTAB_LINE, f"UUID={FS_UUID} /mnt/cryptdata ext4 defaults,noatime")
    new, _ = host_script.fstab_update(short, entry())
    assert new == FSTAB


def test_fstab_trailing_comment_is_dropped_only_on_rewrite() -> None:
    commented = FSTAB.replace(FSTAB_LINE, FSTAB_LINE + " # data")
    assert host_script.fstab_update(commented, entry()) == (None, 1)
    new, _ = host_script.fstab_update(commented, entry(src="/dev/mapper/cryptdata"))
    assert new is not None
    assert "/dev/mapper/cryptdata /mnt/cryptdata ext4 defaults,noatime 0 0\n" in new
    assert "# data" not in new


def test_fstab_appends_and_counts_duplicates() -> None:
    assert host_script.fstab_update("UUID=root / ext4 defaults 0 1", entry()) == (
        f"UUID=root / ext4 defaults 0 1\n{FSTAB_LINE}\n",
        0,
    )
    assert host_script.fstab_update(None, entry()) == (FSTAB_LINE + "\n", 0)
    _, matches = host_script.fstab_update(FSTAB + FSTAB_LINE + "\n", entry())
    assert matches == 2


# -- admission (read-only) -----------------------------------------------------------------


class Host:
    """A fake host for the script: block devices, blkid answers, mounts and files."""

    def __init__(self) -> None:
        self.block = {"/dev/sda"}
        self.blkid: dict[str, dict[str, str]] = {
            "/dev/sda": {"TYPE": "crypto_LUKS", "UUID": UUID},
            "/dev/mapper/cryptdata": {"TYPE": "ext4", "UUID": FS_UUID},
        }
        self.lsblk = {
            "/dev/sda": ("disk", ""),
            "/dev/mapper/cryptdata": ("crypt", "/dev/sda"),
            "/dev/sdb": ("disk", ""),
        }
        self.mounts: dict[str, tuple[str, str]] = {"/mnt/cryptdata": ("/dev/mapper/cryptdata", "rw,noatime")}
        self.files = {"/etc/crypttab": CRYPTTAB_LINE + "\n", "/etc/fstab": FSTAB}

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def fake_stat(path: str) -> Any:
            if path not in self.block:
                raise FileNotFoundError(path)
            return type("S", (), {"st_mode": stat_module.S_IFBLK | 0o660})()

        monkeypatch.setattr(host_script.os, "stat", fake_stat)
        monkeypatch.setattr(host_script.os.path, "realpath", lambda path: path)
        monkeypatch.setattr(host_script.os.path, "exists", lambda path: path in self.lsblk)
        monkeypatch.setattr(host_script, "blkid", lambda device: dict(self.blkid.get(device, {})))
        monkeypatch.setattr(host_script, "block_devices", lambda: dict(self.lsblk))
        monkeypatch.setattr(host_script, "mounted", lambda point: self.mounts.get(point))
        monkeypatch.setattr(host_script, "read_text", lambda path: self.files.get(path))


@pytest.fixture
def fake_host(monkeypatch: pytest.MonkeyPatch) -> Host:
    fake = Host()
    fake.install(monkeypatch)
    return fake


def script_cfg(cfg: EncryptedVolumeConfig) -> dict[str, str]:
    return host_payload(cfg)


def test_converged_host_has_nothing_pending(cfg: EncryptedVolumeConfig, fake_host: Host) -> None:
    state = host_script.admit(script_cfg(cfg))
    assert state["pending"] == []
    assert state["active"] is True


def test_closed_mapper_needs_open_and_mount(cfg: EncryptedVolumeConfig, fake_host: Host) -> None:
    del fake_host.lsblk["/dev/mapper/cryptdata"]
    del fake_host.mounts["/mnt/cryptdata"]
    assert host_script.admit(script_cfg(cfg))["pending"] == ["open", "mount"]


def test_unmounted_volume_is_mounted_without_fstab_change(cfg: EncryptedVolumeConfig, fake_host: Host) -> None:
    del fake_host.mounts["/mnt/cryptdata"]
    assert host_script.admit(script_cfg(cfg))["pending"] == ["mount"]


def test_changed_fstab_entry_remounts_and_crypttab_drift_is_rewritten(
    cfg: EncryptedVolumeConfig, fake_host: Host
) -> None:
    fake_host.files["/etc/fstab"] = FSTAB.replace("defaults,noatime", "defaults")
    fake_host.files["/etc/crypttab"] = "cryptdata /dev/sdz /root/k luks\n"
    state = host_script.admit(script_cfg(cfg))
    assert state["pending"] == ["crypttab", "fstab", "remount"]
    assert state["crypttab"] == CRYPTTAB_LINE + "\n"


def test_added_fstab_entry_on_a_mounted_volume_does_not_remount(cfg: EncryptedVolumeConfig, fake_host: Host) -> None:
    fake_host.files["/etc/fstab"] = FSTAB.replace(FSTAB_LINE + "\n", "")
    state = host_script.admit(script_cfg(cfg))
    assert state["pending"] == ["fstab"]
    assert state["fstab"] == FSTAB.replace(FSTAB_LINE + "\n", "") + FSTAB_LINE + "\n"


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (lambda h: h.block.discard("/dev/sda"), "device /dev/sda is missing"),
        (lambda h: h.blkid.update({"/dev/sda": {"TYPE": "ext4"}}), "is not a LUKS container"),
        (
            lambda h: h.blkid.update({"/dev/sda": {"TYPE": "crypto_LUKS", "UUID": "0" * 8 + UUID[8:]}}),
            "LUKS UUID mismatch",
        ),
        (lambda h: h.lsblk.update({"/dev/mapper/other": ("crypt", "/dev/sda")}), "already mapped as /dev/mapper/other"),
        (lambda h: h.lsblk.update({"/dev/mapper/cryptdata": ("crypt", "/dev/sdb")}), "is open on /dev/sdb"),
        (lambda h: h.lsblk.update({"/dev/mapper/cryptdata": ("lvm", "/dev/sda")}), "is not a crypt mapping"),
        (lambda h: h.blkid.update({"/dev/mapper/cryptdata": {}}), "never formats"),
        (lambda h: h.blkid.update({"/dev/mapper/cryptdata": {"TYPE": "xfs"}}), "holds xfs"),
        (lambda h: h.mounts.update({"/mnt/cryptdata": ("/dev/sdb1", "rw")}), "is mounted from /dev/sdb1"),
        (lambda h: h.mounts.update({"/mnt/cryptdata": ("/dev/mapper/cryptdata", "ro,noatime")}), "read-only"),
        (lambda h: h.files.update({"/etc/fstab": FSTAB + FSTAB_LINE + "\n"}), "has 2 entries"),
    ],
)
def test_refusals(cfg: EncryptedVolumeConfig, fake_host: Host, change: Any, reason: str) -> None:
    change(fake_host)
    with pytest.raises(host_script.Refused, match=reason):
        host_script.admit(script_cfg(cfg))


def test_foreign_mount_with_closed_mapper_is_refused(cfg: EncryptedVolumeConfig, fake_host: Host) -> None:
    del fake_host.lsblk["/dev/mapper/cryptdata"]
    fake_host.mounts["/mnt/cryptdata"] = ("/dev/sdb1", "rw")
    with pytest.raises(host_script.Refused, match="while /dev/mapper/cryptdata is closed"):
        host_script.admit(script_cfg(cfg))


def test_check_mode_prints_refusals_and_exits_zero(
    cfg: EncryptedVolumeConfig, fake_host: Host, capsys: pytest.CaptureFixture[str]
) -> None:
    fake_host.blkid["/dev/sda"]["UUID"] = "f" * 8 + UUID[8:]
    encoded = host_command(cfg, "check").rsplit(" ", 1)[1]
    assert host_script.main(["-c", "check", encoded]) == 0
    assert capsys.readouterr().out.startswith("refused: LUKS UUID mismatch")
    assert host_script.main(["-c", "apply", encoded]) == 1


def test_apply_never_formats_closes_or_unmounts(cfg: EncryptedVolumeConfig, fake_host: Host) -> None:
    calls: list[list[str]] = []
    monkey = pytest.MonkeyPatch()
    try:
        monkey.setattr(host_script, "run", lambda argv, check=True: calls.append(argv))
        monkey.setattr(host_script, "write_atomic", lambda *args: calls.append(["write", args[0]]))
        fake_host.files["/etc/fstab"] = FSTAB.replace("defaults,noatime", "defaults")
        host_script.apply(script_cfg(cfg))
    finally:
        monkey.undo()
    assert calls == [["write", "/etc/fstab"], ["mount", "-o", "remount", "/mnt/cryptdata"]]
    for argv in calls:
        assert not {"umount", "luksFormat", "close", "mkfs", "wipefs"} & set(argv)


# -- the deploy's plan ------------------------------------------------------------------------


def converged(cfg: EncryptedVolumeConfig, pending: str = "") -> dict[str, Any]:
    check = host_command(cfg, "check")
    return {
        **fakehost.LINUX,
        check: [f"pending={pending}", "changed=" + ("true" if pending else "false")],
        "command -v cryptsetup": ["/usr/sbin/cryptsetup"],
        **fakehost.directory("/root", mode="drwx------"),
        **fakehost.directory("/mnt/cryptdata"),
        **fakehost.file(cfg.keyfile, PASSPHRASE, mode="-r--------"),
        **fakehost.stat("/etc/crypttab", mode="-rw-r-----"),
        **fakehost.stat("/etc/fstab"),
    }


def deploy(cfg: EncryptedVolumeConfig, responses: dict[str, Any]) -> FakeRun:
    return run_deploy_fake(deploy_encrypted_volume, cfg, SecretStr(PASSPHRASE), responses=responses)


def test_converged_host_is_not_changed(cfg: EncryptedVolumeConfig) -> None:
    run = deploy(cfg, converged(cfg))
    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    assert run.changed_ops == [f"{P}Probe again: /dev/mapper/cryptdata mounted at /mnt/cryptdata"]
    assert not any("apply" in c.split() for c in run.executed_commands)
    assert run.uploads == []
    assert run.stdin == []


def test_pending_steps_run_the_apply_step_once(cfg: EncryptedVolumeConfig) -> None:
    run = deploy(cfg, converged(cfg, pending="open,mount"))
    assert run.succeeded, run.error
    assert run.mutating_changed_ops == [f"{P}Open, record and mount /dev/mapper/cryptdata (open, mount)"]
    applies = [c for c in run.executed_commands if c.endswith(host_command(cfg, "apply"))]
    assert len(applies) == 1


def test_refusal_stops_before_any_operation(cfg: EncryptedVolumeConfig) -> None:
    responses = {**converged(cfg), host_command(cfg, "check"): ["refused: LUKS UUID mismatch: expected a, found b"]}
    run = deploy(cfg, responses)
    assert run.error is not None
    assert "LUKS UUID mismatch" in str(run.error)
    assert "nothing was changed" in str(run.error)
    assert run.ops == []


def test_failed_admission_fails_closed(cfg: EncryptedVolumeConfig) -> None:
    responses = {**converged(cfg), host_command(cfg, "check"): ["", "ops-deploy-probe-failed"]}
    run = deploy(cfg, responses)
    assert run.error is not None
    assert "admission" in str(run.error)
    assert run.ops == []


def test_missing_cryptsetup_is_installed_and_the_keyfile_written_as_a_secret(cfg: EncryptedVolumeConfig) -> None:
    responses = {**converged(cfg, pending="open,mount"), "command -v cryptsetup": []}
    responses.pop(f"sha256sum {cfg.keyfile} ")
    run = deploy(cfg, responses)
    assert run.succeeded, run.error
    assert f"{P}Install cryptsetup" in run.mutating_changed_ops
    assert f"{P}Write the keyfile /root/.luks-key-cryptdata" in run.mutating_changed_ops
    assert all(PASSPHRASE not in c for c in run.executed_commands)
    install = next(c for c in run.executed_commands if "apt-get" in c and "install" in c)
    assert "cryptsetup" in install
    assert "cryptsetup-initramfs" in install


@pytest.mark.parametrize("secret", ["", "a\0b"])
def test_unusable_passphrases_are_refused(cfg: EncryptedVolumeConfig, secret: str) -> None:
    with pytest.raises(ValueError, match="passphrase"):
        run_deploy_fake(deploy_encrypted_volume, cfg, SecretStr(secret), responses=converged(cfg))
