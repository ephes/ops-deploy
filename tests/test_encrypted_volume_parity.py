"""encrypted_volume's config defaults are the encrypted_volume_prepare role's.

With ``OPS_LIBRARY_PATH`` set, the defaults of ``EncryptedVolumeConfig`` are
compared with the role's ``defaults/main.yml``. (Moved from the open_webui
parity tests when Open WebUI was retired on 2026-11-09.)
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
import yaml

from ops_deploy.infra import EncryptedVolumeConfig

OPS_LIBRARY = os.environ.get("OPS_LIBRARY_PATH")
needs_ops_library = pytest.mark.skipif(not OPS_LIBRARY, reason="OPS_LIBRARY_PATH not set")


def role_defaults(role: str) -> dict[str, Any]:
    assert OPS_LIBRARY is not None
    loaded: dict[str, Any] = yaml.safe_load(Path(OPS_LIBRARY, "roles", role, "defaults", "main.yml").read_text())
    return loaded


@needs_ops_library
def test_encrypted_volume_defaults_are_the_roles() -> None:
    role = role_defaults("encrypted_volume_prepare")
    cfg = EncryptedVolumeConfig(device="/dev/sda", expected_luks_uuid="e301d851-3454-4b1b-a3a2-5e71f18af8d7")
    for name in (
        "mapper_name",
        "mount_point",
        "fs_type",
        "mount_opts",
        "fstab_dump",
        "fstab_passno",
        "keyfile_owner",
        "keyfile_group",
        "keyfile_mode",
        "crypttab_options",
        "mount_owner",
        "mount_group",
        "mount_mode",
    ):
        assert getattr(cfg, name) == role[f"encrypted_volume_{name}"], name
    assert list(cfg.packages) == role["encrypted_volume_packages"]
    assert role["encrypted_volume_keyfile_path"] == "/root/.luks-key-{{ encrypted_volume_mapper_name }}"
    assert cfg.keyfile == "/root/.luks-key-cryptdata"
    # The safety defaults the deploy hard-codes.
    assert role["encrypted_volume_allow_format"] is False
    assert role["encrypted_volume_use_keyfile"] is True
    assert role["encrypted_volume_device_by_id"] == ""
