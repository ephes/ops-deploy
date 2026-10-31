"""Candidate verification and installed-drift repair on owned public fixtures."""

import hashlib
import io
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest

from ops_deploy.services.homeassistant import custom_conversation_patch as HELPER


class CustomConversationPatchTests(unittest.TestCase):
    def test_candidate_and_installed_states_preserve_metadata_and_repeat(self) -> None:
        with tempfile.TemporaryDirectory(prefix="owned-cc-patch-") as temporary:
            root = Path(temporary)
            archive = root / "source.tar.gz"
            before = b"owned source\n" + HELPER.BEFORE + b"\n"
            after = before.replace(HELPER.BEFORE, HELPER.AFTER)
            with tarfile.open(archive, "w:gz") as target:
                member = tarfile.TarInfo(
                    "custom-conversation-1.7.0/custom_components/custom_conversation/config_flow.py"
                )
                member.size = len(before)
                target.addfile(member, io.BytesIO(before))
            archive_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
            component = root / "component"
            component.mkdir()
            source = component / "config_flow.py"
            source.write_bytes(before)
            source.chmod(0o640)
            metadata = source.stat()
            with patch.multiple(
                HELPER,
                ARCHIVE_SHA256=archive_sha,
                SOURCE_SHA256=hashlib.sha256(before).hexdigest(),
                PATCHED_SHA256=hashlib.sha256(after).hexdigest(),
            ):
                assert HELPER.needs_patch(str(component), "1.7.0", archive_sha)
                desired = HELPER.prepare(str(archive), "1.7.0", archive_sha)
                assert desired == after
                assert source.read_bytes() == before  # Candidate stage never writes.
                assert HELPER.apply(str(component), desired)
                current = source.stat()
                assert (current.st_uid, current.st_gid, current.st_mode) == (
                    metadata.st_uid,
                    metadata.st_gid,
                    metadata.st_mode,
                )
                assert not HELPER.needs_patch(str(component), "1.7.0", archive_sha)
                assert not HELPER.apply(str(component), desired)
                assert source.stat().st_mtime_ns == current.st_mtime_ns
                assert HELPER.PATCH_ID + " " + HELPER.PATCHED_SHA256 in HELPER.expected_stamp("1.7.0", archive_sha)
                # Managed installed drift is reconciled from the qualified candidate.
                source.write_bytes(b"owned installed corruption\n")
                assert HELPER.needs_patch(str(component), "1.7.0", archive_sha)
                assert HELPER.apply(str(component), HELPER.prepare(str(archive), "1.7.0", archive_sha))
                assert source.read_bytes() == after
                with (
                    patch.object(HELPER, "SOURCE_SHA256", "0" * 64),
                    pytest.raises(ValueError, match="candidate source mismatch"),
                ):
                    HELPER.prepare(str(archive), "1.7.0", archive_sha)
                assert source.read_bytes() == after
                archive.write_bytes(b"owned candidate corruption")
                with pytest.raises(ValueError, match="candidate archive mismatch"):
                    HELPER.prepare(str(archive), "1.7.0", archive_sha)
                assert source.read_bytes() == after

    def test_old_and_custom_sources_are_not_patched_or_read(self) -> None:
        for version, checksum in [
            ("1.6.1", HELPER.ARCHIVE_SHA256),
            ("1.7.0", "a" * 64),
            ("owned-custom", "b" * 64),
        ]:
            with self.subTest(version=version, checksum=checksum):
                assert not HELPER.needs_patch("/owned-does-not-exist", version, checksum)
                assert HELPER.prepare("/owned-does-not-exist", version, checksum) is None
                assert HELPER.expected_stamp(version, checksum) == version + " " + checksum

    def test_absent_installed_file_selects_reconciliation_without_candidate_read(self) -> None:
        assert HELPER.needs_patch("/owned-does-not-exist", HELPER.VERSION, HELPER.ARCHIVE_SHA256)


if __name__ == "__main__":
    unittest.main()
