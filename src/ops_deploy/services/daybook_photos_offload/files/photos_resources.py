"""Declared Photos configuration/log metadata and GUI-owned publication only.

Filesystem primitives are the already qualified Sessions implementation. No
Photos library, ledger, log body, application or model is opened by this stage.
"""

import os
import pathlib

from ops_photos_filesystem import directory_matches, ensure_directory, ensure_log, file_matches, put_resource


class PhotosResourceError(RuntimeError):
    pass


def directories_current(data, probes):
    return (
        all(directory_matches(row) for row in data["directories"])
        and all(file_matches(row) for row in data["logs"])
        and all(probes.acl_free(row["path"]) for key in ("directories", "logs") for row in data[key])
    )


def resources_current(data, probes):
    return all(file_matches(row, content=True) for row in data["resources"]) and all(
        probes.acl_free(row["path"]) for row in data["resources"]
    )


def require_user(data):
    if os.geteuid() != data["uid"] or data["uid"] <= 0:
        raise PhotosResourceError("photos_resources_original_gui_identity_required")


def clear_acl(path, probes):
    # Metadata preflight/publication already rejected substituted links/types.
    # ACL convergence is an original explicit managed operation, not a fact.
    if not probes.acl_free(path) and probes.run(["/bin/chmod", "-N", str(path)], user=True).returncode:
        raise PhotosResourceError("photos_resources_acl_clear_failed")
    if not probes.acl_free(path):
        raise PhotosResourceError("photos_resources_acl_not_clear")


def preflight_files(data):
    # Original batch metadata admission before any managed log/config write.
    # content=False opens no log/config body and rejects every link/type fault.
    for key in ("logs", "resources"):
        for row in data[key]:
            file_matches(row)


def prepare_directories(data, probes, controls):
    require_user(data)
    controls.require_quiescent()
    preflight_files(data)
    # This does not inspect/create the configured Photos library or ledger.
    for row in data["directories"]:
        ensure_directory(row)
        clear_acl(row["path"], probes)
    for row in data["logs"]:
        ensure_log(row)  # Existing content/inode/timestamps are preserved.
        clear_acl(row["path"], probes)
    if not directories_current(data, probes):
        raise PhotosResourceError("photos_resources_directories_not_current")


def apply_resources(data, probes, controls):
    require_user(data)
    controls.require_quiescent()
    preflight_files(data)
    if not directories_current(data, probes):
        raise PhotosResourceError("photos_resources_directories_required")
    for row in data["resources"]:
        put_resource(row)
        clear_acl(row["path"], probes)
    plist = pathlib.Path(data["plist"])
    if probes.run(["/usr/bin/plutil", "-lint", str(plist)], user=True).returncode:
        raise PhotosResourceError("photos_resources_plist_invalid")
    if not resources_current(data, probes):
        raise PhotosResourceError("photos_resources_not_current_after_publish")
