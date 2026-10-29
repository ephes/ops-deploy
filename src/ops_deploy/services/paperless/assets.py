"""Change-gated installed Python assets and original creates-only datasets."""

from __future__ import annotations

import json
import shlex
from collections.abc import Generator

from pyinfra import host, state
from pyinfra.api import DeployError, StringCommand, operation
from pyinfra.api.operation import OperationMeta
from pyinfra.facts.files import Directory, File
from pyinfra.operations import files, server

from ops_deploy.helpers.probes import StdinLines, probe

from .commands import host_command
from .config import PaperlessConfig
from .operations import as_service


@operation()
def python_assets(cfg: PaperlessConfig, action: str, deferred: bool = False) -> Generator[StringCommand, None, None]:
    if action not in {"ownership", "ocr"}:
        raise ValueError("unknown Python asset action")
    settings = {
        "venv": f"{cfg.site_root}/.venv",
        "username": cfg.username,
        "group": cfg.group,
        "action": action,
        "apply": False,
    }
    command = host_command("python_assets")
    if action == "ocr":
        command = as_service(cfg, command)
    if not (deferred and not state.is_executing):
        answer = probe(command, name=f"Paperless Python {action}", stdin=json.dumps(settings))
        if answer == "current":
            return
        if answer != "pending":
            raise DeployError(f"Paperless Python {action} inspection failed")
    settings["apply"] = True
    yield StringCommand(command, _stdin=StdinLines(json.dumps(settings)), _get_pty=False)


def nltk(cfg: PaperlessConfig) -> None:
    if not cfg.install_nltk_data:
        return
    files.directory(name="Ensure NLTK data directory", path=cfg.nltk_data_path, user="root", group="root", mode="0755")
    for dataset, path in (
        ("stopwords", "corpora/stopwords"),
        ("punkt", "tokenizers/punkt"),
        ("punkt_tab", "tokenizers/punkt_tab"),
    ):
        if not host.get_fact(Directory, path=f"{cfg.nltk_data_path}/{path}"):
            server.shell(
                name=f"Install missing NLTK {dataset}",
                commands=[
                    shlex.join(
                        [
                            f"{cfg.site_root}/.venv/bin/python",
                            "-B",
                            "-m",
                            "nltk.downloader",
                            "-d",
                            cfg.nltk_data_path,
                            dataset,
                        ]
                    )
                ],
            )


def install_marker(cfg: PaperlessConfig) -> OperationMeta:
    # Existence is a compatibility marker, never the package-health oracle.
    # files.file without touch preserves a healthy marker's timestamps.
    return files.file(
        name="Record installed Paperless release",
        path=f"{cfg.site_root}/.paperless-installed-{cfg.version}",
        user=cfg.username,
        group=cfg.group,
        mode="0644",
    )


def apparmor(cfg: PaperlessConfig) -> OperationMeta:
    files.directory(
        name="Ensure local AppArmor directory", path="/etc/apparmor.d/local", user="root", group="root", mode="0755"
    )
    files.file(
        name="Ensure local Ghostscript AppArmor file",
        path="/etc/apparmor.d/local/gs",
        user="root",
        group="root",
        mode="0644",
    )
    block = files.block(
        name="Allow Ghostscript access to Paperless storage",
        path="/etc/apparmor.d/local/gs",
        content=(
            "# Permit Ghostscript (used by Paperless OCR) to read files on encrypted storage\n"
            f"owner {cfg.external_storage_root}/** rwlk,"
        ),
        marker="# {mark} ANSIBLE MANAGED PAPERLESS STORAGE",
    )
    if host.get_fact(File, path="/etc/apparmor.d/gs"):
        # Retain the original optional reload's ignored-failure semantics. A
        # native failure is recorded as such, never called successful reload.
        server.shell(
            name="Reload existing Ghostscript AppArmor profile",
            commands=["apparmor_parser -r /etc/apparmor.d/gs"],
            _if=block.did_change,
            _ignore_errors=True,
        )
    return block
