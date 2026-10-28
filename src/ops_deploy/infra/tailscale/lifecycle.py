"""Ordinary backup/remove and explicitly manual/LAN identity restore APIs."""

from __future__ import annotations

import json
import os
import re
import shlex
import stat
import uuid
from collections.abc import Generator
from pathlib import Path
from typing import Any, cast

from pyinfra import host
from pyinfra.api import DeployError, StringCommand, deploy, operation
from pyinfra.api.arguments import ConnectorArguments
from pyinfra.api.command import FileDownloadCommand, PyinfraCommand
from pyinfra.api.host import Host
from pyinfra.api.state import State
from pyinfra.facts.server import Command, Which
from pyinfra.operations import apt, files, server

from ops_deploy.base._common import require_linux, require_systemd
from ops_deploy.core.secrets import SecretValues
from ops_deploy.helpers.probes import StdinLines, probe, verify_probe
from ops_deploy.services._lifecycle import stop_disable

from .config import TailscaleConfig
from .deploy import AUTH_FIELD, HOST_SCRIPT, helper
from .lifecycle_config import TailscaleBackupConfig, TailscaleManualRestoreConfig, TailscaleRemoveConfig

SCRIPT = (Path(__file__).parents[1] / "files/tailscale_lifecycle.py").read_text()


@operation()
def lifecycle(action: str, data: str) -> Generator[StringCommand, None, None]:
    if action not in {"backup", "restore"}:
        raise DeployError("unknown Tailscale lifecycle action")
    answer = probe(helper(SCRIPT, action + "-plan"), name="Declared identity lifecycle admission", stdin=data)
    if answer != "pending":
        raise DeployError("Identity lifecycle admission/integrity failed; no state/service action attempted")
    yield StringCommand(helper(SCRIPT, action), _stdin=StdinLines(data), _get_pty=False, _shell_executable="sh")


def private_local(path: Path) -> None:
    for part in (*reversed(path.parents), path):
        if part.is_symlink():
            raise DeployError("Local identity backup path must not contain symlinks")
    if path in {Path("/"), Path.home(), Path("/tmp"), Path("/var"), Path("/home"), Path("/Users")}:
        raise DeployError("Identity backup destination must be its own private directory")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise DeployError("Local identity backup directory must belong to the current operator")
    path.chmod(0o700)


class PrivateArchiveDownload(PyinfraCommand):
    """SFTP via a private login-user handoff, never pyinfra sudo chmod +r."""

    def __init__(self, archive: str, destination: Path, user: str, link: Path) -> None:
        super().__init__()
        self.archive, self.destination, self.user, self.link = archive, destination, user, link
        self.remote = "/tmp/ops-deploy-tailscale-fetch-" + uuid.uuid4().hex

    def __repr__(self) -> str:
        return "PrivateArchiveDownload(identity archive; private handoff)"

    def execute(self, state: State, host: Host, connector_arguments: ConnectorArguments) -> None:
        private_local(self.destination.parent)
        descriptor = os.open(self.destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        os.close(descriptor)
        quote = shlex.quote
        stage = (
            "install -m 0600 -o "
            + quote(self.user)
            + " -- "
            + quote(self.archive)
            + " "
            + quote(self.remote + "/archive")
            + " && chown "
            + quote(self.user)
            + " -- "
            + quote(self.remote)
        )
        created, _ = host.run_shell_command(
            StringCommand("umask 077; mkdir -- " + quote(self.remote)), **{**connector_arguments, "_timeout": 15}
        )
        if not created:
            raise DeployError("Private archive handoff directory not created; existing path preserved")
        try:
            prepared, _ = host.run_shell_command(StringCommand(stage), **{**connector_arguments, "_timeout": 30})
            if not prepared:
                raise DeployError("Private identity archive handoff failed")
            # Strip inherited privilege switches before SFTP. This requests no
            # sudo upload/download and cannot enter pyinfra's chmod+r staging.
            arguments_dict: dict[str, Any] = dict(connector_arguments)
            for key in ("_sudo", "_sudo_user", "_su_user", "_doas", "_doas_user", "_dzdo", "_dzdo_user"):
                arguments_dict.pop(key, None)
            arguments = cast(ConnectorArguments, arguments_dict)
            downloaded = FileDownloadCommand(self.remote + "/archive", str(self.destination)).execute(
                state, host, arguments
            )
            if not downloaded:
                raise DeployError("Private identity archive download failed")
            os.chmod(self.destination, 0o600, follow_symlinks=False)
            if self.link.exists() and not self.link.is_symlink():
                raise DeployError("Local latest backup link is an ordinary file; existing data preserved")
            temporary = self.link.with_name("." + self.link.name + "." + uuid.uuid4().hex)
            temporary.symlink_to(self.destination)
            os.replace(temporary, self.link)
        finally:
            # The unique temp directory was admitted by mkdir without -p. rm
            # does not follow a replaced top-level symlink. No archive output.
            cleaned, _ = host.run_shell_command(
                StringCommand("rm -rf -- " + quote(self.remote)), **{**connector_arguments, "_timeout": 30}
            )
            if not cleaned:
                raise DeployError("Private identity archive handoff cleanup unproven; retain writer ownership")


@operation()
def fetch_archive(archive: str, local_dir: Path, prefix: str) -> Generator[PrivateArchiveDownload, None, None]:
    # The authenticated SSH transport already knows its login username. Read
    # that connection metadata, without running another identity command or
    # changing a privilege global argument.
    client = getattr(host.connector, "client", None)
    transport = client.get_transport() if client is not None else None
    if transport is None or not transport.is_authenticated():
        raise DeployError("Private archive fetch needs the existing authenticated SSH transport")
    user = transport.get_username()
    if not isinstance(user, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", user):
        raise DeployError("Cannot establish existing SSH login identity for private transfer")
    yield PrivateArchiveDownload(archive, local_dir / Path(archive).name, user, local_dir / (prefix + "-latest.tar.gz"))


@deploy("Backup Tailscale identity")
def deploy_tailscale_backup(cfg: TailscaleBackupConfig) -> None:
    require_linux("Tailscale backup")
    stamp = host.get_fact(Command, command="date +%Y%m%dT%H%M%S")
    if not isinstance(stamp, str) or not re.fullmatch(r"[0-9]{8}T[0-9]{6}", stamp):
        raise DeployError("Cannot establish original host-local backup timestamp")
    name = cfg.prefix + "-" + stamp
    lifecycle(
        name="Create original private identity/config/dropin backup",
        action="backup",
        data=json.dumps({**cfg.model_dump(mode="json"), "name": name}),
    )
    if cfg.create_archive and cfg.fetch_local:
        fetch_archive(
            name="Fetch identity archive with private handoff and local0600",
            archive=cfg.root + "/" + name + ".tar.gz",
            local_dir=cfg.local_dir,
            prefix=cfg.prefix,
        )


@deploy("Manual LAN restore Tailscale identity")
def deploy_tailscale_manual_restore(
    cfg: TailscaleManualRestoreConfig, runtime: TailscaleConfig, secrets: SecretValues
) -> None:
    require_linux("Tailscale manual restore")
    require_systemd("Tailscale manual restore")
    if cfg.dry_run:
        verify_probe(
            helper(SCRIPT, "restore-plan"),
            name="Manual restore archive integrity/path validation only",
            expect="pending",
            stdin=cfg.model_dump_json(),
        )
        return
    credential = "" if runtime.manual_up else secrets.require((AUTH_FIELD,))[AUTH_FIELD]
    if not runtime.manual_up and (not credential or credential.lower() in {"changeme", "placeholder", "example"}):
        raise DeployError("Non-manual Tailscale rejoin requires the original private auth key")
    lifecycle(
        name="Validate archive, then stop/restore original identity and requested service state",
        action="restore",
        data=cfg.model_dump_json(),
    )
    if cfg.force_reup and not runtime.manual_up:
        # Original restore reasserts up even for a Running restored identity.
        content = json.dumps({**runtime.model_dump(mode="json"), "auth_key": credential})
        server.shell(
            name="Reassert original explicit post-restore up using private key file",
            commands=[helper(HOST_SCRIPT, "force-join")],
            _stdin=StdinLines(content),
            _get_pty=False,
            _shell_executable="sh",
        )


@deploy("Remove Tailscale")
def deploy_tailscale_remove(cfg: TailscaleRemoveConfig) -> None:
    require_linux("Tailscale removal")
    require_systemd("Tailscale removal")
    if not cfg.confirm:
        raise DeployError("Set the original explicit Tailscale removal confirmation to proceed")
    # Preserve the original stop/disable -> ignored logout ordering. This does
    # not attest that the node's online authorization was revoked.
    stop_disable((cfg.service_name,))
    if not cfg.skip_logout and host.get_fact(Which, command=cfg.binary):
        server.shell(
            name="Original best-effort logout after stop (online revocation unproven)",
            commands=[shlex.quote(cfg.binary) + " logout >/dev/null 2>&1 || true"],
        )
    # Actual1.104.2 postrm rm-rf's state on purge. Keep default false effective;
    # the original role's unconditional purge contradicted that declared flag.
    apt.packages(
        name="Remove package; dpkg purge only when state purge requested",
        packages=[cfg.package_name],
        present=False,
        purge=cfg.purge_state,
    )
    for path in (
        f"/etc/apt/sources.list.d/{cfg.repo_name}.sources",
        f"/etc/apt/sources.list.d/{cfg.repo_name}.list",
        cfg.repo_keyring,
    ):
        files.file(name="Remove original Tailscale repository resource", path=path, present=False)
    if cfg.purge_state:
        files.file(name="Remove original sysconfig on explicit purge", path=cfg.sysconfig_path, present=False)
        for path in (cfg.systemd_dropin_dir, cfg.state_dir):
            files.directory(name="Remove explicitly purged identity path", path=path, present=False)
