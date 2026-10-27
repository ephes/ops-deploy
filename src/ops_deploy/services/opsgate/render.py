"""Original template bytes and account-scoped resource ownership."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from collections.abc import Mapping
from importlib.resources import files
from pathlib import Path
from typing import Any
from urllib.parse import quote

import jinja2

from .config import PACKAGE, OpsGateConfig

SECRET_DEFAULTS: dict[str, Any] = json.loads(files(PACKAGE).joinpath("secret_defaults.json").read_text())


def payload(cfg: OpsGateConfig, secrets: Mapping[str, Any]) -> dict[str, Any]:
    unknown = set(secrets) - set(SECRET_DEFAULTS)
    if unknown:
        raise ValueError("OpsGate received an unsupported secret field")
    values = {**cfg.model_dump(mode="json"), **SECRET_DEFAULTS, **secrets}
    for name in (
        "opsgate_session_secret",
        "opsgate_submit_token_nyxmon",
        "opsgate_submit_token_operator",
        "opsgate_runner_token",
    ):
        value = values[name]
        if not isinstance(value, str) or len(value.strip()) < 20 or "CHANGEME" in value:
            raise ValueError("OpsGate credentials are incomplete")
    password = values["opsgate_ui_password_bcrypt"]
    if not isinstance(password, str) or not re.fullmatch(r"\$2[aby]\$.+", password) or "CHANGEME" in password:
        raise ValueError("OpsGate bcrypt credential is incomplete")
    optional = values["opsgate_submit_token_openclaw"]
    if not isinstance(optional, str) or (optional.strip() and (len(optional.strip()) < 20 or "CHANGEME" in optional)):
        raise ValueError("OpsGate optional producer credential is invalid")
    for name in SECRET_DEFAULTS:
        if name == "opsgate_ops_github_deploy_keys":
            continue
        if not isinstance(values[name], str) or "\x00" in values[name]:
            raise ValueError("OpsGate secret field has an invalid type")
        if not name.endswith(("private_key", "public_key")) and any(c in values[name] for c in "\r\n"):
            raise ValueError("OpsGate runtime credentials must be single-line values")
    account_private = values["opsgate_ops_github_ssh_private_key"].strip()
    account_public = values["opsgate_ops_github_ssh_public_key"].strip()
    if bool(account_private) != bool(account_public):
        raise ValueError("OpsGate GitHub account key requires both components")
    deploy_keys = values["opsgate_ops_github_deploy_keys"]
    if not isinstance(deploy_keys, dict):
        raise ValueError("OpsGate deploy keys must be a mapping")
    ssh_repos = {
        repo.name
        for repo in cfg.opsgate_ops_workspace_repositories
        if repo.repo.startswith(("git@github.com:", "ssh://git@github.com/"))
    }
    for name, key in deploy_keys.items():
        if name not in ssh_repos or not isinstance(key, dict) or set(key) != {"private_key", "public_key"}:
            raise ValueError("OpsGate deploy key must name one GitHub SSH workspace")
        if any(not isinstance(value, str) or not value.strip() or "\x00" in value for value in key.values()):
            raise ValueError("OpsGate deploy key is incomplete")
        if any(c in key["public_key"].strip() for c in "\r\n"):
            raise ValueError("OpsGate deploy public key must be one line")
    if cfg.opsgate_ops_manage_workspace_repos and (
        not cfg.opsgate_ops_workspace_repositories or (ssh_repos - set(deploy_keys) and not account_private)
    ):
        raise ValueError("OpsGate managed GitHub SSH workspaces require their configured keys")
    values["opsgate_rust_binary"] = cfg.opsgate_rust_install_root + "/" + cfg.opsgate_rust_version + "/opsgate"
    environment = jinja2.Environment(
        loader=jinja2.PackageLoader(PACKAGE, "templates"),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    environment.filters.update(
        quote=shlex.quote,
        bool=bool,
        ternary=lambda condition, yes, no: yes if condition else no,
    )
    resources: dict[str, dict[str, Any]] = {}

    def resource(path: str, content: str, owner: str, group: str, mode: int) -> None:
        if path in resources:
            raise ValueError("OpsGate managed resources overlap")
        resources[path] = {
            "content": content,
            "sha256": hashlib.sha256(content.encode()).hexdigest(),
            "owner": owner,
            "group": group,
            "mode": mode,
        }

    def template(name: str, path: str, owner: str, group: str, mode: int, **extra: Any) -> None:
        resource(path, environment.get_template(name).render({**values, **extra}), owner, group, mode)

    for unit, group in (("api", cfg.control_service_group), ("runner", cfg.ops_group)):
        template(f"opsgate-{unit}.env.j2", cfg.opsgate_config_dir + f"/opsgate-{unit}.env", "root", group, 0o640)
        template(
            f"opsgate.{unit}.launchd.plist.j2",
            values[f"opsgate_{unit}_launchd_plist_path"],
            "root",
            "wheel",
            0o644,
            opsgate_launchd_render_impl=values[f"opsgate_{unit}_impl"],
        )
        template(
            f"opsgate.{unit}.launchd.plist.j2",
            cfg.opsgate_launchd_python_plist_dir + "/" + values[f"opsgate_{unit}_launchd_label"] + ".plist",
            "root",
            "wheel",
            0o644,
            opsgate_launchd_render_impl="python",
        )
    template("ops.gitconfig.j2", cfg.ops_home_dir + "/.gitconfig", cfg.ops_user, cfg.ops_group, 0o640)
    template("ops.ssh.config.j2", cfg.opsgate_ops_ssh_config_path, cfg.ops_user, cfg.ops_group, 0o600)
    template("ops.tmux.conf.j2", cfg.opsgate_tmux_conf_path, cfg.ops_user, cfg.ops_group, 0o644)
    credentials = {
        "opsgate_ops_ssh_private_key": (cfg.ops_home_dir + "/.ssh/id_ed25519", 0o600),
        "opsgate_ops_ssh_public_key": (cfg.ops_home_dir + "/.ssh/id_ed25519.pub", 0o644),
        "opsgate_ops_github_ssh_private_key": (cfg.opsgate_ops_github_ssh_private_key_path, 0o600),
        "opsgate_ops_github_ssh_public_key": (cfg.opsgate_ops_github_ssh_public_key_path, 0o644),
        "opsgate_ops_age_private_key": (cfg.ops_home_dir + "/.config/sops/age/keys.txt", 0o600),
    }
    for name, (path, mode) in credentials.items():
        if values[name].strip():
            resource(path, values[name].strip() + "\n", cfg.ops_user, cfg.ops_group, mode)
    for name, pair in deploy_keys.items():
        for suffix, key, mode in (("", "private_key", 0o600), (".pub", "public_key", 0o644)):
            resource(
                cfg.opsgate_ops_github_deploy_key_path_prefix + name + suffix,
                pair[key].strip() + "\n",
                cfg.ops_user,
                cfg.ops_group,
                mode,
            )
    if cfg.opsgate_ops_github_username.strip() and values["opsgate_ops_github_token"].strip():
        credential = (
            "https://"
            + quote(cfg.opsgate_ops_github_username, safe="")
            + ":"
            + quote(values["opsgate_ops_github_token"], safe="")
            + "@github.com\n"
        )
        resource(cfg.ops_home_dir + "/.git-credentials", credential, cfg.ops_user, cfg.ops_group, 0o600)
    data = cfg.model_dump(mode="json")
    data.update(contents=resources, deploy_key_names=sorted(deploy_keys), rust_binary=values["opsgate_rust_binary"])
    data["remove"] = (
        []
        if account_private or not deploy_keys
        else [
            cfg.opsgate_ops_github_ssh_private_key_path,
            cfg.opsgate_ops_github_ssh_public_key_path,
        ]
    )
    if cfg.opsgate_rust_local_archive:
        archive = Path(cfg.opsgate_rust_local_archive)
        if not archive.is_file():
            raise ValueError("OpsGate controller archive is unavailable")
        content = archive.read_bytes()
        actual = hashlib.sha256(content).hexdigest()
        if cfg.opsgate_rust_sha256 and actual != cfg.opsgate_rust_sha256:
            raise ValueError("OpsGate controller archive differs from its pinned checksum")
        data["opsgate_rust_sha256"] = actual
        # Explicit development archive is public release material, not a secret.
        # It travels only when installation is actually selected.
        import base64

        data["archive_payload"] = base64.b64encode(content).decode()
    return data
