"""Every file and directory the role writes, per step: path, bytes, owner, group, mode.

Pure functions of the resolved variables; :mod:`.deploy` writes them in the
role's order and ``tests/test_openclaw_parity.py`` compares them with what
ansible-core computed (``tests/parity/openclaw_deploy``).
"""

from __future__ import annotations

import posixpath
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from ops_deploy.services.openclaw import render as r
from ops_deploy.services.openclaw.variables import ansible_bool as bool_

Vars = Mapping[str, Any]
# The container's uid/gid, which owns the bind-mounted data tree.
CONTAINER = "1000"


@dataclass(frozen=True)
class FileSpec:
    path: str
    content: bytes
    mode: str
    owner: str = CONTAINER
    group: str = CONTAINER
    # ``copy: force: false``: written only while the path does not exist.
    create_only: bool = False
    # Carries credentials: written with ``secret_file`` semantics, never shown.
    secret: bool = False


@dataclass(frozen=True)
class DirSpec:
    path: str
    mode: str
    owner: str = CONTAINER
    group: str = CONTAINER


def _text(path: str, text: str, mode: str, **kwargs: Any) -> FileSpec:
    return FileSpec(path=path, content=text.encode(), mode=mode, **kwargs)


def _template(v: Vars, template: str, path: str, mode: str, **kwargs: Any) -> FileSpec:
    return _text(path, r.render(template, v), mode, **kwargs)


def _root(v: Vars, template: str, path: str, mode: str = "0644") -> FileSpec:
    return _template(v, template, path, mode, owner="root", group="root")


# -- directories.yml -------------------------------------------------------------------------


def directories(v: Vars) -> list[DirSpec]:
    user, group = v["openclaw_user"], v["openclaw_group"]
    data = v["openclaw_data_dir"]
    specs = [
        DirSpec(v["openclaw_site_dir"], "0755", user, group),
        DirSpec(str(PurePosixPath(v["openclaw_build_dir"]).parent), "0755", user, group),
        *(
            DirSpec(path, "0700")
            for path in (data, f"{data}/backups", v["openclaw_log_dir"], v["openclaw_agent_workspace_dir"])
        ),
        DirSpec(f"{data}/credentials", "0700"),
    ]
    if bool_(v["openclaw_weeknotes_enabled"]):
        notes, skills = v["openclaw_weeknotes_dir"], v["openclaw_weeknotes_skills_dir"]
        specs += [DirSpec(path, "0750") for path in (notes, f"{notes}/.snapshots", skills)]
        names = [v["openclaw_weeknotes_skill_name"], *v["openclaw_weeknotes_command_skill_names"]]
        specs += [DirSpec(f"{skills}/{name}", "0750") for name in names]
    for feature in ("imap", "calendar", "homeassistant", "paperless", "opsgate"):
        if bool_(v[f"openclaw_{feature}_enabled"]):
            skills = v[f"openclaw_{feature}_skills_dir"]
            names = [v[f"openclaw_{feature}_skill_name"], v[f"openclaw_{feature}_command_skill_name"]]
            specs += [DirSpec(skills, "0750"), *(DirSpec(f"{skills}/{name}", "0750") for name in names)]
    if bool_(v["openclaw_opsgate_enabled"]):
        specs.append(DirSpec(v["openclaw_opsgate_extension_dir"], "0750"))
    if bool_(v["openclaw_paperless_enabled"]):
        specs.append(DirSpec(v["openclaw_paperless_downloads_dir"], "0750"))
    return specs


def workspace_directories(v: Vars) -> list[DirSpec]:
    """workspace_skills.yml's directories (in its order)."""

    root = f"{v['openclaw_agent_workspace_dir']}/skills"
    skills = v["openclaw_workspace_skills"]
    specs = [DirSpec(root, "0750"), *(DirSpec(f"{root}/{skill['name']}", "0750") for skill in skills)]
    for skill in skills:
        for item in skill["files"]:
            # The role's ``root ~ '/' ~ (dest | dirname)``: a trailing slash for a top-level file.
            specs.append(DirSpec(f"{root}/{skill['name']}/{posixpath.dirname(item['dest'])}", "0750"))
    return specs


# -- the gateway -----------------------------------------------------------------------------


def env_file(v: Vars) -> FileSpec:
    return _text(f"{v['openclaw_site_dir']}/.env", r.render_env(v), "0600", owner="root", group="root", secret=True)


def seed_file(v: Vars) -> FileSpec:
    """config.yml's seed (written when there is no config, or with ``openclaw_force_config``)."""

    return _text(f"{v['openclaw_data_dir']}/openclaw.json", r.render_seed(v), str(v["openclaw_gateway_config_mode"]))


def workspace_prompts(v: Vars) -> list[FileSpec]:
    workspace = v["openclaw_agent_workspace_dir"]
    pairs = (("openclaw_reply_system_prompt", "SOUL.md"), ("openclaw_user_profile", "USER.md"))
    return [_text(f"{workspace}/{name}", v[key], "0644") for key, name in pairs if len(v[key]) > 0]


def audio_plan(v: Vars) -> FileSpec:
    return _template(
        v, "openclaw-audio-secrets-plan.json.j2", f"{v['openclaw_data_dir']}/managed-audio-secrets-plan.json", "0600"
    )


def compose_file(v: Vars) -> FileSpec:
    return _root(v, "openclaw-compose.yml.j2", f"{v['openclaw_site_dir']}/docker-compose.yml")


def unit_file(v: Vars) -> FileSpec:
    return _root(v, "openclaw.service.j2", f"/etc/systemd/system/{v['openclaw_service_name']}.service")


def route_file(v: Vars) -> FileSpec:
    return _root(v, "openclaw-traefik.yml.j2", v["openclaw_traefik_config_path"])


def logrotate_file(v: Vars) -> FileSpec:
    return _text("/etc/logrotate.d/openclaw", r.logrotate(v), "0644", owner="root", group="root")


# -- the skills ------------------------------------------------------------------------------


def weeknotes_files(v: Vars) -> list[FileSpec]:
    skills, name = v["openclaw_weeknotes_skills_dir"], v["openclaw_weeknotes_skill_name"]
    pages = {
        "todo": "weeknotes-todo-skill.md.j2",
        "note": "weeknotes-note-skill.md.j2",
        "snooze": "weeknotes-snooze-skill.md.j2",
    }
    return [
        _template(v, "weeknotes-md-skill.json.j2", f"{skills}/{name}/skill.json", "0640"),
        *(
            _template(v, pages[item], f"{skills}/{item}/SKILL.md", "0640")
            for item in v["openclaw_weeknotes_command_skill_names"]
        ),
        _template(v, "weeknotes-md-handler.sh.j2", f"{skills}/{name}/handler.sh", "0750"),
    ]


def _credentials(path: str, payload: Mapping[str, Any]) -> FileSpec:
    return _text(path, r.credentials_json(payload), "0600", secret=True)


def _skill(v: Vars, feature: str, manifest: str, handler: str, page: str | None) -> list[FileSpec]:
    skills = v[f"openclaw_{feature}_skills_dir"]
    skill, command = v[f"openclaw_{feature}_skill_name"], v[f"openclaw_{feature}_command_skill_name"]
    specs = [
        _template(v, manifest, f"{skills}/{skill}/skill.json", "0640"),
        _template(v, handler, f"{skills}/{skill}/handler.py", "0750"),
    ]
    if page is not None:
        specs.append(_template(v, page, f"{skills}/{command}/SKILL.md", "0640"))
    return specs


def feature_files(v: Vars) -> list[FileSpec]:
    """imap.yml, calendar.yml, paperless.yml, homeassistant.yml and opsgate.yml, in that order."""

    specs: list[FileSpec] = []
    if bool_(v["openclaw_imap_enabled"]):
        specs.append(_credentials(v["openclaw_imap_credentials_path"], r.imap_credentials(v)))
        if bool_(v["openclaw_smtp_enabled"]):
            specs.append(_credentials(v["openclaw_smtp_credentials_path"], r.smtp_credentials(v)))
        specs += _skill(v, "imap", "mail-imap-skill.json.j2", "mail-imap-handler.py.j2", "mail-skill.md.j2")
    if bool_(v["openclaw_calendar_enabled"]):
        specs.append(_credentials(v["openclaw_calendar_credentials_path"], r.calendar_runtime(v)))
        specs.append(_text(v["openclaw_calendar_health_state_path"], "{}\n", "0600", create_only=True))
        specs += _skill(v, "calendar", "calendar-skill.json.j2", "calendar-handler.py.j2", "calendar-skill.md.j2")
    if bool_(v["openclaw_paperless_enabled"]):
        specs.append(_credentials(v["openclaw_paperless_credentials_path"], r.paperless_runtime(v)))
        specs.append(_text(v["openclaw_paperless_health_state_path"], "{}\n", "0600", create_only=True))
        specs += _skill(v, "paperless", "paperless-skill.json.j2", "paperless-handler.py.j2", "paperless-skill.md.j2")
    if bool_(v["openclaw_homeassistant_enabled"]):
        specs.append(_credentials(v["openclaw_homeassistant_credentials_path"], r.homeassistant_runtime(v)))
        specs += _skill(
            v,
            "homeassistant",
            "homeassistant-read-skill.json.j2",
            "homeassistant-read-handler.py.j2",
            "homeassistant-skill.md.j2",
        )
    if bool_(v["openclaw_opsgate_enabled"]):
        specs.append(_credentials(v["openclaw_opsgate_credentials_path"], r.opsgate_runtime(v)))
        specs += _skill(v, "opsgate", "opsgate-submit-skill.json.j2", "opsgate-submit-handler.py.j2", None)
        extension = v["openclaw_opsgate_extension_dir"]
        specs.append(_template(v, "opsgate-plugin.json.j2", f"{extension}/openclaw.plugin.json", "0640"))
        specs.append(_template(v, "opsgate-plugin-index.ts.j2", f"{extension}/index.ts", "0640"))
        command = v["openclaw_opsgate_command_skill_name"]
        specs.append(
            _template(v, "opsgate-skill.md.j2", f"{v['openclaw_opsgate_skills_dir']}/{command}/SKILL.md", "0640")
        )
    return specs


def workspace_skill_files(v: Vars) -> list[FileSpec]:
    root = f"{v['openclaw_agent_workspace_dir']}/skills"
    return [
        FileSpec(f"{root}/{skill['name']}/{item['dest']}", Path(item["src"]).read_bytes(), item.get("mode", "0640"))
        for skill in v["openclaw_workspace_skills"]
        for item in skill["files"]
    ]


def manifest_file(v: Vars) -> FileSpec:
    return _text(v["openclaw_managed_skills_manifest_path"], r.managed_skills_manifest(v), "0644")


# -- metrics.yml -----------------------------------------------------------------------------


def metrics_files(v: Vars) -> dict[str, FileSpec]:
    """The collector and server scripts and the three units, by role."""

    timer, service = v["openclaw_metrics_endpoint_timer_name"], v["openclaw_metrics_endpoint_service_name"]
    return {
        "collector": _root(
            v, "openclaw-metrics-collector.py.j2", v["openclaw_metrics_endpoint_collector_path"], "0755"
        ),
        "httpd": _root(v, "openclaw-metrics-httpd.py.j2", v["openclaw_metrics_endpoint_server_path"], "0755"),
        "collector_unit": _root(v, "openclaw-metrics-collector.service.j2", f"/etc/systemd/system/{timer}.service"),
        "timer_unit": _root(v, "openclaw-metrics-collector.timer.j2", f"/etc/systemd/system/{timer}.timer"),
        "endpoint_unit": _root(v, "openclaw-metrics-endpoint.service.j2", f"/etc/systemd/system/{service}.service"),
    }
