"""Literal DNS removal routing/policy and metadata failure boundaries."""

from __future__ import annotations

import importlib.util
import json
import shlex
import stat
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from ops_deploy.services.dns.remove import (
    FALLBACK,
    RESOLVED_FILE,
    UNITS,
    DnsRemoveConfig,
    _command,
    deploy_dns_remove,
    selected_paths,
)
from ops_deploy.testing import FakeRun, run_deploy_fake
from tests import fakehost


def snapshot(cfg: DnsRemoveConfig, *, present: bool = False) -> dict[str, Any]:
    paths = {
        p: ({"mode": stat.S_IFDIR | 0o700, "uid": 0, "gid": 0} if present else None)
        for p in [*selected_paths(cfg), RESOLVED_FILE, "/etc/resolv.conf"]
    }
    paths[RESOLVED_FILE] = None
    paths["/etc/resolv.conf"] = {"mode": stat.S_IFREG | 0o644, "uid": 0, "gid": 0}
    return {
        "paths": paths,
        "units": {
            u: {
                "metadata_status": "ok",
                "LoadState": "loaded" if present else "not-found",
                "ActiveState": "active" if present else "inactive",
                "UnitFileState": "enabled" if present else "",
            }
            for u in [*UNITS, "systemd-resolved.service"]
        },
        "account": "present" if present else "absent",
        "package": "installed" if present else "not-installed",
        "ufw": {"status": "ok", "selected": ["53/tcp"] if present else []},
        "cron": {"status": "ok", "selected": ["Pi-hole gravity update"] if present else []},
    }


def remove(cfg: DnsRemoveConfig, value: dict[str, Any] | None, **responses: Any) -> FakeRun:
    base = {
        **fakehost.LINUX,
        **fakehost.directory("/etc"),
        "cat /proc/1/comm": ["systemd"],
        _command("snapshot"): [json.dumps(value)] if value is not None else ["ops-deploy-probe-failed"],
        **fakehost.file("/etc/resolv.conf", FALLBACK),
        **responses,
    }
    return run_deploy_fake(deploy_dns_remove, cfg, responses=base)


def test_confirmation_fails_before_any_commands() -> None:
    result = remove(DnsRemoveConfig(), None)
    assert not result.succeeded
    assert "not confirmed" in str(result.error)
    assert not result.executed_commands
    assert not result.uploads


def test_original_order_and_named_resources_include_config_only_purge() -> None:
    cfg = DnsRemoveConfig(confirm=True, restore_systemd_resolved=False)
    state = snapshot(cfg, present=True)
    state["package"] = "config-files"
    result = remove(cfg, state)
    assert result.succeeded, result.error
    commands = result.executed_commands
    assert commands.index("rm -rf -- /etc/systemd/system/ddns-update.service") < commands.index(
        "userdel --remove ddns || true"
    )
    assert commands.index("userdel --remove ddns || true") < commands.index("rm -rf -- /etc/unbound/unbound.conf.d")
    assert commands.index("rm -rf -- /etc/unbound/unbound.conf.d") < commands.index(
        "apt-get -y -q remove --purge unbound"
    )
    assert commands.index("apt-get -y -q remove --purge unbound") < commands.index("rm -rf -- /var/cache/unbound")
    assert commands.index("rm -rf -- /var/cache/unbound") < commands.index("ufw delete allow 53/tcp || true")
    cron = next(c for c in commands if c.endswith(" clean-cron"))
    assert commands.index(cron) < commands.index("rm -rf -- /etc/.pihole")
    assert "rm -rf -- /var/lib/ddns" in commands
    assert not any("22/tcp" in command for command in commands)
    assert not any("systemd-resolved" in command for command in commands)
    # No broad Users/Groups fact or shadow verifier read is required.
    assert not any("cat /etc/passwd" in str(event) or "/etc/shadow" in str(event) for event in result.events)


def test_gone_repeat_with_resolver_disabled_has_no_managed_commands() -> None:
    cfg = DnsRemoveConfig(confirm=True, restore_systemd_resolved=False)
    result = remove(cfg, snapshot(cfg))
    assert result.succeeded, result.error
    assert not result.executed_commands
    assert not result.changed_ops


def test_retained_stopped_disabled_blocklist_units_do_not_reload_on_repeat() -> None:
    cfg = DnsRemoveConfig(confirm=True, restore_systemd_resolved=False)
    state = snapshot(cfg)
    for unit in ("unbound-blocklist.service", "unbound-blocklist.timer"):
        state["units"][unit] = {
            "metadata_status": "ok",
            "LoadState": "loaded",
            "ActiveState": "inactive",
            "UnitFileState": "disabled",
        }
    result = remove(cfg, state)
    assert result.succeeded, result.error
    assert not result.executed_commands
    assert not result.changed_ops


def test_non_ddns_shared_state_and_custom_unbound_paths_are_preserved_literally() -> None:
    cfg = DnsRemoveConfig(
        confirm=True,
        restore_systemd_resolved=False,
        unbound_config_dir="/custom/unbound/conf",
        unbound_lib_dir="/custom/unbound/lib",
        ddns_state_dir="/custom/shared-state",
    )
    assert cfg.ddns_state_dir not in selected_paths(cfg)
    result = remove(cfg, snapshot(cfg, present=True))
    assert result.succeeded, result.error
    assert "rm -rf -- /custom/unbound/conf" in result.executed_commands
    assert "rm -rf -- /custom/unbound/lib" in result.executed_commands
    assert not any("shared-state" in c for c in result.executed_commands)


def test_default_restore_resolved_keeps_existing_link_and_service_and_only_waits_readonly() -> None:
    cfg = DnsRemoveConfig(confirm=True)
    state = snapshot(cfg)
    state["paths"][RESOLVED_FILE] = {"mode": stat.S_IFREG | 0o644, "uid": 0, "gid": 0}
    state["paths"]["/etc/resolv.conf"] = {"mode": stat.S_IFLNK | 0o777, "uid": 0, "gid": 0}
    responses = {
        **fakehost.service("systemd-resolved.service"),
        **fakehost.symlink("/etc/resolv.conf", "/run/systemd/resolve/stub-resolv.conf"),
    }
    result = remove(cfg, state, **responses)
    assert result.succeeded, result.error
    assert len(result.executed_commands) == 1
    assert "127.0.0.53" in result.executed_commands[0]
    assert not result.uploads


def test_missing_resolved_uses_only_original_fixed_public_fallback() -> None:
    cfg = DnsRemoveConfig(confirm=True)
    state = snapshot(cfg)
    result = remove(cfg, state)
    assert result.succeeded, result.error
    assert not result.executed_commands
    assert not result.uploads


def test_unknown_systemd_and_ufw_metadata_preserve_explicit_original_error_tolerance() -> None:
    cfg = DnsRemoveConfig(confirm=True, restore_systemd_resolved=False)
    state = snapshot(cfg)
    state["units"]["unbound.service"] = {"metadata_status": "error"}
    state["ufw"] = {"status": "error", "selected": []}
    result = remove(cfg, state)
    assert result.succeeded, result.error
    assert "timeout 30s systemctl stop unbound.service || true" in result.executed_commands
    assert "systemctl disable unbound.service || true" in result.executed_commands
    assert {c for c in result.executed_commands if c.startswith("ufw delete")} == {
        "ufw delete allow " + rule + " || true" for rule in ("53/tcp", "53/udp", "4711/tcp", "5335/tcp", "5335/udp")
    }


@pytest.mark.parametrize("kind", ["failed", "paths", "unit", "unexpected-rule", "unexpected-cron", "package"])
def test_missing_or_malformed_metadata_never_reaches_mutation(kind: str) -> None:
    cfg = DnsRemoveConfig(confirm=True)
    state: dict[str, Any] | None = snapshot(cfg)
    assert state is not None
    if kind == "failed":
        state = None
    elif kind == "paths":
        state["paths"].pop("/etc/resolv.conf")
    elif kind == "unit":
        state["units"]["unbound.service"] = {}
    elif kind == "unexpected-rule":
        state["ufw"]["selected"] = ["22/tcp"]
    elif kind == "unexpected-cron":
        state["cron"]["selected"] = ["unowned cron"]
    else:
        state["package"] = "permission-denied"
    result = remove(cfg, state)
    assert not result.succeeded
    assert not result.executed_commands
    assert not result.uploads


def test_named_ansible_cron_cleanup_preserves_every_other_byte() -> None:
    path = Path(__file__).parents[1] / "src/ops_deploy/services/dns/files/remove_state.py"
    spec = importlib.util.spec_from_file_location("dns_remove_state", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    body = (
        "# retain exact spaces  \n#Ansible: Keep\n7 1 * * * /unowned\n"
        "#Ansible: Pi-hole gravity update\n0 2 * * * /selected\n# tail\n"
    )
    assert module.selected_cron(body) == ["Pi-hole gravity update"]
    assert module.without_selected(body) == "# retain exact spaces  \n#Ansible: Keep\n7 1 * * * /unowned\n# tail\n"
    assert module.without_selected(module.without_selected(body)) == module.without_selected(body)


def test_dns_custom_spaced_paths_remain_literal_and_shell_quoted() -> None:
    cfg = DnsRemoveConfig(
        confirm=True,
        restore_systemd_resolved=False,
        unbound_config_dir="/custom unbound/config",
        ddns_state_dir="/custom state/owned ddns",
    )
    result = remove(cfg, snapshot(cfg, present=True))
    assert result.succeeded, result.error
    assert "rm -rf -- '/custom unbound/config'" in result.executed_commands
    assert "rm -rf -- '/custom state/owned ddns'" in result.executed_commands
    with pytest.raises(ValueError, match="validation error"):
        DnsRemoveConfig(ddns_config_dir="/custom;command")


@pytest.mark.parametrize("value", ["/custom/owned-ddns/", "/custom/owned-ddns/.", "/ddns"])
def test_original_state_guard_uses_raw_spelling_without_broadening_deletion(value: str) -> None:
    cfg = DnsRemoveConfig(confirm=True, restore_systemd_resolved=False, ddns_state_dir=value)
    result = remove(cfg, snapshot(cfg, present=True))
    assert result.succeeded, result.error
    # The old canonicalizer caused an actual explicit rm proposal here, even
    # though the literal original role predicate skips the auxiliary path.
    assert "rm -rf -- " + str(PurePosixPath(value)) not in result.executed_commands
    assert cfg.ddns_state_dir == value
    assert value not in selected_paths(cfg)


@pytest.mark.parametrize("value", ["/custom/./owned ddns", "/./ddns", "///ddns", "/.//ddns"])
def test_original_raw_state_guard_keeps_spelling_sensitive_aliases(value: str) -> None:
    cfg = DnsRemoveConfig(confirm=True, restore_systemd_resolved=False, ddns_state_dir=value)
    assert cfg.ddns_state_dir == value
    assert cfg.ddns_state_dir in selected_paths(cfg)
    result = remove(cfg, snapshot(cfg, present=True))
    assert result.succeeded, result.error
    # These aliases deliberately match the literal original role predicate.
    assert "rm -rf -- " + shlex.quote(value) in result.executed_commands
