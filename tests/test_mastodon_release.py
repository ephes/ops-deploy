"""Exercise the actual pyinfra caller composition and secret-safe step ordering."""

from __future__ import annotations

import json
from typing import Any

from ops_deploy.services.mastodon import deploy_mastodon
from ops_deploy.services.mastodon.render import render, render_env
from ops_deploy.testing import run_deploy_fake
from tests import fakehost
from tests.test_mastodon import converged, secrets
from tests.test_mastodon_release_source import release_config


def inspection(**changes: Any) -> dict[str, Any]:
    return {
        "source": False,
        "runtime": {"ruby": False, "ruby_tool": False, "node": False, "node_version": "24.17.0"},
        "dependencies": {"bundle": False, "yarn": False, "assets": False},
        "env": False,
        "pending_migrations": [],
        "applied_migrations": ["20260101000000"],
        "rollout_debt": False,
        "cache_clear_debt": False,
        "prime": False,
        **changes,
    }


def responses(cfg: Any, observed: dict[str, Any]) -> dict[str, Any]:
    result = converged(cfg)
    result["'runtime-inspect'"] = [json.dumps(observed["runtime"])]
    result["'inspect'"] = [json.dumps(observed)]
    # Exact action tokens at the end are not quoted by shlex for plain words.
    result[" runtime-inspect"] = [json.dumps(observed["runtime"])]
    result[" inspect"] = [json.dumps(observed)]
    result.update(
        fakehost.file(
            cfg.site_path + "/.env.production",
            render_env(cfg, secrets()).reveal().decode(),
            user="mastodon",
            mode="-rw-------",
        )
    )
    for kind, name in (("service", cfg.maintenance_service_name), ("timer", cfg.maintenance_timer_name)):
        result.update(
            fakehost.file(
                cfg.maintenance_unit_dir + "/" + name + "." + kind, render(cfg, "maintenance." + kind + ".j2")
            )
        )
    result.update(fakehost.file(cfg.maintenance_script_path, render(cfg, "maintenance.sh.j2"), mode="-rwxr-xr-x"))
    result.update(fakehost.service(cfg.maintenance_timer_name + ".timer"))
    return result


def test_actual_release_caller_converged_has_zero_mutations() -> None:
    cfg = release_config()
    run = run_deploy_fake(deploy_mastodon, cfg=cfg, secrets=secrets(), responses=responses(cfg, inspection()))
    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []
    assert "fixture-secret-sentinel" not in repr(run.events)
    assert "fixture-secret-sentinel" not in repr(run.ops)


def test_release_orders_cache_clear_then_single_app_restart_then_health() -> None:
    cfg = release_config()
    observed = inspection(source=True, env=True, pending_migrations=["20260102000000"])
    run = run_deploy_fake(deploy_mastodon, cfg=cfg, secrets=secrets(), responses=responses(cfg, observed))
    assert run.succeeded, run.error
    names = [str(operation.name) for operation in run.ops]
    joined = "\n".join(names)
    assert "Update selected Mastodon Git checkout" in joined
    assert "Install and verify selected locked Ruby dependencies" in joined
    assert "Apply candidate pending migration identities: 20260102000000" in joined
    assert "Build and verify selected Mastodon production assets" in joined
    commands = run.executed_commands
    clear = next(i for i, value in enumerate(commands) if value.endswith(" cache_clear"))
    health = next(i for i, value in enumerate(commands) if value.endswith(" health"))
    for component in ("web", "sidekiq", "streaming"):
        restarts = [i for i, value in enumerate(commands) if "systemctl restart mastodon-" + component in value]
        assert len(restarts) == 1
        assert clear < restarts[0] < health
    assert "fixture-secret-sentinel" not in repr(run.events)


def test_numeric_node_resolution_uses_actual_index_not_a_guessed_patch() -> None:
    from io import StringIO
    from unittest.mock import patch

    from ops_deploy.services.mastodon.release import node_version

    index = json.dumps([{"version": value} for value in ("v24.17.1", "v24.17.4", "v24.18.0", "v22.12.3")])
    with patch("ops_deploy.services.mastodon.release.urlopen", return_value=StringIO(index)):
        assert node_version("24.17", None) == "24.17.4"
    with patch("ops_deploy.services.mastodon.release.urlopen", return_value=StringIO(index)):
        assert node_version("22", None) == "22.12.3"
    with patch(
        "ops_deploy.services.mastodon.release.urlopen", side_effect=AssertionError("must reuse installed match")
    ):
        assert node_version("24.17", "24.17.0") == "24.17.0"
