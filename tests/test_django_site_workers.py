"""Worker restart obligations, uv transport and opt-in optional env semantics."""

from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core.secrets import SecretValues
from ops_deploy.services.django_site import DbWorker, DjangoSiteConfig, EnvEntry, EnvSpec, Secret
from ops_deploy.services.django_site.config import EnvLiteral
from ops_deploy.services.django_site.django import deps_probe, uv_command
from ops_deploy.services.django_site.render import render, render_env
from tests import fakehost
from tests.django_site_fixtures import converged, site_config, values
from tests.marina_fixtures import make_source
from tests.test_django_site import changed, deploy


def worker_site(tmp_path: Path) -> DjangoSiteConfig:
    return site_config(make_source(tmp_path), workers=(DbWorker(unit="marina-db-worker", backend="transcripts"),))


def responses(cfg: DjangoSiteConfig, sec: SecretValues) -> dict[str, Any]:
    worker = cfg.workers[0]
    return {
        **converged(cfg, sec),
        **fakehost.file(
            f"{cfg.site_path}/{worker.unit}.sh",
            render("worker.sh.j2", cfg, worker=worker),
            user=cfg.user,
            mode="-rwxr-xr-x",
        ),
        **fakehost.file(f"/etc/systemd/system/{worker.unit}.service", render("worker.service.j2", cfg, worker=worker)),
        **fakehost.service(worker.unit + ".service"),
    }


def test_worker_converged_runs_no_mutation(tmp_path: Path) -> None:
    cfg = worker_site(tmp_path)
    sec = values(cfg)
    run = deploy(cfg, sec, responses(cfg, sec))
    assert not run.mutating_changed_ops


@pytest.mark.parametrize("change", ["source", "env", "worker_unit", "resume"])
def test_worker_restart_gate_and_marker_order(tmp_path: Path, change: str) -> None:
    cfg = worker_site(tmp_path)
    sec = values(cfg)
    facts = responses(cfg, sec)
    if change == "env":
        facts.update(fakehost.file(str(cfg.env_path), "old", user=cfg.user, mode="-rw-------"))
    if change == "worker_unit":
        facts.update(fakehost.file("/etc/systemd/system/marina-db-worker.service", "old"))
    if change == "resume":
        facts["grep -x -e .ops-deploy-pending"] = [".ops-deploy-restart-marina-db-worker"]
    run = deploy(cfg, sec, facts, rsync=changed() if change == "source" else None)
    commands = "\n".join(run.executed_commands)
    assert "systemctl restart marina-db-worker.service" in commands
    if change in {"env", "worker_unit", "resume"}:
        assert commands.index("touch /var/lib/ops-deploy/marina/.ops-deploy-restart-marina-db-worker") < commands.index(
            "systemctl restart marina-db-worker.service"
        )
    assert commands.rindex("rm -f /var/lib/ops-deploy/marina/.ops-deploy-pending") > commands.index(
        "systemctl restart marina-db-worker.service"
    )
    if change == "worker_unit":
        assert "systemctl restart marina.service" not in commands


def test_uv_transport_applies_to_probe_and_real_sync(tmp_path: Path) -> None:
    cfg = worker_site(tmp_path)
    cfg = cfg.model_copy(
        update={"app": cfg.app.model_copy(update={"uv_env": (EnvLiteral(key="GIT_CONFIG_VALUE_0", value="HTTP/1.1"),)})}
    )
    assert "GIT_CONFIG_VALUE_0=HTTP/1.1" in deps_probe(cfg)
    assert "GIT_CONFIG_VALUE_0=HTTP/1.1" in uv_command(cfg)


def test_python_version_assert_refuses_missing_and_mismatched_pin(tmp_path: Path) -> None:
    cfg = worker_site(tmp_path)
    raw = cfg.model_dump()
    raw["app"]["assert_python_version"] = True
    for pin in (None, "3.10"):
        if pin:
            (cfg.source.path / ".python-version").write_text(pin)
        with pytest.raises(ValueError, match="python-version"):
            DjangoSiteConfig.model_validate(raw)
    assert cfg.app.python is not None
    (cfg.source.path / ".python-version").write_text(cfg.app.python + "\n")
    DjangoSiteConfig.model_validate(raw)


def test_optional_empty_is_opt_in_and_omit_is_independent(tmp_path: Path) -> None:
    cfg = site_config(
        make_source(tmp_path),
        env=EnvSpec(
            extra=(
                EnvEntry(key="OPTIONAL", value=Secret(secret="optional", allow_empty=True)),
                EnvEntry(key="OMITTED", value=Secret(secret="optional", allow_empty=True), omit_empty=True),
            )
        ),
    )
    env = render_env(cfg, values(cfg, optional="")).reveal().decode()
    assert "OPTIONAL=''" in env
    assert "OMITTED=" not in env
    assert "optional" not in cfg.required_secret_keys
    strict = site_config(cfg.source.path, env=EnvSpec(extra=(EnvEntry(key="STRICT", value=Secret(secret="strict")),)))
    with pytest.raises(KeyError):
        render_env(strict, values(strict, strict=""))
    with pytest.raises(ValueError, match="placeholder"):
        render_env(cfg, values(cfg, optional="CHANGEME"))


def test_worker_units_and_uv_reserved_env_are_refused(tmp_path: Path) -> None:
    cfg = worker_site(tmp_path)
    raw = cfg.model_dump()
    raw["workers"] = [{"unit": cfg.unit_name}]
    with pytest.raises(ValueError, match="must differ"):
        DjangoSiteConfig.model_validate(raw)
    raw = cfg.model_dump()
    raw["app"]["uv_env"] = [{"key": "HOME", "value": "/tmp"}]
    with pytest.raises(ValueError, match="reserved key"):
        DjangoSiteConfig.model_validate(raw)


@pytest.mark.parametrize("target", ["db", "key", "storage", "admin"])
def test_security_secrets_cannot_be_optional(tmp_path: Path, target: str) -> None:
    cfg = worker_site(tmp_path)
    raw = cfg.model_dump()
    if target == "db":
        raw["admin"] = None
        raw["database"] = {
            "kind": "postgres",
            "name": "fixture",
            "user": "fixture",
            "password": {"secret": "postgres_password", "allow_empty": True},
        }
    elif target == "key":
        raw["env"]["secret_key"]["allow_empty"] = True
    elif target == "storage":
        raw["env"]["extra"] = [
            {"key": "DJANGO_AWS_SECRET_ACCESS_KEY", "value": {"secret": "s3_key", "allow_empty": True}}
        ]
    else:
        raw["admin"]["password"]["allow_empty"] = True
    with pytest.raises(ValueError, match="must stay required"):
        DjangoSiteConfig.model_validate(raw)


@pytest.mark.parametrize(("queue", "extra"), [(None, ()), ("transcripts", ("--log-level", "INFO"))])
def test_worker_argv_matches_wagtail_origin(tmp_path: Path, queue: str | None, extra: tuple[str, ...]) -> None:
    import shlex

    import jinja2

    cfg = worker_site(tmp_path)
    worker = cfg.workers[0].model_copy(update={"queue": queue, "extra_args": extra})
    template = Path(__file__).parent / "parity/ansible/wagtail_deploy__wagtail-db-worker.service.j2"
    old = jinja2.Template(template.read_text()).render(
        wagtail_service_name=cfg.unit_name,
        wagtail_user=cfg.user,
        wagtail_group=cfg.group_name,
        wagtail_site_path=str(cfg.app_path),
        wagtail_django_settings_module=cfg.app.settings_module,
        wagtail_env_path=str(cfg.env_path),
        wagtail_python=str(cfg.venv_bin / "python"),
        wagtail_manage_py=str(cfg.app_path / "manage.py"),
        wagtail_db_worker_backend=worker.backend,
        wagtail_db_worker_id=worker.worker_id or worker.unit,
        wagtail_db_worker_queue_name=queue or "",
        wagtail_db_worker_interval_seconds=worker.interval,
        wagtail_db_worker_extra_args=shlex.join(extra),
        wagtail_cache_dir=str(cfg.cache_dir),
    )
    old_command = old.partition("ExecStart=")[2].split("\n\n", 1)[0].replace("\\\n", " ")
    new = render("worker.sh.j2", cfg, worker=worker)
    new_command = next(line.removeprefix("exec ") for line in new.splitlines() if line.startswith("exec "))
    old_argv = shlex.split(old_command)
    new_argv = shlex.split(new_command)
    new_argv[1] = str(cfg.app_path / new_argv[1])
    assert old_argv == new_argv
    assert f". {cfg.env_path}" in new
    assert "RestartSec=10" in render("worker.service.j2", cfg, worker=worker)


def test_failed_worker_rollout_does_not_clear_restart_obligations(tmp_path: Path) -> None:
    cfg = worker_site(tmp_path)
    sec = values(cfg)
    facts = responses(cfg, sec)
    facts["systemctl restart marina-db-worker.service"] = {"success": False}
    run = deploy(cfg, sec, facts, rsync=changed(), succeed=False)
    assert not run.succeeded
    commands = "\n".join(run.executed_commands)
    assert "systemctl restart marina.service" in commands
    assert "rm -f /var/lib/ops-deploy/marina/.ops-deploy-pending" not in commands


def test_worker_health_failure_retains_obligations(tmp_path: Path) -> None:
    cfg = worker_site(tmp_path)
    sec = values(cfg)
    facts = responses(cfg, sec)
    facts["systemctl is-active --quiet marina-db-worker.service"] = {"success": False}
    run = deploy(cfg, sec, facts, rsync=changed(), succeed=False)
    assert not run.succeeded
    assert not any(c.startswith("rm -f /var/lib/ops-deploy/marina/.ops-deploy-pending") for c in run.executed_commands)


def test_worker_strict_hardening_matches_web(tmp_path: Path) -> None:
    cfg = worker_site(tmp_path).model_copy(update={"hardening": "strict"})
    web = render("unit.service.j2", cfg)
    worker = render("worker.service.j2", cfg, worker=cfg.workers[0])
    for key in (
        "ProtectKernelTunables",
        "ProtectKernelModules",
        "ProtectControlGroups",
        "RestrictAddressFamilies",
        "LockPersonality",
        "RestrictRealtime",
        "SystemCallArchitectures",
    ):
        assert next(line for line in web.splitlines() if line.startswith(key + "=")) in worker


@pytest.mark.parametrize("unit", ["gunicorn", "next"])
def test_worker_launcher_cannot_overwrite_web_or_frontend(tmp_path: Path, unit: str) -> None:
    raw = worker_site(tmp_path).model_dump()
    raw["workers"] = [{"unit": unit}]
    with pytest.raises(ValueError, match="reserved launcher"):
        DjangoSiteConfig.model_validate(raw)
