"""Actual worker processes and real pyinfra facts on an isolated PostgreSQL host."""

from __future__ import annotations

import subprocess
from pathlib import Path

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.services.django_site import DjangoSiteConfig, deploy_django_site
from ops_deploy.testing import SshRun, run_deploy_ssh
from tests.smoke.conftest import SmokeHost
from tests.smoke.test_django_site_postgres_smoke import source_tree


def test_worker_process_gates_and_resume(smoke_host: SmokeHost, tmp_path: Path) -> None:
    smoke_host.run(
        "systemctl stop worker-smoke worker-smoke-db-worker 2>/dev/null || true; "
        "runuser -u postgres -- dropdb --if-exists worker-smoke; "
        "runuser -u postgres -- dropuser --if-exists worker-smoke; "
        "rm -rf /home/worker-smoke/site /var/lib/ops-deploy/worker_smoke; "
        "rm -f /etc/systemd/system/worker-smoke*.service /etc/traefik/dynamic/worker-smoke*.yml; "
        "systemctl daemon-reload"
    )
    source = tmp_path / "source"
    source_tree(source)
    # A real Django management worker with the origin's CLI contract and an
    # observable process start counter. No fake connector responses are used.
    (source / "school/management/commands/db_worker.py").write_text("""import time
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
class Command(BaseCommand):
 def add_arguments(self,p):
  for name in ('backend','worker-id','queue-name','interval'): p.add_argument('--'+name)
 def handle(self,*args,**kwargs):
  get_user_model().objects.count()
  with open('cache/worker-starts','a') as f: f.write('started\\n')
  while True: time.sleep(1)
""")
    (
        source / "school/management/commands/ensure_default_site.py"
    ).write_text("""from django.core.management.base import BaseCommand
class Command(BaseCommand):
 def handle(self,*args,**kwargs):
  with open('cache/site-count','a') as f: f.write('site\\n')
""")
    (source / ".python-version").write_text("3.12\n")
    subprocess.run(["uv", "lock", "--project", str(source)], check=True, capture_output=True)
    cfg = DjangoSiteConfig.model_validate(
        {
            "service_name": "worker_smoke",
            "unit": "worker-smoke",
            "title": "Worker smoke",
            "user": "worker-smoke",
            "home": "/home/worker-smoke",
            "site_path": "/home/worker-smoke/site",
            "secrets": SecretRef("fixture.yml"),
            "source": {"path": source, "delete": True, "excludes": (".git", ".venv")},
            "app": {
                "settings_module": "school.settings",
                "wsgi_app": "school.wsgi:application",
                "port": 10122,
                "python": "3.12",
                "assert_python_version": True,
                "uv_args": ("--frozen", "--no-default-groups"),
                "uv_env": (
                    {"key": "GIT_CONFIG_COUNT", "value": "1"},
                    {"key": "GIT_CONFIG_KEY_0", "value": "http.version"},
                    {"key": "GIT_CONFIG_VALUE_0", "value": "HTTP/1.1"},
                ),
            },
            "database": {"kind": "postgres", "name": "worker-smoke", "user": "worker-smoke"},
            "workers": ({"unit": "worker-smoke-db-worker", "backend": "transcripts", "queue": "default"},),
            "env": {"extra": ({"key": "OPTIONAL", "value": {"secret": "optional", "allow_empty": True}},)},
            "repair_cache_ownership": True,
            "steps": {
                "required_static": ("staticfiles/staticfiles.json",),
                "extra": (
                    {
                        "name": "index",
                        "marker": ".ops-deploy-index",
                        "steps": ({"name": "Index", "argv": ("update_index",)},),
                    },
                    {
                        "name": "default site",
                        "when": "first",
                        "marker": ".ops-deploy-default-site",
                        "steps": ({"name": "Site", "argv": ("ensure_default_site",)},),
                    },
                ),
            },
            "route": {
                "fqdn": "worker.example.invalid",
                "host_rule": "Host(`worker.example.invalid`)",
                "wagtail": True,
                "public_reason": "Synthetic worker test",
            },
            "hardening": True,
        }
    )
    assert cfg.secrets is not None
    sec = SecretValues(
        cfg.secrets, {"django_secret_key": "synthetic-key", "postgres_password": "synthetic-db", "optional": ""}
    )

    def run() -> SshRun:
        result = run_deploy_ssh(deploy_django_site, cfg, sec, host_name=smoke_host.name, host_data=smoke_host.host_data)
        assert result.succeeded, (result.error, [o.name for o in result.ops if not o.succeeded])
        return result

    def state() -> list[str]:
        smoke_host.run("sleep 1")
        return [
            smoke_host.out(f"systemctl show {u} -p MainPID -p ActiveEnterTimestampMonotonic -p NRestarts")
            for u in ("worker-smoke", "worker-smoke-db-worker", "traefik")
        ]

    first = run()
    assert first.mutating_changed_ops
    before = state()
    assert smoke_host.out("wc -l < /home/worker-smoke/site/cache/worker-starts") == "1"
    smoke_host.run(
        "echo media > /home/worker-smoke/site/media/sentinel; "
        "echo cache > /home/worker-smoke/site/cache/sentinel; "
        "ln -s .venv /home/worker-smoke/site/venv; "
        "chown -h worker-smoke:worker-smoke /home/worker-smoke/site/venv; "
        "chown worker-smoke:worker-smoke /home/worker-smoke/site/media/sentinel /home/worker-smoke/site/cache/sentinel"
    )
    second = run()
    assert not second.mutating_changed_ops
    assert state() == before
    assert smoke_host.out("wc -l < /home/worker-smoke/site/cache/site-count") == "1"
    assert smoke_host.out("wc -l < /home/worker-smoke/site/cache/worker-starts") == "1"
    # A source edit must restart both processes once; a converged rerun neither.
    (source / "source-change.txt").write_text("changed")
    run()
    changed = state()
    assert changed[0] != before[0]
    assert changed[1] != before[1]
    assert changed[2] == before[2]
    assert smoke_host.out("wc -l < /home/worker-smoke/site/cache/worker-starts") == "2"
    assert not run().mutating_changed_ops
    assert state() == changed
    # An interrupted worker-only rollout is owed without a web restart.
    smoke_host.run("touch /var/lib/ops-deploy/worker_smoke/.ops-deploy-restart-worker-smoke-db-worker")
    run()
    resumed = state()
    assert resumed[0] == changed[0]
    assert resumed[1] != changed[1]
    assert resumed[2] == changed[2]
    assert smoke_host.out("wc -l < /home/worker-smoke/site/cache/worker-starts") == "3"
    assert smoke_host.out("cat /home/worker-smoke/site/media/sentinel") == "media"
    assert smoke_host.out("cat /home/worker-smoke/site/cache/sentinel") == "cache"
    assert smoke_host.out("stat -c %a /home/worker-smoke/site/media") == "755"
    assert smoke_host.out("readlink /home/worker-smoke/site/venv") == ".venv"
    assert not run().mutating_changed_ops

    # A start command can succeed while Type=simple immediately exits. The
    # liveness operation must fail before the restart obligation is cleared.
    healthy_cfg = cfg
    cfg = cfg.model_copy(update={"workers": (cfg.workers[0].model_copy(update={"extra_args": ("--invalid-option",)}),)})
    failed = run_deploy_ssh(deploy_django_site, cfg, sec, host_name=smoke_host.name, host_data=smoke_host.host_data)
    assert not failed.succeeded
    assert (
        smoke_host.out(
            "test -e /var/lib/ops-deploy/worker_smoke/.ops-deploy-restart-worker-smoke-db-worker && echo owed"
        )
        == "owed"
    )
    cfg = healthy_cfg
    run()
    assert not run().mutating_changed_ops
