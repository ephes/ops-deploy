"""Synthetic PostgreSQL Django conversion/resume on an isolated Linux VM."""

from __future__ import annotations

import subprocess
from pathlib import Path

import yaml

from ops_deploy.core import SecretRef, SecretValues
from ops_deploy.services.django_site import DjangoSiteConfig, deploy_django_site
from ops_deploy.testing import SshRun, run_deploy_ssh
from tests.smoke.conftest import SmokeHost


def source_tree(path: Path) -> None:
    files = {
        "pyproject.toml": '[project]\nname="school-smoke"\nversion="0.1.0"\nrequires-python=">=3.12"\ndependencies=["django>=5.2,<5.3","gunicorn>=23","psycopg[binary]>=3.2"]\n',  # noqa: E501
        "manage.py": 'import os,sys\nos.environ.setdefault("DJANGO_SETTINGS_MODULE","school.settings")\nfrom django.core.management import execute_from_command_line\nexecute_from_command_line(sys.argv)\n',  # noqa: E501
        "school/__init__.py": "",
        "school/settings.py": """import os
from urllib.parse import urlsplit,unquote
SECRET_KEY=os.environ['DJANGO_SECRET_KEY']
ALLOWED_HOSTS=['*']
u=urlsplit(os.environ['DATABASE_URL'])
DATABASES={'default':{'ENGINE':'django.db.backends.postgresql','NAME':u.path[1:],'USER':u.username,'PASSWORD':unquote(u.password),'HOST':u.hostname,'PORT':u.port}}
INSTALLED_APPS=['django.contrib.auth','django.contrib.contenttypes','django.contrib.staticfiles','school']
ROOT_URLCONF='school.urls'
STATIC_URL='/static/'
STATIC_ROOT='staticfiles'
STORAGES={'default':{'BACKEND':'django.core.files.storage.FileSystemStorage'},'staticfiles':{'BACKEND':'django.contrib.staticfiles.storage.ManifestStaticFilesStorage'}}
""",
        "school/wsgi.py": 'import os\nos.environ.setdefault("DJANGO_SETTINGS_MODULE","school.settings")\nfrom django.core.wsgi import get_wsgi_application\napplication=get_wsgi_application()\n',  # noqa: E501
        "school/urls.py": 'from django.http import HttpResponse\nfrom django.urls import path\nurlpatterns=[path("",lambda request:HttpResponse("school smoke"))]\n',  # noqa: E501
        "school/management/__init__.py": "",
        "school/management/commands/__init__.py": "",
        "school/management/commands/update_index.py": 'from django.core.management.base import BaseCommand\nclass Command(BaseCommand):\n def handle(self,*args,**kwargs):\n  open("cache/index-count","a").write("indexed\\n")\n',  # noqa: E501
        "school/management/commands/bootstrap.py": """import os
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
class Command(BaseCommand):
 def handle(self,*args,**kwargs):
  U=get_user_model()
  if not U.objects.filter(username='editor').exists():
   U.objects.create_superuser('editor','editor@example.com',os.environ['DJANGO_SUPERUSER_PASSWORD'])
""",
    }
    for name, content in files.items():
        file = path / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(content)
    subprocess.run(["uv", "lock", "--project", str(path)], check=True, capture_output=True)


def test_postgres_conversion_idempotence_and_resume(smoke_host: SmokeHost, tmp_path: Path) -> None:
    smoke_host.run(
        "systemctl stop school-smoke 2>/dev/null || true; "
        "runuser -u postgres -- dropdb --if-exists school-smoke; "
        "runuser -u postgres -- dropuser --if-exists school-smoke; "
        "rm -rf /home/school-smoke/site /var/lib/ops-deploy/school_smoke; "
        "rm -f /etc/systemd/system/school-smoke.service /etc/traefik/dynamic/school-smoke*.yml; "
        "systemctl daemon-reload"
    )
    source = tmp_path / "source"
    source_tree(source)
    cfg = DjangoSiteConfig.model_validate(
        {
            "service_name": "school_smoke",
            "title": "School smoke",
            "user": "school-smoke",
            "home": "/home/school-smoke",
            "site_path": "/home/school-smoke/site",
            "secrets": SecretRef("fixture.yml"),
            "source": {"path": source, "delete": True, "excludes": (".git", ".venv")},
            "app": {
                "settings_module": "school.settings",
                "wsgi_app": "school.wsgi:application",
                "port": 10121,
                "python": "3.12",
                "timeout": 600,
                "uv_args": ("--frozen", "--no-default-groups"),
            },
            "database": {"kind": "postgres", "name": "school-smoke", "user": "school-smoke"},
            "route": {
                "fqdn": "school.example.invalid",
                "host_rule": "Host(`school.example.invalid`)",
                "wagtail": True,
                "noindex": True,
                "extra_middlewares": ("school-smoke-noindex@file",),
                "public_reason": "Synthetic school smoke",
            },
            "steps": {
                "required_static": ("staticfiles/staticfiles.json",),
                "extra": (
                    {
                        "name": "index",
                        "marker": ".ops-deploy-index",
                        "steps": ({"name": "Update index", "argv": ("update_index",)},),
                    },
                    {
                        "name": "bootstrap",
                        "when": "first",
                        "marker": ".ops-deploy-bootstrap",
                        "steps": (
                            {
                                "name": "Bootstrap school",
                                "argv": ("bootstrap",),
                                "stdin_env": (
                                    {"key": "DJANGO_SUPERUSER_PASSWORD", "value": {"secret": "editor_password"}},
                                ),
                            },
                        ),
                    },
                ),
            },
            "hardening": True,
        }
    )
    assert cfg.secrets is not None
    values = SecretValues(
        cfg.secrets,
        {
            "django_secret_key": "synthetic-django-key",
            "postgres_password": "synthetic-db-password",
            "editor_password": "synthetic-editor-password",
        },
    )

    def run() -> SshRun:
        result = run_deploy_ssh(
            deploy_django_site, cfg, values, host_name=smoke_host.name, host_data=smoke_host.host_data
        )
        assert result.succeeded, (result.error, [(op.name, op.succeeded) for op in result.ops if not op.succeeded])
        return result

    first = run()
    assert first.mutating_changed_ops
    smoke_host.run(
        "echo preserved > /home/school-smoke/site/media/sentinel; echo cached > /home/school-smoke/site/cache/sentinel; "  # noqa: E501
        "chown school-smoke:school-smoke /home/school-smoke/site/media/sentinel /home/school-smoke/site/cache/sentinel"
    )
    # Put the actual frozen origin templates in place through Ansible, then
    # convert that file set once. Provisioning/data already exist above.
    origin = Path(__file__).parents[1] / "parity/ansible"
    origin_vars = {
        "wagtail_service_name": "school-smoke",
        "wagtail_user": "school-smoke",
        "wagtail_group": "school-smoke",
        "wagtail_site_path": str(cfg.site_path),
        "wagtail_env_path": str(cfg.env_path),
        "wagtail_cache_dir": str(cfg.cache_dir),
        "wagtail_venv_bin": str(cfg.venv_bin),
        "wagtail_django_settings_module": cfg.app.settings_module,
        "wagtail_gunicorn_workers": cfg.app.workers,
        "wagtail_gunicorn_timeout": cfg.app.timeout,
        "wagtail_gunicorn_extra_args": "",
        "wagtail_app_host": "127.0.0.1",
        "wagtail_app_port": cfg.app.port,
        "wagtail_wsgi_module": "school.wsgi",
        "wagtail_django_secret_key": "synthetic-django-key",
        "wagtail_admin_url": "hidden_admin/",
        "wagtail_django_allowed_hosts": cfg.allowed_hosts,
        "wagtail_django_cache_location": str(cfg.cache_dir),
        "wagtail_postgres_user": "school-smoke",
        "wagtail_postgres_password": "synthetic-db-password",
        "wagtail_postgres_host": "localhost",
        "wagtail_postgres_port": 5432,
        "wagtail_postgres_database": "school-smoke",
        "wagtail_require_object_storage": False,
        "wagtail_require_sentry": False,
        "wagtail_django_mailgun_api_key": "synthetic-mail",
        "wagtail_mailgun_sender_domain": "mail.example.invalid",
        "wagtail_mailgun_api_url": "",
        "wagtail_django_server_email": "server@example.invalid",
        "wagtail_env_extra": {},
        "wagtail_traefik_host_rule": cfg.route.host_rule,
        "wagtail_traefik_entrypoints": ["web-secure"],
        "wagtail_traefik_middlewares": ["school-smoke-noindex@file"],
        "wagtail_traefik_cert_resolver": "letsencrypt",
    }
    play = [
        {
            "hosts": "all",
            "gather_facts": False,
            "vars": origin_vars,
            "tasks": [
                {
                    "name": "Install origin file set",
                    "ansible.builtin.template": {
                        "src": "{{ item.src }}",
                        "dest": "{{ item.dest }}",
                        "mode": "0600",
                        "owner": "school-smoke",
                        "group": "school-smoke",
                    },
                    "loop": [
                        {"src": str(origin / "wagtail_deploy__wagtail.env.j2"), "dest": str(cfg.env_path)},
                        {
                            "src": str(origin / "wagtail_deploy__wagtail.service.j2"),
                            "dest": "/etc/systemd/system/school-smoke.service",
                        },
                        {
                            "src": str(origin / "wagtail_deploy__wagtail.traefik.yml.j2"),
                            "dest": "/etc/traefik/dynamic/school-smoke.traefik.yml",
                        },
                    ],
                },
                {
                    "ansible.builtin.systemd_service": {
                        "name": "school-smoke",
                        "daemon_reload": True,
                        "state": "restarted",
                    }
                },
            ],
        }
    ]
    play_path = tmp_path / "origin.yml"
    play_path.write_text(yaml.safe_dump(play))
    argv = [
        "ansible-playbook",
        "-i",
        f"{smoke_host.hostname},",
        "-u",
        "root",
        "--private-key",
        smoke_host.key,
        "-e",
        f"ansible_port={smoke_host.port}",
        "-e",
        "ansible_shell_executable=/bin/sh",
        "--ssh-common-args",
        f"-o UserKnownHostsFile={smoke_host.known_hosts} -o StrictHostKeyChecking=yes",
        str(play_path),
    ]
    result = subprocess.run(argv, text=True, capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr
    traefik = smoke_host.out("systemctl show -p MainPID --value traefik")
    old_pid = smoke_host.out("systemctl show -p MainPID --value school-smoke")
    converted = run()
    assert converted.mutating_changed_ops
    assert smoke_host.out("systemctl show -p MainPID --value school-smoke") != old_pid
    assert smoke_host.out("systemctl show -p MainPID --value traefik") == traefik
    pid = smoke_host.out("systemctl show -p MainPID --value school-smoke")
    second = run()
    assert not second.mutating_changed_ops, second.mutating_changed_ops
    assert smoke_host.out("systemctl show -p MainPID --value school-smoke") == pid
    assert smoke_host.out("cat /home/school-smoke/site/media/sentinel") == "preserved"
    # A prior pyinfra source sync interrupted before migrations/restart. A
    # following Ansible --delete sync does not own the root-only markers.
    smoke_host.run("touch /var/lib/ops-deploy/school_smoke/.ops-deploy-pending")
    (source / "school/urls.py").write_text((source / "school/urls.py").read_text() + "\n# source change\n")
    resumed = run()
    assert any("migrations" in name for name in resumed.mutating_changed_ops)
    assert smoke_host.out("cat /home/school-smoke/site/cache/index-count").splitlines() == ["indexed", "indexed"]
    assert not run().mutating_changed_ops
