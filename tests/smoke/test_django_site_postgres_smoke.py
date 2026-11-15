"""Synthetic PostgreSQL Django site: drift, idempotence and resume on an isolated Linux VM."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

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


def test_postgres_idempotence_and_resume(smoke_host: SmokeHost, tmp_path: Path) -> None:
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
    assert smoke_host.out("stat -c %a /home/school-smoke/site/media") == "755"
    smoke_host.run(
        "ln -s .venv /home/school-smoke/site/venv; chown -h school-smoke:school-smoke /home/school-smoke/site/venv"
    )
    for relative in (".ruff_cache", "school/.ruff_cache"):
        directory = source / relative
        directory.mkdir()
        (directory / "cache-entry").write_text("controller lint cache")
    smoke_host.run(
        "echo preserved > /home/school-smoke/site/media/sentinel; echo cached > /home/school-smoke/site/cache/sentinel; "  # noqa: E501
        "chown school-smoke:school-smoke /home/school-smoke/site/media/sentinel /home/school-smoke/site/cache/sentinel"
    )
    traefik = smoke_host.out("systemctl show -p MainPID --value traefik")
    run()
    assert smoke_host.out("stat -c %a /home/school-smoke/site/media") == "755"
    assert smoke_host.out("readlink /home/school-smoke/site/venv") == ".venv"
    assert smoke_host.out("find /home/school-smoke/site -name .ruff_cache -print") == ""
    assert smoke_host.out("systemctl show -p MainPID --value traefik") == traefik
    pid = smoke_host.out("systemctl show -p MainPID --value school-smoke")
    second = run()
    assert not second.mutating_changed_ops, second.mutating_changed_ops
    assert smoke_host.out("systemctl show -p MainPID --value school-smoke") == pid
    assert smoke_host.out("cat /home/school-smoke/site/media/sentinel") == "preserved"
    # A prior source sync interrupted before migrations/restart: the next run resumes.
    smoke_host.run("touch /var/lib/ops-deploy/school_smoke/.ops-deploy-pending")
    (source / "school/urls.py").write_text((source / "school/urls.py").read_text() + "\n# source change\n")
    resumed = run()
    assert any("migrations" in name for name in resumed.mutating_changed_ops)
    assert smoke_host.out("cat /home/school-smoke/site/cache/index-count").splitlines() == ["indexed", "indexed"]
    assert not run().mutating_changed_ops

    # A wrong existing path is refused while planning, before app restart or
    # source sync. Exercise both a real symlink and a regular file on Linux.
    pid = smoke_host.out("systemctl show -p MainPID --value school-smoke")
    for create in ("ln -s media-held media", "touch media"):
        smoke_host.run("cd /home/school-smoke/site && mv media media-held && " + create)
        try:
            with pytest.raises(ValueError, match="media"):
                run()
            assert smoke_host.out("systemctl show -p MainPID --value school-smoke") == pid
        finally:
            smoke_host.run("cd /home/school-smoke/site && rm media && mv media-held media")
