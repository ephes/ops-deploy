"""Deploy weeknotes.home to the smoke target: real end state, converged reruns, data kept.

Needs a daybook checkout: ``DAYBOOK_SOURCE``, else ``$PROJECTS_ROOT/daybook``.
Its committed ``HEAD`` is exported, so uncommitted files never reach the VM.
The operations wiring (FastDeploy service row, Echoport target and token,
Nyxmon checks) runs against stand-ins for those services
(``weeknotes_home_stubs.py``): their interfaces are the real ones, the
services are not on the VM.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest
from pyinfra.api.command import StringCommand
from pyinfra.connectors.util import make_unix_command

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.weeknotes_home import WeeknotesHomeConfig, deploy_weeknotes_home
from ops_deploy.services.weeknotes_home.deploy import _site_manage
from ops_deploy.testing import SshRun, run_deploy_ssh
from tests.smoke.conftest import TIMINGS, SmokeHost
from tests.smoke.weeknotes_home_stubs import reset_script, setup_script, teardown_script

HOST = "weeknotes.example.invalid"
HOME = "/home/weeknotes-home"
SITE = f"{HOME}/site"
FD_SERVICE = {"name": "weeknotes-home-backup", "cwd": "/tmp", "deploy_script": "deploy.sh"}
OPERATOR = f"smoke-operator-{secrets.token_hex(6)}"
PSQL = "runuser -u postgres -- psql -XAtq -d weeknotes_home"


def daybook_checkout() -> Path | None:
    configured = os.environ.get("DAYBOOK_SOURCE")
    if configured:
        return Path(configured)
    root = os.environ.get("PROJECTS_ROOT")
    return Path(root) / "daybook" if root else None


@dataclass(frozen=True)
class Deployed:
    cfg: WeeknotesHomeConfig
    secrets: SecretValues
    guarded: SshRun
    first: SshRun
    second: SshRun
    fresh_clone: SshRun
    code_change: SshRun
    wired: SshRun
    wired_again: SshRun


@pytest.fixture(scope="module")
def deployed(smoke_host: SmokeHost, tmp_path_factory: pytest.TempPathFactory) -> Deployed:
    checkout = daybook_checkout()
    if checkout is None or not (checkout / ".git").exists():
        pytest.skip("no daybook checkout (set DAYBOOK_SOURCE or PROJECTS_ROOT)")
    assert smoke_host.out("hostname").startswith("lima-"), "refusing to reset a host that is not a lima smoke VM"
    smoke_host.run("bash -s", input=reset_script())
    archive = subprocess.run(["git", "-C", str(checkout), "archive", "HEAD"], check=True, capture_output=True)
    source = tmp_path_factory.mktemp("daybook")
    subprocess.run(["tar", "-x", "-C", str(source)], input=archive.stdout, check=True)
    ref = SecretRef("secrets/smoke/weeknotes_home.yml")
    cfg = WeeknotesHomeConfig(
        source_path=source,
        secrets=ref,
        traefik_host=HOST,
        django_allowed_hosts=("127.0.0.1", "localhost", HOST),
        django_csrf_trusted_origins=(f"https://{HOST}",),
        cast_base_url="https://cast.example.invalid",
    )
    values = SecretValues(
        ref,
        {
            # `$`, a backtick, quotes and backslash pairs: the env file must
            # survive systemd and the loader (env_exec.py, run through fish).
            "django_secret_key": f"smoke-key-{secrets.token_hex(24)}$`x\"y\\\\z'\\",
            "postgres_password": f"smoke-pg-{secrets.token_hex(12)}",
            "api_token": f"smoke-api-{secrets.token_hex(24)}",
            "basic_auth_password": f"smoke-pw-{secrets.token_hex(12)}",
            "fastdeploy_token_user": OPERATOR,
        },
    )

    def deploy(label: str, config: WeeknotesHomeConfig) -> SshRun:
        run = run_deploy_ssh(
            deploy_weeknotes_home, config, values, host_name=smoke_host.name, host_data=smoke_host.host_data
        )
        TIMINGS[f"weeknotes-home {label} run"] = run.seconds
        return run

    # Like the playbook: nothing but weeknotes-home may hold the port (checked first).
    smoke_host.run("systemd-run --unit=weeknotes-port-squatter python3 -m http.server 10062 --bind 127.0.0.1")
    smoke_host.run("sleep 1")
    try:
        guarded = deploy("guard", cfg)
    finally:
        smoke_host.run("systemctl stop weeknotes-port-squatter", check=False)
    assert not guarded.succeeded

    fresh = tmp_path_factory.mktemp("daybook-fresh")
    subprocess.run(["tar", "-x", "-m", "-C", str(fresh)], input=archive.stdout, check=True)
    first = deploy("first", cfg)
    assert first.succeeded, (first.error, [op for op in first.ops if not op.succeeded])
    # Data the deploys must never lose: a row in the app database, files in cache and static.
    smoke_host.run(f"{PSQL} -c \"CREATE TABLE smoke_marker (note text); INSERT INTO smoke_marker VALUES ('kept')\"")
    smoke_host.run(
        f"runuser -u weeknotes-home -- sh -c 'echo kept > {SITE}/cache/weeknotes-home/marker; "
        f"echo kept > {SITE}/static/weeknotes-home/marker'"
    )
    runs = [first]
    for label, config in (("second", cfg), ("fresh clone", cfg.model_copy(update={"source_path": fresh}))):
        run = deploy(label, config)
        assert run.succeeded, (label, run.error, [op for op in run.ops if not op.succeeded])
        runs.append(run)
    (fresh / "README.md").write_text(f"changed {secrets.token_hex(4)}\n")
    code_change = deploy("code change", cfg.model_copy(update={"source_path": fresh}))
    assert code_change.succeeded, (code_change.error, [op for op in code_change.ops if not op.succeeded])

    smoke_host.run("bash -s", input=setup_script(OPERATOR, json.dumps(FD_SERVICE)))
    wired_cfg = cfg.model_copy(update={"source_path": fresh, "operations_wiring": True})
    wired = deploy("wired first", wired_cfg)
    assert wired.succeeded, (wired.error, [op for op in wired.ops if not op.succeeded])
    wired_again = deploy("wired second", wired_cfg)
    assert wired_again.succeeded, (wired_again.error, [op for op in wired_again.ops if not op.succeeded])
    return Deployed(cfg, values, guarded, runs[0], runs[1], runs[2], code_change, wired, wired_again)


def test_port_collision_stops_the_deploy(deployed: Deployed) -> None:
    failed = [op.name for op in deployed.guarded.ops if not op.succeeded]
    assert failed
    assert failed[0] == "Deploy weeknotes-home | Port preflight tcp/10062"
    assert deployed.guarded.mutating_changed_ops == []


def test_second_run_has_no_mutating_changes(deployed: Deployed) -> None:
    assert any(name.endswith("| Write .env.weeknotes-home") for name in deployed.first.changed_ops)
    assert deployed.second.mutating_changed_ops == []
    assert all(op.succeeded for op in deployed.second.ops if op.read_only)


def test_fresh_clone_of_unchanged_code_is_a_noop(deployed: Deployed) -> None:
    assert deployed.fresh_clone.mutating_changed_ops == []


def test_code_change_restarts_once_and_keeps_data(smoke_host: SmokeHost, deployed: Deployed) -> None:
    changed = deployed.code_change.mutating_changed_ops
    assert any(name.endswith("| Sync daybook source") for name in changed)
    # The gated Django steps ran (through root's fish login shell) and succeeded.
    assert any(name.endswith("| Run weeknotes-home migrations") for name in changed)
    assert any(name.endswith("| Collect weeknotes-home static files") for name in changed)
    assert any(name.endswith("| Restart weeknotes-home.service") for name in changed)
    assert smoke_host.out(f"{PSQL} -c 'select note from smoke_marker'") == "kept"
    assert smoke_host.out(f"cat {SITE}/cache/weeknotes-home/marker {SITE}/static/weeknotes-home/marker") == "kept\nkept"


def test_manage_commands_see_the_env_file_values(smoke_host: SmokeHost, deployed: Deployed) -> None:
    assert smoke_host.out("getent passwd root | cut -d: -f7") == "/usr/bin/fish"
    probe = "import os, sys; sys.stdout.write(os.environ['DJANGO_SECRET_KEY'])"
    # Sent as pyinfra sends it: ``sh -c '...'`` through root's fish login shell.
    command = make_unix_command(
        StringCommand(_site_manage(deployed.cfg, "shell", "--verbosity", "0", "-c", probe))
    ).get_raw_value()
    result = smoke_host.run(command, login_shell=True)
    assert result.stdout == deployed.secrets["django_secret_key"]


def test_service_runs_and_is_healthy(smoke_host: SmokeHost, deployed: Deployed) -> None:
    assert smoke_host.out("systemctl is-active weeknotes-home") == "active"
    assert smoke_host.out("systemctl is-enabled weeknotes-home") == "enabled"
    assert smoke_host.out("curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:10062/healthz") == "200"
    assert smoke_host.out(f"stat -c '%a %U %G' {SITE}/.env.weeknotes-home") == "600 weeknotes-home weeknotes-home"
    # The venv is the role's, next to the source.
    assert smoke_host.out(f"test -x {SITE}/.venv-weeknotes-home/bin/gunicorn && echo ok") == "ok"


def test_database_belongs_to_the_service_role(smoke_host: SmokeHost, deployed: Deployed) -> None:
    owner = "select pg_get_userbyid(datdba) from pg_database where datname = 'weeknotes_home'"
    assert smoke_host.out(f'runuser -u postgres -- psql -XAtq -c "{owner}"') == "weeknotes_home"
    assert smoke_host.out(f"{PSQL} -c 'select count(*) > 0 from django_migrations'") == "t"


def test_traefik_guards_the_public_route(smoke_host: SmokeHost, deployed: Deployed) -> None:
    curl = f"curl -ks -o /dev/null -w '%{{http_code}}' --resolve {HOST}:443:127.0.0.1 https://{HOST}/healthz"
    # The host itself is no trusted client range: Basic Auth is required.
    assert smoke_host.out(curl) == "401"
    password = deployed.secrets["basic_auth_password"]
    authed = smoke_host.run(f"{curl} -K -", input=f'user = "admin:{password}"\n')
    assert authed.stdout.strip() == "200"
    route = smoke_host.out("cat /etc/traefik/dynamic/weeknotes-home.yml")
    assert "weeknotes-home-ext:" in route
    assert '- "admin:$2y$05$' in route
    assert "removeHeader: True" in route


def test_operations_wiring_applies_then_settles(smoke_host: SmokeHost, deployed: Deployed) -> None:
    changed = deployed.wired.mutating_changed_ops
    assert any(name.endswith("| Sync FastDeploy service row for the backup service") for name in changed)
    assert any("upsert the Echoport backup target" in name for name in changed)
    assert any(name.endswith("| Upsert Nyxmon checks") for name in changed)
    assert deployed.wired_again.mutating_changed_ops == []
    row = smoke_host.out('runuser -u postgres -- psql -XAtq -d fastdeploy -c "select data::jsonb from service"')
    assert json.loads(row) == FD_SERVICE
    targets = json.loads(smoke_host.out("cat /home/echoport/site/targets.json"))
    assert [t["name"] for t in targets] == ["weeknotes_home"]
    target = targets[0]
    assert target["restore_owner"] == "weeknotes-home:weeknotes-home"
    assert target["target_mode"] == "service_owned"
    assert target["schedule"] == "10 4 * * *"
    assert target["service_token"].count(".") == 2
    # One token for both runs: the second found it valid.
    assert smoke_host.out("wc -l < /home/fastdeploy/site/issued.log").strip() == "1"
    checks = smoke_host.out(
        "runuser -u nyxmon -- python3 -c \"import sqlite3; c = sqlite3.connect('/home/nyxmon/site/db.sqlite3'); "
        "print(*[r[0] for r in c.execute('select name from health_check order by name')], sep=';')\""
    )
    assert checks == "weeknotes.home backup freshness;weeknotes.home local health"


def test_token_is_replaced_when_unusable_and_legacy_target_is_adopted(
    smoke_host: SmokeHost, deployed: Deployed, tmp_path: Path
) -> None:
    store = "/home/echoport/site/targets.json"
    rename = (
        f"import json; rows = json.load(open('{store}')); rows[0]['name'] = 'weeknotes-home'; "
        f"rows[0]['service_token'] = 'not-a-jwt'; json.dump(rows, open('{store}', 'w'))"
    )
    smoke_host.run(f'python3 -c "{rename}"')
    before = int(smoke_host.out("wc -l < /home/fastdeploy/site/issued.log"))
    config = deployed.cfg.model_copy(update={"operations_wiring": True})

    run = run_deploy_ssh(
        deploy_weeknotes_home, config, deployed.secrets, host_name=smoke_host.name, host_data=smoke_host.host_data
    )

    assert run.succeeded, (run.error, [op for op in run.ops if not op.succeeded])
    assert int(smoke_host.out("wc -l < /home/fastdeploy/site/issued.log")) == before + 1
    targets = json.loads(smoke_host.out(f"cat {store}"))
    assert [t["name"] for t in targets] == ["weeknotes_home"]
    assert targets[0]["service_token"] != "not-a-jwt"
    again = run_deploy_ssh(
        deploy_weeknotes_home, config, deployed.secrets, host_name=smoke_host.name, host_data=smoke_host.host_data
    )
    assert again.mutating_changed_ops == []


def test_no_secret_on_disk_outside_its_files(smoke_host: SmokeHost, deployed: Deployed) -> None:
    for key, value in deployed.secrets.items():
        found = smoke_host.run(
            f"grep -rlF --no-messages -f - /tmp /var/tmp /dev/shm /root {HOME} /home/echoport /home/nyxmon "
            f"--exclude=.env.weeknotes-home --exclude=targets.json || true",
            input=f"{value}\n",
        )
        assert found.stdout.strip() == "", key
    assert deployed.secrets["basic_auth_password"] not in smoke_host.out("cat /etc/traefik/dynamic/weeknotes-home.yml")


def test_teardown_of_the_stubs(smoke_host: SmokeHost, deployed: Deployed) -> None:
    # Last: leave the VM without the stand-ins (the module fixture created them).
    smoke_host.run("bash -s", input=teardown_script())
