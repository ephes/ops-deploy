"""Deploy-level scenarios for graphyard ingress, Vector, auth bootstrap and the whole stack."""

import base64
import hashlib
import re
from pathlib import Path
from typing import Any

import pytest
from pyinfra.api import deploy

from ops_deploy.core import ConfigValidationError
from ops_deploy.helpers.traefik import hash_password
from ops_deploy.services.graphyard import (
    GraphyardAuthConfig,
    GraphyardIngressConfig,
    GraphyardVectorConfig,
    deploy_graphyard,
    deploy_graphyard_auth,
    deploy_graphyard_ingress,
    deploy_graphyard_vector,
)
from ops_deploy.services.graphyard import auth as auth_module
from ops_deploy.services.graphyard import ingress as ingress_module
from ops_deploy.services.graphyard import stack as stack_module
from ops_deploy.services.graphyard import vector as vector_module
from ops_deploy.testing import FakeRun, RecordingRsyncRunner, run_deploy_fake
from tests import fakehost
from tests.graphyard_fixtures import (
    SECRETS,
    auth_config,
    ingress_config,
    make_source,
    secrets_values,
    stack_config,
    vector_config,
)
from tests.test_graphyard import as_file, assert_no_secret_leaks
from tests.test_graphyard import converged as core_converged
from tests.test_infra_docker_vector import vector_converged

ROUTE = "/etc/traefik/dynamic/graphyard.yml"
ENV = "/etc/graphyard/graphyard.env"
FRAGMENT = "/etc/vector/config.d/20-graphyard-host-metrics.yaml"
GLOBAL = "/etc/vector/config.d/00-global.yaml"
DEFAULTS = "/etc/default/vector"
HASH = hash_password(SECRETS["basic_auth_password"])


def names(run: FakeRun, prefix: str) -> list[str]:
    return [name.removeprefix(prefix) for name in run.mutating_changed_ops]


# -- ingress ------------------------------------------------------------------------

INGRESS = "Deploy graphyard ingress | "


def env_lines(cfg: GraphyardIngressConfig) -> list[str]:
    return [f"{key}={value}" for key, value in cfg.env_lines.items()]


def ingress_converged(cfg: GraphyardIngressConfig) -> dict[str, Any]:
    return {
        "grep -E '^(": env_lines(cfg),
        f"test -f {ENV}": ["present"],
        **fakehost.LINUX,
        **fakehost.directory("/etc/traefik/dynamic"),
        **fakehost.file(ROUTE, ingress_module.render_route(cfg, HASH)),
    }


def run_ingress(cfg: GraphyardIngressConfig, responses: dict[str, Any] | None = None) -> FakeRun:
    run = run_deploy_fake(deploy_graphyard_ingress, cfg, secrets_values(), responses=responses or dict(fakehost.LINUX))
    assert run.succeeded, (run.error, [op.name for op in run.ops if not op.succeeded])
    return run


def test_ingress_first_run_writes_the_route_and_the_env_lines() -> None:
    cfg = ingress_config()
    responses = {f"test -f {ENV}": ["present"], **fakehost.LINUX}

    run = run_ingress(cfg, responses)

    route = run.upload(ROUTE).decode()
    assert "Host(`graphyard.example.invalid`)" in route
    assert "certResolver: letsencrypt" in route
    assert SECRETS["basic_auth_password"] not in route
    assert '- "admin:$2y$05$' in route
    assert names(run, INGRESS) == [
        "Ensure Traefik dynamic directory",
        "Write Traefik route graphyard",
        "Set the reverse proxy hosts in the Graphyard environment",
        "Restart graphyard-web",
        "Restart graphyard-agent",
    ]
    edit = next(c for c in run.executed_commands if "graphyard-env" in c)
    assert "DJANGO_ALLOWED_HOSTS=127.0.0.1,localhost,graphyard.example.invalid" in edit
    assert "GRAFANA_BASE_URL=https://grafana.example.invalid" in edit
    # Nothing restarts Traefik: its file provider watches the directory.
    assert not any("traefik" in c and "systemctl" in c for c in run.executed_commands)
    assert_no_secret_leaks(run)


def test_ingress_second_run_changes_nothing() -> None:
    cfg = ingress_config()

    run = run_ingress(cfg, ingress_converged(cfg))

    assert names(run, INGRESS) == []
    assert run.uploaded_paths == []


def test_ingress_env_drift_is_set_and_restarts_the_app() -> None:
    cfg = ingress_config(django_admin_url="admin/")
    responses = ingress_converged(cfg)
    responses["grep -E '^("] = [*env_lines(cfg)[:-1], "DJANGO_ADMIN_URL=hidden_admin/"]

    run = run_ingress(cfg, responses)

    assert names(run, INGRESS) == [
        "Set the reverse proxy hosts in the Graphyard environment",
        "Restart graphyard-web",
        "Restart graphyard-agent",
    ]


def test_ingress_missing_env_file_fails_when_required() -> None:
    responses: dict[Any, Any] = {re.compile(r"^test -f /etc/graphyard/graphyard.env \|\|"): {"success": False}}
    responses.update(fakehost.LINUX)

    run = run_deploy_fake(deploy_graphyard_ingress, ingress_config(), secrets_values(), responses=responses)

    assert not run.succeeded
    assert next(op.name for op in run.ops if not op.succeeded) == INGRESS + "Require the Graphyard environment file"
    assert not any("graphyard-env" in c for c in run.executed_commands)


def test_ingress_without_env_management_only_writes_the_route() -> None:
    cfg = ingress_config(manage_graphyard_env=False, basic_auth_enabled=False, inventory_enabled=True)

    run = run_deploy_fake(deploy_graphyard_ingress, cfg, None, responses=dict(fakehost.LINUX))

    assert run.succeeded
    assert run.uploaded_paths == [ROUTE]
    assert "graphyard-inventory" in run.upload(ROUTE).decode()
    assert "basicAuth" not in run.upload(ROUTE).decode()


@pytest.mark.parametrize(
    "bad",
    [
        {"graphyard_host": "graphyard.example.com"},
        {"django_admin_url": "/admin/"},
        {"django_admin_url": "admin"},
        {"internal_ip_ranges": ("not-a-network",)},
        {"graphyard_backend_url": "http://127.0.0.1"},
        {"django_allowed_hosts": ()},
    ],
)
def test_ingress_config_rejects_bad_inputs(bad: dict[str, Any]) -> None:
    with pytest.raises((ConfigValidationError, ValueError)):
        ingress_config(**bad)


def test_ingress_needs_the_basic_auth_password() -> None:
    from ops_deploy.core.secrets import SecretValues

    with pytest.raises(ValueError, match="basic_auth_password"):
        ingress_module.traefik_config(ingress_config(), SecretValues(secrets_values().ref, {}))


def test_ingress_env_edit_behaves_like_lineinfile(tmp_path: Path) -> None:
    import subprocess
    import sys

    env = tmp_path / "graphyard.env"
    env.write_text("A=1\nDJANGO_ALLOWED_HOSTS=old\nB=2\nDJANGO_ALLOWED_HOSTS=older\n")
    env.chmod(0o640)
    args = ["DJANGO_ALLOWED_HOSTS=a,b", "GRAFANA_BASE_URL=https://g"]

    changed = subprocess.run(
        [sys.executable, "-I", "-c", ingress_module.ENV_EDIT, str(env), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    again = subprocess.run(
        [sys.executable, "-I", "-c", ingress_module.ENV_EDIT, str(env), *args],
        check=True,
        capture_output=True,
        text=True,
    )

    assert (
        env.read_text() == "A=1\nDJANGO_ALLOWED_HOSTS=old\nB=2\nDJANGO_ALLOWED_HOSTS=a,b\nGRAFANA_BASE_URL=https://g\n"
    )
    assert oct(env.stat().st_mode & 0o777) == "0o640"
    assert changed.stdout.split() == ["DJANGO_ALLOWED_HOSTS", "GRAFANA_BASE_URL"]
    assert again.stdout.strip() == ""
    backups = [p for p in tmp_path.iterdir() if p.name.endswith("~")]
    assert len(backups) == 1
    assert "older" in backups[0].read_text()


# -- vector -------------------------------------------------------------------------

VECTOR = "Deploy graphyard vector | "


def vector_host(cfg: GraphyardVectorConfig, **drift: str) -> dict[str, Any]:
    fragment = vector_module.render_fragment(cfg, secrets_values()).reveal().decode()
    content = {FRAGMENT: fragment, GLOBAL: vector_module.render_global(cfg), **drift}
    responses: dict[str, Any] = {
        **vector_converged(cfg.apt),
        **fakehost.stat("/var/lib/vector", user="vector", mode="drwxr-x---"),
        **fakehost.stat("/etc/vector/config.d", group="vector", mode="drwxr-x---"),
        **fakehost.directory("/etc/default"),
        **as_file(DEFAULTS, "# vector\nVECTOR_CONFIG_DIR=/etc/vector/config.d\n"),
        **fakehost.service("vector.service"),
    }
    for path, text in content.items():
        responses.update(as_file(path, text, group="vector", mode="-rw-r-----"))
    return responses


def run_vector(cfg: GraphyardVectorConfig, responses: dict[str, Any] | None = None) -> FakeRun:
    run = run_deploy_fake(deploy_graphyard_vector, cfg, secrets_values(), responses=responses or dict(fakehost.UBUNTU))
    assert run.succeeded, (run.error, [op.name for op in run.ops if not op.succeeded])
    return run


def test_vector_first_run_installs_validates_and_starts() -> None:
    cfg = vector_config()

    run = run_vector(cfg)
    commands = run.executed_commands

    assert any("apt-get" in c and "install" in c and "vector" in c for c in commands)
    assert run.upload(GLOBAL).decode() == 'data_dir: "/var/lib/vector"\n'
    # The fragment holds the ingest token: installed from stdin, never uploaded.
    assert FRAGMENT not in run.uploaded_paths
    validate = next(i for i, c in enumerate(commands) if "vector validate --config-dir" in c)
    assert validate < commands.index("systemctl restart vector.service")
    staged = next(stdin for command, stdin in run.stdin if "vector validate" in command)
    assert base64.b64decode(staged).decode() == vector_module.render_fragment(cfg, secrets_values()).reveal().decode()
    assert "systemctl enable vector.service" in commands
    assert "systemctl start vector.service" in commands
    assert_no_secret_leaks(run)


def test_vector_second_run_changes_nothing() -> None:
    cfg = vector_config()

    run = run_vector(cfg, vector_host(cfg))

    assert names(run, VECTOR) == []
    assert run.uploaded_paths == []
    assert run.changed_ops == [VECTOR + "Validate the staged Vector configuration"]


def test_vector_fragment_change_restarts_vector_once() -> None:
    cfg = vector_config()

    run = run_vector(cfg, vector_host(cfg, **{FRAGMENT: "sources: {}\n"}))

    assert names(run, VECTOR) == ["Deploy the Graphyard Vector config fragment", "Restart vector.service"]


def test_vector_rotated_token_rewrites_the_fragment() -> None:
    cfg = vector_config()
    responses = vector_host(cfg)

    run = run_deploy_fake(
        deploy_graphyard_vector, cfg, secrets_values(vector_ingest_token="rotated-token"), responses=responses
    )

    assert run.succeeded
    assert names(run, VECTOR) == ["Deploy the Graphyard Vector config fragment", "Restart vector.service"]
    assert "rotated-token" not in run.all_text()


def test_vector_other_global_data_dir_stops_before_any_change() -> None:
    cfg = vector_config()

    run = run_deploy_fake(
        deploy_graphyard_vector,
        cfg,
        secrets_values(),
        responses=vector_host(cfg, **{GLOBAL: 'data_dir: "/srv/vector"\n'}),
    )

    assert not run.succeeded
    assert "data_dir=/srv/vector" in str(run.error)
    assert run.executed_commands == []


def test_vector_validation_stages_the_live_directory() -> None:
    command = vector_module.validate_command(vector_config())

    assert "find /etc/vector/config.d -maxdepth 1 -type f" in command
    assert "! -name 20-graphyard-host-metrics.yaml ! -name 00-global.yaml" in command
    assert "vector validate --config-dir" in command
    assert "--skip-healthchecks" not in command


@pytest.mark.parametrize(
    "bad", [{"collectors": ()}, {"ingest_url": "ftp://x"}, {"config_name": "x.toml"}, {"data_dir": "rel"}]
)
def test_vector_config_rejects_bad_inputs(bad: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="validation error"):
        vector_config(**bad)


# -- auth bootstrap -----------------------------------------------------------------

AUTH = "Deploy graphyard auth bootstrap | "
SALT = "abcdefghij"
DJANGO_PARAMS = "pbkdf2_sha256$1000$saltsaltsalt"


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def users_probe(password: str = SECRETS["django_bootstrap_password"], flags: str = "1 1 1") -> list[str]:
    raw = hashlib.pbkdf2_hmac("sha256", password.encode(), b"saltsaltsalt", 1000)
    encoded = f"{DJANGO_PARAMS}${base64.b64encode(raw).decode()}"
    return [
        "25 objects imported automatically",
        f"user {digest('someone-else')} 1 0 0 - {digest('x')}",
        f"user {digest(SECRETS['django_bootstrap_username'])} {flags} {DJANGO_PARAMS} {digest(encoded)}",
    ]


def grafana_probe(
    password: str = SECRETS["grafana_admin_password"], url: str = "http://graphyard-influxdb:8086"
) -> list[str]:
    stored = hashlib.pbkdf2_hmac("sha256", password.encode(), SALT.encode(), 10000, dklen=50).hex()
    return [f"admin {SALT} {digest(stored)}", f"datasource {url}", "lockouts 0"]


def auth_converged(**changes: list[str]) -> dict[str, Any]:
    return {
        "manage.py shell -c": changes.get("users", users_probe()),
        "login_attempt": changes.get("grafana", grafana_probe()),
        "check /opt/apps": changes.get("provisioning", ["UNCHANGED"]),
        "then docker inspect --format": changes.get("network", ["present"]),
        **fakehost.LINUX,
    }


def run_auth(cfg: GraphyardAuthConfig, responses: dict[str, Any]) -> FakeRun:
    run = run_deploy_fake(deploy_graphyard_auth, cfg, secrets_values(), responses=responses)
    assert run.succeeded, (run.error, [op.name for op in run.ops if not op.succeeded])
    assert_no_secret_leaks(run)
    return run


def test_auth_converged_writes_nothing() -> None:
    run = run_auth(auth_config(), auth_converged())

    assert names(run, AUTH) == []
    # Only the read-only datasource health check reads a credential.
    assert [command.split(";")[0] for command, _ in run.stdin] == ["IFS= read -r basic"]


def test_auth_first_run_on_a_fresh_stack_checks_on_the_host() -> None:
    responses = {"manage.py shell -c": [], "login_attempt": ["absent"], "check /opt/apps": ["?"], **fakehost.LINUX}

    run = run_auth(auth_config(), responses)

    assert names(run, AUTH) == [
        "Ensure the Graphyard bootstrap Django user is present with the expected password",
        "Attach InfluxDB to the shared network",
        "Update the Grafana datasource URL when it does not match the target",
        "Update the Grafana datasource provisioning URL when it does not match the target",
        "Restart Grafana for the new datasource URL",
        "Reset the Grafana admin password when it does not match",
        "Clear Grafana login lockout rows for the admin user",
    ]
    reset = next(command for command, _ in run.stdin if "reset-admin-password" in command)
    assert '[ "$state" = MATCH ] && exit 0' in reset
    assert "--password-from-stdin" in reset


@pytest.mark.parametrize(
    ("users", "why"),
    [
        (users_probe(password="old-password"), "password"),
        (users_probe(flags="1 0 1"), "staff flag"),
        (["user nobody 1 1 1 x y"], "missing"),
    ],
)
def test_auth_django_user_drift_runs_the_roles_script(users: list[str], why: str) -> None:
    run = run_auth(auth_config(), auth_converged(users=users))

    assert names(run, AUTH) == ["Ensure the Graphyard bootstrap Django user is present with the expected password"], why
    command, stdin = next((c, s) for c, s in run.stdin if "GRAPHYARD_BOOTSTRAP_USERNAME" in c)
    assert stdin == f"{SECRETS['django_bootstrap_username']}\n{SECRETS['django_bootstrap_password']}\n"
    assert "user.check_password(password)" in command


def test_auth_wrong_grafana_password_is_reset_and_verified() -> None:
    run = run_auth(auth_config(), auth_converged(grafana=grafana_probe(password="old")))

    assert names(run, AUTH) == ["Reset the Grafana admin password when it does not match"]
    assert "Deploy graphyard auth bootstrap | Verify the Grafana admin password hash" in run.changed_ops


def test_auth_datasource_url_drift_is_fixed_and_restarts_grafana() -> None:
    run = run_auth(auth_config(), auth_converged(grafana=grafana_probe(url="http://172.18.0.3:8086")))

    assert names(run, AUTH) == [
        "Update the Grafana datasource URL when it does not match the target",
        "Restart Grafana for the new datasource URL",
    ]
    assert "docker restart graphyard-grafana >/dev/null" in run.executed_commands


def test_auth_provisioning_file_drift_is_fixed() -> None:
    run = run_auth(auth_config(), auth_converged(provisioning=["CHANGED"]))

    assert names(run, AUTH) == [
        "Update the Grafana datasource provisioning URL when it does not match the target",
        "Restart Grafana for the new datasource URL",
    ]


def test_auth_lockout_rows_are_cleared() -> None:
    grafana = grafana_probe()
    grafana[2] = "lockouts 3"

    run = run_auth(auth_config(), auth_converged(grafana=grafana))

    assert names(run, AUTH) == ["Clear Grafana login lockout rows for the admin user"]


def test_auth_influx_off_the_shared_network_is_attached() -> None:
    run = run_auth(auth_config(), auth_converged(network=[""]))

    assert names(run, AUTH) == ["Attach InfluxDB to the shared network"]


def test_auth_missing_grafana_user_fails() -> None:
    grafana = grafana_probe()
    grafana[0] = "admin - -"

    run = run_deploy_fake(
        deploy_graphyard_auth, auth_config(), secrets_values(), responses=auth_converged(grafana=grafana)
    )

    assert not run.succeeded
    assert "no user admin" in str(run.error)


def test_django_hash_is_djangos_pbkdf2() -> None:
    # Django: make_password("pw", "salt", "pbkdf2_sha256") at 1000 iterations.
    expected = (
        "pbkdf2_sha256$1000$salt$" + base64.b64encode(hashlib.pbkdf2_hmac("sha256", b"pw", b"salt", 1000)).decode()
    )

    assert auth_module.django_hash("pw", "pbkdf2_sha256$1000$salt") == expected
    assert auth_module.django_hash("pw", "argon2$x$y") is None


def test_auth_needs_the_shared_network_name() -> None:
    with pytest.raises(ValueError, match="grafana_shared_network_name"):
        GraphyardAuthConfig.model_validate({})


@pytest.mark.parametrize("key", ["django_bootstrap_username", "django_bootstrap_password", "grafana_admin_password"])
def test_auth_secrets_are_checked(key: str) -> None:
    with pytest.raises(ValueError, match=key):
        auth_module.check_secrets(secrets_values(**{key: "CHANGEME"}))


# -- stack --------------------------------------------------------------------------


def test_stack_runs_core_vector_ingress_and_auth_in_the_playbooks_order(tmp_path: Path) -> None:
    cfg = stack_config(make_source(tmp_path))

    run = run_deploy_fake(
        deploy_graphyard, cfg, secrets_values(), RecordingRsyncRunner(), responses=dict(fakehost.UBUNTU)
    )

    assert run.succeeded, run.error
    order = [
        next(i for i, op in enumerate(run.ops) if op.name.startswith(f"Deploy graphyard | {first}"))
        for first in (
            "Sync Graphyard source",
            "Deploy the Graphyard Vector config fragment",
            "Write Traefik route graphyard",
            "Ensure the Graphyard bootstrap Django user",
        )
    ]
    assert order == sorted(order)
    assert_no_secret_leaks(run)


def test_converged_stack_changes_nothing(tmp_path: Path) -> None:
    cfg = stack_config(make_source(tmp_path))
    responses: dict[str, Any] = {
        **auth_converged(),
        **ingress_converged(cfg.ingress),
        **core_converged(cfg.core),
    }
    for key, value in vector_host(cfg.vector).items():
        if key == "dpkg -l":
            value = list(dict.fromkeys([*responses[key], *value]))
        responses.setdefault(key, value)
    responses["dpkg -l"] = list(
        dict.fromkeys([*core_converged(cfg.core)["dpkg -l"], *vector_host(cfg.vector)["dpkg -l"]])
    )

    run = run_deploy_fake(deploy_graphyard, cfg, secrets_values(), RecordingRsyncRunner(), responses=responses)

    assert run.succeeded, run.error
    assert run.mutating_changed_ops == []


def test_stack_rewrites_a_provisioning_file_the_sync_brings_back(tmp_path: Path) -> None:
    """The repo's provisioning file has another URL: the sync installs it, auth rewrites it and restarts Grafana."""

    source = make_source(tmp_path)
    datasource = source / "deploy/grafana/provisioning/datasources/graphyard.yaml"
    datasource.write_text(datasource.read_text().replace("graphyard-influxdb:8086", "172.18.0.3:8086"))
    cfg = stack_config(source)

    assert stack_module.incoming_provisioning(cfg) == datasource.read_text()

    @deploy("Deploy graphyard auth bootstrap")
    def auth_after_sync() -> None:
        auth_module.auth_steps(cfg.auth, secrets_values(), incoming=stack_module.incoming_provisioning(cfg))

    run = run_deploy_fake(auth_after_sync, responses=auth_converged())

    assert run.succeeded, run.error
    assert names(run, AUTH) == [
        "Update the Grafana datasource provisioning URL when it does not match the target",
        "Restart Grafana for the new datasource URL",
    ]


def test_provisioning_rewrite_needed_matches_the_roles_script() -> None:
    target = "http://graphyard-influxdb:8086"

    assert not auth_module.provisioning_rewrite_needed(f"a:\n    access: proxy\n    url: {target}\n", target)
    assert auth_module.provisioning_rewrite_needed("a:\n    access: proxy\n", target)
    assert auth_module.provisioning_rewrite_needed(f"    url: {target}\n    url: {target}\n", target)
    assert auth_module.provisioning_rewrite_needed("    url: http://x:8086\n", target)


@pytest.mark.parametrize(
    ("patterns", "excluded"),
    [
        ((".git", "*.pyc"), False),
        (("graphyard.yaml",), True),
        (("datasources/",), True),
        (("provisioning/datasources/*.yaml",), True),
        (("/datasources/",), False),
        (("/deploy/grafana/",), True),
        (("graphyard.yaml/",), False),
        # rsync's * stops at a slash, ** does not.
        (("/deploy/*/datasources/*.yaml",), False),
        (("deploy/**/graphyard.yaml",), True),
    ],
)
def test_rsync_excluded_asks_rsync(tmp_path: Path, patterns: tuple[str, ...], excluded: bool) -> None:
    from pathlib import PurePosixPath

    source = make_source(tmp_path)
    relative = PurePosixPath("deploy/grafana/provisioning/datasources/graphyard.yaml")

    assert stack_module.rsync_excluded(source, relative, patterns) is excluded


def test_an_excluded_provisioning_file_is_not_incoming(tmp_path: Path) -> None:
    cfg = stack_config(make_source(tmp_path))
    core = cfg.core.model_copy(update={"source_excludes": (*cfg.core.source_excludes, "datasources/graphyard.yaml")})

    assert stack_module.incoming_provisioning(cfg.model_copy(update={"core": core})) is None


def test_a_symlinked_provisioning_file_is_incoming(tmp_path: Path) -> None:
    """The sync copies symlinks (``-rl``); the exclusion check must list them too."""

    source = make_source(tmp_path)
    datasource = source / "deploy/grafana/provisioning/datasources/graphyard.yaml"
    (datasource.parent / "real.yaml").write_text(datasource.read_text().replace("graphyard-influxdb", "stale"))
    datasource.unlink()
    datasource.symlink_to("real.yaml")
    cfg = stack_config(source)

    assert stack_module.incoming_provisioning(cfg) == (datasource.parent / "real.yaml").read_text()
