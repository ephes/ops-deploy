"""graphyard auth bootstrap: the Graphyard login user, Grafana's admin password and datasource URL.

Port of the ``graphyard_auth_bootstrap_deploy`` role and
``playbooks/deploy-graphyard-auth-bootstrap.yml``. The role is a deploy-time
reconcile, not a one-time bootstrap: ``deploy-graphyard.yml`` runs it after
every stack deploy, and every step compares first and writes only on a
difference. This port keeps that and moves the comparisons to planning, so a
converged host sees no credential written, no container restarted and no
database row touched:

- the Django user (active staff superuser with the secret's password) is read
  through ``manage.py shell`` as the role reads it; the probe prints digests
  and the hash parameters, the password is checked on the controller;
- Grafana's admin password hash, the datasource URL and the login lockout
  rows are read from Grafana's database (read-only); the hash is compared on
  the controller the way the role compares it;
- the datasource provisioning file is checked with the role's own rewrite
  logic in a dry mode.

Credentials reach the host on stdin only. The Grafana admin password is reset
with ``grafana cli ... --password-from-stdin`` instead of the role's command
line argument. Only the shared Docker network mode is ported (the inventory's
setting); the container-IP fallback stays on Ansible.
"""

from __future__ import annotations

import base64
import hashlib
import shlex
from pathlib import PurePosixPath

from pydantic import field_validator
from pyinfra.api import DeployError, deploy
from pyinfra.operations import server

from ops_deploy.base import RoleConfig
from ops_deploy.core.config import UnixUser
from ops_deploy.core.secrets import SecretContent, SecretValues
from ops_deploy.helpers import mark_read_only
from ops_deploy.helpers.probes import probe as strict_probe
from ops_deploy.helpers.probes import verify_probe, when_present
from ops_deploy.ops import secret_stdin
from ops_deploy.services.graphyard._common import Port, Word, absolute, runuser

GRAFANA_HASH_ITERATIONS = 10000
GRAFANA_HASH_LENGTH = 50

# The role's ``manage.py shell`` script, unchanged; it reads the user name and
# password from the environment, which the deploy sets from stdin.
ENSURE_USER = """\
import os
from django.contrib.auth import get_user_model

username = os.environ["GRAPHYARD_BOOTSTRAP_USERNAME"]
password = os.environ["GRAPHYARD_BOOTSTRAP_PASSWORD"]
User = get_user_model()

user, created = User.objects.get_or_create(
    username=username,
    defaults={"is_active": True, "is_staff": True, "is_superuser": True},
)

changed = created
if not user.is_active:
    user.is_active = True
    changed = True
if not user.is_staff:
    user.is_staff = True
    changed = True
if not user.is_superuser:
    user.is_superuser = True
    changed = True
if not user.check_password(password):
    user.set_password(password)
    changed = True

if changed:
    user.save(update_fields=["password", "is_active", "is_staff", "is_superuser"])

print("CHANGED" if changed else "UNCHANGED")
"""
# Read-only: per user a digest of the name, the three flags, the hash
# parameters (algorithm, iterations, salt) and a digest of the stored hash.
USERS_PROBE = """\
import hashlib
from django.contrib.auth import get_user_model
digest = lambda text: hashlib.sha256(text.encode()).hexdigest()
for user in get_user_model().objects.all():
    parts = user.password.split("$")
    params = "$".join(parts[:3]) if len(parts) == 4 and all(parts) else "-"
    flags = [int(bool(flag)) for flag in (user.is_active, user.is_staff, user.is_superuser)]
    print("user", digest(user.get_username()), *flags, params, digest(user.password))
"""
# Read-only (stdlib, as root like the role): the admin user's salt and a
# digest of its hash, the datasource URL and the admin's lockout rows.
GRAFANA_PROBE = """\
import hashlib, sqlite3, sys
db = sqlite3.connect("file:" + sys.argv[1] + "?mode=ro", uri=True)
row = db.execute("select password, salt from user where login = ?", (sys.argv[2],)).fetchone()
print("admin", *(("-", "-") if row is None else (row[1], hashlib.sha256(row[0].encode()).hexdigest())))
row = db.execute("select url from data_source where uid = ?", (sys.argv[3],)).fetchone()
print("datasource", "-" if row is None else (row[0] or "''"))
print("lockouts", db.execute("select count(*) from login_attempt where username = ?", (sys.argv[2],)).fetchone()[0])
"""
# The role's MATCH check; the password comes on stdin.
GRAFANA_MATCH = """\
import hashlib, sqlite3, sys
password = sys.stdin.readline().rstrip("\\n").encode()
db = sqlite3.connect("file:" + sys.argv[1] + "?mode=ro", uri=True)
row = db.execute("select password, salt from user where login = ?", (sys.argv[2],)).fetchone()
if row is None:
    print("MISSING_USER")
    sys.exit(2)
stored_hash, salt = row
desired_hash = hashlib.pbkdf2_hmac("sha256", password, salt.encode(), 10000, dklen=50).hex()
print("MATCH" if stored_hash == desired_hash else "MISMATCH")
"""
# The role's datasource URL update, refusing a missing datasource as its read step does.
DATASOURCE_UPDATE = """\
import sqlite3, sys
db_path, uid, target_url = sys.argv[1:4]
conn = sqlite3.connect(db_path)
row = conn.execute("select url from data_source where uid = ?", (uid,)).fetchone()
if row is None:
    sys.exit("MISSING_DATASOURCE")
if (row[0] or "") != target_url:
    conn.execute("update data_source set url = ? where uid = ?", (target_url, uid))
    conn.commit()
"""
# The role's provisioning file rewrite; ``check`` only reports whether it would change.
PROVISIONING_URL = """\
import sys
from pathlib import Path

mode, path, target_url = sys.argv[1], Path(sys.argv[2]), sys.argv[3]
desired_line = f"    url: {target_url}\\n"

lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
out_lines = []
seen_url = False
changed = False

for line in lines:
  if line.lstrip().startswith("url:"):
    if not seen_url:
      out_lines.append(desired_line)
      seen_url = True
      if line != desired_line:
        changed = True
    else:
      changed = True
  else:
    out_lines.append(line)

if not seen_url:
  changed = True
  inserted = False
  for idx, line in enumerate(out_lines):
    if line.strip().startswith("access:"):
      out_lines.insert(idx + 1, desired_line)
      inserted = True
      break
  if not inserted:
    out_lines.append(desired_line)

if changed and mode == "apply":
  path.write_text("".join(out_lines), encoding="utf-8")

print("CHANGED" if changed else "UNCHANGED")
"""
LOCKOUT_CLEANUP = """\
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
conn.execute("delete from login_attempt where username = ?", (sys.argv[2],))
conn.commit()
"""


class GraphyardAuthConfig(RoleConfig):
    """The role's variables without the ``graphyard_auth_bootstrap_`` prefix.

    Credentials are deploy secrets: ``django_bootstrap_username``,
    ``django_bootstrap_password`` and ``grafana_admin_password``.
    """

    system_user: UnixUser = "graphyard"
    # The system user's home (``HOME`` for its commands, as ``become_user`` sets it).
    home: PurePosixPath = PurePosixPath("/opt/apps/graphyard")
    python: PurePosixPath = PurePosixPath("/opt/apps/graphyard/site/.venv/bin/python")
    manage_py: PurePosixPath = PurePosixPath("/opt/apps/graphyard/site/src/django/manage.py")
    workdir: PurePosixPath = PurePosixPath("/opt/apps/graphyard/site/src/django")
    grafana_container_name: Word = "graphyard-grafana"
    grafana_admin_user: Word = "admin"
    grafana_cli_bin: PurePosixPath = PurePosixPath("/usr/share/grafana/bin/grafana")
    grafana_homepath: PurePosixPath = PurePosixPath("/usr/share/grafana")
    grafana_db_path: PurePosixPath = PurePosixPath("/var/lib/graphyard/grafana/grafana.db")
    grafana_datasource_provisioning_path: PurePosixPath = PurePosixPath(
        "/opt/apps/graphyard/site/deploy/grafana/provisioning/datasources/graphyard.yaml"
    )
    grafana_datasource_uid: Word = "graphyard-influxdb"
    # The Docker network Grafana reaches InfluxDB on (the role's shared-network
    # mode; its container-IP fallback for an empty name is not ported).
    grafana_shared_network_name: Word
    influx_container_name: Word = "graphyard-influxdb"
    influx_container_port: Port = 8086

    @field_validator(
        "home",
        "python",
        "manage_py",
        "workdir",
        "grafana_cli_bin",
        "grafana_homepath",
        "grafana_db_path",
        "grafana_datasource_provisioning_path",
    )
    @classmethod
    def _absolute(cls, value: PurePosixPath) -> PurePosixPath:
        return absolute(value)

    @property
    def target_url(self) -> str:
        return f"http://{self.influx_container_name}:{self.influx_container_port}"


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def check_secrets(secrets: SecretValues) -> None:
    for key in ("django_bootstrap_username", "django_bootstrap_password", "grafana_admin_password"):
        value = secrets.get(key, "")
        if not value or value == "CHANGEME":
            raise ValueError(f"secret {key} must be set and not a placeholder")
        if any(c in value for c in "\r\n"):
            raise ValueError(f"secret {key} must be a single line")


def django_hash(password: str, params: str) -> str | None:
    """Django's encoded PBKDF2-SHA256 hash of ``password`` with stored ``algorithm$iterations$salt``."""

    algorithm, _, rest = params.partition("$")
    iterations, _, salt = rest.partition("$")
    if algorithm != "pbkdf2_sha256" or not iterations.isdigit() or not salt:
        return None
    raw = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(iterations))
    return f"{algorithm}${int(iterations)}${salt}${base64.b64encode(raw).decode().strip()}"


def django_user_current(probe_output: str, username: str, password: str) -> bool:
    """Whether the probed users include ``username`` as an active staff superuser with ``password``."""

    for line in probe_output.splitlines():
        parts = line.split()
        if len(parts) != 7 or parts[0] != "user" or parts[1] != _digest(username):
            continue
        encoded = django_hash(password, parts[5])
        return parts[2:5] == ["1", "1", "1"] and encoded is not None and _digest(encoded) == parts[6]
    return False


def grafana_state(probe_output: str) -> dict[str, list[str]]:
    return {line.split()[0]: line.split()[1:] for line in probe_output.splitlines() if line.split()}


def grafana_password_matches(admin: list[str], password: str) -> bool:
    """The role's MATCH: PBKDF2-SHA256, 10000 rounds, 50 bytes, hex; compared by digest."""

    if len(admin) != 2 or admin[0] == "-":
        return False
    salt, stored = admin
    desired = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), GRAFANA_HASH_ITERATIONS, dklen=GRAFANA_HASH_LENGTH
    ).hex()
    return _digest(desired) == stored


def _python_script(script: str, *args: str) -> str:
    return shlex.join(["python3", "-I", "-c", script, *args])


def _django_user(cfg: GraphyardAuthConfig, secrets: SecretValues) -> None:
    home = {"HOME": str(cfg.home)}
    workdir = shlex.quote(str(cfg.workdir))
    listing = f"cd {workdir} && " + runuser(
        cfg.system_user, [str(cfg.python), str(cfg.manage_py), "shell", "-c", USERS_PROBE], env=home
    )
    check = when_present([cfg.python, cfg.manage_py], listing, otherwise="")
    users = strict_probe(check, name="graphyard bootstrap user")
    username, password = secrets["django_bootstrap_username"], secrets["django_bootstrap_password"]
    current = users is not None and django_user_current(users, username, password)
    script = (
        "IFS= read -r GRAPHYARD_BOOTSTRAP_USERNAME; IFS= read -r GRAPHYARD_BOOTSTRAP_PASSWORD; "
        "export GRAPHYARD_BOOTSTRAP_USERNAME GRAPHYARD_BOOTSTRAP_PASSWORD; "
        f"exec {shlex.join([str(cfg.python), str(cfg.manage_py), 'shell', '-c', ENSURE_USER])}"
    )
    if not current:
        secret_stdin(
            name="Ensure the Graphyard bootstrap Django user is present with the expected password",
            command=f"cd {workdir} && {runuser(cfg.system_user, ['sh', '-c', script], env=home)} >/dev/null",
            content=SecretContent(f"{username}\n{password}\n"),
        )
    if users is None:
        verify_probe(check, name="graphyard bootstrap user")


def _network(cfg: GraphyardAuthConfig) -> None:
    network = cfg.grafana_shared_network_name
    attached = f'{{{{if index .NetworkSettings.Networks "{network}"}}}}present{{{{end}}}}'
    grafana, influx = shlex.quote(cfg.grafana_container_name), shlex.quote(cfg.influx_container_name)
    mark_read_only(
        server.shell(
            name="Require Grafana on the shared network",
            commands=[
                f'[ "$(docker inspect --format {shlex.quote(attached)} {grafana})" = present ] || '
                f"{{ echo 'Grafana container {cfg.grafana_container_name} is not attached to Docker network "
                f"{network}' >&2; exit 1; }}"
            ],
        )
    )
    inspect = f"docker inspect --format {shlex.quote(attached)} {influx}"
    state = strict_probe(
        f"if docker inspect {influx} >/dev/null 2>&1; then {inspect}; fi", name="InfluxDB on the shared network"
    )
    if state is None or state.strip() != "present":
        server.shell(
            name="Attach InfluxDB to the shared network",
            commands=[
                f'[ "$(docker inspect --format {shlex.quote(attached)} {influx})" = present ] || '
                f"docker network connect {shlex.quote(network)} {influx}"
            ],
        )


def auth_steps(cfg: GraphyardAuthConfig, secrets: SecretValues, *, incoming: str | None = None) -> None:
    """``incoming``: the provisioning file a source sync of the same run installs (the stack)."""

    check_secrets(secrets)
    for required, what in ((cfg.manage_py, "manage.py"), (cfg.python, "python")):
        mark_read_only(
            server.shell(
                name=f"Require graphyard {what}",
                commands=[
                    f"test -e {shlex.quote(str(required))} || {{ echo 'Graphyard manage.py/python paths do not exist. "
                    "Ensure graphyard is deployed before auth bootstrap.' >&2; exit 1; }"
                ],
            )
        )
    _django_user(cfg, secrets)

    grafana = shlex.quote(cfg.grafana_container_name)
    mark_read_only(
        server.shell(
            name="Require the Graphyard Grafana container to be running",
            commands=[
                f'[ "$(docker inspect --format {{{{.State.Running}}}} {grafana})" = true ] || '
                f"{{ echo 'Grafana container {cfg.grafana_container_name} is not running' >&2; exit 1; }}"
            ],
        )
    )
    _network(cfg)
    db, provisioning = str(cfg.grafana_db_path), str(cfg.grafana_datasource_provisioning_path)
    for path, what in ((db, "Grafana database"), (provisioning, "Grafana datasource provisioning file")):
        mark_read_only(
            server.shell(
                name=f"Require the {what}",
                commands=[f"test -e {shlex.quote(path)} || {{ echo '{what} {path} does not exist' >&2; exit 1; }}"],
            )
        )
    _grafana(cfg, secrets, incoming)


def provisioning_rewrite_needed(text: str, target: str) -> bool:
    """Whether the role's provisioning rewrite would change ``text`` (one ``url:`` line, the target)."""

    urls = [line for line in text.splitlines(keepends=True) if line.lstrip().startswith("url:")]
    return urls != [f"    url: {target}\n"]


def _grafana(cfg: GraphyardAuthConfig, secrets: SecretValues, incoming: str | None) -> None:
    db, provisioning = str(cfg.grafana_db_path), str(cfg.grafana_datasource_provisioning_path)
    grafana = shlex.quote(cfg.grafana_container_name)
    target = cfg.target_url
    user, password = cfg.grafana_admin_user, secrets["grafana_admin_password"]

    listing = _python_script(GRAFANA_PROBE, db, user, cfg.grafana_datasource_uid)
    found = strict_probe(when_present([db], listing, otherwise="absent"), name="Grafana admin and datasource")
    state = grafana_state(found or "")
    known = found is not None and "admin" in state
    if known and (state["admin"][:1] == ["-"] or state.get("datasource") == ["-"]):
        missing = f"user {user}" if state["admin"][:1] == ["-"] else f"datasource {cfg.grafana_datasource_uid}"
        raise DeployError(f"Grafana has no {missing}")
    password_matches = known and grafana_password_matches(state["admin"], password)
    url_current = known and state.get("datasource") == [target]
    lockouts = state.get("lockouts", ["?"]) if known else ["?"]
    file_state = strict_probe(
        when_present([provisioning], _python_script(PROVISIONING_URL, "check", provisioning, target), otherwise="?"),
        name="Grafana datasource provisioning file",
    )

    if not url_current:
        server.shell(
            name="Update the Grafana datasource URL when it does not match the target",
            commands=[_python_script(DATASOURCE_UPDATE, db, cfg.grafana_datasource_uid, target)],
        )
    # A file the source sync is about to install needs the rewrite again (the role's
    # sync and rewrite take turns on every stack run then, as here).
    file_planned = (
        file_state is None
        or file_state.strip() != "UNCHANGED"
        or (incoming is not None and provisioning_rewrite_needed(incoming, target))
    )
    if file_planned:
        server.shell(
            name="Update the Grafana datasource provisioning URL when it does not match the target",
            commands=[_python_script(PROVISIONING_URL, "apply", provisioning, target) + " >/dev/null"],
        )
    if not url_current or file_planned:
        server.shell(
            name="Restart Grafana for the new datasource URL", commands=[f"docker restart {grafana} >/dev/null"]
        )
        mark_read_only(
            server.shell(
                name="Wait for the Grafana API after the restart",
                commands=[
                    f"for i in $(seq 1 15); do docker exec {grafana} sh -lc "
                    "'curl -fsS --max-time 5 http://127.0.0.1:3000/api/health >/dev/null' && exit 0; sleep 2; done; "
                    "echo 'Grafana did not come back' >&2; exit 1"
                ],
            )
        )
    mark_read_only(
        server.shell(
            name="Verify Grafana reaches the InfluxDB ping endpoint",
            commands=[
                f"docker exec {grafana} sh -lc {shlex.quote(f'curl -fsS --max-time 5 -I {target}/ping >/dev/null')}"
            ],
        )
    )
    _admin_password(cfg, password, password_matches)
    if lockouts != ["0"]:
        server.shell(
            name="Clear Grafana login lockout rows for the admin user",
            commands=[_python_script(LOCKOUT_CLEANUP, db, user)],
        )
    basic = base64.b64encode(f"{user}:{password}".encode()).decode()
    health = f"http://127.0.0.1:3000/api/datasources/uid/{cfg.grafana_datasource_uid}/health"
    mark_read_only(
        secret_stdin(
            name="Verify the Grafana datasource health through the API",
            command=(
                "IFS= read -r basic; out=$(printf 'Authorization: Basic %s\\n' \"$basic\" | "
                f"docker exec -i {grafana} curl -fsS --max-time 10 -H @- {shlex.quote(health)}) || exit 1; "
                'case "$out" in *\'"status":"OK"\'*) ;; '
                "*) echo 'Grafana datasource health is not OK' >&2; exit 1 ;; esac"
            ),
            content=SecretContent(f"{basic}\n"),
        )
    )


def _admin_password(cfg: GraphyardAuthConfig, password: str, matches: bool) -> None:
    """Reset Grafana's admin password when its hash does not match (checked again on the host first)."""

    db, user = str(cfg.grafana_db_path), cfg.grafana_admin_user
    grafana = shlex.quote(cfg.grafana_container_name)
    check = f"printf '%s\\n' \"$password\" | {_python_script(GRAFANA_MATCH, db, user)}"
    reset = shlex.join(
        [
            str(cfg.grafana_cli_bin),
            "cli",
            "--homepath",
            str(cfg.grafana_homepath),
            "admin",
            "reset-admin-password",
            "--password-from-stdin",
        ]
    )
    if matches:
        return
    secret_stdin(
        name="Reset the Grafana admin password when it does not match",
        command=(
            f'IFS= read -r password; state=$({check}); [ "$state" = MATCH ] && exit 0; '
            f'[ "$state" = MISMATCH ] || {{ echo "Grafana admin check: $state" >&2; exit 1; }}; '
            f"printf '%s\\n' \"$password\" | docker exec -i {grafana} {reset} >/dev/null"
        ),
        content=SecretContent(f"{password}\n"),
    )
    mark_read_only(
        secret_stdin(
            name="Verify the Grafana admin password hash",
            command=(
                f'IFS= read -r password; for i in 1 2 3 4 5; do [ "$({check})" = MATCH ] && exit 0; sleep 1; done; '
                "echo 'Grafana admin password hash does not match' >&2; exit 1"
            ),
            content=SecretContent(f"{password}\n"),
        )
    )


@deploy("Deploy graphyard auth bootstrap")
def deploy_graphyard_auth(cfg: GraphyardAuthConfig, secrets: SecretValues) -> None:
    auth_steps(cfg, secrets)
