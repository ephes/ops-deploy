"""Deploy chesslab to the smoke target: database guard, real end state, converged rerun.

Needs a chess (chesslab) checkout: ``CHESSLAB_SOURCE``, else ``$PROJECTS_ROOT/chess``.
Its committed ``HEAD`` is exported, so local databases and uncommitted files
never reach the VM. The Echoport/Nyxmon wiring is off here (neither runs on the
VM); the fake-connector tests cover it.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import pytest

from ops_deploy.core.rsync import subprocess_rsync_runner
from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.ops.sync_tree import rsync_argv
from ops_deploy.services._service_home import remote_rsync_command
from ops_deploy.services.chesslab import ChesslabConfig, deploy_chesslab
from ops_deploy.testing import SshRun, run_deploy_ssh
from tests.smoke.conftest import TIMINGS, SmokeHost

HOST = "chess.example.invalid"
HOME = "/home/chesslab"
DB = f"{HOME}/data/chess.db"


def chesslab_checkout() -> Path | None:
    configured = os.environ.get("CHESSLAB_SOURCE")
    if configured:
        return Path(configured)
    root = os.environ.get("PROJECTS_ROOT")
    return Path(root) / "chess" if root else None


@dataclass(frozen=True)
class Deployed:
    cfg: ChesslabConfig
    secrets: SecretValues
    guarded: SshRun
    first: SshRun
    second: SshRun
    fresh_clone: SshRun


@pytest.fixture(scope="module")
def deployed(smoke_host: SmokeHost, tmp_path_factory: pytest.TempPathFactory) -> Deployed:
    checkout = chesslab_checkout()
    if checkout is None or not (checkout / ".git").exists():
        pytest.skip("no chess checkout (set CHESSLAB_SOURCE or PROJECTS_ROOT)")
    if smoke_host.out(f"test -e {DB} && echo present || true") == "present":
        pytest.skip(f"{DB} already exists on the smoke target; the guard check needs a host without it")
    source = tmp_path_factory.mktemp("chess")
    archive = subprocess.run(["git", "-C", str(checkout), "archive", "HEAD"], check=True, capture_output=True)
    subprocess.run(["tar", "-x", "-C", str(source)], input=archive.stdout, check=True)
    ref = SecretRef("secrets/smoke/chesslab.yml")
    cfg = ChesslabConfig(
        source_path=source,
        secrets=ref,
        traefik_host=HOST,
        django_allowed_hosts=("127.0.0.1", "localhost", HOST),
        django_csrf_trusted_origins=(f"https://{HOST}",),
    )
    users = [{"username": "smoke-trainer", "password": f"smoke-user-{secrets.token_hex(12)}", "owner": "Smoke_Owner"}]
    values = SecretValues(
        ref,
        {
            "session_secret": f'smoke-key-{secrets.token_hex(24)}$`"x',
            "users": json.dumps(users),
            "basic_auth_password": f"smoke-pw-{secrets.token_hex(12)}",
        },
    )

    def deploy(label: str, config: ChesslabConfig) -> SshRun:
        run = run_deploy_ssh(deploy_chesslab, config, values, host_name=smoke_host.name, host_data=smoke_host.host_data)
        TIMINGS[f"chesslab {label} run"] = run.seconds
        return run

    # Like the role: no database, no deploy (the site is left alone).
    guarded = deploy("guard", cfg)
    assert not guarded.succeeded
    # The database comes from elsewhere in production; here an empty SQLite file.
    smoke_host.run(f"runuser -u chesslab -- touch {DB}")
    fresh = tmp_path_factory.mktemp("chess-fresh")
    subprocess.run(["tar", "-x", "-m", "-C", str(fresh)], input=archive.stdout, check=True)
    runs = []
    for label, config in (
        ("first", cfg),
        ("second", cfg),
        ("fresh clone", cfg.model_copy(update={"source_path": fresh})),
    ):
        run = deploy(label, config)
        assert run.succeeded, (label, run.error, [op for op in run.ops if not op.succeeded])
        runs.append(run)
    return Deployed(cfg, values, guarded, *runs)


def test_missing_database_stops_the_deploy(deployed: Deployed) -> None:
    assert not any(name.endswith("| Sync chesslab source") for name in deployed.guarded.changed_ops)


def test_second_run_has_no_mutating_changes(deployed: Deployed) -> None:
    assert any(name.endswith("| Write .env") for name in deployed.first.changed_ops)
    assert deployed.second.mutating_changed_ops == []
    assert all(op.succeeded for op in deployed.second.ops if op.read_only)


def test_fresh_clone_of_unchanged_code_is_a_noop(deployed: Deployed) -> None:
    assert deployed.fresh_clone.mutating_changed_ops == []


def test_service_runs_and_is_healthy(smoke_host: SmokeHost, deployed: Deployed) -> None:
    assert smoke_host.out("systemctl is-active chesslab") == "active"
    assert smoke_host.out("systemctl is-enabled chesslab") == "enabled"
    assert '"ok": true' in smoke_host.out("curl -s http://127.0.0.1:10019/healthz")


def test_env_is_private_and_users_exist(smoke_host: SmokeHost, deployed: Deployed) -> None:
    assert smoke_host.out(f"stat -c '%a %U %G' {HOME}/site/.env") == "600 chesslab chesslab"
    assert smoke_host.out(f"stat -c '%a %U %G' {HOME}/.ops-deploy-users") == "600 root root"
    query = "select u.is_superuser, p.lichess_username from auth_user u join accounts_profile p on p.user_id = u.id"
    assert smoke_host.out(f"sqlite3 -readonly {DB} '{query}'") == "1|smoke_owner"


def test_traefik_serves_internal_clients_and_guards_the_rest(smoke_host: SmokeHost, deployed: Deployed) -> None:
    curl = f"curl -ks -o /dev/null -w '%{{http_code}}' --resolve {HOST}:443:127.0.0.1 https://{HOST}/healthz"
    # 127.0.0.1/32 is one of chesslab's internal ranges: no auth from the host itself.
    assert smoke_host.out(curl) == "200"
    route = smoke_host.out("cat /etc/traefik/dynamic/chesslab.yml")
    assert "chesslab-ext:" in route
    assert '- "admin:$2y$05$' in route


def test_no_secret_on_disk_outside_its_files(smoke_host: SmokeHost, deployed: Deployed) -> None:
    for key, value in deployed.secrets.items():
        if key == "users":
            continue
        found = smoke_host.run(
            f"grep -rlF --no-messages -f - /tmp /var/tmp /dev/shm /root {HOME} --exclude=.env --exclude='chess.db*' "
            "|| true",
            input=f"{value}\n",
        )
        assert found.stdout.strip() == "", key
    password = json.loads(deployed.secrets["users"])[0]["password"]
    found = smoke_host.run(f"grep -rlF --no-messages -f - /tmp /var/tmp /dev/shm /root {HOME} || true", input=password)
    assert found.stdout.strip() == ""
    assert deployed.secrets["basic_auth_password"] not in smoke_host.out("cat /etc/traefik/dynamic/chesslab.yml")


def test_port_preflight_refuses_another_listener(smoke_host: SmokeHost, deployed: Deployed) -> None:
    smoke_host.run("systemctl stop chesslab")
    squatter = "systemd-run --unit=chesslab-port-squatter python3 -m http.server 10019 --bind 127.0.0.1"
    smoke_host.run(f"{squatter} && sleep 1")
    try:
        run = run_deploy_ssh(
            deploy_chesslab,
            deployed.cfg,
            deployed.secrets,
            host_name=smoke_host.name,
            host_data=smoke_host.host_data,
        )
        assert not run.succeeded
        failed = [op.name for op in run.ops if not op.succeeded]
        assert failed
        assert failed[0] == "Deploy chesslab | Port preflight tcp/10019"
        assert run.mutating_changed_ops == []
    finally:
        smoke_host.run("systemctl stop chesslab-port-squatter; systemctl start chesslab", check=False)
    assert smoke_host.out("systemctl is-active chesslab") == "active"


# --- root writes in service homes (docs/plans/root-writes-in-service-homes.md) ---
#
# The cases the pilot plan asks for. They run after the tests above and leave
# chesslab deployed and healthy.

SITE = f"{HOME}/site"
# A directory the service must never be able to change: root's, closed to others.
ROOT_TARGET = "/root/chesslab-redirect-target"
# One the service owns: here only the guard stands between the link and a transfer.
OWN_TARGET = f"{HOME}/redirect-target"


def _redeploy(smoke_host: SmokeHost, deployed: Deployed, cfg: ChesslabConfig | None = None) -> SshRun:
    return run_deploy_ssh(
        deploy_chesslab,
        cfg or deployed.cfg,
        deployed.secrets,
        host_name=smoke_host.name,
        host_data=smoke_host.host_data,
    )


def _listing(smoke_host: SmokeHost, path: str) -> str:
    """Every entry below ``path`` with owner, group, mode, type, link target and content hash."""

    return smoke_host.out(
        f"find {path} -printf '%p %u %g %m %y %l\\n' | sort; find {path} -type f -exec sha256sum {{}} + | sort -k2"
    )


def _plant_target(smoke_host: SmokeHost, path: str, owner: str) -> str:
    smoke_host.run(
        f"rm -rf {path} && mkdir -m 0755 {path} {path}/sub && echo marker > {path}/marker && "
        f"echo inner > {path}/sub/inner && ln -s marker {path}/link && chown -hR {owner}:{owner} {path}"
    )
    return _listing(smoke_host, path)


def test_every_command_runs_with_the_accounts_own_credentials(smoke_host: SmokeHost, deployed: Deployed) -> None:
    identity = smoke_host.out("cd / && runuser -u chesslab -- id")
    uid, gid = smoke_host.out("id -u chesslab"), smoke_host.out("id -g chesslab")
    assert identity == f"uid={uid}(chesslab) gid={gid}(chesslab) groups={gid}(chesslab)"
    # What the path check of the deploy relies on.
    assert smoke_host.out("stat -c '%U %a %F' / /home") == "root 755 directory\nroot 755 directory"
    assert smoke_host.out(f"stat -c '%U %G %F' {HOME} {SITE} {HOME}/data") == "\n".join(
        ["chesslab chesslab directory"] * 3
    )
    foreign = f"find {SITE} {HOME}/data -xdev \\( ! -user chesslab -o ! -group chesslab -o -type d -perm -2000 \\)"
    assert smoke_host.out(foreign) == ""


def test_verify_only_passes_on_the_converged_host_and_changes_nothing(
    smoke_host: SmokeHost, deployed: Deployed
) -> None:
    before = _listing(
        smoke_host, f"{HOME} -path {SITE}/.venv -prune -o -name __pycache__ -prune -o ! -name 'chess.db-*'"
    )
    started = smoke_host.out("systemctl show -p ActiveEnterTimestamp,NRestarts chesslab traefik")

    run = _redeploy(smoke_host, deployed, deployed.cfg.model_copy(update={"verify_only": True}))

    assert run.succeeded, (run.error, [op for op in run.ops if not op.succeeded])
    assert run.mutating_changed_ops == []
    assert [op.name.split(" | ")[1] for op in run.ops if op.read_only] == [
        "Check the path to /home/chesslab",
        "Audit ownership below the chesslab home",
        "Show the identity of chesslab",
        "Check chesslab database",
    ]
    assert (
        _listing(smoke_host, f"{HOME} -path {SITE}/.venv -prune -o -name __pycache__ -prune -o ! -name 'chess.db-*'")
        == before
    )
    assert smoke_host.out("systemctl show -p ActiveEnterTimestamp,NRestarts chesslab traefik") == started


def test_verify_only_stops_on_a_changed_source_without_transferring(
    smoke_host: SmokeHost, deployed: Deployed, tmp_path: Path
) -> None:
    source = tmp_path / "changed"
    subprocess.run(["cp", "-R", str(deployed.cfg.source_path), str(source)], check=True)
    (source / "verify-only-marker.txt").write_text("must not arrive\n")

    run = _redeploy(smoke_host, deployed, deployed.cfg.model_copy(update={"verify_only": True, "source_path": source}))

    assert not run.succeeded
    assert "verify_only: chesslab is not converged" in str(run.error)
    assert smoke_host.out(f"test -e {SITE}/verify-only-marker.txt && echo present || true") == ""


def test_changed_source_is_received_as_the_service_user(
    smoke_host: SmokeHost, deployed: Deployed, tmp_path: Path
) -> None:
    source = tmp_path / "changed"
    subprocess.run(["cp", "-R", str(deployed.cfg.source_path), str(source)], check=True)
    (source / "root-writes-marker.txt").write_text("received as chesslab\n")
    (source / "root-writes-dir").mkdir()
    (source / "root-writes-dir" / "inner.txt").write_text("inner\n")
    changed = deployed.cfg.model_copy(update={"source_path": source})

    run = _redeploy(smoke_host, deployed, changed)

    assert run.succeeded, (run.error, [op for op in run.ops if not op.succeeded])
    assert any(name.endswith("| Sync chesslab source") for name in run.mutating_changed_ops)
    # No --chown any more: a root receiver would have left these root-owned.
    owners = smoke_host.out(
        f"stat -c '%U %G' {SITE}/root-writes-marker.txt {SITE}/root-writes-dir {SITE}/root-writes-dir/inner.txt"
    )
    assert owners == "\n".join(["chesslab chesslab"] * 3)
    assert smoke_host.out(f"find {SITE} -xdev ! -user chesslab") == ""
    assert _redeploy(smoke_host, deployed, changed).mutating_changed_ops == []
    # Back to the original source: the sync deletes as the user, too.
    back = _redeploy(smoke_host, deployed)
    assert back.succeeded, back.error
    assert smoke_host.out(f"test -e {SITE}/root-writes-dir && echo present || true") == ""
    assert '"ok": true' in smoke_host.out("curl -s --retry 10 --retry-connrefused http://127.0.0.1:10019/healthz")


def test_the_accounts_sqliterc_is_not_run_by_the_probe(smoke_host: SmokeHost, deployed: Deployed) -> None:
    ran = f"{HOME}/sqliterc-ran"
    smoke_host.run(
        f"printf '.shell touch {ran}\\n' > {HOME}/.sqliterc && chown chesslab:chesslab {HOME}/.sqliterc && rm -f {ran}"
    )
    try:
        # The control: this account's sqlite3 does run the file without -init.
        smoke_host.run(f"cd / && runuser -u chesslab -- env HOME={HOME} sqlite3 -readonly {DB} 'select 1'", check=False)
        assert smoke_host.out(f"test -e {ran} && echo ran || true") == "ran"
        smoke_host.run(f"rm -f {ran}")

        run = _redeploy(smoke_host, deployed)

        assert run.succeeded, run.error
        assert run.mutating_changed_ops == []
        assert smoke_host.out(f"test -e {ran} && echo ran || true") == ""
    finally:
        smoke_host.run(f"rm -f {HOME}/.sqliterc {ran}")


@pytest.fixture
def site_aside(smoke_host: SmokeHost, deployed: Deployed) -> Iterator[str]:
    """Move the real site away for a test and put it back afterwards, whatever happened."""

    aside = f"{HOME}/site.real"
    smoke_host.run(f"systemctl stop chesslab; systemctl reset-failed chesslab; mv {SITE} {aside}")
    try:
        yield aside
    finally:
        smoke_host.run(
            f"if [ -L {SITE} ]; then rm -f {SITE}; fi; "
            f"if [ -d {aside} ]; then rm -rf {SITE} && mv {aside} {SITE}; fi; "
            f"rm -rf {ROOT_TARGET} {OWN_TARGET}; systemctl reset-failed chesslab; systemctl start chesslab"
        )


def test_redirected_site_fails_the_deploy_and_leaves_the_target_alone(
    smoke_host: SmokeHost, deployed: Deployed, site_aside: str, tmp_path: Path
) -> None:
    before = _plant_target(smoke_host, ROOT_TARGET, "root")
    smoke_host.run(f"ln -s {ROOT_TARGET} {SITE} && chown -h chesslab:chesslab {SITE}")
    source = tmp_path / "changed"
    subprocess.run(["cp", "-R", str(deployed.cfg.source_path), str(source)], check=True)
    (source / "redirected.txt").write_text("must not arrive\n")

    run = _redeploy(smoke_host, deployed, deployed.cfg.model_copy(update={"source_path": source}))

    assert not run.succeeded
    assert _listing(smoke_host, ROOT_TARGET) == before
    assert smoke_host.out(f"readlink {SITE}") == ROOT_TARGET


@pytest.mark.parametrize(("target", "owner"), [(ROOT_TARGET, "root"), (OWN_TARGET, "chesslab")])
@pytest.mark.parametrize("dry_run", [True, False])
def test_redirected_destination_is_refused_by_the_receiver_itself(
    smoke_host: SmokeHost,
    deployed: Deployed,
    site_aside: str,
    tmp_path: Path,
    target: str,
    owner: str,
    dry_run: bool,
) -> None:
    # sync_tree's own rsync command, without the plan-time refusal in front of
    # it: the remote side must not change the link's target. For root's
    # directory the user's rights alone must be enough; for the user's own the
    # guard refuses the link.
    before = _plant_target(smoke_host, target, owner)
    smoke_host.run(f"ln -s {target} {SITE} && chown -h chesslab:chesslab {SITE}")
    source = tmp_path / "source"
    source.mkdir()
    (source / "redirected.txt").write_text("must not arrive\n")
    # The connection sync_tree builds from the same host data.
    ssh_command = [
        "ssh",
        "-p",
        str(smoke_host.port),
        "-i",
        smoke_host.key,
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        f"UserKnownHostsFile={smoke_host.known_hosts}",
        "-o",
        "StrictHostKeyChecking=yes",
    ]
    argv = rsync_argv(
        source, PurePosixPath(SITE), f"root@{smoke_host.hostname}", ssh_command=ssh_command, dry_run=dry_run
    )
    argv.insert(argv.index("-e"), "--rsync-path=" + remote_rsync_command("chesslab", PurePosixPath(SITE)))

    result = subprocess_rsync_runner(argv)

    assert result.returncode != 0, result.stdout
    assert _listing(smoke_host, target) == before


def test_guard_alone_does_not_protect_roots_directory_the_uid_does(
    smoke_host: SmokeHost, deployed: Deployed, site_aside: str
) -> None:
    # The boundary is the receiver's UID, not the guard: as chesslab, writing
    # through the link into root's directory fails even with no check at all.
    before = _plant_target(smoke_host, ROOT_TARGET, "root")
    smoke_host.run(f"ln -s {ROOT_TARGET} {SITE} && chown -h chesslab:chesslab {SITE}")

    attempt = smoke_host.run(
        f"cd / && runuser -u chesslab -- sh -c 'echo x > {SITE}/planted; rm -f {SITE}/marker; chmod 777 {SITE}/'",
        check=False,
    )

    assert attempt.returncode != 0
    assert _listing(smoke_host, ROOT_TARGET) == before


def test_missing_site_is_recreated_by_the_service_user(smoke_host: SmokeHost, deployed: Deployed) -> None:
    # The tests above stopped and started the unit in quick succession: clear systemd's start limit.
    smoke_host.run(f"systemctl stop chesslab && systemctl reset-failed chesslab; rm -rf {SITE}")

    run = _redeploy(smoke_host, deployed)

    assert run.succeeded, (run.error, [op for op in run.ops if not op.succeeded])
    assert smoke_host.out(f"stat -c '%U %G %a %F' {SITE}") == "chesslab chesslab 755 directory"
    assert smoke_host.out(f"find {SITE} -xdev ! -user chesslab") == ""
    assert smoke_host.out("systemctl is-active chesslab") == "active"
    assert '"ok": true' in smoke_host.out("curl -s --retry 10 --retry-connrefused http://127.0.0.1:10019/healthz")
    assert _redeploy(smoke_host, deployed).mutating_changed_ops == []
