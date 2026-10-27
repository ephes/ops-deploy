"""Generated remote commands, executed by real shells.

pyinfra wraps each command in ``sh -c '...'`` and sshd hands that line to the
login shell of the deploy user. On macmini root's login shell is fish, which
(unlike sh and bash) treats ``\\\\`` and ``\\'`` inside single quotes as escapes:
a backslash pair in a command reaches ``sh`` halved. These tests run the
commands the way the host does, through bash and through fish, instead of
comparing strings.
"""

import hashlib
import json
import os
import shlex
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path, PurePosixPath

import pytest
from pyinfra.api import deploy
from pyinfra.api.command import StringCommand
from pyinfra.connectors.util import make_unix_command

from ops_deploy.core import SecretContent, SecretRef, SecretValues
from ops_deploy.helpers.probes import (
    FAILED,
    last_line,
    migrations_state,
    probe_command,
    probe_output,
    uv_sync_state,
    verify_probe,
    when_present,
)
from ops_deploy.ops.secret_file import encode_payload, install_command
from ops_deploy.services.chesslab import ChesslabConfig
from ops_deploy.services.chesslab.deploy import _users_probe as _chesslab_users_probe
from ops_deploy.services.django_site import DjangoSiteConfig
from ops_deploy.services.django_site import deploy as django_site_deploy
from ops_deploy.services.django_site.deploy import markers_command
from ops_deploy.services.django_site.django import manage_script, site_shell
from ops_deploy.services.django_site.render import render as render_django_site
from ops_deploy.services.django_site.render import render_env as django_site_env
from ops_deploy.services.weeknotes_home import WeeknotesHomeConfig
from ops_deploy.services.weeknotes_home.deploy import FILES, _site_manage, render_env
from ops_deploy.testing import fish_unsafe, run_deploy_fake
from tests.chesslab_fixtures import make_source as make_chesslab_source
from tests.django_site_fixtures import site_config
from tests.django_site_fixtures import values as django_site_values
from tests.marina_fixtures import make_source as make_marina_source
from tests.weeknotes_home_fixtures import make_source

SRC = Path(__file__).resolve().parents[1] / "src" / "ops_deploy"
LOGIN_SHELLS = ["bash", pytest.param("fish", marks=pytest.mark.skipif(not shutil.which("fish"), reason="no fish"))]
# Quotes, backslash pairs, a backslash before a quote, $ and backticks.
TRICKY = 'a"b\\\\c\\"d\\e\'f$HOME`x`\\'


def run_remote(command: str, login_shell: str, path: str, **env_vars: str) -> subprocess.CompletedProcess[str]:
    """Run ``command`` as sshd does: the login shell gets pyinfra's ``sh -c`` line."""

    line = make_unix_command(StringCommand(command)).get_raw_value()
    env = {**os.environ, "PATH": path, **env_vars}
    return subprocess.run([login_shell, "-c", line], capture_output=True, text=True, env=env, check=False)


@pytest.fixture
def fake_runuser(tmp_path: Path) -> str:
    """A PATH whose ``runuser -u USER -- ARGV`` just runs ARGV (no user switch)."""

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    runuser = bin_dir / "runuser"
    runuser.write_text('#!/bin/sh\n[ "$1" = -u ] && [ "$3" = -- ] || exit 97\nshift 3\nexec "$@"\n')
    runuser.chmod(0o755)
    return f"{bin_dir}:{os.environ['PATH']}"


@pytest.mark.parametrize("login_shell", LOGIN_SHELLS)
def test_weeknotes_manage_command_loads_tricky_env_values(tmp_path: Path, fake_runuser: str, login_shell: str) -> None:
    home = tmp_path / "home"
    cfg = WeeknotesHomeConfig(
        source_path=make_source(tmp_path),
        secrets=SecretRef("secrets/prod/weeknotes_home.yml"),
        traefik_host="weeknotes.example.com",
        home=home,
        site_path=home / "site",
    )
    assert cfg.secrets is not None
    secrets = SecretValues(
        cfg.secrets,
        {
            "django_secret_key": TRICKY,
            "postgres_password": "pg\\\\pw\"'",
            "api_token": "token",
            "basic_auth_password": "pw",
        },
    )
    Path(cfg.service_path).mkdir(parents=True)
    Path(cfg.venv_bin).mkdir(parents=True)
    Path(cfg.venv_bin / "python").symlink_to(sys.executable)
    Path(cfg.env_path).write_bytes(render_env(cfg, secrets).reveal())
    shutil.copy(FILES / "env_exec.py", cfg.env_exec_path)
    # Stands in for Django's manage.py: reports what it was started with.
    Path(cfg.service_path / "manage.py").write_text(
        "import json, os, sys\n"
        "print(json.dumps({'argv': sys.argv[1:], 'cwd': os.getcwd(),"
        " 'secret': os.environ['DJANGO_SECRET_KEY'], 'db': os.environ.get('DATABASE_URL')}))\n"
    )

    command = _site_manage(cfg, "migrate", "--noinput")
    assert not fish_unsafe(make_unix_command(StringCommand(command)).get_raw_value())
    result = run_remote(command, login_shell, fake_runuser)

    assert result.returncode == 0, result.stderr
    seen = json.loads(result.stdout)
    assert seen["argv"] == ["migrate", "--noinput"]
    assert seen["cwd"] == str(cfg.service_path)
    assert seen["secret"] == TRICKY


@pytest.mark.parametrize("login_shell", LOGIN_SHELLS)
def test_fish_halves_backslash_pairs_in_single_quotes(login_shell: str) -> None:
    """The failure mode itself, so the guard below keeps a reason to exist."""

    result = run_remote(f"printf %s x '{chr(92) * 2}'", login_shell, os.environ["PATH"])

    expected = {"bash": "x\\\\", "fish": "x\\"}[login_shell]
    assert result.stdout == expected


def test_fastdeploy_restore_escapes_the_pgpass_password(tmp_path: Path) -> None:
    """lifecycle.sh's pgpass line, sent through the login shell, escapes ``\\`` and ``:``."""

    script = (SRC / "services" / "fastdeploy" / "files" / "lifecycle.sh").read_text()
    start = script.index("pgpass_line() {")
    function = script[start : script.index("\n}\n", start) + 3]
    command = shlex.join(["bash", "-c", function + 'pgpass_line "$PGPW"'])
    assert not fish_unsafe(command)
    for login_shell in ["bash", *(["fish"] if shutil.which("fish") else [])]:
        # The password arrives off the command line, as in the restore.
        result = run_remote(command, login_shell, os.environ["PATH"], PGPW="a\\b:c\\\\d'e")
        assert result.returncode == 0, result.stderr
        assert result.stdout == "*:*:*:*:a\\\\b\\:c\\\\\\\\d'e\n"


def test_scripts_shipped_inline_are_fish_safe() -> None:
    """Host scripts may be sent as ``-c <source>``; none may hold a sequence fish reads differently.

    ``weeknotes_home/files/env_exec.py`` is uploaded as a file (``files.put``)
    precisely because its regex needs backslash pairs.
    """

    shipped = [
        *SRC.glob("**/files/*.sh"),
        *SRC.glob("**/files/*.py"),
        *SRC.glob("services/_lifecycle/*.sh"),
        SRC / "ops" / "_secret_install.py",
    ]
    # These sources are encoded, never interpolated raw. The actual composed
    # command and protected stdin are executed through bash AND fish in
    # test_mail_web_source_and_secret_stdin_through_real_login_shell.
    encoded_mail_web = {
        "services/_mail_web/files/mail_web_common.py",
        "services/_mail_web/files/mail_web_candidate.py",
    }
    offenders = [
        str(path.relative_to(SRC))
        for path in sorted(shipped)
        if path.name != "env_exec.py"
        and str(path.relative_to(SRC)) not in encoded_mail_web
        and fish_unsafe(f"sh -c {shlex.quote(path.read_text())}")
    ]
    assert len(shipped) > 20
    assert offenders == []


def available_shells() -> list[str]:
    return ["bash", *(["fish"] if shutil.which("fish") else [])]


def test_fish_unsafe_is_exactly_what_fish_reads_differently() -> None:
    """The harness guard against real shells: a quoted command round-trips through
    bash always, and through fish exactly when :func:`fish_unsafe` calls it safe."""

    pieces = ["a", " ", "'", '"', "\\", "\\\\", "\\'", "\\n", "\\\n", "$x", "`", "\n", "é"]
    corpus = [
        "printf '%s\\n' x",
        "printf %s 'a\\\\b'",
        "ends in a backslash\\",
        "sed 's/\\(x\\)/\\1/'",
        "find . \\( -name x \\) -exec true {} \\;",
        "line\\\ncontinued",
        *("".join(pieces[(seed * 7 + step * 3) % len(pieces)] for step in range(seed % 9 + 1)) for seed in range(120)),
    ]

    def echoed(shell: str, commands: list[str]) -> list[str] | None:
        script = "".join(f"printf '%s\\0' {shlex.quote(command)}\n" for command in commands)
        result = subprocess.run([shell, "-c", script], capture_output=True, check=False)
        return result.stdout.decode().split("\0")[:-1] if result.returncode == 0 else None

    assert echoed("bash", corpus) == corpus
    if not shutil.which("fish"):
        pytest.skip("no fish")
    safe = [command for command in corpus if not fish_unsafe(f"sh -c {shlex.quote(command)}")]
    assert echoed("fish", safe) == safe
    unsafe = [command for command in corpus if command not in safe]
    assert len(unsafe) > 10
    # One fish per command (an unbalanced quote ends the script); a sample keeps it fast.
    for command in unsafe[:: len(unsafe) // 10]:
        assert echoed("fish", [command]) != [command], command


@pytest.mark.parametrize("login_shell", LOGIN_SHELLS)
def test_secret_file_installs_tricky_content_through_the_login_shell(tmp_path: Path, login_shell: str) -> None:
    """``secret_file`` ships its installer as ``python3 -I -c <source>``: the source crosses the login shell."""

    dest = tmp_path.resolve() / "secret.env"
    content = SecretContent(f"KEY={TRICKY}\n".encode())
    command = install_command(PurePosixPath(dest), len(content), mode="0600")
    assert not fish_unsafe(make_unix_command(StringCommand(command)).get_raw_value())
    line = make_unix_command(StringCommand(command)).get_raw_value()

    result = subprocess.run(
        [login_shell, "-c", line], input=encode_payload(content), capture_output=True, text=True, check=False
    )

    assert result.returncode == 0, result.stderr
    assert dest.read_bytes() == content.reveal()


def migrate_stub(tmp_path: Path, stdout: str, status: int) -> str:
    """A command standing in for ``manage.py migrate --check --plan``."""

    script = tmp_path / f"migrate-{status}-{len(stdout)}"
    script.write_text(f"#!/bin/sh\nprintf '%s\\n' {shlex.quote(stdout)}\necho 'traceback' >&2\nexit {status}\n")
    script.chmod(0o755)
    return shlex.quote(str(script))


@pytest.mark.parametrize("login_shell", LOGIN_SHELLS)
@pytest.mark.parametrize(
    ("stdout", "status", "answer"),
    [
        ("Planned operations:\n  No planned migration operations.", 0, "current"),
        ("Planned operations:\napp.0002_x\n    Add field y", 1, "pending"),
        ("", 1, FAILED),
        ("Unknown command: 'migrate'", 1, FAILED),
    ],
)
def test_migrations_probe_tells_pending_from_errors(
    tmp_path: Path, login_shell: str, stdout: str, status: int, answer: str
) -> None:
    check = migrations_state(migrate_stub(tmp_path, stdout, status))
    # As probe() sends it while planning.
    result = run_remote(probe_command(check), login_shell, os.environ["PATH"])

    assert result.stdout.splitlines()[-1] == answer


@pytest.mark.parametrize("login_shell", LOGIN_SHELLS)
@pytest.mark.parametrize("command", ["printf partial; false", "echo partial; exit 3", "false"])
def test_a_failing_probe_is_none_even_after_partial_output(login_shell: str, command: str) -> None:
    result = run_remote(probe_command(command), login_shell, os.environ["PATH"])

    assert result.returncode == 0
    assert probe_output(result.stdout) is None
    assert (
        probe_output(run_remote(probe_command("printf current"), login_shell, os.environ["PATH"]).stdout) == "current"
    )


@pytest.mark.parametrize("login_shell", LOGIN_SHELLS)
@pytest.mark.parametrize(("status", "answer"), [(0, "current"), (1, "pending"), (2, FAILED)])
def test_uv_sync_probe_tells_out_of_sync_from_errors(login_shell: str, status: int, answer: str) -> None:
    check = uv_sync_state(f"sh -c {shlex.quote(f'exit {status}')}")
    result = run_remote(probe_command(check), login_shell, os.environ["PATH"])

    assert result.stdout.splitlines()[-1] == answer


@pytest.mark.parametrize("login_shell", LOGIN_SHELLS)
def test_probe_guards_and_last_line(tmp_path: Path, login_shell: str) -> None:
    present, missing = tmp_path / "it's here", tmp_path / "gone"
    present.write_text("")
    command = "printf 'first\\nunchanged\\n'"

    def answer(paths: list[Path]) -> str:
        check = when_present([str(path) for path in paths], last_line(command), otherwise="missing")
        return run_remote(probe_command(check), login_shell, os.environ["PATH"]).stdout

    assert answer([present]) == "unchanged\n"
    # A command that starts with a subshell (weeknotes_home's Echoport shell): not "$((" arithmetic.
    subshell = when_present([str(present)], last_line(f"({command})"), otherwise="missing")
    assert run_remote(probe_command(subshell), login_shell, os.environ["PATH"]).stdout == "unchanged\n"
    plan = migrations_state("(echo 'Planned operations:'; exit 1)")
    assert run_remote(probe_command(plan), login_shell, os.environ["PATH"]).stdout == "pending\n"
    assert answer([present, missing]) == "missing\n"
    failing = when_present([str(present)], last_line("echo partial; false"), otherwise="missing")
    assert run_remote(probe_command(failing), login_shell, os.environ["PATH"]).stdout.splitlines()[-1] == FAILED


@pytest.mark.parametrize("login_shell", LOGIN_SHELLS)
@pytest.mark.parametrize(
    ("command", "expect", "ok"),
    [
        ("echo current", "current", True),
        ("echo pending", "current", False),
        ("echo x; exit 3", None, False),
        ("echo anything", None, True),
    ],
)
def test_verify_probe_fails_unless_the_probe_now_passes(
    login_shell: str, command: str, expect: str | None, ok: bool
) -> None:
    @deploy("Verify")
    def verify() -> None:
        verify_probe(command, name="it's a probe", expect=expect)

    run = run_deploy_fake(verify)
    script = run.executed_commands[0]
    result = run_remote(script, login_shell, os.environ["PATH"])

    assert (result.returncode == 0) is ok, result.stderr
    if not ok:
        assert "it's a probe" in result.stderr


@pytest.mark.parametrize("login_shell", LOGIN_SHELLS)
def test_chesslab_users_probe_tells_a_new_database_from_a_broken_one(tmp_path: Path, login_shell: str) -> None:
    db = tmp_path.resolve() / "chess.db"
    cfg = ChesslabConfig(
        source_path=make_chesslab_source(tmp_path),
        secrets=SecretRef("secrets/prod/chesslab.yml"),
        traefik_host="chess.example.com",
        db_path=PurePosixPath(db),
    )
    check = probe_command(_chesslab_users_probe(cfg))

    def answer() -> str | None:
        return probe_output(run_remote(check, login_shell, os.environ["PATH"]).stdout)

    assert answer() == "none\n"  # no database
    db.touch()
    assert answer() == "none\n"  # not migrated yet (the role requires the file first)
    with sqlite3.connect(db) as conn:
        conn.execute("create table auth_user (id integer, username text, is_staff, is_superuser, is_active)")
        conn.execute("create table accounts_profile (user_id integer, lichess_username text, is_trainer_admin)")
        conn.execute("insert into auth_user values (1, 'Trainer', 1, 1, 1)")
        conn.execute("insert into accounts_profile values (1, 'Lichess', 1)")
    conn.close()
    assert answer() == hashlib.sha256(b"trainer|1|1|1|Lichess|1").hexdigest() + "\n"
    db.write_bytes(b"not a database" * 100)
    assert answer() is None


def _django_site(tmp_path: Path) -> DjangoSiteConfig:
    home = tmp_path.resolve() / "home"
    return site_config(make_marina_source(tmp_path), home=home, site_path=home / "site")


# What ``.env`` can carry: quotes, single backslashes, $, backticks, ; and # (no single quote).
TRICKY_ENV = 'a"b\\c$HOME`x` \\d;e "q" #h'


@pytest.mark.parametrize("login_shell", LOGIN_SHELLS)
def test_django_site_manage_command_loads_tricky_env_values(
    tmp_path: Path, fake_runuser: str, login_shell: str
) -> None:
    cfg = _django_site(tmp_path)
    secrets = django_site_values(cfg, django_secret_key=TRICKY_ENV)
    Path(cfg.venv_bin).mkdir(parents=True)
    Path(cfg.venv_bin / "python").symlink_to(sys.executable)
    Path(cfg.env_path).write_bytes(django_site_env(cfg, secrets).reveal())
    Path(cfg.app_path / "manage.py").write_text(
        "import json, os, sys\n"
        "print(json.dumps({'argv': sys.argv[1:], 'cwd': os.getcwd(),"
        " 'secret': os.environ['DJANGO_SECRET_KEY'], 'cache': os.environ['DJANGO_CACHE_LOCATION']}))\n"
    )

    command = site_shell(cfg, manage_script(cfg, "migrate"))
    assert not fish_unsafe(make_unix_command(StringCommand(command)).get_raw_value())
    result = run_remote(command, login_shell, fake_runuser)

    assert result.returncode == 0, result.stderr
    seen = json.loads(result.stdout)
    assert seen == {"argv": ["migrate"], "cwd": str(cfg.app_path), "secret": TRICKY_ENV, "cache": str(cfg.cache_dir)}


def test_django_site_launcher_starts_gunicorn_with_the_env_and_arguments(tmp_path: Path) -> None:
    cfg = _django_site(tmp_path)
    secrets = django_site_values(cfg, django_secret_key=TRICKY_ENV)
    Path(cfg.venv_bin).mkdir(parents=True)
    Path(cfg.env_path).write_bytes(django_site_env(cfg, secrets).reveal())
    gunicorn = Path(cfg.venv_bin / "gunicorn")
    gunicorn.write_text(
        f"#!{sys.executable}\nimport json, os, sys\n"
        "print(json.dumps({'argv': sys.argv[1:], 'cwd': os.getcwd(), 'secret': os.environ['DJANGO_SECRET_KEY'],"
        " 'settings': os.environ['DJANGO_SETTINGS_MODULE']}))\n"
    )
    gunicorn.chmod(0o755)
    launcher = Path(cfg.site_path / "gunicorn.sh")
    launcher.write_text(render_django_site("gunicorn.sh.j2", cfg))

    result = subprocess.run(["bash", str(launcher)], capture_output=True, text=True, check=False)

    assert result.returncode == 0, result.stderr
    seen = json.loads(result.stdout)
    assert seen["cwd"] == str(cfg.app_path)
    assert seen["secret"] == TRICKY_ENV
    assert seen["settings"] == "config.settings.production"
    assert seen["argv"] == [
        "-w",
        "4",
        "--access-logfile",
        "-",
        "--error-logfile",
        "-",
        "--access-logformat",
        '%({x-forwarded-for}i)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"',
        "-b",
        "127.0.0.1:10019",
        "-t",
        "3600",
        "config.wsgi",
    ]


@pytest.mark.parametrize("login_shell", LOGIN_SHELLS)
def test_django_site_marker_fact_lists_only_markers(
    tmp_path: Path, login_shell: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _django_site(tmp_path)
    monkeypatch.setattr(django_site_deploy, "STATE_ROOT", PurePosixPath(tmp_path.resolve() / "state"))
    state = Path(django_site_deploy.state_dir(cfg))
    state.mkdir(parents=True)
    for name in (".ops-deploy-pending", ".ops-deploy-restart-marina", ".ops-deploy-admin", ".ops-deploy-pendingx"):
        (state / name).touch()

    fact = markers_command(cfg)
    result = run_remote(fact, login_shell, os.environ["PATH"])

    assert result.returncode == 0, result.stderr
    assert sorted(result.stdout.split()) == [".ops-deploy-pending", ".ops-deploy-restart-marina"]
    assert run_remote(fact.replace(str(state), str(state / "missing")), login_shell, os.environ["PATH"]).stdout == ""
