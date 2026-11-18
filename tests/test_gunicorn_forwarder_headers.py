"""Every gunicorn a role starts ignores client-set forwarder headers.

gunicorn's ``forwarder_headers`` (default ``SCRIPT_NAME,PATH_INFO``) lets a
trusted proxy peer (``forwarded_allow_ips``, loopback by default, which is
Traefik) pass those headers into the WSGI environ; ``SCRIPT_NAME`` becomes the
mount prefix that gunicorn strips from the request path. Traefik deletes them at
the edge (``helpers/templates/_edge.j2``); ``--forwarder-headers=`` is the second
layer (gunicorn 23 or newer), so a header that still reaches gunicorn is dropped
(``header_map=drop``) instead of becoming the mount prefix. django_site has the switch
``AppSpec.accept_forwarder_headers`` (``tests/test_django_site.py``).
"""

from __future__ import annotations

import re
from pathlib import Path

SERVICES = Path(__file__).resolve().parents[1] / "src" / "ops_deploy" / "services"

# Launch commands: a unit's ExecStart or a launcher's exec.
_LAUNCH = re.compile(r"^(ExecStart=|exec )")

# The option-driven launcher; its default keeps gunicorn's behavior.
OPTION_DRIVEN = {"django_site/templates/gunicorn.sh.j2"}


# ``uv run`` options that take a separate value (``--opt value``).
_UV_RUN_VALUE_OPTIONS = frozenset(
    {
        "--cache-dir", "--color", "--config-file", "--default-index", "--directory", "--env-file",
        "--exclude-newer", "--extra", "--extra-index-url", "--find-links", "-f", "--group", "--index",
        "--index-strategy", "--index-url", "--keyring-provider", "--link-mode", "--no-binary-package",
        "--no-build-package", "--no-group", "--only-group", "--package", "--prerelease", "--project",
        "--python", "-p", "--python-platform", "--refresh-package", "--reinstall-package", "--resolution",
        "--upgrade-package", "-P", "--with", "-w", "--with-editable", "--with-requirements",
    }
)  # fmt: skip


def _runs_gunicorn(args: list[str]) -> bool:
    """``args`` (after the executable and its options) start gunicorn."""

    words = iter(args)
    for word in words:
        if word in ("-m", "--module"):
            return next(words, None) == "gunicorn"
        if word.startswith("-"):
            if "=" not in word and word in _UV_RUN_VALUE_OPTIONS:
                next(words, None)
            continue
        name = word.rsplit("/", 1)[-1]
        if name.startswith("python"):
            return _python_runs_gunicorn(list(words))
        return name == "gunicorn"
    return False


def _python_runs_gunicorn(args: list[str]) -> bool:
    """A Python interpreter's ``args`` run ``-m gunicorn``, CPython's option rules.

    Flag groups (``-Im``) are read letter by letter; ``-X``/``-W`` take the
    rest of the group or the next word; ``-m`` ends the options with the
    module; ``-c``, ``-`` (stdin), ``--`` and a script path end them without.
    """

    words = iter(args)
    for word in words:
        if word in ("-", "--") or not word.startswith("-") or word.startswith("--"):
            return False
        group = word[1:]
        while group:
            letter, group = group[0], group[1:]
            if letter in "XW":
                if not group:
                    next(words, None)
                break
            if letter == "m":
                return (group or next(words, None)) == "gunicorn"
            if letter == "c":
                return False
    return False


def _starts_gunicorn(line: str) -> bool:
    """The launched executable is gunicorn: directly, ``python -m gunicorn`` or through ``uv run``."""

    # A Jinja expression is one word: ``{{ venv }}/gunicorn``, ``{{ uv_path }}``.
    command = _LAUNCH.sub("", line)
    command = re.sub(r"\{\{(.*?)\}\}", lambda m: "{{" + "".join(m.group(1).split()) + "}}", command)
    words = command.lstrip("@-:+!").split()
    if not words:
        return False
    executable = words[0].rsplit("/", 1)[-1]
    if executable == "gunicorn":
        return True
    if executable.startswith("python"):
        return _python_runs_gunicorn(words[1:])
    uv = executable == "uv" or (words[0].startswith("{{") and "uv" in words[0])
    return uv and words[1:2] == ["run"] and _runs_gunicorn(words[2:])


def _commands(text: str) -> list[str]:
    """Logical lines: backslash continuations joined."""

    return text.replace("\\\n", " ").splitlines()


def _gunicorn_launches(services: Path = SERVICES) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for path in sorted(services.glob("*/templates/**/*")):
        if not path.is_file():
            continue
        rel = path.relative_to(services).as_posix()
        for line in _commands(path.read_text(encoding="utf-8")):
            line = line.strip()
            if _LAUNCH.match(line) and _starts_gunicorn(line):
                found.setdefault(rel, []).append(line)
    return found


def test_the_sweep_finds_the_known_gunicorn_launchers() -> None:
    assert set(_gunicorn_launches()) >= {
        "archive/templates/archive.service.j2",
        "daybook_operations_api/templates/service.j2",
        "django_site/templates/gunicorn.sh.j2",
        "homelab/templates/systemd.service.j2",
        "opaq_app/templates/opaq-app.service.j2",
        "paperless/templates/paperless.service.j2",
        "weeknotes_home/templates/weeknotes-home.service.j2",
        "work_app/templates/work-app.service.j2",
    }


def test_every_gunicorn_launch_drops_forwarder_headers() -> None:
    missing = [
        f"{rel}: {line}"
        for rel, lines in _gunicorn_launches().items()
        if rel not in OPTION_DRIVEN
        for line in lines
        if not re.search(r"\s--forwarder-headers=(\s|$)", line)
    ]
    assert not missing, "gunicorn without --forwarder-headers=:\n" + "\n".join(missing)


def test_the_option_driven_launcher_still_has_the_switch() -> None:
    text = (SERVICES / "django_site/templates/gunicorn.sh.j2").read_text(encoding="utf-8")
    assert "{% if not cfg.app.accept_forwarder_headers %}  --forwarder-headers ''" in text


def test_the_sweep_sees_bare_executables_and_nested_templates(tmp_path: Path) -> None:
    nested = tmp_path / "demo" / "templates" / "units"
    nested.mkdir(parents=True)
    (nested / "a.service.j2").write_text("[Service]\nExecStart=gunicorn app.wsgi\n")
    (nested / "b.sh.j2").write_text("#!/bin/sh\nexec gunicorn \\\n  -b 127.0.0.1:1 app.wsgi\n")
    (nested / "c.service.j2").write_text("ExecStart=/usr/bin/python -m notgunicorn\n")
    (nested / "d.service.j2").write_text("ExecStart=/usr/bin/logger --tag=gunicorn -- task complete\n")
    (nested / "e.service.j2").write_text("ExecStart=/usr/local/bin/uv run gunicorn app.wsgi\n")
    (nested / "f.service.j2").write_text("ExecStart=/usr/bin/logger run gunicorn app.wsgi\n")
    (nested / "g.service.j2").write_text("ExecStart={{ app_uv_path }} run --no-sync gunicorn app.wsgi\n")
    (nested / "h.service.j2").write_text("ExecStart=/usr/local/bin/uv run --project /srv/app gunicorn app.wsgi\n")
    (nested / "i.service.j2").write_text("ExecStart=/usr/local/bin/uv run --with gunicorn python app.py\n")
    (nested / "j.service.j2").write_text("ExecStart=/srv/venv/bin/python -m gunicorn app.wsgi\n")
    (nested / "k.service.j2").write_text("ExecStart=/usr/local/bin/uv run -w packaging gunicorn app.wsgi\n")
    (nested / "l.service.j2").write_text("ExecStart=/usr/local/bin/uv run --no-sync python -m gunicorn app.wsgi\n")
    (nested / "m.service.j2").write_text("ExecStart=/usr/local/bin/uv run -w gunicorn python app.py\n")
    (nested / "n.service.j2").write_text("ExecStart=/usr/local/bin/uv run --no-sync python -I -m gunicorn app.wsgi\n")
    (nested / "o.service.j2").write_text("ExecStart=/srv/venv/bin/python3 -Im gunicorn app.wsgi\n")
    (nested / "p.service.j2").write_text("ExecStart=/srv/venv/bin/python3 -X dev -m gunicorn app.wsgi\n")
    (nested / "q.service.j2").write_text("ExecStart=/srv/venv/bin/python3 -I app.py gunicorn\n")
    (nested / "r.service.j2").write_text("ExecStart=/srv/venv/bin/python3 -Ximporttime -m gunicorn app.wsgi\n")
    (nested / "s.service.j2").write_text("ExecStart=/srv/venv/bin/python3 - -m gunicorn\n")
    (nested / "t.service.j2").write_text("ExecStart=/srv/venv/bin/python3 -c pass -m gunicorn\n")
    assert set(_gunicorn_launches(tmp_path)) == {
        "demo/templates/units/a.service.j2",
        "demo/templates/units/b.sh.j2",
        "demo/templates/units/e.service.j2",
        "demo/templates/units/g.service.j2",
        "demo/templates/units/h.service.j2",
        "demo/templates/units/j.service.j2",
        "demo/templates/units/k.service.j2",
        "demo/templates/units/l.service.j2",
        "demo/templates/units/n.service.j2",
        "demo/templates/units/o.service.j2",
        "demo/templates/units/p.service.j2",
        "demo/templates/units/r.service.j2",
    }


# Role -> the unit template name its deploy renders. Each checks the venv's
# gunicorn (23 or newer) before it writes or restarts that unit; paperless also
# repairs it first (files/runtime_state.py, gunicorn>=23).
CHECKED_ROLES = {
    "archive": '"archive.service.j2"',
    "daybook_operations_api": "systemd_unit(",
    "homelab": "systemd_unit(",
    "opaq_app": '"opaq-app.service.j2"',
    "weeknotes_home": '"weeknotes-home.service.j2"',
    "work_app": '"work-app.service.j2"',
    "django_site": '"Write gunicorn.sh"',
    "paperless": '"paperless.service.j2"',
}
# The venv each role's unit launches (paperless.service.j2: paperless_virtualenv, render.py).
CHECKED_VENV = {role: "cfg.venv_path" for role in CHECKED_ROLES} | {"paperless": 'f"{cfg.site_root}/.venv"'}


def test_roles_check_the_gunicorn_version_before_the_unit() -> None:
    late = []
    for role, unit_marker in CHECKED_ROLES.items():
        text = (SERVICES / role / "deploy.py").read_text(encoding="utf-8")
        check = text.find(f"require_gunicorn_forwarder_headers({CHECKED_VENV[role]})")
        if check < 0 or check > text.find(unit_marker, text.find("def deploy_")):
            late.append(role)
    assert not late, f"no gunicorn version check before the unit: {late}"
