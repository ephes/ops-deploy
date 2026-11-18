"""gunicorn's ``--forwarder-headers`` option: the version check before a unit uses it.

Every role that starts gunicorn with a fixed command line passes
``--forwarder-headers=`` (django_site: ``--forwarder-headers ''`` behind its
switch ``app.accept_forwarder_headers``), so gunicorn ignores client-set
``SCRIPT_NAME``/``PATH_INFO`` headers from its trusted proxy peer
(``docs/traefik.md``, "Second layer: gunicorn ignores forwarder headers").
"""

from __future__ import annotations

import shlex
from pathlib import PurePosixPath

from pyinfra.api.operation import OperationMeta
from pyinfra.operations import server

from ops_deploy.helpers import mark_read_only

# A normalized PEP 440 version (as an installer names the dist-info directory), no epoch.
_NORMALIZED_VERSION = r"[0-9]+(\.[0-9]+)*((a|b|rc)[0-9]+)?(\.post[0-9]+)?(\.dev[0-9]+)?(\+[a-z0-9]+(\.[a-z0-9]+)*)?"
# ``--forwarder-headers`` exists since gunicorn 22.0, but 22.0 refuses it as an
# unknown argument; 23.0 is the first release that takes it.
GUNICORN_FORWARDER_HEADERS_MIN_MAJOR = 23


def require_gunicorn_forwarder_headers(venv: PurePosixPath | str, *, name: str | None = None) -> OperationMeta:
    """Fail unless the gunicorn installed in ``venv`` takes ``--forwarder-headers`` (23 or newer).

    Runs before a unit with that option is written or restarted, so a source
    whose lock pins an older gunicorn stops the deploy instead of leaving a
    unit that cannot start. Reads the ``gunicorn-<version>.dist-info``
    directory name only; nothing from the venv is executed.
    """

    venv = str(venv)
    if not venv.startswith("/") or any(c in venv for c in "\0\n"):
        raise ValueError("venv must be an absolute path without NUL or newline")
    minimum = GUNICORN_FORWARDER_HEADERS_MIN_MAJOR
    # The venv is the script's $0: quoted, only the glob after it expands.
    script = (
        'set -- "$0"/lib/python*/site-packages/gunicorn-*.dist-info; '
        'if [ "$#" -ne 1 ] || [ ! -d "$1" ]; then '
        'echo "$0: expected exactly one installed gunicorn" >&2; exit 1; fi; '
        # A normalized PEP 440 version without epoch (23.0.0, 23.0.0rc1, 23.0.1.post1+local.1);
        # its major is the leading digits.
        "v=${1##*/gunicorn-}; v=${v%.dist-info}; major=${v%%[!0-9]*}; "
        # grep matches line by line: a name with a newline is refused first.
        'case "$v" in *"\n"*) major= ;; *) '
        f"printf '%s\\n' \"$v\" | LC_ALL=C grep -Eqx {shlex.quote(_NORMALIZED_VERSION)} || major= ;; esac; "
        'case "$major" in "") '
        'echo "$0: unreadable gunicorn version $v" >&2; exit 1;; esac; '
        f'if [ "$major" -lt {minimum} ]; then '
        f'echo "$0: gunicorn $v refuses --forwarder-headers, needs {minimum} or newer" >&2; exit 1; fi'
    )
    return mark_read_only(
        server.shell(
            name=name or f"Require gunicorn {minimum} or newer in {venv}",
            commands=[shlex.join(["sh", "-c", script, venv])],
        )
    )
