# Runs one register playbook's own Nyxmon check script with a check mode.
# Run with the host's ``python3 -I -c`` as the Nyxmon user, after the
# ``PARAMS = ...`` line of :data:`ops_deploy.services._echoport_runner.nyxmon.CODE`
# (it reads them from the first stdin line, so the check data stays off argv),
# with the environment the playbook's task sets (``NYXMON_DB_PATH``,
# ``NYXMON_SERVICE_NAME``).
#
# The playbook's script (P["script"]) stays as it is, with one change: it reads
# its values from VALUES (P["values"], in place of the playbook's Jinja). It
# opens the database with ``sqlite3.connect``, writes, commits and prints
# "changed=true" or "changed=false" as its last line.
#
# Modes (P["mode"]):
#   check  runs the script with ``sqlite3.connect`` opening the database read
#          only, so nothing can be written. Prints "unchanged" when the script
#          ends with "changed=false", "pending" when it ends with
#          "changed=true" or tries to write (every write of the script also
#          sets changed), and "refused: <reason>" when it fails otherwise.
#   apply  runs the script as the playbook does and prints its last line, then
#          "applied".
import contextlib
import io
import sqlite3
import urllib.parse

P = PARAMS  # type: ignore[name-defined]  # noqa: F821

READ_ONLY = "attempt to write a readonly database"


class Pending(Exception):
    """The script tried to write: the check is pending."""


def read_only_connect(connect):
    def opened(database, *args, **kwargs):
        kwargs.pop("uri", None)
        uri = "file:" + urllib.parse.quote(str(database)) + "?mode=ro"
        return connect(uri, *args, uri=True, **kwargs)

    return opened


def run_script(read_only):
    namespace = {"__name__": "__echoport_runner_nyxmon__", "VALUES": P["values"]}
    out = io.StringIO()
    connect = sqlite3.connect
    if read_only:
        sqlite3.connect = read_only_connect(connect)
    try:
        with contextlib.redirect_stdout(out):
            try:
                exec(compile(P["script"], "<runner nyxmon script>", "exec"), namespace)
            except sqlite3.OperationalError as exc:
                if read_only and READ_ONLY in str(exc):
                    raise Pending() from exc
                raise
    finally:
        sqlite3.connect = connect
    lines = out.getvalue().strip().splitlines()
    return lines[-1] if lines else ""


def check():
    try:
        last = run_script(read_only=True)
    except Pending:
        print("pending")
        return
    except (Exception, SystemExit) as exc:  # noqa: BLE001 - any failure stops the deploy
        reason = " ".join(f"{type(exc).__name__}: {exc}".split())[:500]
        print(f"refused: {reason}")
        return
    if last == "changed=false":
        print("unchanged")
    elif last == "changed=true":
        print("pending")
    else:
        print(f"refused: the script ended with {last[:100]!r}, not changed=true or changed=false")


def apply():
    last = run_script(read_only=False)
    if last not in ("changed=true", "changed=false"):
        raise RuntimeError(f"the script ended with {last[:100]!r}, not changed=true or changed=false")
    print(last)
    print("applied")


if P["mode"] == "check":
    check()
elif P["mode"] == "apply":
    apply()
else:
    raise RuntimeError(f"unknown mode {P['mode']!r}")
