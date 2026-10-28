"""Owned uv 0.13.5 installed-sdist check; no app, GUI, inventory or model."""

from __future__ import annotations

import sys
from pathlib import Path

from daybook_resources_native_fixture import provenance
from mac_apps_owned import OwnedMac, command


def main() -> None:
    owned = OwnedMac("daybook-uv-check")
    failure: BaseException | None = None
    try:
        provenance(owned)
        uv = str(Path(sys.executable).parent / "uv")
        version = command(uv, "--version").stdout.strip()
        assert version.startswith("uv 0.13.5 ")
        owned.report["fixture_uv_version"] = version
        result = command(
            "/usr/bin/sudo", "-n", "-H", "-u", "runner", "--", "/usr/bin/env",
            "PYTHONDONTWRITEBYTECODE=1", "S8_UV_CHECK_BIN=" + uv,
            sys.executable, "-m", "pytest", "-vv", "-p", "no:cacheprovider",
            str(Path(__file__).resolve().parents[1] / "tests/test_daybook_uv_sdist.py"),
            check=False, timeout=120,
        )
        (owned.evidence / "owned-sdist-check.log").write_text(result.stdout + result.stderr)
        print(result.stdout, flush=True)
        print(result.stderr, flush=True)
        assert result.returncode == 0
        owned.report.update(
            status="passed",
            scoped_cases=["sessions", "shared-runtime-user"],
            checks="current twice, missing installed distribution refused without repair, restored current",
            backend_tripwire="real setup build observed; no backend import or build during any check",
            metadata="whole owned project/environment bytes, inode, ownership, modes, mtime/ctime exact per check",
            scope="Owned sdist mechanism only; root interpreter guards unchanged and separately qualified. "
                  "No installed Daybook app, inventory, launchd, model or credential invocation. "
                  "UV temporary/cache I/O allowed; no global zero-I/O claim.",
        )
    except BaseException as error:
        failure = error
    finally:
        failure = owned.finish(failure)
    if failure is not None:
        raise failure


if __name__ == "__main__":
    main()
