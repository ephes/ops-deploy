"""Wait for a timer's already queued oneshot; never start a second invocation."""

import subprocess
import sys
import time


def wait(unit, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = subprocess.run(
            ["systemctl", "show", unit, "-p", "Job", "-p", "ActiveState", "-p", "Result"],
            check=True,
            capture_output=True,
            text=True,
        )
        values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        job = values.get("Job", "").split(" ")[0]
        if "Job" in values and job in ("", "0") and values.get("ActiveState") in ("inactive", "failed"):
            if values.get("Result") != "success":
                raise RuntimeError("timer-triggered DNS job failed")
            return
        time.sleep(0.2)
    raise RuntimeError("timer-triggered DNS job did not complete")


if __name__ == "__main__":
    if sys.argv[1:] not in (["ddns-update.service"], ["unbound-blocklist.service"]):
        sys.exit("unexpected DNS periodic unit")
    wait(sys.argv[1])
