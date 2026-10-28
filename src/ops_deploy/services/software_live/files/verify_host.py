
# --- ops-deploy driver (appended to the vendored software_live_impl.py) -------
# The role's verify_impl.yml on the host: its read-only probe, retried until
# software_live_verify() reports nothing (about 30 s). Standard library only.
import argparse as _argparse
import json as _json
import subprocess as _subprocess
import sys as _sys
import time as _time

_PROBE = r"""
set -o pipefail
proc="$3"
binary="$1"
shadow="$2"
if [ -n "$binary" ] && [ -e "$binary" ]; then
  printf 'real\t%s\n' "$(realpath -- "$binary")"
fi
for unit in software-live-endpoint.service software-live-collector.service $shadow; do
  show=$(systemctl show --property=ActiveState,MainPID,ExecMainStatus,ExecStart -- "$unit") || continue
  state='' main=0 status=''
  while IFS= read -r line; do
    case "$line" in
      ActiveState=*) state=${line#*=} ;;
      MainPID=*) main=${line#*=} ;;
      ExecMainStatus=*) status=${line#*=} ;;
      ExecStart=*) printf 'prop\t%s\t%s\n' "$unit" "$line" ;;
    esac
  done <<< "$show"
  printf 'unit\t%s\t%s\t%s\t%s\n' "$unit" "$state" "$main" "$status"
  case "$main" in
    ''|0|*[!0-9]*) continue ;;
  esac
  if exe=$(readlink -- "$proc/$main/exe"); then
    printf 'exe\t%s\t%s\n' "$unit" "$exe"
  fi
  if [ -r "$proc/$main/cmdline" ]; then
    while IFS= read -r -d '' arg; do
      printf 'arg\t%s\t%s\n' "$unit" "$arg"
    done < "$proc/$main/cmdline"
  fi
done
printf 'done\n'
"""


def _main() -> int:
    parser = _argparse.ArgumentParser()
    parser.add_argument("--proc-root", required=True)
    parser.add_argument("--expect", required=True)
    parser.add_argument("--retries", type=int, required=True)
    parser.add_argument("--delay", type=int, required=True)
    args = parser.parse_args()
    expect = _json.loads(args.expect)
    shadow = "software-live-shadow-endpoint.service" if expect.get("shadow") else ""
    problems: list = ["not checked"]
    for attempt in range(args.retries):
        done = _subprocess.run(
            ["bash", "-c", _PROBE, "bash", expect.get("binary") or "", shadow, args.proc_root],
            capture_output=True,
            text=True,
        )
        problems = software_live_verify({"rc": done.returncode, "stdout_lines": done.stdout.splitlines()}, expect)
        if not problems:
            return 0
        if attempt + 1 < args.retries:
            _time.sleep(args.delay)
    print(
        "The production units do not run the selected implementation: "
        + "; ".join(problems)
        + ". No pin moved and nothing was pruned. Deploy with impl python to roll back.",
        file=_sys.stderr,
    )
    return 1


if __name__ == "__main__":
    _sys.exit(_main())
