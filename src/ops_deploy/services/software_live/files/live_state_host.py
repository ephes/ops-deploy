# Appended to the byte-exact role filter; emits only release protection decisions.
import json as _json
import stat as _stat
import subprocess as _subprocess
import sys as _sys
from pathlib import Path as _Path

_PROBE = 'set -o pipefail\nproc="$1"\ncgroup="$2"\nroot="$3"\nif real=$(realpath -- "$root" 2>/dev/null); then\n  printf \'root\\t%s\\n\' "$real"\nfi\nfor unit in software-live-endpoint.service software-live-collector.service \\\n            software-live-shadow-endpoint.service software-live-shadow-collector.service; do\n  if ! show=$(systemctl show --property=ActiveState,MainPID,ControlPID,ControlGroup,ExecCondition,ExecStartPre,ExecStart,ExecStartPost,ExecReload,ExecStop,ExecStopPost -- "$unit"); then\n    printf \'error\\t%s\\n\' "$unit"\n    continue\n  fi\n  state=\'\' main=0 control=0 cg=\'\'\n  while IFS= read -r line; do\n    case "$line" in\n      ActiveState=*) state=${line#*=} ;;\n      MainPID=*) main=${line#*=} ;;\n      ControlPID=*) control=${line#*=} ;;\n      ControlGroup=*) cg=${line#*=} ;;\n      Exec*=*) printf \'prop\\t%s\\t%s\\n\' "$unit" "$line" ;;\n    esac\n  done <<< "$show"\n  printf \'unit\\t%s\\t%s\\t%s\\t%s\\t%s\\n\' "$unit" "$state" "$main" "$control" "$cg"\n  pids="$main $control"\n  case "$state" in\n    activating|active|deactivating|reloading|refreshing)\n      if [ -n "$cg" ] && procs=$(cat -- "$cgroup$cg/cgroup.procs" 2>/dev/null); then\n        pids="$pids $procs"\n      elif [ -n "$cg" ] && procs=$(cat -- "$cgroup/systemd$cg/cgroup.procs" 2>/dev/null); then\n        pids="$pids $procs"\n      else\n        printf \'nocgroup\\t%s\\n\' "$unit"\n      fi\n      ;;\n  esac\n  for pid in $pids; do\n    case "$pid" in\n      \'\'|0|*[!0-9]*) continue ;;\n    esac\n    if exe=$(readlink -- "$proc/$pid/exe"); then\n      printf \'exe\\t%s\\t%s\\t%s\\n\' "$unit" "$pid" "$exe"\n    elif [ -e "$proc/$pid" ]; then\n      printf \'noexe\\t%s\\t%s\\n\' "$unit" "$pid"\n    fi\n  done\ndone\nprintf \'done\\n\'\n'


def _main():
    cfg = _json.loads(_sys.argv[1])
    root = cfg['root']
    paths = cfg['paths']
    records = []
    for name in paths['dropins'] + paths['units'] + [paths['pin'], paths['shadow_pin']]:
        path = _Path(name)
        record = {'path': name, 'exists': True, 'isreg': False, 'content': None}
        try:
            mode = path.lstat().st_mode
            record['isreg'] = _stat.S_ISREG(mode)
            if record['isreg']:
                record['content'] = path.read_text()
        except FileNotFoundError:
            record['exists'] = False
        except (OSError, UnicodeError):
            pass
        records.append(record)
    done = _subprocess.run(['bash','-c',_PROBE,'bash',cfg['proc'],cfg['cgroup'],root],
        capture_output=True,text=True)
    result = software_live_live_state({'rc':done.returncode,'stdout_lines':done.stdout.splitlines()},
        records,[root],paths)
    print(_json.dumps(result,sort_keys=True))


if __name__ == '__main__':
    _main()
