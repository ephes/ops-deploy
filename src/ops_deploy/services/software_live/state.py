"""Gate the role's initial collection, retaining its wait and rewrite assertion."""

from __future__ import annotations

import json
import shlex
from collections.abc import Sequence
from dataclasses import dataclass

from pyinfra.api import DeployError
from pyinfra.api.operation import OperationMeta
from pyinfra.operations import server

from ops_deploy.helpers.probes import probe, stdin_arguments
from ops_deploy.services.software_live.config import SoftwareLiveConfig

STATE_PROBE = """import json,sys,time
from pathlib import Path
p=Path(sys.argv[1])
try:
 s=p.stat()
except FileNotFoundError:
 print(json.dumps({'exists':False,'fresh':False}));sys.exit(0)
try:
 d=json.loads(p.read_text());t=d['generated_at_epoch']
 fresh=isinstance(t,(int,float)) and not isinstance(t,bool) and 0 <= time.time()-t <= 1800
except (ValueError,KeyError,TypeError):
 fresh=False
print(json.dumps({'exists':True,'fresh':fresh,'mtime_ns':s.st_mtime_ns}))
"""
COLLECT = """import json,subprocess,sys,time
from pathlib import Path
p=Path(sys.argv[1]);retries=int(sys.argv[2]);delay=int(sys.argv[3])
for i in range(retries):
 r=subprocess.run(['systemctl','show','--property=ActiveState','--value','software-live-collector.service'],capture_output=True,text=True)
 if r.returncode==0 and r.stdout.strip() not in ('activating','deactivating','reloading','refreshing'):
  break
 if i+1<retries:time.sleep(delay)
else:sys.exit('software-live collector did not become idle')
try:before=p.stat().st_mtime_ns
except FileNotFoundError:before=None
subprocess.run(['systemctl','start','software-live-collector.service'],check=True)
try:after=p.stat().st_mtime_ns
except FileNotFoundError:sys.exit('software-live collection did not create state')
if before is not None and after <= before:
 sys.exit('software-live initial collection did not rewrite state; no pin moved or release pruned')
"""


@dataclass(frozen=True)
class Observation:
    exists: bool
    fresh: bool


def observation(cfg: SoftwareLiveConfig) -> Observation:
    value = probe(
        shlex.join(["/usr/bin/python3", "-I", "-", str(cfg.state_path)]),
        name="Inspect software observation freshness",
        stdin=STATE_PROBE,
    )
    try:
        data = json.loads(value or "")
        if type(data["exists"]) is not bool or type(data["fresh"]) is not bool:
            raise ValueError("invalid status")
        return Observation(data["exists"], data["fresh"])
    except (ValueError, KeyError, TypeError):
        raise DeployError("cannot inspect software observation freshness") from None


def collect(cfg: SoftwareLiveConfig, before: Observation, triggers: Sequence[OperationMeta]) -> OperationMeta:
    """The accepted D5 change: current fresh state alone does not request a run."""
    return server.shell(
        name="Collect a changed or stale software observation",
        commands=[
            shlex.join(
                [
                    "/usr/bin/python3",
                    "-I",
                    "-",
                    str(cfg.state_path),
                    str(cfg.collector_wait_retries),
                    str(cfg.verify_delay),
                ]
            )
        ],
        _if=lambda: not before.fresh or any(op.did_change() for op in triggers),
        **stdin_arguments(COLLECT),
    )
