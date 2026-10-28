"""Original Sessions uv/Homebrew prerequisites and explicit classifier probe.

The model probe is managed application work. It is never part of a fact/pure
resource observation, even though the original Ansible task used changed_when.
Child output remains in memory and only fixed failure categories can escape.
"""

import os
import base64
import json
import pwd
import re
import shlex
import subprocess

from ops_sessions_resources import ResourceError

PROBE_FRAME = b"\nOPS_SESSIONS_PROBE="
PROBE_HELPER = '''import json,os,signal,subprocess,sys
result={"schema_version":1,"ok":False,"reason":"failed","owned_group":False}
try:
 data=json.load(sys.stdin)
 child=subprocess.Popen(["/bin/bash","-c",data["script"]],stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                        env={**os.environ,**data["environment"]},start_new_session=True,cwd="/")
 # Popen's successful start_new_session creates this same-UID group/session.
 # No poll/wait has reaped the child, so its PID/group ID is still reserved.
 # Check queryable metadata too; Darwin can answer ESRCH for an unreaped zombie
 # leader, in which case creation remains the authoritative ownership proof.
 result["owned_group"]=True
 try:result["owned_group"]=os.getpgid(child.pid)==child.pid and os.getsid(child.pid)==child.pid
 except ProcessLookupError:pass
 try:
  out,err=child.communicate(timeout=data["timeout"])
  result["ok"]=child.returncode==0 and out.strip()==b"OK"
 except subprocess.TimeoutExpired:
  result["reason"]="timeout"
  if result["owned_group"]:
   try:
    os.killpg(child.pid,signal.SIGKILL)
   except ProcessLookupError:pass
   except Exception:result["reason"]="cleanup_failed"
  else:result["reason"]="cleanup_failed"
  try:child.communicate(timeout=2)
  except subprocess.TimeoutExpired:
   result["reason"]="cleanup_failed"
   for stream in (child.stdout,child.stderr):
    if stream is not None:stream.close()
   try:child.wait(timeout=1)
   except subprocess.TimeoutExpired:pass
except Exception:pass
sys.stdout.write("\\nOPS_SESSIONS_PROBE="+json.dumps(result,sort_keys=True)+"\\n")
raise SystemExit(0 if result["ok"] else 1)
'''


class Dependencies:
    def __init__(self, cfg):
        self.cfg = cfg
        pwd.getpwnam(cfg["daybook_sessions_service_user"])

    def command(self, argv, *, user=None, environment=None):
        environment = environment or {}
        if environment:
            argv = ["/usr/bin/env", *[key + "=" + value for key, value in environment.items()], *argv]
        if user is not None:
            account = pwd.getpwnam(user)
            if os.geteuid() != account.pw_uid:
                argv = ["/usr/bin/sudo", "-H", "-S", "-n", "-i", "-u", user, "--", *argv]
        return argv

    def run(self, argv, *, user=None, environment=None):
        try:
            return subprocess.run(self.command(argv, user=user, environment=environment), capture_output=True, cwd="/")
        except OSError:
            raise ResourceError("sessions_dependency_command_failed") from None

    def brew(self):
        cfg = self.cfg
        selected = cfg["daybook_sessions_brew_bin"]
        if not selected:
            selected = "/opt/homebrew/bin/brew" if os.path.exists("/opt/homebrew/bin/brew") else "/usr/local/bin/brew"
        user = cfg["daybook_sessions_brew_user"] or None
        if cfg["daybook_sessions_brew_packages"] and (not os.path.isfile(selected) or (user is None and os.geteuid() == 0)):
            raise ResourceError("sessions_brew_owner_or_binary_missing")
        if user is not None:
            pwd.getpwnam(user)
        for package in cfg["daybook_sessions_brew_packages"]:
            if not isinstance(package, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9@+_.:/-]*", package):
                raise ResourceError("sessions_brew_package_invalid")
        return selected, user

    def inspect(self):
        cfg = self.cfg
        if self.run([cfg["daybook_sessions_uv_bin"], "--version"],
                    environment={"PATH": cfg["daybook_sessions_launchd_path"]}).returncode:
            raise ResourceError("sessions_uv_unavailable")
        binary, user = self.brew()
        missing = [package for package in cfg["daybook_sessions_brew_packages"]
                   if self.run([binary, "list", "--versions", package], user=user).returncode]
        return {"current": not missing and not (cfg["daybook_sessions_brew_packages"] and cfg["daybook_sessions_brew_update"])}

    def apply(self):
        cfg = self.cfg
        if self.run([cfg["daybook_sessions_uv_bin"], "--version"],
                    environment={"PATH": cfg["daybook_sessions_launchd_path"]}).returncode:
            raise ResourceError("sessions_uv_unavailable")
        binary, user = self.brew()
        if cfg["daybook_sessions_brew_packages"] and cfg["daybook_sessions_brew_update"]:
            if self.run([binary, "update"], user=user).returncode:
                raise ResourceError("sessions_brew_update_failed")
        for package in cfg["daybook_sessions_brew_packages"]:
            if self.run([binary, "list", "--versions", package], user=user).returncode:
                if self.run([binary, "install", package], user=user).returncode:
                    raise ResourceError("sessions_brew_install_failed")

    def probe(self):
        cfg = self.cfg
        if not cfg["daybook_archive_quote_classifier_enabled"] or not cfg["daybook_archive_quote_classifier_probe_enabled"]:
            return
        home, user = cfg["daybook_sessions_service_home"], cfg["daybook_sessions_service_user"]
        environment = {"PATH": cfg["daybook_sessions_launchd_path"], "HOME": home, "USER": user, "LOGNAME": user,
                       "XDG_CONFIG_HOME": home + "/.config", "XDG_CACHE_HOME": home + "/.cache",
                       "XDG_DATA_HOME": home + "/.local/share"}
        # The configured model command is intentionally an opaque original shell
        # expression. Only the fixed synthetic prompt is added, shell-quoted.
        script = "set -o pipefail; printf '%s\\n' " + shlex.quote(cfg["daybook_archive_quote_classifier_probe_prompt"])
        script += " | " + cfg["daybook_archive_quote_classifier_cmd"]
        # The deadline/group owner must be INSIDE the GUI execution context:
        # sudo/use_pty can create another session, so killing sudo's outer PGID
        # would not prove the model pipeline stopped. This wrapper creates and
        # signals only its own same-UID child's new session/group.
        encoded = base64.b64encode(PROBE_HELPER.encode()).decode()
        program = "import base64;exec(compile(base64.b64decode('" + encoded + "'),'<sessions-probe>','exec'))"
        argv = self.command(["/usr/bin/python3", "-I", "-B", "-S", "-c", program], user=user)
        payload = json.dumps({"script": script, "environment": environment,
                              "timeout": cfg["daybook_archive_quote_classifier_probe_timeout_seconds"]}).encode()
        try:
            child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd="/")
        except OSError:
            raise ResourceError("sessions_classifier_probe_failed") from None
        try:
            # Configured model budget is unchanged; five seconds bounds wrapper
            # startup, exact-child cleanup and report transport separately.
            out, _err = child.communicate(input=payload,
                timeout=cfg["daybook_archive_quote_classifier_probe_timeout_seconds"] + 5)
        except subprocess.TimeoutExpired:
            # Only this direct outer child is signaled. The GUI wrapper owns the
            # model group/deadline; an absent report remains a cleanup failure.
            try:
                child.kill()
            except ProcessLookupError:
                pass
            try:child.communicate(timeout=1)
            except subprocess.TimeoutExpired:
                for stream in (child.stdout,child.stderr):
                    if stream is not None:stream.close()
                try:child.wait(timeout=1)
                except subprocess.TimeoutExpired:pass
            raise ResourceError("sessions_classifier_probe_cleanup_failed") from None
        try:
            _prefix, separator, report = out.rpartition(PROBE_FRAME)
            if not separator:raise ValueError
            observed = json.loads(report.split(b"\n",1)[0])
            if (set(observed)!={"schema_version","ok","reason","owned_group"}
                    or type(observed["schema_version"]) is not int or observed["schema_version"]!=1
                    or type(observed["ok"]) is not bool or type(observed["owned_group"]) is not bool
                    or observed["reason"] not in {"failed","timeout","cleanup_failed"}):raise ValueError
        except (ValueError,TypeError,KeyError,AttributeError):
            raise ResourceError("sessions_classifier_probe_failed") from None
        if observed["reason"]=="cleanup_failed":
            raise ResourceError("sessions_classifier_probe_cleanup_failed")
        if observed["reason"]=="timeout":
            if not observed["owned_group"]:
                raise ResourceError("sessions_classifier_probe_cleanup_failed")
            raise ResourceError("sessions_classifier_probe_timed_out")
        if child.returncode or not observed["ok"]:
            raise ResourceError("sessions_classifier_probe_failed")
