# Runs one register playbook's own Echoport target script with a check mode.
# Run by ``manage.py shell -c`` in the Echoport site as the echoport user,
# after the ``PARAMS = ...`` lines that
# :func:`ops_deploy.services._echoport_runner.target.target_code` prepends.
#
# The playbook's script (P["script"]) stays as it is, with two changes: it
# reads its values from VALUES (P["values"], in place of the playbook's Jinja)
# and a newly issued FastDeploy token from SERVICE_TOKEN (empty: keep the
# stored one), in place of ``fd_service_token_value``. It must not exit: in
# check mode an exit counts as a refusal.
#
# Modes (P["mode"]):
#   check  runs the script without writing: every model save is recorded
#          instead (after the model's own validation, so ``full_clean`` runs),
#          other writes (``QuerySet.update``, deletes, bulk writes) are
#          recorded and skipped, and the transaction is rolled back. Prints
#          "unchanged" when no recorded save would change a stored field and
#          no token is due, "pending" otherwise, and "refused: <reason>" when
#          the script raises (a playbook refusal such as "Refusing implicit
#          reactivation", or a validation error): the deploy stops before any
#          write.
#   apply  with P["token"] set and a token due, reads it from stdin (one line)
#          and prints "need-token" (running nothing) when none arrives; then
#          runs the script as the playbook does and prints "applied".
#
# P["token"] (optional): {"targets": [...], "service": str, "renewal_days": int,
# "force_rotate": bool}. The stored token of the first existing target is
# inspected as ops-control's files/fastdeploy/echoport_service_token_status.py
# does it; token_claims and rotation_reason are that script's and
# _echoport/files/echoport_target.py's: keep the three in step.
#
# The script's own output is withheld; a token is never printed.
import base64
import contextlib
import io
import json
import re
import sys
import time

from django.db import models, transaction

P = PARAMS  # type: ignore[name-defined]  # noqa: F821

JWT_SHAPE = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


def token_claims(token):
    if not isinstance(token, str) or not JWT_SHAPE.fullmatch(token):
        return None
    try:
        segment = token.split(".")[1]
        segment += "=" * (-len(segment) % 4)
        claims = json.loads(base64.urlsafe_b64decode(segment.encode("ascii")).decode("utf-8"))
    except (AttributeError, IndexError, UnicodeError, ValueError):
        return None
    return claims if isinstance(claims, dict) else None


def rotation_reason(token, service, renewal_days, now):
    if not token:
        return "missing"
    claims = token_claims(token)
    if claims is None:
        return "undecodable"
    if claims.get("type") != "service" or claims.get("service") != service:
        return "wrong_scope"
    if not claims.get("jti"):
        return "legacy_without_jti"
    try:
        expires_at = int(claims["exp"])
    except (KeyError, TypeError, ValueError):
        return "no_expiry"
    if expires_at <= now + renewal_days * 86400:
        return "expiring"
    return None


def token_due(spec):
    from backups.models import BackupTarget

    stored = ""
    for name in spec["targets"]:
        target = BackupTarget.objects.filter(name=name).first()
        if target is not None:
            stored = target.service_token
            break
    reason = rotation_reason(stored, spec["service"], spec["renewal_days"], int(time.time()))
    return bool(spec["force_rotate"]) or reason is not None


def run_script(token):
    namespace = {"__name__": "__echoport_runner_target__", "VALUES": P["values"], "SERVICE_TOKEN": token}
    with contextlib.redirect_stdout(io.StringIO()):
        exec(compile(P["script"], "<runner target script>", "exec"), namespace)


class Recorder:
    """Stands in for the database writes while the check runs."""

    def __init__(self):
        self.saves = []
        self.other_writes = 0

    def save_base(self, instance, *args, **kwargs):
        self.saves.append((instance, kwargs.get("update_fields")))

    def write(self, *args, **kwargs):
        self.other_writes += 1
        return 0

    @contextlib.contextmanager
    def installed(self):
        patched = [
            (models.Model, "save_base", lambda instance, *a, **k: self.save_base(instance, *a, **k)),
            (models.Model, "delete", lambda *a, **k: self.write()),
            (models.QuerySet, "update", lambda *a, **k: self.write()),
            (models.QuerySet, "delete", lambda *a, **k: self.write()),
            (models.QuerySet, "bulk_create", lambda *a, **k: self.write()),
            (models.QuerySet, "bulk_update", lambda *a, **k: self.write()),
        ]
        originals = [(owner, name, getattr(owner, name)) for owner, name, _ in patched]
        for owner, name, replacement in patched:
            setattr(owner, name, replacement)
        try:
            yield self
        finally:
            for owner, name, original in originals:
                setattr(owner, name, original)


def changes(instance, update_fields):
    if instance._state.adding or instance.pk is None:
        return True
    stored = type(instance)._base_manager.filter(pk=instance.pk).first()
    if stored is None:
        return True
    names = set(update_fields) if update_fields is not None else None
    for field in instance._meta.concrete_fields:
        if getattr(field, "auto_now", False) or getattr(field, "auto_now_add", False):
            continue
        if names is not None and field.name not in names and field.attname not in names:
            continue
        if field.to_python(field.value_from_object(instance)) != field.value_from_object(stored):
            return True
    return False


def check():
    due = token_due(P["token"]) if P.get("token") else False
    recorder = Recorder()
    with transaction.atomic():
        try:
            with recorder.installed():
                # A token that is due counts as issued: the script sees one to store.
                run_script("<new token>" if due else "")
        except (Exception, SystemExit) as exc:  # noqa: BLE001 - any refusal (or an exit) stops the deploy
            transaction.set_rollback(True)
            reason = " ".join(f"{type(exc).__name__}: {exc}".split())[:500]
            print(f"refused: {reason}")
            return
        pending = due or recorder.other_writes > 0 or any(changes(i, f) for i, f in recorder.saves)
        transaction.set_rollback(True)
    print("pending" if pending else "unchanged")


def apply():
    token = ""
    if P.get("token") and token_due(P["token"]):
        token = sys.stdin.readline().strip()
        if not token:
            print("need-token")
            return
    run_script(token)
    print("applied")


if P["mode"] == "check":
    check()
elif P["mode"] == "apply":
    apply()
else:
    raise RuntimeError(f"unknown mode {P['mode']!r}")
