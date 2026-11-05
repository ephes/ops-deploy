# Runs one register playbook's own Echoport target script with a check mode.
# Run by ``manage.py shell -c`` in the Echoport site as the echoport user,
# after the ``PARAMS = ...`` lines that
# :func:`ops_deploy.services._echoport_runner.target.target_code` prepends.
#
# The playbook's script (P["script"]) stays as it is, with two changes: it
# reads its values from VALUES (P["values"], in place of the playbook's Jinja)
# and a newly issued FastDeploy token from SERVICE_TOKEN (empty: keep the
# stored one), in place of ``fd_service_token_value``. ``SystemExit`` with
# status 0 (or none) ends the script normally, as it ends ``manage.py shell``.
#
# Modes (P["mode"]):
#   check  runs the script in a transaction that is always rolled back, so
#          nothing it writes stays. Before the script first writes to a model
#          (a save, ``QuerySet.update``, a delete, a bulk write) that model's
#          rows are read; after the script they are read again. Prints
#          "unchanged" when they are the same apart from ``auto_now`` and
#          ``auto_now_add`` fields (``updated_at``) and no token is due,
#          "pending" otherwise, and "refused: <reason>" when the script raises
#          or exits with another status (a playbook refusal such as "Refusing
#          implicit reactivation", or Echoport's validation in ``save``): the
#          deploy stops before any write.
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
        try:
            exec(compile(P["script"], "<runner target script>", "exec"), namespace)
        except SystemExit as exc:
            if exc.code not in (0, None):
                raise


def rows(model):
    fields = [
        field
        for field in model._meta.concrete_fields
        if not (getattr(field, "auto_now", False) or getattr(field, "auto_now_add", False))
    ]
    return {obj.pk: tuple(field.value_from_object(obj) for field in fields) for obj in model._base_manager.all()}


class Watcher:
    """Reads a model's rows before the script first writes to it."""

    WRITES = (
        ("Model", "save_base"),
        ("Model", "delete"),
        ("QuerySet", "update"),
        ("QuerySet", "delete"),
        ("QuerySet", "bulk_create"),
        ("QuerySet", "bulk_update"),
    )

    def __init__(self):
        self.before = {}

    def touch(self, model):
        if model not in self.before:
            self.before[model] = rows(model)

    def wrap(self, owner, original):
        watcher = self

        def write(obj, *args, **kwargs):
            watcher.touch(obj.model if owner is models.QuerySet else type(obj))
            return original(obj, *args, **kwargs)

        return write

    @contextlib.contextmanager
    def installed(self):
        originals = []
        for owner_name, name in self.WRITES:
            owner = getattr(models, owner_name)
            original = getattr(owner, name)
            originals.append((owner, name, original))
            setattr(owner, name, self.wrap(owner, original))
        try:
            yield self
        finally:
            for owner, name, original in originals:
                setattr(owner, name, original)

    def changed(self):
        return any(rows(model) != before for model, before in self.before.items())


def check():
    due = token_due(P["token"]) if P.get("token") else False
    watcher = Watcher()
    with transaction.atomic():
        try:
            with watcher.installed():
                # A token that is due counts as issued: the script sees one to store.
                run_script("<new token>" if due else "")
            pending = due or watcher.changed()
        except (Exception, SystemExit) as exc:  # noqa: BLE001 - any refusal stops the deploy
            transaction.set_rollback(True)
            reason = " ".join(f"{type(exc).__name__}: {exc}".split())[:500]
            print(f"refused: {reason}")
            return
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
