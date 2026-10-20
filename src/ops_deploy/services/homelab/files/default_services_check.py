# Run by ``manage.py shell -c`` in the homelab site with ``.env`` loaded.
# Read-only: prints "current" when ``manage.py add_default_services`` would
# write nothing, "pending" when it would create or change a row or store a
# logo file. The command itself runs, with every SQL write and every file
# storage write or delete refused before it happens, inside a transaction that
# is rolled back. Any other error fails the probe (the deploy then runs the
# command and checks again).
import contextlib
import io

from django.core.files.storage import FileSystemStorage
from django.core.management import call_command
from django.db import connections, transaction

WRITES = {"insert", "update", "delete", "replace", "create", "drop", "alter"}


class WouldWrite(Exception):
    pass


def refuse_writes(execute, sql, params, many, context):
    words = str(sql).split(None, 1)
    if words and words[0].lower() in WRITES:
        raise WouldWrite()
    return execute(sql, params, many, context)


def refuse(*args, **kwargs):
    raise WouldWrite()


FileSystemStorage._save = refuse
FileSystemStorage.delete = refuse

state = "current"
with contextlib.ExitStack() as stack:
    for alias in connections:
        stack.enter_context(connections[alias].execute_wrapper(refuse_writes))
    try:
        with transaction.atomic():
            call_command("add_default_services", stdout=io.StringIO(), stderr=io.StringIO())
            transaction.set_rollback(True)
    except WouldWrite:
        state = "pending"
print(state)
