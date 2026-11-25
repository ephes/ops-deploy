# Run by ``manage.py shell -c`` in the homelab site with ``.env`` loaded.
# Read-only: prints "current" when ``manage.py add_default_services`` would
# write nothing, "pending" when it would create or change a row or store a
# logo file. The command itself runs, with every SQL write and every file
# storage write or delete refused before it happens. It runs in autocommit, as
# the command requires since homelab 96f7f4e: a write is refused before it
# reaches the database, so there is nothing to roll back. Any other error fails
# the probe (the deploy then runs the command and checks again).
import contextlib
import io

from django.core.files.storage import FileSystemStorage
from django.core.management import call_command
from django.db import connections

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
        call_command("add_default_services", stdout=io.StringIO(), stderr=io.StringIO())
    except WouldWrite:
        state = "pending"
print(state)
