"""Original Inbox resource publication using qualified descriptor primitives.

Only declared resource contents are compared in memory. No credential digest,
source recording, ledger, log content, application constructor or API is read.
All preparation/publication is explicit managed work, never a status fact.
"""


from ops_inbox_controls import require_inbox_quiescent
from ops_inbox_filesystem import (directory_matches, ensure_directory, file_matches,
                                  ensure_log, put_resource, remove_declared_file, directory_fd, resource_path)


class InboxResourceError(RuntimeError):
    pass


def directories_current(data):
    return (all(directory_matches(spec) for spec in data['directories'])
            and all(file_matches(spec) for spec in data['logs']))


def resources_current(data, *, final=False):
    specs = data['final_resources'] if final else data['resources']
    current = all(file_matches(spec, content=True) for spec in specs)
    retired = data.get('retired_long_plist')
    if retired is not None:
        # Metadata only. Deletion is separately managed after proven quiescence.
        path = resource_path(retired)
        try:
            with directory_fd(path.parent) as parent:
                import os
                os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            current = False
    return current


def prepare_directories(data, probes):
    require_inbox_quiescent(data, probes)
    for spec in data['directories']:
        ensure_directory(spec)
    for spec in data['logs']:
        ensure_log(spec)  # Never reads, truncates or touches existing log data.
    if not directories_current(data):
        raise InboxResourceError('inbox_directories_not_current_after_prepare')


def apply_resources(data, probes):
    require_inbox_quiescent(data, probes)
    if not directories_current(data):
        raise InboxResourceError('inbox_managed_directories_required')
    # Installer always publishes original disabled-first resources; final keeper
    # expectations are an observation projection, never a second writer here.
    for spec in data['resources']:
        put_resource(spec)
    retired = data.get('retired_long_plist')
    if retired is not None:
        remove_declared_file(retired)
    if not resources_current(data):
        raise InboxResourceError('inbox_resources_not_current_after_apply')
