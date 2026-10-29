"""Original closeout effects only; no source, app, credential or launchd calls."""

import json
import os
import sys

from ops_closeout_filesystem import directory_fd, file_matches, put_resource, remove_declared_file, resource_path

MARKER = ("This machine was closed out: its original command is gone and `rollback`\n"
          "refuses. Recover inside the model -- the keeper repairs the supervisor, and a\n"
          "source that must stop is disabled on the server.\n")


def resource(data):
    return {'path': data['marker'], 'owner': data['owner'], 'group': data['group'], 'mode': 0o644, 'content': MARKER}


def exists(name):
    path = resource_path(name)
    try:
        with directory_fd(path.parent) as parent:
            os.stat(path.name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def closeout(data, action):
    marker = resource(data)
    marker_current = file_matches(marker, content=True)  # Refuse static unsafe marker before deleting backup.
    current = not exists(data['legacy_plist']) and marker_current
    if action == 'status':
        return 'current' if current else 'change'
    if action == 'apply':
        remove_declared_file(data['legacy_plist'])
        put_resource(marker)
    elif action != 'verify':
        raise ValueError()
    if exists(data['legacy_plist']) or not file_matches(marker, content=True):
        raise RuntimeError()
    return 'current' if current else 'changed'


def main():
    try:
        raw = sys.stdin.buffer.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError()
        print(closeout(json.loads(raw), sys.argv[1]))
    except Exception:
        print('runtime_closeout_unavailable', file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
