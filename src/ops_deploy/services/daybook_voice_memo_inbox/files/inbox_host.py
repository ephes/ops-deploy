"""Bound Inbox component entrypoint. Status never creates or stops anything.

No recording, ledger, activation marker, importer/application status or Journal
is opened here. Existing credential/resource expectations remain private stdin.
"""

import json
import os
import pathlib
import re
import sys

from ops_daybook_observer import NativeProbes
from ops_inbox_controls import InboxError, NativeControls, quiesce_inbox, require_inbox_quiescent, require_runtime_stopped
from ops_inbox_filesystem import ensure_directory
from ops_inbox_python import converge_python
from ops_inbox_resources import directories_current, prepare_directories, apply_resources, resources_current
from ops_inbox_source import code_matches, converge_checkout, installed_revision, require_clean_checkout
from ops_inbox_transfer import prepare_transfer, publish_bundle, cleanup_transfer


def prerequisites(data, controls):
    if os.geteuid() != 0:
        raise InboxError('inbox_requires_original_root_install')
    for executable in ('/usr/bin/git', data['uv_bin'], data['ffprobe'], data['ffmpeg']):
        if not pathlib.Path(executable).is_file() or not os.access(executable, os.X_OK):
            raise InboxError('inbox_executable_prerequisite_missing')
    result = controls.run(['/bin/launchctl', 'print', 'gui/' + str(data['uid'])])
    if result.returncode:
        raise InboxError('inbox_aqua_unavailable')


def source_current(data, probes):
    previous = installed_revision(data['checkout'])
    if previous is None:
        return False
    require_clean_checkout(data['checkout'])
    return (previous == data['revision'] and code_matches(data['checkout'], data['source_hashes'])
            and probes.runtime_current())


def inspect(data, controls, probes, *, final=True):
    prerequisites(data, controls)
    source = source_current(data, probes)
    layout = directories_current(data)
    resources = resources_current(data, final=final)
    installer_resources = resources_current(data)
    stopped = True
    try:
        require_runtime_stopped(data, controls)
    except InboxError as error:
        if str(error) != 'inbox_operations_runtime_still_running':
            raise
        stopped = False
    quiescent = False
    if stopped:
        try:
            require_inbox_quiescent(data, controls)
            quiescent = True
        except InboxError as error:
            if str(error) not in {'inbox_label_not_disabled', 'inbox_label_not_quiescent'}:
                raise
    return {'source_current': source, 'directories_current': layout,
            'resources_current': resources, 'install_resources_current': installer_resources,
            'runtime_stopped': stopped, 'quiescent': quiescent}


def main():
    try:
        raw = sys.stdin.buffer.read(8 * 1024 * 1024 + 1)
        if len(raw) > 8 * 1024 * 1024:
            raise ValueError()
        data = json.loads(raw)
        action = sys.argv[1]
        # Original connecting identity owns ordinary SFTP staging. No sudo or
        # application/account lookup is needed for these explicit operations.
        if action in {'prepare-transfer', 'cleanup-transfer'}:
            (prepare_transfer if action == 'prepare-transfer' else cleanup_transfer)(data)
            print(json.dumps({'current': True}))
            return
        controls, probes = NativeControls(), NativeProbes(data)
        if probes.account.pw_uid != data['uid'] or data['uid'] <= 0:
            raise InboxError('inbox_account_uid_mismatch')
        prerequisites(data, controls)
        if action in {'status', 'verify', 'verify-installed'}:
            if action == 'verify-installed':
                require_inbox_quiescent(data, controls)
            result = inspect(data, controls, probes, final=action != 'verify-installed')
            if action != 'status' and not all(result[key] for key in (
                    'source_current', 'directories_current', 'resources_current')):
                raise InboxError('inbox_not_current_after_converge')
        elif action == 'quiesce':
            result = {'changed': quiesce_inbox(data, controls)}
        elif action == 'directories':
            prepare_directories(data, controls)
            result = {'current': True}
        elif action == 'source':
            try:
                publish_bundle(data, controls)
                converge_checkout(data, controls)
                if installed_revision(data['checkout']) != data['revision'] or not code_matches(data['checkout'], data['source_hashes']):
                    raise InboxError('inbox_source_not_current_after_converge')
                result = {'current': True}
            finally:
                cleanup_transfer(data)
        elif action == 'python':
            require_inbox_quiescent(data, controls)
            ensure_directory({'path': data['python_install_dir'], 'owner': 'root', 'group': 'wheel', 'mode': 0o755})
            converge_python(data, controls, probes)
            result = {'current': True}
        elif action == 'smoke':
            require_inbox_quiescent(data, controls)
            # Original service-user import/help smoke is managed application
            # work, never a status fact or a purported no-I/O observation.
            for tail in (
                ['-c', 'import daybook, sqlite3, ssl'],
                ['-c', 'from daybook.cli import main; raise SystemExit(main())', 'voice-memos', '--help'],
            ):
                outcome = probes.run([data['python'], '-B', '-I', *tail], user=True)
                if outcome.returncode:
                    raise InboxError('inbox_original_application_smoke_failed')
            result = {'current': True}
        elif action == 'resources':
            apply_resources(data, controls)
            result = {'current': True}
        else:
            raise ValueError()
        print(json.dumps(result, sort_keys=True))
    except Exception as error:
        reason = str(error)
        if not re.fullmatch(r'inbox_[a-z_]+', reason):
            reason = 'inbox_component_failed'
        print(reason, file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
