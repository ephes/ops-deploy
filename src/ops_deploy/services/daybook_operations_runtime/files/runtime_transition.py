"""Original attended cutover/rollback, managed app effects and local mutation.

Loaded from immutable public package bytes. No fact calls this module. Original
executor status/idle may open Journals or expire authority and remains managed.
Raw application/launchd/profile contents never appear in output or exceptions.
"""

import base64
import grp
import pwd
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import time
import types

from ops_daybook_guards import (require_profile_transition, parse_transition_status,
                               require_transition_status, require_start_status)
from ops_daybook_observer import NativeProbes, safe_file, code_current, store_count
from ops_daybook_stage import make_directory, put, validate_client
from ops_transition_filesystem import directory_fd, put_bytes, remove_declared_file

STATUS_FRAME = b'\nOPS_DAYBOOK_EXECUTOR_STDOUT='
STATUS_CAPTURE = ('import base64,subprocess,sys;'
                  'r=subprocess.run(sys.argv[1:],capture_output=True);'
                  "sys.stdout.buffer.write(b'\\nOPS_DAYBOOK_EXECUTOR_STDOUT='+base64.b64encode(r.stdout)+b'\\n');"
                  'raise SystemExit(r.returncode)')


class TransitionError(RuntimeError):
    pass


class NativeTransition(NativeProbes):
    def __init__(self, data):
        super().__init__(data)
        self.cfg = types.SimpleNamespace(**{**data, 'kinds': [types.SimpleNamespace(**kind) for kind in data['kinds']]})
        self.domain = 'gui/' + str(self.account.pw_uid)
        self.service = self.domain + '/' + data['label']

    def label(self):
        result = self.run(['/bin/launchctl', 'print', self.service])
        if result.returncode == 0:
            return result
        diagnostic = (result.stdout or b'') + (result.stderr or b'')
        if result.returncode == 113 and ('Could not find service "' + self.data['label'] + '"').encode() in diagnostic:
            return result
        raise TransitionError('runtime_transition_label_unavailable')

    def serving(self):
        result = self.run(['/usr/bin/pgrep', '-u', self.data['user'], '-f', '[o]perations serve'])
        if result.returncode not in {0, 1}:
            raise TransitionError('runtime_transition_process_probe_failed')
        return result.returncode == 0

    def source_current(self):
        if not code_current(self.data, self):
            raise TransitionError('runtime_transition_source_not_current')

    def previous(self):
        found = safe_file(self.data['policy'])
        return json.loads(found[1]) if found is not None else None

    def closed_out(self):
        path = pathlib.Path(self.data['closeout_marker'])
        try:
            with directory_fd(path.parent) as parent:
                info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return False
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise TransitionError('runtime_transition_closeout_marker_invalid')
        return True

    def client(self, command):
        data = self.data
        tail = [data['python'], '-I', '-c', 'from daybook.cli import main; raise SystemExit(main())',
                'operations', command, '--policy', data['policy'], '--policy-owner', data['owner'],
                '--binding', data['binding']]
        argv = [data['python'], '-I', '-c', STATUS_CAPTURE, *tail]
        if os.geteuid() != self.account.pw_uid:
            argv = ['/usr/bin/sudo', '-H', '-S', '-n', '-i', '-u', data['user'], '--', *argv]
        # Original GUI-account login context/application bounds, no invented
        # whole-call timeout, retries or fallback to monitor-purpose credentials.
        result = subprocess.run(argv, capture_output=True, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        if result.returncode:
            raise TransitionError('runtime_transition_client_failed')
        if command == 'idle':
            return None  # Original idle proof uses only the genuine exit status.
        try:
            _, separator, framed = result.stdout.rpartition(STATUS_FRAME)
            if not separator:
                raise ValueError()
            raw = base64.b64decode(framed.split(b'\n', 1)[0], validate=True)
            return parse_transition_status(json.loads(raw))
        except (ValueError, KeyError, TypeError, RecursionError):
            raise TransitionError('runtime_transition_status_invalid') from None

    def old_store_empty(self):
        data = self.data
        return (store_count(pathlib.Path(data['journal']) / 'deliveries', data['user'], 'staff') == 0
                and store_count(pathlib.Path(data['journal']) / 'halts', data['user'], 'staff') == 0)

    def prepare_resources(self):
        data = self.data
        import grp
        gid = grp.getgrnam('staff').gr_gid
        for path in (pathlib.Path(data['journal']), pathlib.Path(data['journal']) / 'deliveries',
                     pathlib.Path(data['journal']) / 'halts', pathlib.Path(data['credential']).parent):
            make_directory(path, self.account.pw_uid, gid)
        # Original credential and candidate staging precedes the label transition.
        for row in data['resources']:
            if row['path'] not in {data['policy'], data['plist']}:
                put(row)

    def disable(self):
        if self.run(['/bin/launchctl', 'disable', self.service]).returncode:
            raise TransitionError('runtime_transition_disable_failed')

    def unload_idle(self):
        # Exact original 75 retries / five-second legacy-label idle window.
        # A keeper/serve was already refused before mutation, never waited out.
        for attempt in range(76):
            label = self.label()
            if label.returncode == 113 or not re.search(rb'state = (running|spawning)', label.stdout):
                break
            if attempt == 75:
                raise TransitionError('runtime_transition_legacy_label_not_idle')
            time.sleep(5)
        if label.returncode == 0 and self.run(['/bin/launchctl', 'bootout', self.service]).returncode:
            raise TransitionError('runtime_transition_bootout_failed')
        if self.label().returncode != 113:
            raise TransitionError('runtime_transition_label_not_unloaded')

    def command_bytes(self, path, resource):
        """Only the two declared command resources; metadata before body read."""
        path = pathlib.Path(path)
        try:
            with directory_fd(path.parent) as parent:
                descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        except FileNotFoundError:
            return None
        try:
            before = os.fstat(descriptor)
            expected = (pwd.getpwnam(resource['owner']).pw_uid, grp.getgrnam(resource['group']).gr_gid, 0o644)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 1024 * 1024
                    or (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) != expected):
                raise TransitionError('runtime_transition_command_boundary_invalid')
            chunks, remaining = [], 1024 * 1024 + 1
            while remaining:
                body = os.read(descriptor, min(remaining, 65536))
                if not body:
                    break
                chunks.append(body)
                remaining -= len(body)
            after = os.fstat(descriptor)
            fields = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            if not remaining or any(getattr(before, key) != getattr(after, key) for key in fields):
                raise TransitionError('runtime_transition_command_changed_during_read')
            return b''.join(chunks)
        finally:
            os.close(descriptor)

    def select_command(self):
        data = self.data
        live, saved = pathlib.Path(data['plist']), pathlib.Path(data['legacy_plist'])
        live_resource = next(row for row in data['resources'] if row['path'] == str(live))
        old = self.command_bytes(live, live_resource)
        saved_body = self.command_bytes(saved, live_resource)
        if data['action'] == 'cutover':
            if old is not None and saved_body is None and not self.closed_out():
                # Qualified no-replace primitive preserves the first rollback
                # command even if another original actor wins publication.
                put_bytes({**live_resource, 'path': str(saved)}, old, replace=False)
                self.command_bytes(saved, live_resource)  # Validate an actual winner, never overwrite it.
            put(live_resource)
            return True
        if saved_body is None:
            remove_declared_file(str(live))
            return False
        # Original remote copy accepts binary plists too; do not decode or
        # transform the saved command's private bytes into a text-only contract.
        if old != saved_body:
            put_bytes(live_resource, saved_body)
        return True

    def validate_commands(self):
        resource = next(row for row in self.data['resources'] if row['path'] == self.data['plist'])
        self.command_bytes(self.data['plist'], resource)
        self.command_bytes(self.data['legacy_plist'], resource)

    def publish_policy(self):
        put(next(row for row in self.data['resources'] if row['path'] == self.data['policy']))
        validate_client(self.data, self, pure=False)  # Original managed constructor, no relabelled fact.

    def start(self, has_command):
        data = self.data
        ready = self.client('status')
        require_start_status(data['action'], ready)
        if self.run(['/bin/launchctl', 'enable', self.service]).returncode:
            raise TransitionError('runtime_transition_enable_failed')
        if has_command and self.run(['/bin/launchctl', 'bootstrap', self.domain, data['plist']]).returncode:
            raise TransitionError('runtime_transition_bootstrap_failed')


def transition(driver):
    cfg = driver.cfg
    if cfg.action not in {'cutover', 'rollback'} or not cfg.confirmed:
        raise TransitionError('runtime_transition_original_confirmation_required')
    driver.source_current()
    previous = driver.previous()
    label = driver.label()
    serving = driver.serving()
    closed = driver.closed_out()
    require_profile_transition(cfg, previous, closed_out=closed, label_loaded=label.returncode == 0, serving=serving)
    if (label.returncode == 0 and re.search(rb'(?m)^\s*(serve|host-keep)\s*$', label.stdout)) or serving:
        raise TransitionError('runtime_transition_requires_quiescence')
    # Static original-command rails must refuse before any staging/disable or
    # bootout; select_command rechecks after the original idle/unload window.
    driver.validate_commands()
    if previous is not None:
        require_transition_status(cfg.action, driver.client('status'))
    driver.prepare_resources()
    driver.disable()
    driver.unload_idle()
    if cfg.action == 'rollback' and not driver.old_store_empty():
        raise TransitionError('runtime_transition_rollback_store_not_drained')
    driver.client('idle')
    has_command = driver.select_command()
    driver.publish_policy()
    if cfg.start:
        driver.start(has_command)
    return {'transitioned': True, 'started': bool(cfg.start and has_command)}


def main():
    try:
        raw = sys.stdin.buffer.read(8 * 1024 * 1024 + 1)
        if len(raw) > 8 * 1024 * 1024:
            raise ValueError()
        data = json.loads(raw)
        print(json.dumps(transition(NativeTransition(data)), sort_keys=True))
    except Exception as error:
        category = str(error)
        if not re.fullmatch(r'runtime_[a-z_]+', category):
            category = 'runtime_transition_failed'
        print(category, file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
