"""Original user-owned runtime code/env replacement precondition.

Metadata and declared code/lock predicates only, no profile, application,
Journal, model or private record calls. Used by the pending code installer.
"""

import os
import pathlib
import re
import subprocess

from ops_runtime_code_source import SourceProbes, checkout_shape, cleanup_transfer, inspect, publish_transfer


class RuntimeCodeError(RuntimeError):
    pass



class RuntimeCodeProbes(SourceProbes):
    def uv_environment(self, *, install=False):
        environment = {**os.environ, 'GIT_TERMINAL_PROMPT': '0', 'GIT_OPTIONAL_LOCKS': '0',
                       'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
                       'PYTHONDONTWRITEBYTECODE': '1', 'UV_NO_PROGRESS': '1',
                       'UV_PYTHON_PREFERENCE': 'only-managed',
                       'UV_PROJECT_ENVIRONMENT': self.data['checkout'] + '/.venv'}
        if not install:
            environment['UV_PYTHON_DOWNLOADS'] = 'never'
        return environment

    def run(self, argv, user=False, extra=None):
        if argv[0] != self.data['uv_bin']:
            return super().run(argv, user=user, extra=extra)
        if os.geteuid() != self.account.pw_uid:
            raise RuntimeCodeError('runtime_code_connecting_identity_mismatch')
        # Use the same inherited non-login UV context for predicates and work.
        # XDG/UV location/config variables must not disappear from find/check.
        try:
            return subprocess.run(argv, capture_output=True,
                                  env={**self.uv_environment(), **(extra or {})}, cwd='/', timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            raise RuntimeCodeError('runtime_code_probe_failed') from None

    def locked_environment_current(self):
        data = self.data
        checked = self.run([data['uv_bin'], '--directory', data['checkout'], 'sync', '--check', '--frozen', '--no-dev',
                            '--offline', '--no-python-downloads', '--no-cache', '--python', data['python_version']], user=True)
        if checked.returncode not in {0, 1}:
            raise RuntimeCodeError('runtime_code_lock_check_unavailable')
        return checked.returncode == 0

    def runtime_current(self):
        data = self.data
        # Original code.yml establishes interpreter drift before asking whether
        # the lock matches. A moved/missing selector or home is drift, never an
        # invented rc2 lock refusal before the original repair can be chosen.
        found = self.run([data['uv_bin'], 'python', 'find', '--no-project', data['python_version']], user=True)
        if found.returncode:
            return False
        expected = found.stdout.decode().strip()
        if not re.search('/cpython-' + re.escape(data['python_version']) + r'-[^/]+/bin/python[0-9.]*$', expected):
            return False
        from ops_daybook_observer import safe_file
        config = safe_file(pathlib.Path(data['checkout']) / '.venv/pyvenv.cfg')
        if config is None or re.findall(rb'(?m)^home = (.*)$', config[1]) != [str(pathlib.Path(expected).parent).encode()]:
            return False
        if not pathlib.Path(data['python']).is_file() or not os.access(data['python'], os.X_OK):
            return False
        interpreter = self.run([data['python'], '-I', '-B', '-S', '-c',
            "import sys;v='%d.%d.%d'%sys.version_info[:3];"
            "raise SystemExit(0 if v==sys.argv[1] and sys.base_prefix==sys.argv[2] else 1)",
            data['python_version'], str(pathlib.Path(expected).parent.parent)], user=True)
        if interpreter.returncode:
            return False
        return self.locked_environment_current()

    def managed(self, argv):
        if os.geteuid() != self.account.pw_uid:
            raise RuntimeCodeError('runtime_code_connecting_identity_mismatch')
        install = argv[:3] == [self.data['uv_bin'], 'python', 'install']
        result = subprocess.run(argv, capture_output=True, env=self.uv_environment(install=install), cwd='/')
        if result.returncode:
            raise RuntimeCodeError('runtime_code_command_failed')

def inspect_code(data, probes=None, *, planning=False):
    probes = probes or RuntimeCodeProbes(data)
    if data.get('owner') != 'user' or os.geteuid() != probes.account.pw_uid:
        raise RuntimeCodeError('runtime_code_connecting_identity_mismatch')
    replacing = False
    if checkout_shape(data, probes.account, planning=planning):
        head = probes.run(['/usr/bin/git', '-C', data['checkout'], 'rev-parse', 'HEAD'], user=True)
        if head.returncode == 0:
            revision = head.stdout.decode().strip()
            if not re.fullmatch(r'[0-9a-f]{40}', revision):
                raise RuntimeCodeError('runtime_code_revision_unavailable')
            replacing = revision != data['revision']
    # A readable DIFFERENT revision is removed by original code.yml, including
    # its old tracked/untracked state. Inspecting that branch must not add the
    # unrelated Sessions force:false dirty-checkout refusal before replacement.
    state = inspect({**data, 'force': replacing}, probes, planning=planning)
    if not replacing and pathlib.Path(data['checkout']).exists():
        if probes.git('status', '--porcelain', '--untracked-files=all').strip():
            raise RuntimeCodeError('runtime_code_checkout_not_clean')
    state = {**state, 'replacing': replacing}
    # Existing correct source and lock may stay in use. This is the original
    # runtime code.yml guard, not a barrier added to legacy Sessions checkouts.
    if state['current']:
        return state
    label = 'gui/' + str(probes.account.pw_uid) + '/' + data['label']
    loaded = probes.run(['/bin/launchctl', 'print', label])
    if loaded.returncode not in {0, 113}:
        raise RuntimeCodeError('runtime_code_label_unavailable')
    serving = probes.run(['/usr/bin/pgrep', '-u', data['user'], '-f', '[o]perations serve'])
    if serving.returncode not in {0, 1}:
        raise RuntimeCodeError('runtime_code_serving_unavailable')
    if loaded.returncode != 113 or serving.returncode != 1:
        raise RuntimeCodeError('runtime_code_or_environment_in_use')
    return state


def managed_python(data, probes):
    # Original optional pinned installation, not a fact or hidden preparation.
    inspect_code(data, probes)
    found = probes.run([data['uv_bin'], 'python', 'find', '--no-project', data['python_version']],
                       user=True, extra={'UV_PYTHON_PREFERENCE': 'only-managed', 'UV_PYTHON_DOWNLOADS': 'never'})
    if found.returncode:
        probes.managed([data['uv_bin'], 'python', 'install', '--no-bin', data['python_version']])
    verified = probes.run([data['uv_bin'], 'python', 'find', '--no-project', data['python_version']],
                          user=True, extra={'UV_PYTHON_PREFERENCE': 'only-managed', 'UV_PYTHON_DOWNLOADS': 'never'})
    if verified.returncode:
        raise RuntimeCodeError('runtime_code_pinned_interpreter_unavailable')



def remove_environment(probes, path):
    probes.managed(['/usr/bin/python3', '-I', '-B', '-c',
                    'import pathlib,shutil,sys;p=pathlib.Path(sys.argv[1]);'
                    'p.unlink() if p.is_symlink() else shutil.rmtree(p)', str(path)])


def apply_code(data, probes):
    try:
        state = inspect_code(data, probes)
        if state['current']:
            return
        checkout = pathlib.Path(data['checkout'])
        if state['replacing']:
            # Validated declared user-owned repository only; the original
            # Runtime role removes a readable different revision before init.
            remove_environment(probes, checkout)
        probes.managed(['/usr/bin/git', 'init', '--quiet', '--template=', str(checkout)])
        publish_transfer(data, probes)
        heads = probes.run(['/usr/bin/git', 'bundle', 'list-heads', data['bundle_path']], user=True)
        if heads.returncode or not any(line.startswith(data['revision'].encode() + b' refs/') for line in heads.stdout.splitlines()):
            raise RuntimeCodeError('runtime_code_bundle_mismatch')
        probes.managed(probes.git_command('fetch', '--quiet', '--no-tags', data['bundle_path'], '+refs/*:refs/bundle/*'))
        probes.managed(probes.git_command('checkout', '--detach', data['revision']))
        if probes.git('status', '--porcelain', '--untracked-files=all').strip():
            raise RuntimeCodeError('runtime_code_checkout_not_clean')
        managed_python(data, probes)
        found = probes.run([data['uv_bin'], 'python', 'find', '--no-project', data['python_version']], user=True,
                           extra={'UV_PYTHON_PREFERENCE': 'only-managed', 'UV_PYTHON_DOWNLOADS': 'never'})
        expected = found.stdout.decode().strip()
        if found.returncode or not re.search('/cpython-' + re.escape(data['python_version']) + r'-[^/]+/bin/python[0-9.]*$', expected):
            raise RuntimeCodeError('runtime_code_managed_interpreter_invalid')
        from ops_daybook_observer import safe_file
        config = safe_file(checkout / '.venv/pyvenv.cfg')
        home = str(pathlib.Path(expected).parent).encode()
        drift = (config is None or re.findall(rb'(?m)^home = (.*)$', config[1]) != [home]
                 or not pathlib.Path(data['python']).is_file() or not os.access(data['python'], os.X_OK))
        environment = checkout / '.venv'
        if drift and os.path.lexists(environment):
            remove_environment(probes, environment)
        if drift or not probes.locked_environment_current():
            probes.managed([data['uv_bin'], '--directory', str(checkout), *data['sync_args']])
        config = safe_file(checkout / '.venv/pyvenv.cfg')
        if config is None or re.findall(rb'(?m)^home = (.*)$', config[1]) != [home]:
            raise RuntimeCodeError('runtime_code_interpreter_home_invalid')
        if not inspect_code(data, probes)['current']:
            raise RuntimeCodeError('runtime_code_not_current_after_sync')
    finally:
        if data.get('staged_bundle'):
            cleanup_transfer(data)

def main():
    import json
    import sys
    from ops_daybook_observer import MAX_INPUT, ObservationError
    from ops_runtime_code_source import SourceError

    try:
        raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise ValueError()
        data = json.loads(raw)
        probes = RuntimeCodeProbes(data)
        action = sys.argv[1]
        if action in {'status', 'guard'}:
            state = inspect_code(data, probes, planning=True)
            print('current' if state['current'] else 'change')
        elif action == 'prepare-transfer':
            inspect_code(data, probes)
            from ops_runtime_code_source import prepare_transfer
            prepare_transfer(data)
            print('prepared')
        elif action == 'apply':
            apply_code(data, probes)
            print('current')
        elif action == 'verify':
            if not inspect_code(data, probes)['current']:
                raise RuntimeCodeError('runtime_code_not_current')
            print('current')
        else:
            raise ValueError()
    except Exception as error:
        message = str(error) if isinstance(error, (RuntimeCodeError, SourceError, ObservationError)) else 'runtime_code_unavailable'
        print(message, file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
