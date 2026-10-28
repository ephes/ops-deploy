"""Original protected Inbox Python convergence, explicit managed actions only.

The caller must bind the typed original layout and exact source before these
functions. Child diagnostics remain private in memory. No importer, Journal,
activation, model, recording or credential operation belongs in this module.
"""

import grp
import hashlib
import os
import pathlib
import re
import stat
import subprocess
import uuid

from ops_inbox_controls import require_inbox_quiescent
from ops_daybook_observer import safe_file


class InboxPythonError(RuntimeError):
    pass


def root_environment(data, *, downloads=False):
    expected = pathlib.Path(data['checkout']).parent.parent / 'python'
    if pathlib.Path(data['python_install_dir']) != expected:
        raise InboxPythonError('inbox_python_tree_mismatch')
    env = {'HOME': '/var/root', 'UV_NO_PROGRESS': '1',
           'UV_PYTHON_INSTALL_DIR': str(expected), 'UV_PYTHON_PREFERENCE': 'only-managed',
           'UV_PROJECT_ENVIRONMENT': str(pathlib.Path(data['checkout']) / '.venv')}
    if not downloads:
        env['UV_PYTHON_DOWNLOADS'] = 'never'
    return env


def managed(data, argv, *, cwd=None, downloads=False):
    environment = {**os.environ, **root_environment(data, downloads=downloads),
                   'PYTHONDONTWRITEBYTECODE': '1'}
    # No invented outer deadline for original managed Python install/sync.
    result = subprocess.run(argv, cwd=cwd, env=environment, capture_output=True)
    if result.returncode:
        raise InboxPythonError('inbox_python_managed_command_failed')
    return result.stdout


def require_root_inputs(data):
    """Managed-UV admission mirrors the qualified observer's metadata rails.

    Unlike final observation, first installation can lack a pyvenv.cfg. No UV
    query/build is allowed to execute from writable existing root code or .pth.
    """
    checkout = pathlib.Path(data['checkout'])
    roots = (checkout, pathlib.Path(data['python_install_dir']))
    boundary = checkout.parent.parent
    locks = {checkout / '.venv/.lock', roots[1] / '.lock'}
    def unavailable(error):
        raise error
    for root in roots:
        for path in (root, *root.parents):
            info = path.lstat()
            protected = path == boundary or boundary in path.parents
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                    or info.st_mode & 0o022 and (protected or not info.st_mode & stat.S_ISVTX)):
                raise InboxPythonError('inbox_python_root_inputs_unsafe')
        for parent, directories, names in os.walk(root, followlinks=False, onerror=unavailable):
            for name in [*directories, *names]:
                path = pathlib.Path(parent) / name
                info = path.lstat()
                if info.st_uid != 0:
                    raise InboxPythonError('inbox_python_root_inputs_unsafe')
                if path in locks:
                    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o111):
                        raise InboxPythonError('inbox_python_root_inputs_unsafe')
                elif stat.S_ISLNK(info.st_mode):
                    target = path.resolve(strict=True)
                    if not any(target == owned or owned in target.parents for owned in roots):
                        raise InboxPythonError('inbox_python_root_inputs_unsafe')
                elif not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)) or info.st_mode & 0o022:
                    raise InboxPythonError('inbox_python_root_inputs_unsafe')


def interpreter_source(data, probes):
    require_root_inputs(data)
    source = managed(data, [data['uv_bin'], 'python', 'find', '--no-project', data['python_version']]).decode().strip()
    pattern = re.escape(data['python_install_dir'] + '/cpython-' + data['python_version']) + r'-[^/]+/bin/python3\.14'
    if not re.fullmatch(pattern, source):
        raise InboxPythonError('inbox_python_source_path_invalid')
    digest = probes.protected_binary_hash(source, copied=False)
    if digest is None:
        raise InboxPythonError('inbox_python_source_boundary_invalid')
    return pathlib.Path(source), digest


def copy_interpreter(data, source, digest, probes):
    """Publish a regular root-owned single-link0755 copy, never follow venv link."""
    destination = pathlib.Path(data['python'])
    parent = destination.parent
    boundary = pathlib.Path(data['checkout']).parent.parent
    for path in (parent, *parent.parents):
        info = path.lstat()
        protected = path == boundary or boundary in path.parents
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o022 and (protected or not info.st_mode & stat.S_ISVTX)):
            raise InboxPythonError('inbox_python_copy_parent_invalid')
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = '.inbox-python-' + uuid.uuid4().hex
    source_fd = target_fd = None
    published = False
    try:
        source_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        source_before = os.fstat(source_fd)
        if (not stat.S_ISREG(source_before.st_mode) or source_before.st_uid != 0
                or source_before.st_mode & 0o022 or not 0 < source_before.st_size <= 256 * 1024 * 1024):
            raise InboxPythonError('inbox_python_copy_source_invalid')
        target_fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o755, dir_fd=parent_fd)
        hashed = hashlib.sha256()
        remaining = source_before.st_size + 1
        while remaining:
            body = os.read(source_fd, min(65536, remaining))
            if not body:
                break
            remaining -= len(body)
            hashed.update(body)
            view = memoryview(body)
            while view:
                written = os.write(target_fd, view)
                if written <= 0:
                    raise InboxPythonError('inbox_python_copy_failed')
                view = view[written:]
        source_after = os.fstat(source_fd)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_uid', 'st_mode')
        if (remaining == 0 or hashed.digest() != digest
                or any(getattr(source_before, key) != getattr(source_after, key) for key in fields)):
            raise InboxPythonError('inbox_python_source_changed_during_copy')
        os.fchown(target_fd, 0, grp.getgrnam('wheel').gr_gid)
        os.fchmod(target_fd, 0o755)
        os.fsync(target_fd)
        os.close(target_fd)
        target_fd = None
        os.replace(temporary, destination.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        published = True
    finally:
        if source_fd is not None:
            os.close(source_fd)
        if target_fd is not None:
            os.close(target_fd)
        if not published:
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)
    if probes.protected_binary_hash(str(destination), copied=True) != digest:
        raise InboxPythonError('inbox_python_installed_copy_boundary_invalid')


def converge_python(data, controls, probes):
    """Original root install -> frozen sync -> regular-copy boundary, no app call."""
    if os.geteuid() != 0:
        raise InboxPythonError('inbox_python_requires_original_root_install')
    require_inbox_quiescent(data, controls)
    tree = pathlib.Path(data['python_install_dir'])
    # Managed directory preparation belongs to the full controller, not a fact.
    if (not tree.is_dir() or tree.is_symlink() or tree.stat().st_uid != 0
            or tree.stat().st_mode & 0o022):
        raise InboxPythonError('inbox_python_managed_tree_required')
    require_root_inputs(data)
    managed(data, [data['uv_bin'], 'python', 'install', '--no-bin', data['python_version']], downloads=True)
    source, digest = interpreter_source(data, probes)
    checkout = pathlib.Path(data['checkout'])
    configuration = checkout / '.venv/pyvenv.cfg'
    found = safe_file(configuration)
    contents = found[1] if found is not None else None
    if contents is not None and re.findall(rb'(?m)^home = (.*)$', contents) != [str(source.parent).encode()]:
        import shutil
        shutil.rmtree(checkout / '.venv')  # Original quiesced, state-free environment replacement.
    require_root_inputs(data)
    managed(data, [data['uv_bin'], 'sync', '--frozen', '--no-dev', '--python', data['python_version']], cwd=checkout)
    found = safe_file(configuration)
    if found is None or re.findall(rb'(?m)^home = (.*)$', found[1]) != [str(source.parent).encode()]:
        raise InboxPythonError('inbox_python_synchronized_home_mismatch')
    copy_interpreter(data, source, digest, probes)
    if not probes.runtime_current():
        raise InboxPythonError('inbox_python_runtime_not_current_after_sync')
