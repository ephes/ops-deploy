"""Host-side release probe/install/commit. Stdout contains status words only."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request


class NativeError(Exception):
    pass


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def state(cfg):
    directory = Path(cfg['state_dir'])
    for part in (directory.parent, directory):
        if part.exists() or part.is_symlink():
            info = part.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise NativeError('state directory must be a real root-owned private directory')
    if directory.exists() and directory.stat().st_mode & 0o077:
        raise NativeError('service state directory must be root-only')
    path = directory / 'applied.json'
    if path.is_symlink():
        raise NativeError('applied state must not be a symlink')
    return json.loads(path.read_text()) if path.exists() else None


def source_record(cfg):
    source = cfg['source']
    if source is None:
        return None
    path = Path(source['dest'])
    return {'identity': source, 'binary_sha256': digest(path)}


def main(mode, cfg):
    applied = state(cfg)
    source = cfg['source']
    if mode == 'probe':
        if source is None:
            print('current' if applied else 'adopt')
            return
        binary = Path(source['dest'])
        if not binary.exists():
            print('install')
            return
        if binary.is_symlink() or not binary.is_file():
            raise NativeError('release destination must be a regular file')
        info = binary.stat()
        if info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise NativeError('unsafe release owner or write permissions; review before executing or replacing it')
        record = source_record(cfg)
        previous = applied.get('source') if applied else None
        same_content = previous is not None and previous['binary_sha256'] == record['binary_sha256']
        managed_drift = previous is not None and previous['identity'] == source and not same_content
        # An unchanged digest attests the version adopted/installed previously.
        # Changed content must still be version-probed: a manual newer release
        # must never be overwritten, including when its file mode also drifted.
        if same_content:
            versions = [previous['identity']['version']]
        else:
            try:
                result = subprocess.run([str(binary), *source['version_args']], capture_output=True, text=True, timeout=15)
                versions = re.findall(r'(?<![0-9.])[0-9]+(?:\.[0-9]+)+(?![0-9.])', result.stdout) if result.returncode == 0 else []
            except (OSError, subprocess.TimeoutExpired, UnicodeDecodeError):
                versions = []
        if not versions:
            if managed_drift:
                # No recognizable version: restore the previously approved pin
                # only for a tracked binary whose content actually changed.
                print('install')
                return
            raise NativeError('unmanaged installed release version is unrecognized')
        if any(tuple(map(int, v.split('.'))) > tuple(map(int, source['version'].split('.'))) for v in versions):
            raise NativeError('refusing release downgrade')
        if source['version'] not in versions or stat.S_IMODE(info.st_mode) != 0o755:
            print('install')
            return
        record = source_record(cfg)
        if applied is None or applied.get('source') is None:
            print('adopt')
        elif applied['source'] != record:
            print('install')
        else:
            print('current')
    elif mode == 'install':
        dest = Path(source['dest'])
        # Named members are read individually, never extracted onto the filesystem.
        # Neither traversal, symlinks nor device members can escape the staging dir.
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / 'release.tar.gz'
            with urllib.request.urlopen(source['url'], timeout=120) as remote, archive.open('wb') as stream:
                while chunk := remote.read(1024 * 1024):
                    stream.write(chunk)
            if digest(archive) != source['checksum']:
                raise NativeError('release archive checksum mismatch')
            with tarfile.open(archive, 'r:gz') as tar:
                member = tar.getmember(source['member'])
                if not member.isfile():
                    raise NativeError('release member must be a regular file')
                reader = tar.extractfile(member)
                if reader is None:
                    raise NativeError('release member cannot be read')
                fd, staged = tempfile.mkstemp(prefix='.ops-deploy-release-', dir=dest.parent)
                try:
                    with os.fdopen(fd, 'wb') as stream, reader:
                        while chunk := reader.read(1024 * 1024):
                            stream.write(chunk)
                        stream.flush()
                        os.fsync(stream.fileno())
                        os.fchmod(stream.fileno(), 0o755)
                        os.fchown(stream.fileno(), 0, 0)
                    candidate = subprocess.run([staged, *source['version_args']], capture_output=True, text=True, timeout=15)
                    versions = re.findall(r'(?<![0-9.])[0-9]+(?:\.[0-9]+)+(?![0-9.])', candidate.stdout)
                    if candidate.returncode or source['version'] not in versions:
                        raise NativeError('verified archive member reports an unexpected version')
                    os.replace(staged, dest)
                finally:
                    Path(staged).unlink(missing_ok=True)
    elif mode == 'commit':
        record = {'source': source_record(cfg)}
        path = Path(cfg['state_dir']) / 'applied.json'
        fd, staged = tempfile.mkstemp(prefix='.applied-', dir=path.parent)
        try:
            with os.fdopen(fd, 'w') as stream:
                json.dump(record, stream, sort_keys=True)
                stream.write('\n')
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(staged, path)
        finally:
            Path(staged).unlink(missing_ok=True)
    else:
        raise NativeError('unknown action')


if __name__ == '__main__':
    try:
        main(sys.argv[1], json.loads(sys.argv[2]))
    except Exception as exc:
        # No argv, archive URL, config or subprocess output in failures.
        print(str(exc) if isinstance(exc, NativeError) else 'native release operation failed', file=sys.stderr)
        sys.exit(1)
