"""Install one pinned GoToSocial release directory (host side, run as root with python3 -I).

The role's binary.yml: download the release archive, verify its sha256 and
unpack it with ``tar --no-same-owner`` into ``<install_root>/releases/<version>``.
Here the archive is fetched and unpacked in a private staging directory next to
the release directory and renamed into place only when it is complete, so an
interrupted run never leaves a release directory that looks installed. An
existing release directory without the binary is not overwritten.

Argument: JSON with ``url``, ``sha256`` (hex) and ``release_dir``. Errors print
a fixed message only (no URL, path content or tool output).
"""
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path


class InstallError(Exception):
    pass


def main(cfg):
    release = Path(cfg['release_dir'])
    releases = release.parent
    # Root on a host (the deploy connects as root); the tests run it as themselves.
    uid, gid = os.geteuid(), os.getegid()
    info = releases.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022:
        raise InstallError('releases directory must be a root-owned directory not writable by others')
    if os.path.lexists(release / 'gotosocial'):
        return
    if os.path.lexists(release):
        if release.is_symlink() or not release.is_dir():
            raise InstallError('release path exists and is not a directory')
        if any(release.iterdir()):
            raise InstallError('release directory exists without the gotosocial binary; review it')
    work = Path(tempfile.mkdtemp(prefix='.ops-deploy-gotosocial-', dir=releases))
    try:
        archive = work / 'release.tar.gz'
        digest = hashlib.sha256()
        with urllib.request.urlopen(cfg['url'], timeout=120) as remote, archive.open('wb') as out:
            while chunk := remote.read(1024 * 1024):
                digest.update(chunk)
                out.write(chunk)
        if digest.hexdigest() != cfg['sha256']:
            raise InstallError('release archive checksum mismatch')
        tree = work / 'tree'
        tree.mkdir()
        result = subprocess.run(
            ['tar', '--extract', '--gzip', '--no-same-owner', '--file', str(archive), '--directory', str(tree)],
            capture_output=True,
        )
        if result.returncode != 0:
            raise InstallError('unpacking the release archive failed')
        binary = tree / 'gotosocial'
        if binary.is_symlink() or not binary.is_file():
            raise InstallError('release archive has no gotosocial binary')
        os.chown(tree, uid, gid)
        os.chmod(tree, 0o755)
        if os.path.lexists(release):
            release.rmdir()
        os.rename(tree, release)
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == '__main__':
    try:
        main(json.loads(sys.argv[1]))
    except Exception as exc:
        message = str(exc) if isinstance(exc, InstallError) else 'release install failed: ' + type(exc).__name__
        print(message, file=sys.stderr)
        sys.exit(1)
