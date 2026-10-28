"""Per-run existing-identity SFTP, checked root publication, explicit cleanup.

No directory creation in facts. Preparation and root publication are managed;
cleanup removes only this UUID directory and its exact declared bundle member.
"""

import hashlib
import os
import pathlib
import re
import stat
import uuid

from ops_inbox_filesystem import directory_fd
from ops_inbox_controls import require_inbox_quiescent


class InboxTransferError(RuntimeError):
    pass


def transfer_path(data):
    path = pathlib.Path(data['transfer_dir'])
    if (path.parent not in {pathlib.Path('/private/var/tmp'), pathlib.Path('/tmp')}
            or not re.fullmatch(r'ops-deploy-daybook-inbox-[0-9a-f]{32}', path.name)
            or pathlib.Path(data['uploaded_bundle']) != path / 'source.bundle'
            or type(data['transfer_uid']) is not int or data['transfer_uid'] < 0
            or not re.fullmatch(r'[0-9a-f]{64}', data['bundle_sha256'])):
        raise InboxTransferError('inbox_transfer_declaration_invalid')
    return path


def prepare_transfer(data):
    path = transfer_path(data)
    if os.geteuid() != data['transfer_uid']:
        raise InboxTransferError('inbox_transfer_identity_mismatch')
    with directory_fd(path.parent) as parent:
        info = os.fstat(parent)
        if info.st_uid not in {0, os.geteuid()} or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
            raise InboxTransferError('inbox_transfer_parent_invalid')
        os.mkdir(path.name, 0o700, dir_fd=parent)
        try:
            with directory_fd(path) as made:
                os.fchmod(made, 0o700)
        except BaseException:
            os.rmdir(path.name, dir_fd=parent)
            raise


def checked_directory(data):
    path = transfer_path(data)
    return directory_fd(path)


def publish_bundle(data, controls):
    if os.geteuid() != 0:
        raise InboxTransferError('inbox_transfer_original_root_required')
    require_inbox_quiescent(data, controls)
    destination = pathlib.Path(data['bundle'])
    with checked_directory(data) as directory, directory_fd(destination.parent) as parent:
        origin = os.fstat(directory)
        protected = os.fstat(parent)
        if origin.st_uid != data['transfer_uid'] or stat.S_IMODE(origin.st_mode) != 0o700:
            raise InboxTransferError('inbox_transfer_directory_invalid')
        if protected.st_uid != 0 or protected.st_mode & 0o022:
            raise InboxTransferError('inbox_transfer_install_parent_invalid')
        source = os.open('source.bundle', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        temporary = '.inbox-bundle-' + uuid.uuid4().hex
        output = None
        try:
            before = os.fstat(source)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_uid != data['transfer_uid'] or stat.S_IMODE(before.st_mode) != 0o600
                    or not 0 < before.st_size <= 512 * 1024 * 1024):
                raise InboxTransferError('inbox_transfer_bundle_invalid')
            output = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            hashed = hashlib.sha256()
            remaining = before.st_size + 1
            while remaining:
                body = os.read(source, min(65536, remaining))
                if not body:
                    break
                remaining -= len(body)
                hashed.update(body)
                view = memoryview(body)
                while view:
                    written = os.write(output, view)
                    if written <= 0:
                        raise InboxTransferError('inbox_transfer_copy_failed')
                    view = view[written:]
            after = os.fstat(source)
            fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_uid', 'st_mode', 'st_nlink')
            if (not remaining or hashed.hexdigest() != data['bundle_sha256']
                    or any(getattr(before, key) != getattr(after, key) for key in fields)):
                raise InboxTransferError('inbox_transfer_source_changed')
            os.fchmod(output, 0o600)
            os.fsync(output)
            os.close(output)
            output = None
            os.replace(temporary, destination.name, src_dir_fd=parent, dst_dir_fd=parent)
        finally:
            os.close(source)
            if output is not None:
                os.close(output)
            try:
                os.unlink(temporary, dir_fd=parent)
            except FileNotFoundError:
                pass


def cleanup_transfer(data):
    path = transfer_path(data)
    if os.geteuid() not in {0, data['transfer_uid']}:
        raise InboxTransferError('inbox_transfer_identity_mismatch')
    with directory_fd(path.parent) as parent:
        try:
            with directory_fd(path) as directory:
                info = os.fstat(directory)
                if info.st_uid != data['transfer_uid'] or stat.S_IMODE(info.st_mode) != 0o700:
                    raise InboxTransferError('inbox_transfer_directory_invalid')
                try:
                    os.unlink('source.bundle', dir_fd=directory)
                except FileNotFoundError:
                    pass
            os.rmdir(path.name, dir_fd=parent)
        except FileNotFoundError:
            pass
