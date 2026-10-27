"""Compare without writes; validate complete Unbound candidate before owned changes."""
import glob
import json
import re
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile

OWNED = {
    '/etc/unbound/unbound.conf.d/00-base.conf',
    '/etc/unbound/unbound.conf.d/05-forward-zones.conf',
    '/etc/unbound/unbound.conf.d/06-local-records.conf',
    '/etc/unbound/unbound.conf.d/10-split-dns.conf',
    '/var/lib/unbound/allowlist.conf',
}


def run(args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def state(path):
    p = Path(path)
    if p.is_symlink() or (p.exists() and not p.is_file()):
        raise ValueError('managed DNS path is not a regular file')
    if not p.exists():
        return None
    s = p.stat()
    return (p.read_bytes(), stat.S_IMODE(s.st_mode), s.st_uid, s.st_gid)


def replace(path, value):
    p = Path(path)
    if value is None:
        p.unlink(missing_ok=True)
        return
    content, mode, uid, gid = value
    fd, temporary = tempfile.mkstemp(prefix='.dns-', dir=p.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
            os.fchmod(f.fileno(), mode)
            os.fchown(f.fileno(), uid, gid)
        os.replace(temporary, p)
    finally:
        Path(temporary).unlink(missing_ok=True)


def stage_includes(root):
    """Walk the actual include graph, independent of filename extension.

    Every absolute include/glob points into the candidate, including unrelated
    external includes. Relative or malformed includes are refused rather than
    accidentally validating the live tree under ambiguous working directories.
    """
    pending = ['/etc/unbound/unbound.conf']
    visited = set()
    pattern = re.compile(r'^(\s*include(?:-toplevel)?\s*:\s*)(?:"([^"]+)"|(\S+))(\s*(?:#.*)?)$')
    while pending:
        original = pending.pop()
        if original in visited:
            continue
        visited.add(original)
        candidate = root / original.lstrip('/')
        text = candidate.read_text()
        lines = []
        for line in text.splitlines(keepends=True):
            match = pattern.fullmatch(line.rstrip('\n'))
            if match:
                include = match.group(2) or match.group(3)
                if not include.startswith('/') or '..' in Path(include).parts:
                    raise ValueError('DNS candidate requires absolute include paths')
                inside = include.startswith(('/etc/unbound/', '/var/lib/unbound/'))
                if not inside:
                    for source in glob.glob(include):
                        source_path = Path(source)
                        if not source_path.is_file():
                            raise ValueError('DNS include is not a regular file')
                        dest = root / source.lstrip('/')
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        if not dest.exists():
                            shutil.copy2(source, dest)
                staged_pattern = str(root / include.lstrip('/'))
                pending.extend('/' + str(Path(p).relative_to(root)) for p in glob.glob(staged_pattern))
                line = match.group(1) + '"' + staged_pattern + '"' + match.group(4) + ('\n' if line.endswith('\n') else '')
            elif re.match(r'^\s*include(?:-toplevel)?\s*:', line):
                raise ValueError('unsupported DNS include syntax')
            else:
                # Trust anchors and the declared working directory are also
                # read from the staged copy. Only include directives add edges.
                for prefix in ('/etc/unbound', '/var/lib/unbound'):
                    line = line.replace(prefix, str(root / prefix.lstrip('/')))
            lines.append(line)
        candidate.write_text(''.join(lines))


def main(request):
    desired = request['files']
    if set(desired) != OWNED:
        raise ValueError('unexpected DNS managed paths')
    originals = {p: state(p) for p in desired}
    # Package account may not exist yet during first planning.
    try:
        unbound = pwd.getpwnam('unbound')
        owner = (unbound.pw_uid, unbound.pw_gid)
    except KeyError:
        owner = (-1, -1)
    candidates = {
        p: None if text is None else (text.encode(), 0o644, *(owner if p.startswith('/var/') else (0, 0)))
        for p, text in desired.items()
    }
    changed = [p for p in desired if originals[p] != candidates[p]]
    if not changed:
        print('changed=false')
        return
    if not request.get('apply'):
        print('changed=true')
        return
    if owner == (-1, -1):
        raise ValueError('Unbound package account is missing')
    active = subprocess.run(['systemctl', 'is-active', '--quiet', 'unbound']).returncode == 0
    # A whole config-tree copy includes package files and unrelated operator snippets.
    # Generated blocklists and the trust anchor are copied for validation only.
    with tempfile.TemporaryDirectory(prefix='ops-dns-') as temp:
        root = Path(temp)
        for tree in ('/etc/unbound', '/var/lib/unbound'):
            shutil.copytree(tree, root / tree.lstrip('/'), symlinks=False)
        for p, text in desired.items():
            candidate = root / p.lstrip('/')
            if text is None:
                candidate.unlink(missing_ok=True)
            else:
                candidate.write_text(text)
        stage_includes(root)
        run(['unbound-checkconf', str(root / 'etc/unbound/unbound.conf')])
        installed = []
        try:
            for p in changed:
                replace(p, candidates[p])
                installed.append(p)
            run(['systemctl', 'restart' if active else 'start', 'unbound'])
            for address, expected in request['probes']:
                answer = run(['dig', '@' + address, request['probe_name'], 'A', '+short', '+time=3', '+tries=1'])
                if expected not in answer.splitlines():
                    raise ValueError('DNS candidate response mismatch')
        except BaseException:
            for p in reversed(installed):
                replace(p, originals[p])
            if active:
                run(['systemctl', 'restart', 'unbound'])
            else:
                run(['systemctl', 'stop', 'unbound'])
            raise
    print('changed=true')


if __name__ == '__main__':
    try:
        main(json.load(sys.stdin))
    except subprocess.CalledProcessError as error:
        print('DNS validation/activation command failed: ' + Path(error.cmd[0]).name + ' exit ' + str(error.returncode), file=sys.stderr)
        sys.exit(1)
    except Exception:
        # No candidate data or credential-bearing payload in error output.
        print('DNS configuration validation/apply failed', file=sys.stderr)
        sys.exit(1)
