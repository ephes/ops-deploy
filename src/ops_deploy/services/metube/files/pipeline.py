"""MeTube-only Git/uv/UI pipeline; invoked as the unprivileged service user."""
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.request


def run(argv, *, cwd=None, env=None, optional=False):
    result = subprocess.run(argv, cwd=cwd, env={**os.environ, **(env or {})}, capture_output=True, text=True)
    if result.returncode and not optional:
        # Upstream dependency logs carry no deployment secrets, but keep failures bounded.
        raise RuntimeError(f"MeTube {argv[0]} failed: {(result.stderr or result.stdout)[-1600:]}")
    return result


def git(path, *args, optional=False):
    return run(['git', '-c', 'core.hooksPath=/dev/null', '-C', str(path), *args], optional=optional)


def revision(path):
    if not (path / '.git').is_dir():
        return ''
    return git(path, 'rev-parse', 'HEAD', optional=True).stdout.strip()


def stamp(path):
    try:
        return path.read_text().strip()
    except FileNotFoundError:
        return ''


def checkout(cfg, path):
    if not (path / '.git').is_dir():
        path.mkdir(parents=True, exist_ok=True)
        git(path, 'init', '--quiet', '--template=')
        git(path, 'remote', 'add', 'origin', cfg['repo'])
    else:
        git(path, 'remote', 'set-url', 'origin', cfg['repo'])
    git(path, 'fetch', '--quiet', '--no-tags', 'origin', cfg['commit'])
    git(path, 'checkout', '--quiet', '--force', '--detach', cfg['commit'])
    if revision(path) != cfg['commit']:
        raise RuntimeError('MeTube fetched a different revision')
    if hashlib.sha256((path / 'uv.lock').read_bytes()).hexdigest() != cfg['lock_sha256']:
        raise RuntimeError('MeTube checkout lock differs from the verified candidate')


def sync(cfg, path, venv, *, dry=False):
    argv = [cfg['uv_path'], 'sync', '--frozen', '--no-dev', '--python', cfg['python_version']]
    if dry:
        argv += ['--dry-run', '--offline']
    return run(argv, cwd=path, env={'UV_PROJECT_ENVIRONMENT': str(venv), 'UV_NO_PROGRESS': '1'}, optional=dry)


def runtime_changed(cfg, path, venv):
    if not (venv / 'bin/python').exists() or not (path / 'uv.lock').is_file():
        return True
    result = sync(cfg, path, venv, dry=True)
    return result.returncode != 0 or bool(re.search(r'^Would (?:install|uninstall|replace|create|download) ', result.stdout + result.stderr, re.M))


def ui_good(path, commit):
    tree = path / 'ui/dist/metube'
    return stamp(tree / '.metube-ui-rev') == commit and (tree / 'browser/index.html').is_file()


def safe_paths(cfg):
    paths = [Path(cfg[key]) for key in ('site_path', 'build_dir', 'build_root', 'venv_path', 'stage_venv',
                                       'home', 'state_dir', 'download_dir', 'audio_download_dir', 'temp_dir')]
    for base in (Path(cfg['site_path']), Path(cfg['build_dir'])):
        paths.extend(base / suffix for suffix in ('uv.lock', 'ui/dist', 'ui/dist/metube', 'ui/dist/metube.new',
                                                  'ui/dist/metube.old', '.ops-deploy-metube-pending'))
    if any(path.resolve() != path for path in paths):
        raise RuntimeError('MeTube refuses symlink traversal in managed/retained paths')


def status(cfg, phase):
    path = Path(cfg['build_dir'] if phase == 'stage' else cfg['site_path'])
    venv = Path(cfg['stage_venv'] if phase == 'stage' else cfg['venv_path'])
    dirty = path.is_dir() and (path / '.git').is_dir() and git(path, 'diff', '--quiet', optional=True).returncode != 0
    return dirty or (phase == 'live' and (path / '.ops-deploy-metube-pending').exists()) or revision(path) != cfg['commit'] or not ui_good(path, cfg['commit']) or runtime_changed(cfg, path, venv)


def quiet(cfg):
    """Inspect only: never cancel, delete or enqueue a user's downloads."""
    with urllib.request.urlopen(cfg['health_url'] + 'history', timeout=10) as response:
        history = json.load(response)
    if not isinstance(history, dict) or not all(isinstance(history.get(k), list) for k in ('queue', 'pending', 'done')):
        raise RuntimeError('MeTube queue response is not understood')
    counts = {k: len(history[k]) for k in ('queue', 'pending', 'done')}
    if counts['queue'] or counts['pending']:
        raise RuntimeError(f'MeTube has active/queued work; retained unchanged: {counts}')
    print(json.dumps(counts))


def apply(cfg, phase):
    if phase == 'stage':
        path, venv = Path(cfg['build_dir']), Path(cfg['stage_venv'])
        checkout(cfg, path)
        # Resolve/install the exact lock before the UI build or any live source change.
        sync(cfg, path, venv)
        run([str(venv / 'bin/python'), '-I', '-c', cfg['trust_script']])
        if not ui_good(path, cfg['commit']):
            tree = path / 'ui/dist/metube'
            # A failed build must never leave a prior success stamp for this commit.
            if tree.exists():
                shutil.rmtree(tree)
            env = {'HOME': cfg['build_root'], 'CI': 'true', 'COREPACK_ENABLE_DOWNLOAD_PROMPT': '0', 'NG_CLI_ANALYTICS': 'false', 'NODE_ENV': '', 'npm_config_production': 'false'}
            ui = path / 'ui'
            if (ui / 'pnpm-lock.yaml').is_file():
                install = ['corepack', 'pnpm', 'install', '--frozen-lockfile']
                build = ['corepack', 'pnpm', 'run', 'build']
            else:
                install, build = ['npm', 'ci'], ['npm', 'run', 'build', '--']
            run(install, cwd=ui, env=env)
            run(build + ['--configuration', cfg['ui_build_configuration']], cwd=ui, env={**env, 'NODE_ENV': 'production'})
            if not (tree / 'browser/index.html').is_file():
                raise RuntimeError('MeTube UI build produced no browser/index.html')
            (tree / '.metube-ui-rev').write_text(cfg['commit'] + '\n')
        return
    stage, path = Path(cfg['build_dir']), Path(cfg['site_path'])
    if status(cfg, 'stage'):
        raise RuntimeError('MeTube staging is incomplete; live install left unchanged')
    if cfg['protect_queue'] and run(['systemctl', 'is-active', '--quiet', cfg['service_name']], optional=True).returncode == 0:
        quiet(cfg)
    (path / '.ops-deploy-metube-pending').write_text(cfg['commit'] + '\n')
    checkout(cfg, path)
    if not ui_good(path, cfg['commit']):
        parent = path / 'ui/dist'
        parent.mkdir(parents=True, exist_ok=True)
        new, old = parent / 'metube.new', parent / 'metube.old'
        for target in (new, old):
            if target.exists():
                shutil.rmtree(target)
        shutil.copytree(stage / 'ui/dist/metube', new)
        live = parent / 'metube'
        if live.exists():
            live.rename(old)
        try:
            new.rename(live)
        except BaseException:
            if old.exists():
                old.rename(live)
            raise
        if old.exists():
            shutil.rmtree(old)
    sync(cfg, path, Path(cfg['venv_path']))
    run([str(Path(cfg['venv_path']) / 'bin/python'), '-I', '-c', cfg['trust_script']])


if __name__ == '__main__':
    action, phase, data = sys.argv[1:]
    cfg = json.loads(data)
    safe_paths(cfg)
    if action == 'status':
        print('changed' if status(cfg, phase) else 'current')
    elif action == 'quiet':
        quiet(cfg)
    else:
        apply(cfg, phase)
