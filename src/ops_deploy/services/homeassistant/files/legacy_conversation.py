"""Original legacy-component/package metadata and one named registry selection.

No API, package import, writes or exported names/bodies. The original find walks
only the configured virtualenv/lib metadata, without following descendant links.
"""
import fnmatch
import json
import os
import stat
import sys
from pathlib import Path


def present(path):
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    return True


def inspect(config_path, virtualenv_path):
    component = present(Path(config_path) / 'custom_components/custom_conversation')
    library = Path(virtualenv_path) / 'lib'
    found = False
    skipped = 0

    def skipped_walk(error):
        nonlocal skipped
        skipped += 1

    if present(library):
        # Original find records an inaccessible/non-directory path as skipped,
        # not a deployment failure. Never expose its path/error text.
        if not library.is_dir():
            skipped += 1
        else:
            for root, directories, filenames in os.walk(library, followlinks=False, onerror=skipped_walk):
                for name in filenames + directories:
                    # Original hidden:false skips a hidden candidate itself;
                    # os.walk still descends hidden parent directories.
                    if name.startswith('.'):
                        continue
                    try:
                        metadata = os.lstat(os.path.join(root, name))
                    except OSError:
                        skipped += 1
                        continue
                    if stat.S_ISDIR(metadata.st_mode) and fnmatch.fnmatch(name, 'litellm*.dist-info'):
                        found = True
    storage = Path(config_path) / '.storage/core.config_entries'
    retire = False
    if present(storage):
        document = json.loads(storage.read_bytes())
        entries = document['data']['entries']
        if not isinstance(entries, list):
            raise ValueError('invalid entries')
        retire = any(isinstance(entry, dict) and entry.get('domain') == 'custom_conversation' for entry in entries)
    return dict(component_present=component, litellm_present=found,
                rebuild=component or found, retire=retire, skipped_metadata=skipped)


def main():
    try:
        payload = json.load(sys.stdin)
        result = inspect(payload['config_path'], payload['virtualenv_path'])
    except Exception:
        print(json.dumps({'success': False}))
        return 1
    print(json.dumps({'success': True, **result}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
