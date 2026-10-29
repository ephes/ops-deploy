"""Photos component: metadata/code facts, explicit original managed stages.

No Photos library entries, ledger/log body, application, model or unrelated
operations keeper is opened. Only the library directory itself is validated.
"""

import json
import os
import pathlib
import re
import sys

from ops_photos_source import PhotosProbes, PhotosSourceError, ancestors_current, prepare_ancestors, check_checkout, require_bundle, converge_source
from ops_photos_environment import environment_current, converge_environment
from ops_photos_controls import PhotosControls
from ops_photos_resources import directories_current, resources_current, prepare_directories, apply_resources, preflight_files
from ops_photos_transfer import prepare_transfer, publish_bundle, cleanup_transfer


def prerequisites(data, controls, probes, *, gui=False):
    expected = data['uid'] if gui else 0
    if os.geteuid() != expected or probes.account.pw_uid != data['uid']:
        raise PhotosSourceError('photos_component_original_identity_required')
    for executable in ('/usr/bin/git', data['uv_bin']):
        if not pathlib.Path(executable).is_file() or not os.access(executable, os.X_OK):
            raise PhotosSourceError('photos_component_executable_unavailable')
    library = pathlib.Path(data['library'])
    # Original pwd -P equality. No listing or traversal of library contents.
    if not library.is_dir() or library.resolve(strict=True) != library:
        raise PhotosSourceError('photos_component_library_not_canonical')
    state = controls.snapshot()
    if not state['domain_available'] or state['loaded'] is None or state['disabled'] is None:
        raise PhotosSourceError('photos_component_launchd_metadata_unavailable')
    return state


def inspect(data, controls, probes):
    state = prerequisites(data, controls, probes)
    preflight_files(data)  # Reject every substituted file before any queued work.
    ancestors = ancestors_current(data, probes)
    source = check_checkout(data, probes) if ancestors else False
    bundle = False
    if ancestors:
        try:
            require_bundle(data, probes)
            bundle = True
        except PhotosSourceError as error:
            if str(error) not in {'photos_source_bundle_missing', 'photos_source_bundle_wrong_main', 'photos_source_bundle_drift'}:
                raise
    environment = environment_current(data, probes) if source else False
    quiet = state['disabled'] is True and state['loaded'] is False and state['known_absent']
    desired = (state['disabled'] is False and state['loaded'] is True) if data['launchd_enabled'] else quiet
    return {
        'source_current': bool(ancestors and source and bundle),
        'environment_current': environment,
        'directories_current': directories_current(data, probes),
        'resources_current': resources_current(data, probes),
        'quiescent': bool(quiet),
        'state_current': bool(desired),
    }


def main():
    try:
        raw = sys.stdin.buffer.read(8 * 1024 * 1024 + 1)
        if len(raw) > 8 * 1024 * 1024:
            raise ValueError()
        data = json.loads(raw)
        action = sys.argv[1]
        if action in {'prepare-transfer', 'cleanup-transfer'}:
            (prepare_transfer if action == 'prepare-transfer' else cleanup_transfer)(data)
            print(json.dumps({'current': True}))
            return
        controls, probes = PhotosControls(data), PhotosProbes(data)
        prerequisites(data, controls, probes, gui=action in {'directories', 'resources'})
        if action in {'status', 'verify'}:
            result = inspect(data, controls, probes)
            if action == 'verify' and not all(value for key, value in result.items() if key != 'quiescent'):
                raise PhotosSourceError('photos_component_not_current_after_converge')
        elif action == 'quiesce':
            result = controls.quiesce()
        elif action == 'source':
            try:
                controls.require_quiescent()
                prepare_ancestors(data, probes)
                # Admission precedes publication, including an existing checkout's
                # attestation/cleanliness and a substituted persistent bundle.
                check_checkout(data, probes)
                publish_bundle(data, controls)
                if not probes.acl_free(data['bundle']):
                    if probes.run(['/bin/chmod', '-N', data['bundle']]).returncode:
                        raise PhotosSourceError('photos_source_bundle_acl_clear_failed')
                result = converge_source(data, probes, controls)
            finally:
                cleanup_transfer(data)
        elif action == 'python':
            converge_environment(data, probes, controls)
            result = {'current': True}
        elif action == 'directories':
            prepare_directories(data, probes, controls)
            result = {'current': True}
        elif action == 'resources':
            apply_resources(data, probes, controls)
            result = {'current': True}
        elif action == 'activate':
            result = controls.activate()
        else:
            raise ValueError()
        print(json.dumps(result, sort_keys=True))
    except Exception as error:
        reason = str(error)
        if not re.fullmatch(r'photos_[a-z_]+', reason):
            reason = 'photos_component_failed'
        print(reason, file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
