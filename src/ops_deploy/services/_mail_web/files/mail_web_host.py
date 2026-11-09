"""Narrow mail-web admission and activation. Nothing is staged on a no-op."""

def main(q):
    if q['app'] not in ('postfixadmin','snappymail'):
        raise ValueError('unknown mail web application')
    schema_admission(q)
    code_changed=release_needed(q)
    seed_needed=needs_seed(q)
    credentials=credential_state(q)
    grants_changed=app_grants(q)
    desired=desired_files(q,credentials)
    current={p:file_state(p) for p in desired}
    changed=[p for p in desired if desired[p]!=current[p]]
    database_changed=q['app']=='postfixadmin' and (credentials.get('schema') is None or credentials['admin_changed'] or credentials['mapping_changed'])
    fpm='php'+q['php']+'-fpm'
    active={u:service_active(u) for u in (fpm,'nginx')}
    needs=bool(seed_needed or code_changed or changed or database_changed or grants_changed or not all(active.values()))
    if not needs:
        print('changed=false')
        return
    if not q.get('apply'):
        print('changed=true')
        return
    q['peer_health']=peer_health(q)
    credentials=credential_state(q,apply=True)
    desired=desired_files(q,credentials)
    with tempfile.TemporaryDirectory(prefix='mail-web-') as temporary:
        stage=Path(temporary)
        tree=extract_release(q,stage) if code_changed or seed_needed else None
        if tree is not None:
            values=code_values(q,tree) if code_changed else {}
            values.update(seed_values(q,tree))
            values.update(desired)
        else:values=desired
        originals={p:file_state(p) for p in values}
        changes={p:v for p,v in values.items() if originals[p]!=v}
        stage_context(q,stage/'candidate',desired)
        # Archive/vendor bytes and all candidate syntax have passed before writes.
        created_dirs=[];installed=[]
        try:
            if code_changed and active[fpm]:run(['systemctl','stop',fpm])
            for path,value in changes.items():
                if value is not None:
                    missing=[];parent=Path(path).parent
                    while not parent.exists():missing.append(parent);parent=parent.parent
                    for parent in reversed(missing):
                        safe_parents(parent);parent.mkdir(mode=0o755);created_dirs.append(parent)
                        if q['app']=='snappymail' and (str(parent)==q['data'] or str(parent).startswith(q['data']+'/')):
                            os.chown(parent,*identity(q['user'],q['group']));os.chmod(parent,0o750)
                replace_file(path,value);installed.append(path)
            if q['app']=='postfixadmin':
                app_grants(q,apply=True)
                if credentials.get('schema') is None:
                    p=subprocess.run(['runuser','-u',q['web_user'],'--','/usr/bin/php'+q['php'],'public/upgrade.php'],cwd=q['root'],capture_output=True,text=True,timeout=120)
                    if p.returncode:raise ValueError('mail web upstream fresh schema initialization failed')
                    check=credential_state(q)
                    if check.get('schema')!='1851':raise ValueError('mail web schema initialization did not reach selected version')
            activate(q,changes,code_changed,active)
            if q['app']=='postfixadmin' and database_changed:
                credential_state(q,reconcile=True)
        except BaseException:
            # Attempt every owned restore independently; retain the original cause.
            for path in reversed(installed):
                try:replace_file(path,originals[path])
                except Exception:print('mail web owned-file recovery failed',file=sys.stderr)
            for directory in reversed(created_dirs):
                try:directory.rmdir()
                except OSError:pass
            for unit in (fpm,'nginx'):
                try:
                    if active[unit]:run(['systemctl','restart' if unit==fpm else 'reload',unit])
                    elif service_active(unit):run(['systemctl','stop',unit])
                except Exception:print('mail web runtime recovery failed',file=sys.stderr)
            raise
    print('changed=true')


if __name__=='__main__':
    try:main(json.load(sys.stdin))
    except Exception:
        # Upstream diagnostics and internal payloads may contain secrets.
        print('mail web operation failed; owned-file recovery attempted',file=sys.stderr)
        raise SystemExit(1)
