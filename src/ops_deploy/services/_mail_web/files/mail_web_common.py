"""Host utilities, composed in memory for the two mail web applications only."""
import configparser
import glob
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request


def run(argv, stdin=None):
    p = subprocess.run(argv, input=stdin, text=True, capture_output=True, timeout=120)
    if p.returncode:
        # The application/SQL diagnostics can contain credentials or account names.
        raise ValueError('mail web command failed: ' + Path(argv[0]).name)
    return p.stdout


def safe_parents(path):
    p = Path(path)
    if not p.is_absolute() or '..' in p.parts or p == Path('/'):
        raise ValueError('unsafe mail web destination')
    for parent in reversed(p.parents):
        if parent.is_symlink() or (parent.exists() and not parent.is_dir()):
            raise ValueError('mail web destination parent is not a real directory')


def file_state(path):
    safe_parents(path)
    p = Path(path)
    if not p.exists() and not p.is_symlink():
        return None
    st = p.lstat()
    if p.is_symlink():
        return ('link', os.readlink(p), stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid)
    if not p.is_file():
        raise ValueError('mail web managed file is not regular')
    return ('file', p.read_bytes(), stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid)


def identity(user, group):
    try:
        return pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid
    except KeyError:
        return -1, -1


def replace_file(path, value):
    safe_parents(path)
    p = Path(path)
    if value is None:
        p.unlink(missing_ok=True)
        return
    kind, content, mode, uid, gid = value
    if min(uid, gid) < 0:
        raise ValueError('mail web account is absent')
    fd, tmp = tempfile.mkstemp(prefix='.mail-web-', dir=p.parent)
    try:
        if kind == 'link':
            os.close(fd)
            os.unlink(tmp)
            os.symlink(content, tmp)
            os.lchown(tmp, uid, gid)
        else:
            with os.fdopen(fd, 'wb') as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
                os.fchmod(f.fileno(), mode)
                os.fchown(f.fileno(), uid, gid)
        os.replace(tmp, p)
    finally:
        Path(tmp).unlink(missing_ok=True)


def credential_state(q, apply=False, reconcile=False):
    c = dict(q['credentials'], apply=apply, reconcile_admin=reconcile)
    if q['app'] == 'postfixadmin':
        path = Path(q['root']) / 'config.local.php'
        text = path.read_text() if path.exists() else ''
        matches = re.findall(r"\$CONF\['setup_password'\]\s*=\s*'((?:\\.|[^'\\])*)'\s*;", text)
        if text and len(matches) != 1:
            raise ValueError('mail web setup hash cannot be read safely')
        c['existing_hash'] = re.sub(r"\\([\\'])", r'\1', matches[0]) if matches else ''
    else:
        path = Path(q['data']) / '_data_/_default_/configs/application.ini'
        ini = configparser.ConfigParser(interpolation=None, strict=True)
        if path.exists():
            ini.read(path)
        c['existing_hash'] = ini.get('security', 'admin_password', fallback='').strip('"')
    c['hash_missing'] = not path.exists()
    php_cli = '/usr/bin/php' + q['php']
    php_ready = bool(shutil.which(php_cli))
    if php_ready and q['app']=='postfixadmin':
        php_ready = run([php_cli,'-r','echo extension_loaded("pgsql") ? "yes" : "no";']) == 'yes'
    if not php_ready:
        if Path(q['root']).exists() and any(p.is_file() or p.is_symlink() for p in Path(q['root']).rglob('*')):
            raise ValueError('existing mail web application requires PHP for admission')
        return {'credential_changed': True, 'setup_hash': '@NEW_HASH@', 'snappy_hash': '@NEW_HASH@', 'schema': None, 'admin_changed': True, 'mapping_changed': True}
    raw = run([php_cli, '-r', CREDENTIALS_SOURCE.removeprefix('<?php')], json.dumps(c))
    return json.loads(raw)


def schema_admission(q):
    if q['app'] != 'postfixadmin':return
    c=q['credentials']
    argv=['runuser','-u',q['db_admin_user'],'--','psql','-XAtq','-v','ON_ERROR_STOP=1','-p',str(c['db_port']),'-d',c['db_name']]
    exists=run(argv,"BEGIN READ ONLY; SELECT to_regclass('public.config') IS NOT NULL; ROLLBACK;").strip()
    if exists=='t':
        version=run(argv,"BEGIN READ ONLY; SELECT value FROM public.config WHERE name='version'; ROLLBACK;").strip()
        if version!='1851':raise ValueError('mail web existing schema does not match selected release')
    elif exists=='f':
        count=run(argv,"BEGIN READ ONLY; SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE'; ROLLBACK;").strip()
        if count!='0':raise ValueError('mail web refuses to initialize nonempty unknown database')
    else:raise ValueError('mail web schema probe failed')


def app_grants(q, apply=False):
    if q['app'] != 'postfixadmin':
        return False
    c = q['credentials']
    if not all(re.fullmatch('[a-z_][a-z0-9_]*', c[k]) for k in ('db_name', 'db_user')):
        raise ValueError('unsupported mail web database identifier')
    sql = "SELECT has_database_privilege('%s','%s','CONNECT') AND has_database_privilege('%s','%s','CREATE') AND has_database_privilege('%s','%s','TEMPORARY') AND has_schema_privilege('%s','public','CREATE');" % (c['db_user'],c['db_name'],c['db_user'],c['db_name'],c['db_user'],c['db_name'],c['db_user'])
    argv = ['runuser', '-u', q['db_admin_user'], '--', 'psql', '-XAtq', '-v', 'ON_ERROR_STOP=1', '-p', str(c['db_port']), '-d', c['db_name']]
    result = run(argv, 'BEGIN READ ONLY;\n'+sql+'\nROLLBACK;').strip()
    if result not in ('t', 'f'):
        raise ValueError('mail web privilege probe failed')
    if result == 'f' and apply:
        run(argv, 'BEGIN; GRANT CONNECT,CREATE,TEMPORARY ON DATABASE "'+c['db_name']+'" TO "'+c['db_user']+'"; GRANT CREATE ON SCHEMA public TO "'+c['db_user']+'"; COMMIT;')
    return result == 'f'


def snappy_ini_state(current, wanted, types, php_cli):
    # Snappy 2.38.2 uses PHP parse_ini_file + casts against its default type.
    source=r'''
$q=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);
$current=@parse_ini_string($q['current'],true);
$wanted=@parse_ini_string($q['wanted'],true);
if ($current===false || $wanted===false) { throw new RuntimeException('invalid Snappy INI'); }
$different=[];
foreach ($wanted as $section=>$fields) {
    if (!is_array($fields)) { throw new RuntimeException('ambiguous Snappy INI'); }
    foreach ($fields as $key=>$expected) {
        $present=isset($current[$section]) && is_array($current[$section]) && array_key_exists($key,$current[$section]);
        $actual=$present ? $current[$section][$key] : null;
        $type=$q['types'][$section][$key];
        $cast=fn($value)=>match($type) {'bool'=>(bool)$value,'int'=>(int)$value,default=>(string)$value};
        if (!$present || $cast($actual)!==$cast($expected)) { $different[]=[$section,$key]; }
        unset($current[$section][$key]);
    }
    if (isset($current[$section]) && !$current[$section]) { unset($current[$section]); }
}
echo json_encode(['different'=>$different,'unowned'=>hash('sha256',json_encode($current))],JSON_THROW_ON_ERROR);
'''
    return json.loads(run([php_cli,'-r',source],json.dumps({'current':current,'wanted':wanted,'types':types})))


def snappy_ini(path, text, php_cli):
    """Own role keys only; preserve app defaults/version/TOTP and unrelated bytes."""
    existing=file_state(path)
    if existing is None:return text.encode(),0o640
    if existing[0]!='file':raise ValueError('SnappyMail configuration must be a regular file')
    current=configparser.ConfigParser(interpolation=None,strict=True)
    wanted=configparser.ConfigParser(interpolation=None,strict=True)
    current.optionxform=str;wanted.optionxform=str
    original=existing[1].decode()
    current.read_string(original);wanted.read_string(text)
    if current.defaults() or wanted.defaults():raise ValueError('ambiguous Snappy INI defaults')
    types={section:{key:'bool' if value in ('On','Off') else 'int' if value.isdigit() else 'str'
                    for key,value in wanted.items(section)} for section in wanted.sections()}
    before=snappy_ini_state(original,text,types,php_cli)
    mode=existing[2] if existing[2] in (0o600,0o640) else 0o640
    if not before['different']:return existing[1],mode
    # The parsers validate semantics. This small editor only replaces the owned
    # single-line assignments; every other line and comment remains byte-exact.
    result=original
    for section,key in before['different']:
        value=wanted.get(section,key)
        if '\n' in value or (current.has_option(section,key) and '\n' in current.get(section,key)):
            raise ValueError('ambiguous multiline owned Snappy setting')
        headers=list(re.finditer(r'(?m)^[ \t]*\[([^]\r\n]+)\][ \t]*(?:[;#][^\r\n]*)?\r?$',result))
        matches=[(n,m) for n,m in enumerate(headers) if m.group(1)==section]
        if len(matches)>1:raise ValueError('ambiguous Snappy INI section')
        if not matches:
            result+='\n['+section+']\n'+key+' = '+value+'\n'
            continue
        n,header=matches[0];end=headers[n+1].start() if n+1<len(headers) else len(result)
        region=result[header.end():end]
        pattern=re.compile(r'(?m)^([ \t]*'+re.escape(key)+r'[ \t]*=[ \t]*)[^\r\n]*(\r?)$')
        assignments=list(pattern.finditer(region))
        if len(assignments)>1:raise ValueError('ambiguous Snappy INI assignment')
        if assignments:
            assignment=assignments[0]
            region=region[:assignment.start()]+assignment.group(1)+value+assignment.group(2)+region[assignment.end():]
        else:region+=('' if region.endswith('\n') else '\n')+key+' = '+value+'\n'
        result=result[:header.end()]+region+result[end:]
    after=snappy_ini_state(result,text,types,php_cli)
    if after['different'] or after['unowned']!=before['unowned']:
        raise ValueError('Snappy INI merge did not preserve application settings')
    return result.encode(),mode


def desired_files(q, creds):
    values = {}
    owner = identity(q['user'], q['group'])
    for path, text in q['files'].items():
        text = text.replace('@OPS_SETUP_HASH@', creds['setup_hash']).replace('@OPS_SNAPPY_HASH@', creds['snappy_hash'])
        private = path.endswith(('/config.local.php', '/application.ini', '.json'))
        uid, gid = owner if q['app']=='snappymail' and path.startswith(q['data']+'/') else (0, identity('root', q['web_group'])[1] if path.endswith('/config.local.php') else 0)
        content,mode=snappy_ini(path,text,'/usr/bin/php'+q['php']) if q['app']=='snappymail' and path.endswith('/application.ini') else (text.encode(),0o640 if private else 0o644)
        values[path] = ('file', content, mode, uid, gid)
    app=q['app']; root=q['root']
    values['/etc/nginx/sites-enabled/'+app] = ('link', '/etc/nginx/sites-available/'+app, 0o777, 0, 0)
    if q['disable_default']:
        values['/etc/nginx/sites-enabled/default'] = None
    if app == 'postfixadmin':
        values[root+'/public/setup.php'] = None
        values[root+'/.installed_version'] = ('file',q['version'].encode(),0o644,0,0)
        values[root+'/.setup_complete'] = ('file', b'PostfixAdmin setup completed.\nsetup.php has been removed for security.\nTo re-run setup, download PostfixAdmin again or restore setup.php from the release archive.\n', 0o644,0,0)
    else:
        values[root+'/data'] = ('link', q['data'],0o777,0,0)
        base=q['data']+'/_data_/_default_/domains/'
        for domain in ('default', *q['domains'], *q['remove_domains']):
            values[base+domain+'.ini']=None
        for domain in q['remove_domains']:
            values[base+domain+'.json']=None
    return values
