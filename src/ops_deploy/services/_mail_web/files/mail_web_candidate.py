"""Complete nginx/FPM candidate context and bounded owned-file recovery."""

def stage_context(q, root, values):
    # Existing unrelated pools/sites/snippets participate in validation.
    for folder in ('/etc/nginx', '/etc/php/'+q['php']+'/fpm'):
        dest=root/folder.lstrip('/')
        shutil.copytree(folder,dest,dirs_exist_ok=True)
    for path,value in values.items():
        if not path.startswith(('/etc/nginx/', '/etc/php/')):
            if value is None or value[0]=='link':
                continue
        dest=root/path.lstrip('/')
        dest.parent.mkdir(parents=True,exist_ok=True)
        if dest.exists() or dest.is_symlink():
            dest.unlink()
        if value is None:
            continue
        if value[0]=='link':
            target=root/value[1].lstrip('/')
            if target.exists():
                shutil.copyfile(target,dest)
        else:
            dest.write_bytes(value[1])
    walk_includes(root,'/etc/nginx/nginx.conf','nginx')
    walk_includes(root,'/etc/php/'+q['php']+'/fpm/php-fpm.conf','fpm')
    for path,value in values.items():
        if path.endswith('.php') and value is not None:
            run(['/usr/bin/php'+q['php'],'-l',str(root/path.lstrip('/'))])
    run(['php-fpm'+q['php'],'-t','-y',str(root/('etc/php/'+q['php']+'/fpm/php-fpm.conf'))])
    run(['nginx','-t','-c',str(root/'etc/nginx/nginx.conf'),'-p','/etc/nginx/'])


def nginx_includes(text):
    # Tokenize nginx directives, retaining source spans: includes may be inline,
    # quoted, commented or nested. Rewriting line-start regexes misses valid input.
    tokens=[];i=0
    while i<len(text):
        if text[i].isspace():i+=1;continue
        if text[i]=='#':
            end=text.find('\n',i);i=len(text) if end<0 else end+1;continue
        start=i;value='';quote=None
        if text[i] in '{};':tokens.append((text[i],i,i+1));i+=1;continue
        while i<len(text):
            char=text[i]
            if char=='\\' and i+1<len(text):value+=text[i+1];i+=2;continue
            if quote:
                if char==quote:quote=None
                else:value+=char
                i+=1;continue
            if char in '\"\'':quote=char;i+=1;continue
            if char.isspace() or char in '{};#':break
            value+=char;i+=1
        if quote:raise ValueError('unterminated nginx candidate string')
        tokens.append((value,start,i))
    beginning=True
    for n,token in enumerate(tokens):
        value,start,end=token
        if beginning and value=='include':
            if n+2>=len(tokens) or tokens[n+2][0]!=';':
                raise ValueError('unsupported nginx candidate include')
            yield tokens[n+1]
        beginning=value in '{};'


def walk_includes(root, initial, kind):
    pending=[initial];seen=set()
    while pending:
        path=pending.pop()
        if path in seen:continue
        seen.add(path)
        dest=root/path.lstrip('/')
        if not dest.exists():
            dest.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(path,dest)
        text=dest.read_text()
        if kind=='nginx':includes=list(nginx_includes(text))
        else:
            pattern=re.compile(r'(?m)^\s*include\s*=\s*([^\n;]+)')
            includes=[(m.group(1).strip(),m.start(1),m.end(1)) for m in pattern.finditer(text)]
        replacements=[]
        for source,start,end in includes:
            source=source.strip('"\'')
            if not source.startswith('/'):
                source=('/etc/nginx/' if kind=='nginx' else str(Path(path).parent)+'/')+source
            if '..' in Path(source).parts or '$' in source:
                raise ValueError('unsupported mail web include path')
            staged=str(root/source.lstrip('/'))
            inside=source.startswith('/etc/nginx/') if kind=='nginx' else source.startswith('/etc/php/')
            if not inside:
                for name in glob.glob(source):
                    target=root/name.lstrip('/')
                    if not target.exists():
                        target.parent.mkdir(parents=True,exist_ok=True)
                        shutil.copyfile(name,target)
            for name in glob.glob(staged):pending.append('/'+str(Path(name).relative_to(root)))
            replacements.append((start,end,'"'+staged+'"' if kind=='nginx' else staged))
        for start,end,value in reversed(replacements):text=text[:start]+value+text[end:]
        dest.write_text(text)


def service_active(unit):
    return subprocess.run(['systemctl','is-active','--quiet',unit],capture_output=True).returncode==0


def health(q):
    if not q['healthcheck']:return
    # No authenticated personal session. Match the role's ordinary local redirect.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs):return None
    opener=urllib.request.build_opener(NoRedirect)
    import time
    for attempt in range(q['healthcheck_retries']):
        try:
            try:
                response=opener.open('http://127.0.0.1:'+str(q['port'])+'/',timeout=q['healthcheck_timeout'])
                status=response.status;response.close()
            except urllib.error.HTTPError as exc:status=exc.code
            if status in (200,302,303):return
        except OSError:pass
        time.sleep(1)
    raise ValueError('mail web local HTTP health failed')


def peer_health(q):
    # Shared-runtime preservation check is independent of this app's optional
    # health policy. Read the peer's actual loopback listener, never guess a port.
    other='snappymail' if q['app']=='postfixadmin' else 'postfixadmin'
    path=Path('/etc/nginx/sites-enabled/'+other)
    if not path.exists():return None
    text=re.sub(r'(?m)#.*$', '', path.read_text())
    listeners=re.findall(r'(?m)^\s*listen\s+([^;]+);',text)
    if len(listeners)!=1 or not re.fullmatch(r'127\.0\.0\.1:[0-9]{1,5}',listeners[0].strip()):
        raise ValueError('mail web peer listener cannot be admitted safely')
    port=int(listeners[0].strip().rsplit(':',1)[1])
    if not 1<=port<=65535:raise ValueError('mail web peer listener is invalid')
    return {'port':port,'healthcheck':True,'healthcheck_timeout':10,'healthcheck_retries':3}


def activate(q, changed, code_changed, was_active):
    fpm='php'+q['php']+'-fpm'
    if code_changed or any(p.endswith(('.php','.ini','.json')) or '/pool.d/' in p for p in changed):
        run(['systemctl','restart' if was_active[fpm] else 'start',fpm])
    elif not service_active(fpm):run(['systemctl','start',fpm])
    if any(p.startswith('/etc/nginx/') for p in changed):
        run(['systemctl','reload' if was_active['nginx'] else 'start','nginx'])
    elif not service_active('nginx'):run(['systemctl','start','nginx'])
    health(q)
    if q.get('peer_health') is not None:health(q['peer_health'])
