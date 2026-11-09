"""Pinned archive-owned files only; mutable data and extra old files are retained."""

def release_matches(root, release):
    for name, entry in release['files'].items():
        p=Path(root)/name
        safe_parents(p)
        if 'link' in entry:
            if not p.is_symlink() or os.readlink(p)!=entry['link']:return False
        elif p.is_symlink() or not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=entry['sha256']:
            return False
    return True


def release_needed(q):
    root=Path(q['root'])
    safe_parents(root)
    if root.is_symlink() or (root.exists() and not root.is_dir()):
        raise ValueError('mail web application root is not a real directory')
    if release_matches(root,q['release']):
        return False
    if root.exists():
        # Newly created empty role directories are not application data.
        files=[p for p in root.rglob('*') if p.is_file() or p.is_symlink()]
        if files and not any(release_matches(root,r) for r in q['previous_releases']):
            raise ValueError('mail web existing code differs from known release; preserve local repairs')
    return True


def extract_release(q, stage):
    release=q['release'];archive=stage/'release.tar.gz';tree=stage/'release'
    with urllib.request.urlopen(release['url'],timeout=90) as source, archive.open('wb') as dest:
        shutil.copyfileobj(source,dest)
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=release['sha256']:
        raise ValueError('mail web archive checksum mismatch')
    tree.mkdir()
    with tarfile.open(archive) as tf:
        members={}
        for member in tf.getmembers():
            parts=Path(member.name).parts
            if member.name.startswith('/') or '..' in parts:
                raise ValueError('unsafe mail web archive member')
            if release['strip']:parts=parts[1:]
            name='/'.join(parts)
            if not name:continue
            if name in members:raise ValueError('duplicate mail web archive member')
            members[name]=member
            if not member.isdir() and not member.isfile() and not member.issym():
                raise ValueError('unsupported mail web archive member type')
            if member.issym():
                target=Path(name).parent/member.linkname
                if member.linkname.startswith('/') or '..' in target.parts:
                    raise ValueError('unsafe mail web archive link')
        if set(release['files'])-set(members):
            raise ValueError('mail web archive manifest member missing')
        # Keep archive order: random backward seeks repeatedly decompress gzip.
        for name,member in members.items():
            entry=release['files'].get(name)
            if entry is None:continue
            p=tree/name;p.parent.mkdir(parents=True,exist_ok=True)
            if 'link' in entry:
                if not member.issym() or member.linkname!=entry['link']:
                    raise ValueError('mail web archive link differs from manifest')
                p.symlink_to(entry['link'])
            else:
                if not member.isfile():raise ValueError('mail web archive file type differs')
                data=tf.extractfile(member).read()
                if hashlib.sha256(data).hexdigest()!=entry['sha256']:
                    raise ValueError('mail web archive file differs from manifest')
                p.write_bytes(data)
        # Only a genuinely empty Snappy data tree is seeded, never overlaid.
        if q['app']=='snappymail' and not (Path(q['data'])/'VERSION').exists():
            data_root=Path(q['data'])
            if data_root.exists() and any(p.is_file() or p.is_symlink() for p in data_root.rglob('*')):
                raise ValueError('mail web refuses to seed existing Snappy data')
            for name,member in members.items():
                if name.startswith('data/') and member.isfile():
                    p=tree/name;p.parent.mkdir(parents=True,exist_ok=True)
                    p.write_bytes(tf.extractfile(member).read())
    return tree


def code_values(q, tree):
    values={}
    for name,entry in q['release']['files'].items():
        path=q['root']+'/'+name
        values[path]=('link',entry['link'],0o777,0,0) if 'link' in entry else ('file',(tree/name).read_bytes(),entry['mode'],0,0)
    if q['app']=='postfixadmin':
        values[q['root']+'/.installed_version']=('file',q['version'].encode(),0o644,0,0)
    return values


def seed_values(q,tree):
    if q['app']!='snappymail' or (Path(q['data'])/'VERSION').exists():return {}
    uid,gid=identity(q['user'],q['group']);values={}
    for p in (tree/'data').rglob('*'):
        if p.is_file():values[q['data']+'/'+str(p.relative_to(tree/'data'))]=('file',p.read_bytes(),0o640,uid,gid)
    values[q['data']+'/VERSION']=('file',(q['version']+'\n').encode(),0o644,uid,gid)
    return values


def needs_seed(q):
    if q['app']!='snappymail':return False
    root=Path(q['data']);safe_parents(root)
    if root.is_symlink() or (root.exists() and not root.is_dir()):
        raise ValueError('mail web persistent root must be a real directory')
    marker=root/'VERSION'
    if marker.is_symlink():raise ValueError('mail web persistent marker must be regular')
    if marker.is_file():return False
    if root.exists() and any(p.is_file() or p.is_symlink() for p in root.rglob('*')):
        raise ValueError('mail web refuses to seed existing Snappy data')
    return True
