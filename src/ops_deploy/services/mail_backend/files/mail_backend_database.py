"""Core mail catalogs only; protected stdin, fixed state/count output.

Check performs transient native PostgreSQL catalog validation (temporary views
rolled back), NOT a read-only/physical-zero-write operation. No mailbox bodies
are read. Existing owners/grants/unowned rows are never removed or reassigned.
"""
import json
import re
import secrets
import signal
import subprocess
import sys

import psycopg2
from psycopg2 import sql


def qualified_password_hash(value):
    if not isinstance(value, str):
        return False
    match = re.fullmatch(r"\{SHA512-CRYPT\}\$6\$(?:rounds=([1-9][0-9]{0,8})\$)?([^$:\r\n\0]{1,16})\$[./0-9A-Za-z]{85}[./01]", value)
    return bool(match and all(0x21 <= ord(char) <= 0x7e and char not in "!*:;" and ord(char) != 92 for char in match[2])
                and (match[1] is None or 1000 <= int(match[1]) <= 999999999))


def password_matches(stored, password):
    if not qualified_password_hash(stored):
        raise ValueError('stored initial mailbox hash is unsupported or malformed')
    result = subprocess.run(['doveadm', '-O', 'pw', '-t', stored], input=password+'\n', text=True, capture_output=True, timeout=30)
    if result.returncode not in (0, 75):
        raise ValueError('initial mailbox password verification failed')
    return result.returncode == 0


def generated_password(password):
    result = subprocess.run(['doveadm', '-O', 'pw', '-s', 'SHA512-CRYPT'], input=password+'\n'+password+'\n', text=True, capture_output=True, timeout=30)
    value = result.stdout.strip()
    if result.returncode or not qualified_password_hash(value) or not password_matches(value, password):
        raise ValueError('initial mailbox password generation failed')
    return value


def schema_statements(source):
    # This is the exact role resource: no functions, dollar quotes or arbitrary
    # consumer SQL. Splitting its fixed statements does not parse user SQL.
    clean = '\n'.join(line.split('--', 1)[0] for line in source.splitlines())
    statements = [part.strip() for part in clean.split(';') if part.strip()]
    tables, indexes, views = [], [], []
    for statement in statements:
        table = re.match(r'CREATE TABLE IF NOT EXISTS (mail_[a-z_]+)\s*\(', statement)
        index = re.match(r'CREATE UNIQUE INDEX IF NOT EXISTS (mail_[a-z_]+)\s', statement)
        view = re.match(r'CREATE OR REPLACE VIEW (mail_[a-z_]+) AS\s+(.*)', statement, re.S)
        if table:
            tables.append((table[1], statement))
        elif index:
            indexes.append((index[1], statement))
        elif view:
            views.append((view[1], statement, view[2]))
        else:
            raise ValueError('unrecognized role schema statement')
    if (len(tables), len(indexes), len(views)) != (4, 3, 6):
        raise ValueError('unexpected role schema resource structure')
    return tables, indexes, views


def reconcile(request, apply):
    cfg = request['config']
    for key in ('postgres_database', 'postgres_user'):
        if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,62}', cfg[key]):
            raise ValueError('invalid mail database identity')
    mode = cfg['schema_mode']
    if mode not in ('legacy', 'postfixadmin'):
        raise ValueError('invalid mail schema mode')
    domains = cfg['domains']
    if not domains or any(value.lower() == 'all' for value in domains + cfg['sender_only_domains']):
        raise ValueError('ordinary mail domains must exclude the reserved web admin domain')
    tables, indexes, views = schema_statements(request['schema_sql'])
    conn = psycopg2.connect(dbname=cfg['postgres_database'], port=cfg['postgres_port'], connect_timeout=5)
    changed = False
    temporary_checks = 0

    def change(cur, query, params=None):
        nonlocal changed
        changed = True
        if apply:
            cur.execute(query, params)

    def one(cur, query, params):
        cur.execute(query, params)
        rows = cur.fetchall()
        if len(rows) > 1:
            raise ValueError('mail catalog identity is ambiguous')
        return rows[0] if rows else None

    def alias(cur, address, destination, domain, active=True, insert_only=False):
        if domain.lower() == 'all':
            raise ValueError('reserved web admin domain is outside core ownership')
        row = one(cur, 'SELECT address, goto, domain, active FROM alias WHERE LOWER(address)=LOWER(%s)', (address,))
        if row is None:
            change(cur, 'INSERT INTO alias (address,goto,domain,active,created,modified) VALUES (%s,%s,%s,%s,NOW(),NOW())', (address, destination, domain, active))
        elif not insert_only and (row[1], row[2], bool(row[3])) != (destination, domain, active):
            change(cur, 'UPDATE alias SET goto=%s,domain=%s,active=%s,modified=NOW() WHERE address=%s', (destination, domain, active, row[0]))

    try:
        with conn.cursor() as cur:
            cur.execute("SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='5s'; SET LOCAL search_path=public,pg_temp; SET LOCAL log_statement='none'; SET LOCAL log_min_error_statement='panic'; SET LOCAL log_parameter_max_length_on_error=0")
            available = True
            for name, statement in tables + indexes:
                cur.execute('SELECT to_regclass(%s)', ('public.'+name,))
                if cur.fetchone()[0] is None:
                    change(cur, statement)
                    if not apply:
                        available = False
            if available:
                for name, statement, select in views:
                    candidate = '__ops_mail_candidate_'+secrets.token_hex(12)
                    cur.execute(sql.SQL('CREATE TEMP VIEW {} AS ').format(sql.Identifier(candidate)) + sql.SQL(select))
                    cur.execute('SELECT pg_get_viewdef(%s::regclass,false)', ('pg_temp.'+candidate,))
                    desired = cur.fetchone()[0]
                    cur.execute('SELECT to_regclass(%s)', ('public.'+name,))
                    exists = cur.fetchone()[0] is not None
                    actual = None
                    if exists:
                        cur.execute('SELECT pg_get_viewdef(%s::regclass,false)', ('public.'+name,))
                        actual = cur.fetchone()[0]
                    temporary_checks += 1
                    if actual != desired:
                        change(cur, statement)
                    cur.execute(sql.SQL('DROP VIEW pg_temp.{}').format(sql.Identifier(candidate)))
            else:
                # Missing base tables prevent native view parsing and row
                # observation; apply creates them then validates everything.
                conn.rollback()
                return True, temporary_checks

            # PostgreSQL owners and ACLs are never reset. Add only privileges
            # the original backend role requires, and only when absent. Role
            # parity: it grants database ALL and SELECT ON ALL TABLES IN SCHEMA
            # public, so relations of other applications (e.g. PostfixAdmin)
            # also become readable by the mail login. Nothing is revoked.
            for privilege in ('CONNECT', 'CREATE', 'TEMPORARY'):
                cur.execute('SELECT has_database_privilege(%s,%s,%s)', (cfg['postgres_user'], cfg['postgres_database'], privilege))
                if not cur.fetchone()[0]:
                    change(cur, sql.SQL('GRANT {} ON DATABASE {} TO {}').format(sql.SQL(privilege), sql.Identifier(cfg['postgres_database']), sql.Identifier(cfg['postgres_user'])))
            cur.execute("SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f') AND NOT has_table_privilege(%s,c.oid,'SELECT')", (cfg['postgres_user'],))
            for (table,) in cur.fetchall():
                change(cur, sql.SQL('GRANT SELECT ON TABLE public.{} TO {}').format(sql.Identifier(table), sql.Identifier(cfg['postgres_user'])))

            if apply:
                names = ['mail_domains', 'mail_users', 'mail_aliases', 'mail_domain_aliases']
                if mode == 'postfixadmin':
                    names += ['domain', 'alias_domain', 'mailbox', 'alias']
                cur.execute(sql.SQL('LOCK TABLE {} IN SHARE ROW EXCLUSIVE MODE').format(sql.SQL(',').join(sql.Identifier('public', name) for name in names)))
            for domain in domains:
                row = one(cur, 'SELECT id FROM mail_domains WHERE LOWER(name)=LOWER(%s)', (domain,))
                if row is None:
                    change(cur, 'INSERT INTO mail_domains (name) VALUES (%s)', (domain,))
                if mode == 'postfixadmin':
                    row = one(cur, 'SELECT domain FROM domain WHERE LOWER(domain)=LOWER(%s)', (domain,))
                    if row is None:
                        change(cur, "INSERT INTO domain (domain,description,aliases,mailboxes,maxquota,quota,transport,backupmx,active,created,modified) VALUES (%s,'Managed by mail_backend_deploy',0,0,0,0,'',false,true,NOW(),NOW())", (domain,))
            if mode == 'postfixadmin':
                for domain in cfg['sender_only_domains']:
                    row = one(cur, 'SELECT active FROM domain WHERE LOWER(domain)=LOWER(%s)', (domain,))
                    cur.execute('SELECT 1 FROM alias_domain WHERE active AND (LOWER(alias_domain)=LOWER(%s) OR LOWER(target_domain)=LOWER(%s))', (domain, domain))
                    if cur.fetchone() or (row and row[0]):
                        raise ValueError('sender-only domain is active or has an active recipient mapping')
                    if row is None:
                        change(cur, "INSERT INTO domain (domain,description,aliases,mailboxes,maxquota,quota,transport,backupmx,active,created,modified) VALUES (%s,'Sender-only (no mailboxes) - managed by mail_backend_deploy',0,0,0,0,'',false,false,NOW(),NOW())", (domain.lower(),))

            for mapping in cfg['postfixadmin_domain_aliases']:
                source, target = mapping['alias_domain'].lower(), mapping['target_domain'].lower()
                if 'all' in (source, target):
                    raise ValueError('reserved web admin domain mapping is outside core ownership')
                if mode == 'postfixadmin':
                    row = one(cur, 'SELECT alias_domain,target_domain,active FROM alias_domain WHERE LOWER(alias_domain)=LOWER(%s)', (source,))
                    if row is None:
                        change(cur, 'INSERT INTO alias_domain (alias_domain,target_domain,active,created,modified) VALUES (%s,%s,true,NOW(),NOW())', (source, target))
                    elif (row[1], bool(row[2])) != (target, True):
                        change(cur, 'UPDATE alias_domain SET target_domain=%s,active=true,modified=NOW() WHERE alias_domain=%s', (target, row[0]))
                else:
                    source_row = one(cur, 'SELECT id FROM mail_domains WHERE LOWER(name)=LOWER(%s)', (source,))
                    target_row = one(cur, 'SELECT id FROM mail_domains WHERE LOWER(name)=LOWER(%s)', (target,))
                    if source_row is None or target_row is None:
                        if apply:
                            raise ValueError('legacy domain mapping lacks a domain')
                        changed = True
                        continue
                    row = one(cur, 'SELECT dest_domain_id,active FROM mail_domain_aliases WHERE source_domain_id=%s', (source_row[0],))
                    if row is None:
                        change(cur, 'INSERT INTO mail_domain_aliases (source_domain_id,dest_domain_id,active) VALUES (%s,%s,true)', (source_row[0], target_row[0]))
                    elif row != (target_row[0], True):
                        change(cur, 'UPDATE mail_domain_aliases SET dest_domain_id=%s,active=true WHERE source_domain_id=%s', (target_row[0], source_row[0]))

            initial_password = request.get('initial_password', '')
            if cfg['initial_user'] and initial_password:
                if not isinstance(initial_password, str) or any(c in initial_password for c in '\r\n\0'):
                    raise ValueError('invalid initial mailbox password')
                local, domain = cfg['initial_user'].lower(), cfg['initial_user_domain'].lower()
                address = local+'@'+domain
                if mode == 'postfixadmin':
                    row = one(cur, 'SELECT username,password,active FROM mailbox WHERE LOWER(username)=LOWER(%s)', (address,))
                else:
                    row = one(cur, 'SELECT u.id,u.password,u.active FROM mail_users u JOIN mail_domains d ON d.id=u.domain_id WHERE LOWER(u.localpart)=LOWER(%s) AND LOWER(d.name)=LOWER(%s)', (local, domain))
                matches = password_matches(row[1], initial_password) if row else False
                if not row or not matches or (mode == 'postfixadmin' and not row[2]):
                    changed = True
                    if apply:
                        hashed = row[1] if matches else generated_password(initial_password)
                        if mode == 'postfixadmin':
                            if row:
                                cur.execute('UPDATE mailbox SET password=%s,active=true,modified=NOW() WHERE username=%s', (hashed, row[0]))
                            else:
                                cur.execute("INSERT INTO mailbox (username,password,name,maildir,quota,local_part,domain,active,created,modified) VALUES (%s,%s,'',%s,0,%s,%s,true,NOW(),NOW())", (address, hashed, domain+'/'+local+'/', local, domain))
                        elif row:
                            cur.execute('UPDATE mail_users SET password=%s WHERE id=%s', (hashed, row[0]))
                        else:
                            cur.execute('INSERT INTO mail_users (domain_id,localpart,password) SELECT id,%s,%s FROM mail_domains WHERE LOWER(name)=LOWER(%s)', (cfg['initial_user'], hashed, domain))
                if mode == 'postfixadmin':
                    alias(cur, address, address, domain)

            if cfg['initial_user']:
                for requirement in cfg['required_aliases']:
                    for domain in domains:
                        local = requirement['localpart']
                        destination = (requirement['destination_localpart'] or cfg['initial_user'])+'@'+domain
                        if mode == 'postfixadmin':
                            alias(cur, (local+'@'+domain).lower(), destination.lower(), domain.lower())
                        else:
                            row = one(cur, 'SELECT id FROM mail_domains WHERE LOWER(name)=LOWER(%s)', (domain,))
                            if row is None:
                                changed = True
                                continue
                            cur.execute('SELECT 1 FROM mail_aliases WHERE source_domain_id=%s AND LOWER(source_localpart)=LOWER(%s) AND LOWER(destination)=LOWER(%s)', (row[0], local, destination))
                            if not cur.fetchone():
                                change(cur, 'INSERT INTO mail_aliases (source_domain_id,source_localpart,destination) VALUES (%s,%s,%s)', (row[0], local, destination))

            if mode == 'postfixadmin':
                for forward in cfg['forward_aliases']:
                    address = forward['address'].lower()
                    alias(cur, address, ','.join(forward['destinations']), address.rsplit('@', 1)[1])
                cur.execute("SELECT username,domain FROM mailbox WHERE active AND LOWER(domain)<>'all'")
                for address, domain in cur.fetchall():
                    alias(cur, address.lower(), address.lower(), domain.lower(), insert_only=True)
                for mapping in cfg['postfixadmin_domain_aliases']:
                    source, target = mapping['alias_domain'].lower(), mapping['target_domain'].lower()
                    path = {source, target}
                    leaf = None
                    # Exact original recursive role bound: at most ten links,
                    # cycles do not produce a leaf or delete existing aliases.
                    for depth in range(1, 11):
                        row = one(cur, 'SELECT target_domain FROM alias_domain WHERE active AND LOWER(alias_domain)=LOWER(%s)', (target,))
                        if row is None:
                            leaf = target
                            break
                        target = row[0].lower()
                        if target in path:
                            break
                        path.add(target)
                    if leaf is not None:
                        cur.execute("SELECT local_part,username,active FROM mailbox WHERE LOWER(domain)=%s AND LOWER(domain)<>'all'", (leaf,))
                        for local, username, active in cur.fetchall():
                            alias(cur, (local+'@'+source).lower(), username.lower(), source, bool(active))
            if apply:
                conn.commit()
            else:
                conn.rollback()
            return changed, temporary_checks
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def interrupt(signum, frame):
    raise KeyboardInterrupt()


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGINT, interrupt)
    try:
        if sys.argv[1:] not in (['check'], ['apply']):
            raise ValueError('invalid core mail database action')
        changed, temporary_checks = reconcile(json.load(sys.stdin), sys.argv[1] == 'apply')
        print(json.dumps({'state': 'pending' if changed else 'current', 'transient_postgres_catalog_validations': temporary_checks}))
    except BaseException:
        print('Core mail catalog operation failed; protected details withheld', file=sys.stderr)
        raise SystemExit(1) from None
