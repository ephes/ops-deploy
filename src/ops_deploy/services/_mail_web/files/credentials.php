<?php
// Only JSON on stdin; no values in argv, stderr or final public probe output.
// Selected releases use PHP PASSWORD_DEFAULT (bcrypt on the qualified PHP).
// Invalid encodings are unknown state, never evidence of a wrong password.
function bcrypt_matches(string $password, string $stored): bool {
    if (!preg_match('~^\$2y\$(0[4-9]|[12][0-9]|3[01])\$[./A-Za-z0-9]{21}[.Oeu][./A-Za-z0-9]{30}[.CGKOSWaeimquy26]$~D', $stored)) {
        throw new RuntimeException('mail web bcrypt encoding is unsupported');
    }
    $calculated = crypt($password, $stored);
    if (strlen($calculated) !== 60 || substr($calculated, 0, 29) !== substr($stored, 0, 29)) {
        throw new RuntimeException('mail web bcrypt verification unavailable');
    }
    return hash_equals($stored, $calculated);
}
function sha512_matches(string $password, string $stored): bool {
    if (!preg_match('~^\{SHA512-CRYPT\}\$6\$(?:rounds=([1-9][0-9]{0,8})\$)?([^$:\r\n\x00]{1,16})\$[./0-9A-Za-z]{85}[./01]$~D', $stored, $parts)) {
        throw new RuntimeException('mail web admin hash encoding is unsupported');
    }
    if (($parts[1] !== '' && ((int)$parts[1] < 1000 || (int)$parts[1] > 999999999)) ||
        preg_match('~[^\x21-\x7e]|[!*:;\\\\]~', $parts[2])) {
        throw new RuntimeException('mail web admin hash settings are unsupported');
    }
    $raw = substr($stored, strlen('{SHA512-CRYPT}'));
    $calculated = crypt($password, $raw);
    $setting = substr($raw, 0, strrpos($raw, '$') + 1);
    if (strlen($calculated) !== strlen($raw) || !str_starts_with($calculated, $setting) ||
        !preg_match('~^[./0-9A-Za-z]{85}[./01]$~D', substr($calculated, strlen($setting)))) {
        throw new RuntimeException('mail web admin hash verification unavailable');
    }
    return hash_equals($raw, $calculated);
}
function new_bcrypt(string $password): string {
    $stored = password_hash($password, PASSWORD_DEFAULT);
    if (!bcrypt_matches($password, $stored)) { throw new RuntimeException('mail web bcrypt generation failed'); }
    return $stored;
}
try {
$q = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);
$apply = $q['apply'] ?? false;
$r = ['setup_hash' => '', 'snappy_hash' => '', 'admin_changed' => false];
if ($q['app'] === 'snappymail') {
    $h = $q['existing_hash'];
    $matches = $h !== '' ? bcrypt_matches($q['password'], $h) : false;
    if ($h === '' && !($q['hash_missing'] ?? false)) { throw new RuntimeException('mail web existing admin hash is empty'); }
    $r['credential_changed'] = !$matches;
    $r['snappy_hash'] = $matches ? $h : ($apply ? new_bcrypt($q['password']) : '@NEW_HASH@');
} else {
    $h = $q['existing_hash'];
    $matches = $h !== '' ? bcrypt_matches($q['setup_password'], $h) : false;
    if ($h === '' && !($q['hash_missing'] ?? false)) { throw new RuntimeException('mail web existing setup hash is empty'); }
    $r['credential_changed'] = !$matches;
    $r['setup_hash'] = $matches ? $h : ($apply ? new_bcrypt($q['setup_password']) : '@NEW_HASH@');
    $db = @pg_connect('postgresql://'.rawurlencode($q['db_user']).':'.rawurlencode($q['db_password']).'@'.$q['db_host'].':'.$q['db_port'].'/'.rawurlencode($q['db_name']));
    if (!$db) { throw new RuntimeException('mail web database connection failed'); }
    if (!pg_query($db, 'BEGIN READ ONLY')) { throw new RuntimeException('mail web read transaction failed'); }
    $exists = pg_fetch_result(pg_query($db, "SELECT to_regclass('public.config') IS NOT NULL"), 0, 0) === 't';
    $r['schema'] = null;
    $r['empty_database'] = false;
    if ($exists) {
        $r['schema'] = pg_fetch_result(pg_query($db, "SELECT value FROM public.config WHERE name='version'"), 0, 0);
        if ($r['schema'] !== '1851') { throw new RuntimeException('mail web existing schema does not match selected release'); }
        $result = pg_query_params($db, 'SELECT password,active,superadmin FROM public.admin WHERE username=$1', [$q['admin_email']]);
        if (!$result) { throw new RuntimeException('mail web admin inspection failed'); }
        $admin = pg_fetch_assoc($result);
        $adminMatches = $admin ? sha512_matches($q['admin_password'], $admin['password']) : false;
        $r['admin_changed'] = !$admin || !$adminMatches || $admin['active'] !== 't' || $admin['superadmin'] !== 't';
        $domain = pg_fetch_result(pg_query($db, "SELECT count(*) FROM public.domain WHERE domain='ALL'"),0,0);
        $mapping = pg_fetch_result(pg_query_params($db, "SELECT count(*) FROM public.domain_admins WHERE username=$1 AND domain='ALL'",[$q['admin_email']]),0,0);
        $r['mapping_changed'] = $domain !== '1' || $mapping !== '1';
    } else {
        $count = pg_fetch_result(pg_query($db,"SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE'"),0,0);
        $r['empty_database'] = $count === '0';
        if (!$r['empty_database']) { throw new RuntimeException('mail web refuses nonempty database without selected application schema'); }
        $r['admin_changed'] = true;
        $r['mapping_changed'] = true;
    }
    if (!pg_query($db, 'ROLLBACK')) { throw new RuntimeException('mail web read transaction closure failed'); }
    if ($q['reconcile_admin'] ?? false) {
        if ($r['schema'] !== '1851') { throw new RuntimeException('mail web schema prerequisite missing'); }
        if (!pg_query($db,'BEGIN')) { throw new RuntimeException('mail web admin transaction failed'); }
        $queries = [["INSERT INTO public.domain (domain,description,aliases,mailboxes,transport,backupmx,active) VALUES ('ALL','Superadmin pseudo-domain',0,0,'','0','1') ON CONFLICT (domain) DO NOTHING", []]];
        if ($r['admin_changed']) {
            // Preserve the old salt if the plaintext already matches; no TOTP reset.
            $newHash = $adminMatches ? $admin['password'] : '{SHA512-CRYPT}'.crypt($q['admin_password'], '$6$'.bin2hex(random_bytes(8)).'$');
            if (!sha512_matches($q['admin_password'], $newHash)) { throw new RuntimeException('mail web admin hash generation failed'); }
            $queries[] = ["INSERT INTO public.admin(username,password,superadmin,active,created,modified) VALUES($1,$2,'1','1',NOW(),NOW()) ON CONFLICT(username) DO UPDATE SET password=EXCLUDED.password,superadmin='1',active='1',modified=NOW() WHERE admin.password IS DISTINCT FROM EXCLUDED.password OR NOT admin.superadmin OR NOT admin.active",[$q['admin_email'],$newHash]];
        }
        $queries[] = ["INSERT INTO public.domain_admins(username,domain,active) SELECT $1::varchar,'ALL','1' WHERE NOT EXISTS(SELECT 1 FROM public.domain_admins WHERE username=$1 AND domain='ALL')",[$q['admin_email']]];
        foreach ($queries as [$sql,$args]) { if (!pg_query_params($db,$sql,$args)) { pg_query($db,'ROLLBACK'); throw new RuntimeException('mail web app-specific admin reconciliation failed'); } }
        if (!pg_query($db,'COMMIT')) { throw new RuntimeException('mail web admin commit failed'); }
    }
}
echo json_encode($r, JSON_THROW_ON_ERROR);

} catch (Throwable $error) {
    fwrite(STDERR, "mail web credential state is unknown\n");
    exit(1);
}
