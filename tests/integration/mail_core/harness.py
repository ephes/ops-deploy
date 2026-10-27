# ruff: noqa: E501  (guest scripts are embedded verbatim; wrapping them would change their text)
"""Package-absent native mail core qualification on two owned systemd-nspawn systems.

run.sh builds two minimal Ubuntu 24.04 systems (backend, edge) on one disposable
GitHub-hosted x86_64 VM, without any host path binds, and calls this harness
with the immutable installed implementation. Mail packages are absent until the
public APIs install them. The harness proves:

1. a package fault before install refuses without a substitute Postfix account,
   configuration or daemon;
2. the corrected ordinary first install (backend -> relay -> spam, the umbrella
   order) replaces apt-started default daemons with the validated configuration;
3. owned synthetic .test mail flows edge -> backend (milter, LMTP, IMAPS) and
   backend -> edge -> owned sink (SASL relay); SMTP never leaves the bridge;
4. the actual repeat of every stage has zero managed changes and keeps every PID.

Credentials are generated per run, travel on stdin and are never written to the
evidence directory.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import os
import secrets
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.mail_backend import MailBackendConfig, deploy_mail_backend
from ops_deploy.services.mail_backend.config import DomainAlias, ForwardAlias
from ops_deploy.services.mail_relay import MailRelayConfig, deploy_mail_relay
from ops_deploy.services.mail_spam import MailSpamConfig, deploy_mail_spam
from ops_deploy.services.mail_spam.config import MonitoringProbe
from ops_deploy.testing import run_deploy_ssh

EVIDENCE = Path(sys.argv[1])
STATE = Path(os.environ["MAIL_CORE_STATE"])
HOSTS = {"backend": "192.168.104.1", "edge": "192.168.104.3"}
KEY = STATE / "controller_ed25519"
KNOWN = STATE / "known_hosts"
PFA_ARCHIVE = "https://github.com/postfixadmin/postfixadmin/releases/download/v4.0.5/postfixadmin-v4.0.5-php84.tar.gz"
PFA_SHA256 = "88a55e04dad4f5a2b7729c696cb997ad3a5afb39e31cae1627fa024e7649d70b"
MAIL_PACKAGES = {
    "backend": (*MailBackendConfig(domains=("example.test",)).packages, "rspamd", "unbound", "unbound-anchor"),
    "edge": (*MailRelayConfig(domains=("example.test",)).packages, "postsrsd"),
}
# ca-certificates belongs to the minimal base system; every mail daemon package must be absent.
BASE_PACKAGES = {"ca-certificates"}
OWNED = {
    "postgres_password": secrets.token_urlsafe(24),
    "relay_password": secrets.token_urlsafe(24),
    "initial_user_password": secrets.token_urlsafe(24),
    "web_password": secrets.token_urlsafe(24),
    "redis_password": secrets.token_urlsafe(24),
    "pfa_password": secrets.token_urlsafe(24),
    "srs_secret": secrets.token_urlsafe(32),
}
evidence: dict[str, Any] = {
    "scope": "GitHub-hosted x86_64 Ubuntu VM; two owned systemd-nspawn Ubuntu 24.04 systems on a private bridge; "
    "synthetic .test mail only, SMTP egress rejected at the host; owned CA/credentials generated per run",
    "implementation_sha": os.environ["IMPLEMENTATION_SHA"],
}


def record() -> None:
    target = EVIDENCE / "mail-core-native.json"
    text = json.dumps(evidence, indent=2) + "\n"
    assert not any(value in text for value in OWNED.values()), "owned credential reached evidence"
    target.write_text(text)


def guest(name: str, script: str, stdin: str = "", timeout: int = 900) -> str:
    """Run a bash script on an owned system; the fish root shell only sees base64."""

    encoded = base64.b64encode(
        ("set -euo pipefail\ntest -f /var/lib/mail-core-fixture/OWNED\n" + script).encode()
    ).decode()
    remote = f"python3 -c \"import base64,subprocess,sys;sys.exit(subprocess.run(['bash','-c',base64.b64decode('{encoded}').decode()]).returncode)\""
    argv = [
        "ssh",
        "-i",
        str(KEY),
        "-o",
        "UserKnownHostsFile=" + str(KNOWN),
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "BatchMode=yes",
    ]
    result = subprocess.run(
        [*argv, "root@" + HOSTS[name], remote], input=stdin, text=True, capture_output=True, timeout=timeout
    )
    if result.returncode:
        tail = result.stderr[-4000:]
        assert not any(value in tail for value in OWNED.values())
        (EVIDENCE / f"guest-{name}-failure.txt").write_text(tail)
        raise AssertionError(f"owned {name} step failed")
    return result.stdout


def guest_json(name: str, script: str, stdin: str = "", timeout: int = 900) -> Any:
    return json.loads(guest(name, script, stdin, timeout).strip().splitlines()[-1])


def connection(name: str) -> dict[str, Any]:
    return {
        "ssh_hostname": HOSTS[name],
        "ssh_user": "root",
        "ssh_key": str(KEY),
        "ssh_known_hosts_file": str(KNOWN),
        "ssh_strict_host_key_checking": "yes",
    }


PACKAGE_STATE = r"""
python3 -c "$(cat <<'PY'
import json,subprocess,sys
state={}
for name in sys.argv[1:]:
    r=subprocess.run(['dpkg-query','-W','-f=${db:Status-Status}',name],capture_output=True,text=True)
    state[name]=r.stdout.strip() if r.returncode==0 else 'unknown'
print(json.dumps(state))
PY
)" "$@"
"""


def packages(name: str) -> dict[str, str]:
    script = "set -- " + " ".join(MAIL_PACKAGES[name]) + "\n" + PACKAGE_STATE
    return cast("dict[str, str]", guest_json(name, script))


def assert_absent(name: str, label: str) -> None:
    state = packages(name)
    evidence.setdefault("package_state", {})[f"{name}-{label}"] = state
    present = {package for package, status in state.items() if status == "installed" and package not in BASE_PACKAGES}
    assert not present, f"{name} mail packages present {label}: {sorted(present)}"


def owned_tls() -> None:
    work = STATE / "tls"
    work.mkdir(mode=0o700)

    def run(*argv: str) -> None:
        subprocess.run(argv, check=True, capture_output=True, cwd=work)

    run(
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-sha256",
        "-days",
        "2",
        "-subj",
        "/CN=owned-mail-core-ci-ca",
        "-keyout",
        "ca.key",
        "-out",
        "ca.crt",
    )
    for name, address in (("backend", HOSTS["backend"]), ("edge", HOSTS["edge"])):
        run(
            "openssl",
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            f"/CN={name}.fixture.test",
            "-keyout",
            f"{name}.key",
            "-out",
            f"{name}.csr",
        )
        (work / f"{name}.ext").write_text(f"subjectAltName=DNS:{name}.fixture.test,IP:{address}\n")
        run(
            "openssl",
            "x509",
            "-req",
            "-sha256",
            "-days",
            "2",
            "-in",
            f"{name}.csr",
            "-CA",
            "ca.crt",
            "-CAkey",
            "ca.key",
            "-CAcreateserial",
            "-extfile",
            f"{name}.ext",
            "-out",
            f"{name}.crt",
        )
    for name in HOSTS:
        payload = {
            "ca": (work / "ca.crt").read_text(),
            "crt": (work / f"{name}.crt").read_text(),
            "key": (work / f"{name}.key").read_text(),
            "name": name,
        }
        guest(
            name,
            r"""
python3 -c "$(cat <<'PY'
import json,sys
from pathlib import Path
q=json.load(sys.stdin);d=Path('/etc/mail-core-fixture');d.mkdir(mode=0o755,exist_ok=True)
(d/'ca.crt').write_text(q['ca']);(d/(q['name']+'.crt')).write_text(q['crt'])
k=d/(q['name']+'.key');k.write_text(q['key']);k.chmod(0o600)
PY
)"
""",
            json.dumps(payload),
        )
    evidence["owned_tls"] = {"ca_and_two_san_leaf_certificates": True, "system_trust_modified": False}


def prerequisites() -> None:
    """Existing-host prerequisites the APIs require but do not own: PostgreSQL 17, Redis, PFA schema."""

    guest(
        "backend",
        r"""
export DEBIAN_FRONTEND=noninteractive
install -d -m 0755 /etc/apt/keyrings
curl --fail --silent --show-error https://www.postgresql.org/media/keys/ACCC4CF8.asc -o /etc/apt/keyrings/postgresql.asc
echo 'deb [signed-by=/etc/apt/keyrings/postgresql.asc] https://apt.postgresql.org/pub/repos/apt noble-pgdg main' > /etc/apt/sources.list.d/pgdg.list
apt-get update -qq
apt-get install -y -qq --no-install-recommends postgresql-17 redis-server php8.3-cli php8.3-pgsql php8.3-mbstring php8.3-intl php8.3-xml > /var/lib/mail-core-fixture/prerequisites.log
systemctl is-active --quiet postgresql@17-main redis-server
""",
        timeout=1200,
    )
    assert_absent("backend", "after-prerequisites")
    guest(
        "backend",
        f"ARCHIVE_URL={PFA_ARCHIVE}\nARCHIVE_SHA={PFA_SHA256}\n"
        + r"""
python3 -c "$(cat <<'PY'
import grp,json,os,subprocess,sys
from pathlib import Path
q=json.load(sys.stdin)
with open('/etc/redis/redis.conf','a') as stream:stream.write('requirepass '+q['redis']+'\n')
sql=("SET password_encryption='scram-sha-256';CREATE ROLE postfixadmin LOGIN PASSWORD '"+q['pfa']+"';CREATE DATABASE mail;")
psql=['runuser','-u','postgres','--','psql','-XAtq','-v','ON_ERROR_STOP=1','-d']
subprocess.run(psql+['postgres'],input=sql,text=True,check=True,capture_output=True)
subprocess.run(psql+['mail'],input='GRANT CONNECT,CREATE,TEMPORARY ON DATABASE mail TO postfixadmin;GRANT CREATE ON SCHEMA public TO postfixadmin;',text=True,check=True,capture_output=True)
Path('/var/lib/mail-core-fixture/pfa-config.json').write_text(json.dumps({'password':q['pfa']}));os.chmod('/var/lib/mail-core-fixture/pfa-config.json',0o600)
PY
)"
systemctl restart redis-server
archive=/var/lib/mail-core-fixture/postfixadmin.tar.gz
curl --fail --silent --show-error --location "$ARCHIVE_URL" -o "$archive"
echo "$ARCHIVE_SHA  $archive" | sha256sum --check --status
install -d -m 0755 /opt/postfixadmin-core-fixture
tar -xzf "$archive" --strip-components=1 -C /opt/postfixadmin-core-fixture
install -d -o www-data -g www-data -m 0750 /opt/postfixadmin-core-fixture/templates_c
python3 -c "$(cat <<'PY'
import grp,json,os
from pathlib import Path
secret=Path('/var/lib/mail-core-fixture/pfa-config.json');password=json.loads(secret.read_text())['password'];secret.unlink()
p=Path('/opt/postfixadmin-core-fixture/config.local.php')
p.write_text("<?php\n$CONF['configured']=true;\n$CONF['database_type']='pgsql';\n$CONF['database_host']='127.0.0.1';\n"
             "$CONF['database_user']='postfixadmin';\n$CONF['database_password']='"+password+"';\n$CONF['database_name']='mail';\n"
             "$CONF['encrypt']='dovecot:SHA512-CRYPT';\n")
p.chmod(0o640);os.chown(p,0,grp.getgrnam('www-data').gr_gid)
PY
)"
runuser -u www-data -- bash -c 'cd /opt/postfixadmin-core-fixture && php public/upgrade.php' > /dev/null
""",
        json.dumps({"redis": OWNED["redis_password"], "pfa": OWNED["pfa_password"]}),
        timeout=600,
    )
    catalog = guest_json(
        "backend",
        r"""
runuser -u postgres -- psql -XAtq -d mail <<'SQL'
SELECT json_build_object(
 'pfa_schema_version',(SELECT value FROM config WHERE name='version'),
 'database_owner',(SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='mail'),
 'public_schema_owner',(SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='public'),
 'mail_role_exists',(SELECT count(*)>0 FROM pg_roles WHERE rolname='mail'))
SQL
""",
    )
    assert catalog == {
        "pfa_schema_version": "1851",
        "database_owner": "postgres",
        "public_schema_owner": "pg_database_owner",
        "mail_role_exists": False,
    }, catalog
    evidence["prerequisites"] = {
        "postgresql": "17 (PGDG)",
        "redis_requirepass": True,
        "postfixadmin_upstream_cli": "4.0.5",
        "pfa_archive_sha256": PFA_SHA256,
        "catalog": catalog,
    }
    record()


def configs() -> tuple[MailBackendConfig, MailRelayConfig, MailSpamConfig]:
    backend = MailBackendConfig(
        domains=("example.test", "alias.example.test"),
        sender_only_domains=("send.example.test",),
        schema_mode="postfixadmin",
        initial_user="owner",
        initial_user_domain="example.test",
        hostname="backend.fixture.test",
        mydomain="fixture.test",
        imap_hostname="backend.fixture.test",
        smtp_hostname="backend.fixture.test",
        relay_host="edge.fixture.test",
        relay_port=587,
        inet_interfaces="127.0.0.1,192.168.104.1",
        mynetworks=("127.0.0.0/8", "[::1]/128", "192.168.104.3/32"),
        local_delivery_clients=("192.168.104.21/32",),
        vmail_path="/var/lib/mail-core-vmail",
        tls_cert="/etc/mail-core-fixture/backend.crt",
        tls_key="/etc/mail-core-fixture/backend.key",
        spam_to_junk_enabled=True,
        extra_milters=("unix:rspamd/milter.sock",),
        postfixadmin_domain_aliases=(DomainAlias(alias_domain="alias.example.test", target_domain="example.test"),),
        forward_aliases=(
            ForwardAlias(
                address="forward@example.test", destinations=("dest@remote.fixture.test", "owner@example.test")
            ),
        ),
    )
    relay = MailRelayConfig(
        domains=("example.test", "alias.example.test"),
        hostname="edge.fixture.test",
        mydomain="fixture.test",
        backend_host="backend.fixture.test",
        inet_interfaces="127.0.0.1,192.168.104.3",
        tls_cert="/etc/mail-core-fixture/edge.crt",
        tls_key="/etc/mail-core-fixture/edge.key",
        verify_recipients=True,
        postscreen_enabled=True,
        postscreen_access_extra=("192.168.104.1/32", "198.18.0.21/32"),
        postgrey_whitelist_clients_extra=("192.168.104.1",),
        greylisting_delay=1,
        local_recursor_enabled=False,
        submission_discard_spam=True,
        srs_enabled=True,
        srs_domain="example.test",
    )
    spam = MailSpamConfig(
        resolver_enabled=True,
        resolver_install_packages=True,
        local_addrs_extra=("192.168.104.3/32", "192.168.104.21/32"),
        external_relay_enabled=True,
        # Production thresholds: tag only, no backend reject or greylist.
        reject_score=None,
        greylist_score=None,
        add_header_score=6,
        monitoring_probe=MonitoringProbe(
            source_ip="198.18.0.21",
            sender="owner@example.test",
            recipient="owner@example.test",
            subject_prefix="Owned probe",
        ),
    )
    return backend, relay, spam


def secret_values() -> dict[str, SecretValues]:
    ref = SecretRef("owned-ci-fixture.yml")
    return {
        "backend": SecretValues(
            ref, {k: OWNED[k] for k in ("postgres_password", "relay_password", "initial_user_password")}
        ),
        "relay": SecretValues(ref, {"sasl_password": OWNED["relay_password"], "srs_secret": OWNED["srs_secret"]}),
        "spam": SecretValues(ref, {"web_password": OWNED["web_password"], "redis_password": OWNED["redis_password"]}),
    }


def deploy(stage: str, cfg: Any, values: SecretValues, label: str) -> Any:
    deploys: dict[str, Callable[..., Any]] = {
        "backend": deploy_mail_backend,
        "relay": deploy_mail_relay,
        "spam": deploy_mail_spam,
    }
    fn = deploys[stage]
    host = "edge" if stage == "relay" else "backend"
    run = run_deploy_ssh(fn, cfg, values, host_name=f"owned-mail-{host}", host_data=connection(host))
    ops = [dataclasses.asdict(op) for op in run.ops]
    payload = {
        "stage": stage,
        "label": label,
        "succeeded": run.succeeded,
        "error_type": type(run.error).__name__ if run.error else None,
        "seconds": run.seconds,
        "operations": len(ops),
        "managed_changes": list(run.mutating_changed_ops),
    }
    text = json.dumps({**payload, "ops": ops}, indent=2)
    assert not any(value in text for value in OWNED.values()), "owned credential reached operation evidence"
    (EVIDENCE / f"deploy-{stage}-{label}.json").write_text(text + "\n")
    evidence.setdefault("deploys", []).append(payload)
    record()
    return run


def package_fault(backend: MailBackendConfig, values: SecretValues) -> None:
    guest(
        "backend",
        "printf 'Package: postfix\\nPin: version *\\nPin-Priority: -1\\n' > /etc/apt/preferences.d/mail-core-fixture-fault\n",
    )
    run = deploy("backend", backend, values, "package-fault")
    assert not run.succeeded, "deploy proceeded although Postfix could not be installed"
    state = guest_json(
        "backend",
        r"""
python3 -c "$(cat <<'PY'
import grp,json,pwd,subprocess
from pathlib import Path
def has(fn,name):
    try:fn(name);return True
    except KeyError:return False
procs=subprocess.run(['ps','-eo','comm='],capture_output=True,text=True,check=True).stdout.split()
print(json.dumps({'postfix_user':has(pwd.getpwnam,'postfix'),'postfix_group':has(grp.getgrnam,'postfix'),
 'postdrop_group':has(grp.getgrnam,'postdrop'),'etc_postfix':Path('/etc/postfix').exists(),'etc_dovecot':Path('/etc/dovecot').exists(),
 'mail_core_markers':sorted(p.name for p in Path('/var/lib/ops-deploy/mail-core').glob('*')) if Path('/var/lib/ops-deploy/mail-core').exists() else [],
 'master_running':'master' in procs,'mail_role':subprocess.run(['runuser','-u','postgres','--','psql','-XAtq','-c',"SELECT count(*) FROM pg_roles WHERE rolname='mail'"],capture_output=True,text=True,check=True).stdout.strip()}))
PY
)"
""",
    )
    evidence["package_fault"] = {
        "deploy_refused": True,
        "error_type": type(run.error).__name__ if run.error else None,
        "after": state,
    }
    assert state == {
        "postfix_user": False,
        "postfix_group": False,
        "postdrop_group": False,
        "etc_postfix": False,
        "etc_dovecot": False,
        "mail_core_markers": [],
        "master_running": False,
        "mail_role": "0",
    }, state
    assert_absent("backend", "after-package-fault")
    guest("backend", "rm /etc/apt/preferences.d/mail-core-fixture-fault\n")
    record()


EFFECTIVE = r"""
python3 -c "$(cat <<'PY'
import json,os,subprocess,sys,time
from pathlib import Path
# /proc start ticks count from boot (CLOCK_BOOTTIME); /proc/stat btime is whole seconds only.
ticks=os.sysconf('SC_CLK_TCK');boot=time.clock_gettime(time.CLOCK_REALTIME)-time.clock_gettime(time.CLOCK_BOOTTIME)
def started(pid):return boot+int(Path(f'/proc/{pid}/stat').read_text().rsplit(') ',1)[1].split()[19])/ticks
def pid(unit):
    if unit=='postfix':return int(Path('/var/spool/postfix/pid/master.pid').read_text().split()[0])
    return int(subprocess.run(['systemctl','show','-p','MainPID','--value',unit],capture_output=True,text=True,check=True).stdout)
out={}
for pair in sys.argv[1:]:
    unit,config=pair.split('=',1)
    p=pid(unit);assert p>0,unit
    out[unit]={'pid':p,'active':subprocess.run(['systemctl','is-active','--quiet',unit]).returncode==0,
               'started_after_config':started(p)>Path(config).stat().st_mtime,'config':config}
def postconf(name):return subprocess.run(['postconf','-h',name],capture_output=True,text=True,check=True).stdout.strip()
out['postfix_effective']={'myhostname':postconf('myhostname'),'smtpd_milters':postconf('smtpd_milters'),'relay_domains':postconf('relay_domains')}
out['listeners']=sorted({line.split()[3] for line in subprocess.run(['ss','-Hltn'],capture_output=True,text=True,check=True).stdout.splitlines()})
if 'postsrsd' in out:out['postsrsd_cmdline']=Path(f"/proc/{out['postsrsd']['pid']}/cmdline").read_bytes().replace(b'\0',b' ').decode()
if Path('/usr/bin/doveconf').exists():out['dovecot_ssl']=subprocess.run(['doveconf','-h','ssl'],capture_output=True,text=True,check=True).stdout.strip()
print(json.dumps(out))
PY
)" "$@"
"""
UNITS = {
    "backend": (
        "postfix=/etc/postfix/main.cf",
        "dovecot=/etc/dovecot/dovecot.conf",
        "opendkim=/etc/opendkim.conf",
        "rspamd=/etc/rspamd/local.d/actions.conf",
        "unbound-rspamd=/etc/unbound/rspamd-resolver.conf",
    ),
    "edge": ("postfix=/etc/postfix/main.cf", "postgrey=/etc/default/postgrey", "postsrsd=/etc/default/postsrsd"),
}


def effective(name: str) -> dict[str, Any]:
    return cast("dict[str, Any]", guest_json(name, "set -- " + " ".join(UNITS[name]) + "\n" + EFFECTIVE))


SINK = r"""
install -d -m 0700 /var/lib/mail-core-fixture/sink
cat > /var/lib/mail-core-fixture/sink.py <<'PY'
import email,json,pathlib,socketserver,ssl,uuid
ROOT=pathlib.Path('/var/lib/mail-core-fixture/sink')
class Handler(socketserver.StreamRequestHandler):
    def reply(self,v):self.wfile.write(v+b'\r\n');self.wfile.flush()
    def handle(self):
        self.request.settimeout(20);self.reply(b'220 sink.fixture.test owned sink');sender=b'';rcpt=b'';tls=False
        while True:
            line=self.rfile.readline(8192)
            if not line:break
            cmd=line.split(b' ',1)[0].strip().upper()
            if cmd in (b'EHLO',b'HELO'):
                self.reply(b'250-sink.fixture.test')
                if not tls:self.reply(b'250-STARTTLS')
                self.reply(b'250 SIZE 1048576')
            elif cmd==b'STARTTLS' and not tls:
                self.reply(b'220 Begin TLS');c=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);c.load_cert_chain('/etc/mail-core-fixture/edge.crt','/etc/mail-core-fixture/edge.key')
                self.connection=c.wrap_socket(self.request,server_side=True);self.rfile=self.connection.makefile('rb');self.wfile=self.connection.makefile('wb');tls=True
            elif cmd==b'MAIL':sender=line.split(b':',1)[1].strip().split(b'>')[0].lstrip(b'<');self.reply(b'250 ok')
            elif cmd==b'RCPT':
                rcpt=line.split(b':',1)[1].strip().split(b'>')[0].lstrip(b'<')
                self.reply(b'250 ok' if rcpt.lower().endswith(b'@remote.fixture.test') else b'550 owned .test only')
            elif cmd==b'DATA':
                self.reply(b'354 go');body=bytearray()
                while True:
                    row=self.rfile.readline(65536)
                    if row in (b'.\r\n',b'.\n'):break
                    if not row or len(body)>1048576:raise ValueError('bound')
                    body.extend(row[1:] if row.startswith(b'..') else row)
                m=email.message_from_bytes(bytes(body))
                (ROOT/(str(uuid.uuid4())+'.json')).write_text(json.dumps({'message_id':m.get('Message-ID',''),'tls':tls,'srs':sender.lower().startswith((b'srs0=',b'srs1=')),'dkim':bool(m.get('DKIM-Signature'))}))
                self.reply(b'250 captured')
            elif cmd==b'QUIT':self.reply(b'221 bye');break
            else:self.reply(b'250 ok')
class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True;daemon_threads=True
with Server(('192.168.104.20',25),Handler) as s:s.serve_forever()
PY
systemd-run --quiet --unit=mail-core-owned-sink python3 /var/lib/mail-core-fixture/sink.py
"""

CLIENT = r"""
python3 -c "$(cat <<'PY'
import email.message,email.utils,imaplib,json,smtplib,ssl,sys,time,uuid
q=json.loads(sys.stdin.readline())
ctx=ssl.create_default_context(cafile='/etc/mail-core-fixture/ca.crt')
m=email.message.EmailMessage();m['From']='owner@example.test';m['To']=q['to'];m['Subject']=q['subject']
m['Date']=email.utils.formatdate();m['Message-ID']='<'+str(uuid.uuid4())+'@fixture.test>';m.set_content('Owned synthetic CI fixture mail.')
codes=[]
for attempt in range(10):
    try:
        with smtplib.SMTP(q['host'],q['port'],timeout=30,source_address=(q['source'],0) if q.get('source') else None,local_hostname='client.fixture.test') as s:
            s.ehlo();s.starttls(context=ctx);s.ehlo()
            if q.get('login'):s.login('owner@example.test',q['password'])
            s.send_message(m);codes.append(250);break
    except smtplib.SMTPRecipientsRefused as e:
        (code,text),=e.recipients.values();codes.append(code)
        assert code in (450,451),code
        time.sleep(3)
found=None;milter=None
if q.get('imap'):
    deadline=time.monotonic()+300
    with imaplib.IMAP4_SSL('backend.fixture.test',993,ssl_context=ctx,timeout=10) as imap:
        assert imap.login('owner@example.test',q['password'])[0]=='OK'
        while found is None and time.monotonic()<deadline:
            for folder in ('INBOX','Junk'):
                if imap.select(folder,readonly=True)[0]=='OK':
                    status,data=imap.uid('search',None,'HEADER','Message-ID',m['Message-ID'])
                    if status=='OK' and data[0]:
                        status,rows=imap.uid('fetch',data[0].split()[-1],'(BODY.PEEK[HEADER.FIELDS (X-SPAMD-BAR X-SPAM-STATUS AUTHENTICATION-RESULTS)])')
                        headers=b''.join(row[1] for row in rows if isinstance(row,tuple)).lower()
                        found=folder;milter={'x_spam_status':b'x-spam-status:' in headers,'x_spamd_bar':b'x-spamd-bar:' in headers}
                        break
            time.sleep(1)
print(json.dumps({'codes':codes,'message_id':m['Message-ID'],'imap_folder':found,'rspamd_milter_headers':milter}))
PY
)"
"""


def mail_flows() -> None:
    guest("edge", SINK)
    password = OWNED["initial_user_password"]
    inbound = guest_json(
        "backend",
        CLIENT,
        json.dumps(
            {
                "to": "owner@example.test",
                "subject": "Owned CI inbound",
                "host": "edge.fixture.test",
                "port": 25,
                "source": "198.18.0.21",
                "imap": True,
                "password": password,
            }
        )
        + "\n",
        timeout=600,
    )
    assert (inbound["codes"][-1], inbound["imap_folder"] in ("INBOX", "Junk")) == (250, True), inbound
    # milter_default_action=accept would deliver without Rspamd; its own headers prove the milter ran.
    assert inbound["rspamd_milter_headers"] == {"x_spam_status": True, "x_spamd_bar": True}, inbound
    outbound = guest_json(
        "backend",
        CLIENT,
        json.dumps(
            {
                "to": "dest@remote.fixture.test",
                "subject": "Owned CI outbound",
                "host": "backend.fixture.test",
                "port": 587,
                "login": True,
                "password": password,
            }
        )
        + "\n",
        timeout=300,
    )
    assert outbound["codes"][-1] == 250, outbound
    sink = []
    for _ in range(90):
        sink = guest_json(
            "edge",
            "python3 -c \"import json,pathlib;print(json.dumps([json.loads(p.read_text()) for p in pathlib.Path('/var/lib/mail-core-fixture/sink').glob('*.json')]))\"\n",
        )
        if any(item["message_id"] == outbound["message_id"] for item in sink):
            break
        time.sleep(2)
    delivered = next((item for item in sink if item["message_id"] == outbound["message_id"]), None)
    assert delivered is not None, "owned sink delivery missing"
    assert (delivered["tls"], delivered["dkim"], delivered["srs"]) == (True, True, False), delivered
    queue = guest_json(
        "edge",
        'postqueue -j | python3 -c "import sys,json;print(json.dumps(len([l for l in sys.stdin if l.strip()])))"\n',
    )
    evidence["mail_flows"] = {
        "edge25_to_backend_milter_lmtp_imaps": {
            "edge_codes": inbound["codes"],
            "imap_folder": inbound["imap_folder"],
            "rspamd_milter_headers": inbound["rspamd_milter_headers"],
        },
        "backend587_sasl_relay_edge_to_owned_sink": {
            "tls": True,
            "dkim_signature_present": True,
            "own_sender_not_srs": True,
        },
        "edge_queue_after": queue,
    }
    record()


def versions() -> dict[str, Any]:
    out = {}
    for name in HOSTS:
        out[name] = guest_json(
            name,
            "set -- "
            + " ".join(MAIL_PACKAGES[name])
            + "\n"
            + PACKAGE_STATE.replace("${db:Status-Status}", "${Version}"),
        )
    return out


def journals() -> None:
    """Guest journals for diagnosis; per-run credentials never leave unredacted."""

    for name in HOSTS:
        result = subprocess.run(
            ["journalctl", "-M", f"mc-{name}", "--no-pager", "-n", "400"], capture_output=True, text=True
        )
        text = result.stdout + result.stderr
        hits = sum(text.count(value) for value in OWNED.values())
        for value in OWNED.values():
            text = text.replace(value, "<owned-credential-redacted>")
        (EVIDENCE / f"mc-{name}-journal.log").write_text(text)
        evidence.setdefault("journal_redactions", {})[name] = hits
    record()


def main() -> None:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    (EVIDENCE / "harness-started").write_text("credentials exist from here on\n")
    try:
        qualify()
    finally:
        journals()


def qualify() -> None:
    for name in HOSTS:
        assert_absent(name, "fresh-system")
    owned_tls()
    prerequisites()
    backend, relay, spam = configs()
    values = secret_values()
    package_fault(backend, values["backend"])
    for name in HOSTS:
        assert_absent(name, "before-first-install")
    for stage, cfg in (("backend", backend), ("relay", relay), ("spam", spam)):
        run = deploy(stage, cfg, values[stage], "first")
        assert run.succeeded, f"first {stage} install failed"
    evidence["installed_versions"] = versions()
    first = {name: effective(name) for name in HOSTS}
    evidence["effective_after_first"] = first
    record()
    for name, state in first.items():
        for unit in (pair.split("=", 1)[0] for pair in UNITS[name]):
            assert (state[unit]["active"], state[unit]["started_after_config"]) == (True, True), (
                name,
                unit,
                state[unit],
            )
    assert first["backend"]["postfix_effective"]["myhostname"] == "backend.fixture.test"
    assert "rspamd/milter.sock" in first["backend"]["postfix_effective"]["smtpd_milters"]
    assert first["backend"]["dovecot_ssl"] == "required"
    assert first["edge"]["postfix_effective"]["myhostname"] == "edge.fixture.test"
    # Observable effective configuration of the running daemons (package defaults differ).
    backend_listeners, edge_listeners = set(first["backend"]["listeners"]), set(first["edge"]["listeners"])
    assert {"127.0.0.1:25", "192.168.104.1:25", "127.0.0.1:5335", "127.0.0.1:11334"} <= backend_listeners, (
        backend_listeners
    )
    assert any(item.endswith(":993") for item in backend_listeners), backend_listeners
    assert not {"0.0.0.0:25", "[::]:25", "0.0.0.0:143", "[::]:143"} & backend_listeners, backend_listeners
    assert "192.168.104.3:25" in edge_listeners, edge_listeners
    assert not {"0.0.0.0:25", "[::]:25"} & edge_listeners, edge_listeners
    assert "example.test" in first["edge"]["postsrsd_cmdline"], "postsrsd runs without the configured SRS domain"
    mail_flows()
    before = {name: effective(name) for name in HOSTS}
    for stage, cfg in (("backend", backend), ("relay", relay), ("spam", spam)):
        run = deploy(stage, cfg, values[stage], "repeat")
        assert run.succeeded, f"repeat {stage} failed"
        assert not run.mutating_changed_ops, f"repeat {stage} changed managed state"
    after = {name: effective(name) for name in HOSTS}
    pids = {
        name: {
            unit: (before[name][unit]["pid"], after[name][unit]["pid"])
            for unit in (p.split("=", 1)[0] for p in UNITS[name])
        }
        for name in HOSTS
    }
    evidence["repeat_pids"] = pids
    assert all(b == a for units in pids.values() for b, a in units.values()), pids
    evidence["passed"] = True
    record()
    print(json.dumps({"mail_core_native_passed": True}))


if __name__ == "__main__":
    main()
