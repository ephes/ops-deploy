"""Owned native PHP/FPM/nginx/mail/SQL qualification, never inventory traffic."""

from __future__ import annotations

import ast
import base64
import configparser
import hashlib
import hmac
import http.cookies
import imaplib
import json
import os
import re
import secrets
import shlex
import smtplib
import ssl
import struct
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict
from importlib import import_module
from pathlib import Path
from typing import Any
from unittest.mock import patch

EVIDENCE = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/var/tmp/mail-web-evidence")
FIXTURE = Path("/opt/mail-web-fixture")
MATERIAL = {key: secrets.token_hex(18) for key in ("db_password", "setup_password", "admin_password", "mail_password")}


def run(*args: str, stdin: str | None = None) -> str:
    result = subprocess.run(args, input=stdin, text=True, capture_output=True, timeout=180)
    if result.returncode:
        raise RuntimeError("fixture command failed: " + Path(args[0]).name)
    return result.stdout.strip()


def write(path: str | Path, body: str, mode: int = 0o644) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    p.chmod(mode)


def snapshot() -> dict[str, Any]:
    result = {}
    for root in [
        "/opt/postfixadmin",
        "/opt/snappymail",
        "/var/lib/mail-web-fixture/snappy",
        "/etc/nginx",
        "/etc/php/8.3/fpm",
        "/var/www",
    ]:
        base = Path(root)
        if not base.exists():
            continue
        for p in [base, *sorted(base.rglob("*"))]:
            st = p.lstat()
            result[str(p)] = {
                "mode": st.st_mode,
                "uid": st.st_uid,
                "gid": st.st_gid,
                "mtime": st.st_mtime_ns,
                "ctime": st.st_ctime_ns,
                "link": os.readlink(p) if p.is_symlink() else None,
                "sha": hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() and not p.is_symlink() else None,
            }
    return result


def trace_read_only(text: str) -> None:
    mutations = []
    for line in text.splitlines():
        if not re.search(
            r"^(?:[0-9]+\s+)?(?:open|openat|openat2|creat)\(.*(?:O_WRONLY|O_RDWR|O_CREAT|O_TRUNC)|^(?:[0-9]+\s+)?(?:mkdir|mkdirat|unlink|unlinkat|rename|renameat|renameat2|chmod|fchmod|fchmodat|fchmodat2|chown|lchown|fchown|fchownat|utime|utimes|utimensat|symlink|symlinkat|link|linkat|truncate|ftruncate)\(",
            line,
        ):
            continue
        if re.match(r'^(?:[0-9]+\s+)?(?:open\("/dev/null",|openat\(AT_FDCWD, "/dev/null",)', line):
            continue
        if re.search(
            r'openat\(AT_FDCWD, "/dev/tty", O_RDWR\|O_NONBLOCK\) = -1 ENXIO \(No such device or address\)$', line
        ):
            continue
        mutations.append(line)
    assert not mutations, mutations


def is_upgrader_exec(line: str) -> bool:
    return bool(
        re.match(r'^\d+ execve\("[^" ]*/php[^" ]*",', line)
        and re.search(r'\["(?:/usr/bin/)?php(?:[0-9]+\.[0-9]+)?", "public/upgrade.php"\]', line)
        and line.endswith(" = 0")
    )


def partial_bootstrap_command(command: str) -> str:
    """Inject the historical SQL failure into public source, never secret stdin."""
    argv = shlex.split(command)
    loader = argv[-1]
    calls = [
        node
        for node in ast.walk(ast.parse(loader))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "b64decode"
    ]
    assert len(calls) == 1
    assert len(calls[0].args) == 1
    encoded = ast.literal_eval(calls[0].args[0])
    assert isinstance(encoded, str)
    assert loader.count(encoded) == 1
    source = base64.b64decode(encoded, validate=True).decode()
    assert source.count("$1::varchar") == 1
    mutated = source.replace("$1::varchar", "$1")
    replacement = base64.b64encode(mutated.encode()).decode()
    return shlex.join([*argv[:-1], loader.replace(encoded, replacement)])


def seed_admin_totp(path: Path, value: str, *, php_cli: str = "/usr/bin/php8.3") -> dict[str, Any]:
    """Owned fixture setup: admit only an absent/semantically empty admin TOTP."""
    assert re.fullmatch(r"[A-Z2-7]{32}", value)
    text = path.read_bytes().decode()

    class CasePreservingParser(configparser.ConfigParser):
        def optionxform(self, optionstr: str) -> str:
            return optionstr

    parser = CasePreservingParser(interpolation=None, strict=True)
    parser.read_string(text)
    assert not parser.defaults()
    assert parser.has_section("security")
    source = r"""
$q=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);
$ini=@parse_ini_string($q['text'],true);
if ($ini===false || !isset($ini['security']) || !is_array($ini['security'])) { exit(1); }
$present=array_key_exists('admin_totp',$ini['security']);
$value=$present ? $ini['security']['admin_totp'] : '';
if (!is_string($value)) { exit(1); }
echo json_encode(['present'=>$present,'empty'=>$value==='','sha256'=>hash('sha256',$value)],JSON_THROW_ON_ERROR);
"""

    def parsed(body: str) -> dict[str, Any]:
        result: dict[str, Any] = json.loads(run(php_cli, "-r", source, stdin=json.dumps({"text": body})))
        return result

    prior = parsed(text)
    if not prior["empty"]:
        raise ValueError("owned fixture refuses unexpected nonempty admin TOTP")
    headers = list(re.finditer(r"(?m)^[ \t]*\[([^]\r\n]+)\][ \t]*(?:[;#][^\r\n]*)?(?=\r?$)", text))
    matches = [(n, h) for n, h in enumerate(headers) if h.group(1) == "security"]
    assert len(matches) == 1
    n, header = matches[0]
    end = headers[n + 1].start() if n + 1 < len(headers) else len(text)
    region = text[header.end() : end]
    assignments = list(re.finditer(r"(?m)^[ \t]*admin_totp[ \t]*=[^\r\n]*(?=\r?$)", region))
    assert len(assignments) <= 1
    assignment = 'admin_totp = "' + value + '"'
    if assignments:
        old = assignments[0]
        line = old.group(0)
        prefix = re.match(r"[ \t]*admin_totp[ \t]*=[ \t]*", line)
        assert prefix is not None
        remainder = line[prefix.end() :]
        suffix = re.search(r"[ \t]*[;#].*$|[ \t]*$", remainder)
        assert suffix is not None
        replacement = prefix.group(0) + '"' + value + '"' + suffix.group(0)
        region = region[: old.start()] + replacement + region[old.end() :]
    else:
        newline = "\r\n" if region.startswith("\r\n") else "\n"
        region = newline + assignment + region
    result = text[: header.end()] + region + text[end:]
    after = parsed(result)
    assert after["present"]
    assert after["sha256"] == hashlib.sha256(value.encode()).hexdigest()
    path.write_bytes(result.encode())
    return {"prior_key_present": prior["present"], "prior_semantic_empty": True, "seeded": True}


def credential_admission(cfg: Any) -> None:
    """Owned synthetic corruption controls; production never edits unknown hashes."""
    from ops_deploy.core.secrets import SecretRef, SecretValues

    module = import_module("ops_deploy.services._mail_web.deploy")
    payload = module.render(cfg, SecretValues(SecretRef("fixture.yml"), MATERIAL))
    source = (module.ROOT / "files/credentials.php").read_text().removeprefix("<?php")
    request = dict(payload["credentials"], apply=True, reconcile_admin=True)
    setup = Path("/opt/postfixadmin/config.local.php").read_text()
    match = re.search(r"setup_password'\]\s*=\s*'([^']+)'", setup)
    assert match is not None
    request["existing_hash"] = match.group(1)
    original = sql("SELECT password FROM admin WHERE username='admin@example.test';")
    before = database_identity()
    protections = snapshot()
    malformed = [
        "{SHA512-CRYPT}$6$rounds=0999$salt$" + "A" * 85 + ".",
        "{SHA512-CRYPT}$6$salt$" + "A" * 85 + "z",
        "{SHA512-CRYPT}$6$rounds=1000000000$salt$" + "A" * 85 + ".",
    ]
    results = []
    try:
        for value in malformed:
            sql("UPDATE admin SET password='" + value + "' WHERE username='admin@example.test';")
            corrupted = database_identity()
            result = subprocess.run(
                ["/usr/bin/php8.3", "-r", source], input=json.dumps(request), capture_output=True, text=True, timeout=10
            )
            assert result.returncode != 0
            assert not result.stdout
            assert database_identity() == corrupted
            assert snapshot() == protections
            results.append({"refused": True, "database_unchanged": True, "files_unchanged": True})
    finally:
        # This is explicit owned-fixture setup restoration, never a production repair.
        sql("UPDATE admin SET password='" + original.replace("'", "''") + "' WHERE username='admin@example.test';")
    assert database_identity() == before
    (EVIDENCE / "credential-admission.json").write_text(json.dumps({"cases": results, "restored": True}, indent=2))


def deploy(
    cfg: Any, label: str, *, fail: bool = False, mutate_payload: Any = None, trace: bool = False
) -> dict[str, Any]:
    from pyinfra.api import Config, Inventory, State
    from pyinfra.api.command import QuoteString, StringCommand
    from pyinfra.api.connect import connect_all, disconnect_all
    from pyinfra.api.deploy import add_deploy
    from pyinfra.api.operations import run_ops
    from pyinfra.connectors.local import LocalConnector

    from ops_deploy.core.secrets import SecretRef, SecretValues
    from ops_deploy.testing.harness import collect_ops

    api = import_module("ops_deploy.services." + cfg.service_name)
    entry = getattr(api, "deploy_" + cfg.service_name)
    before = snapshot()
    database_before = database_identity()
    pids = run("systemctl", "show", "nginx", "php8.3-fpm", "-p", "MainPID", "--value")
    original = LocalConnector.run_shell_command
    counter = 0

    def traced(self: Any, command: Any, **kwargs: Any) -> Any:
        nonlocal counter
        counter += 1
        path = EVIDENCE / f"{label}-{counter}.strace"
        raw = command if isinstance(command, str) else str(command.get_raw_value())
        wrapped = StringCommand(
            "strace",
            "-f",
            "-s",
            "1000000",
            "-e",
            "trace=file,process,fchmod,fchown,ftruncate",
            "-o",
            str(path),
            "sh",
            "-c",
            QuoteString(raw),
        )
        result = original(self, wrapped, **kwargs)
        if label.endswith("repeat"):
            trace_read_only(path.read_text())
        return result

    def no_upload(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("repeat uploaded a file")

    patches = []
    if label.endswith("repeat") or trace:
        patches.extend(
            [
                patch.object(LocalConnector, "run_shell_command", traced),
                patch.object(LocalConnector, "put_file", no_upload),
            ]
        )
    if mutate_payload is not None:
        module = import_module("ops_deploy.services._mail_web.deploy")
        original_render = module.render

        def faulty(*args: Any, **kwargs: Any) -> Any:
            payload = original_render(*args, **kwargs)
            mutate_payload(payload)
            return payload

        patches.append(patch.object(module, "render", faulty))
    for item in patches:
        item.start()
    state = State(Inventory(([("@local", {})], {})), Config())
    error = None
    try:
        connect_all(state)
        add_deploy(state, entry, cfg=cfg, secrets=SecretValues(SecretRef("fixture.yml"), MATERIAL))
        run_ops(state)
    except Exception:
        error = traceback.format_exc()
    finally:
        ops = collect_ops(state, "@local")
        disconnect_all(state)
        for item in reversed(patches):
            item.stop()
    record = {
        "error": error,
        "operations": [asdict(o) for o in ops],
        "managed": [o.name for o in ops if o.changed and not o.read_only],
        "failed_operations": [o.name for o in ops if not o.succeeded],
        "failure_may_have_written_staging_or_recovery": bool(error),
        "files_unchanged": before == snapshot(),
        "database_unchanged": database_before == database_identity(),
        "pids_unchanged": pids == run("systemctl", "show", "nginx", "php8.3-fpm", "-p", "MainPID", "--value"),
    }
    (EVIDENCE / (label + ".json")).write_text(json.dumps(record, indent=2))
    assert bool(error) == fail, record
    if not fail:
        assert all(o.succeeded for o in ops), record
    if label.endswith("repeat"):
        assert not record["managed"], record
        assert record["files_unchanged"], record
        assert record["database_unchanged"], record
        assert record["pids_unchanged"], record
    return record


def shell_transport(cfg: Any) -> None:
    from pyinfra.api.command import StringCommand
    from pyinfra.connectors.util import make_unix_command

    from ops_deploy.core.secrets import SecretRef, SecretValues

    module = import_module("ops_deploy.services._mail_web.deploy")
    payload = module.render(cfg, SecretValues(SecretRef("fixture.yml"), MATERIAL))
    payload["release"], payload["previous_releases"] = module.release_records(cfg)
    command = make_unix_command(StringCommand(module.command())).get_raw_value()
    before = snapshot()
    db_before = database_identity()
    pids = run("systemctl", "show", "nginx", "php8.3-fpm", "-p", "MainPID", "--value")
    results = {}
    for shell in ("bash", "fish"):
        trace = EVIDENCE / (cfg.service_name + "-" + shell + "-transport.strace")
        result = subprocess.run(
            [
                "strace",
                "-f",
                "-s",
                "1000000",
                "-e",
                "trace=file,process,fchmod,fchown,ftruncate",
                "-o",
                str(trace),
                shell,
                "-c",
                command,
            ],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            timeout=120,
        )
        assert result.returncode == 0, shell + " transport failed"
        assert result.stdout.strip() == "changed=false"
        trace_read_only(trace.read_text())
        results[shell] = True
    assert snapshot() == before
    assert database_identity() == db_before
    assert run("systemctl", "show", "nginx", "php8.3-fpm", "-p", "MainPID", "--value") == pids
    (EVIDENCE / (cfg.service_name + "-shell-transport.json")).write_text(
        json.dumps(
            {
                "shells": results,
                "files_database_pids_unchanged": True,
                "confidential_payload": "real stdin",
                "source_transport": "base64 source only",
            }
        )
    )


def foundation() -> None:
    from pydantic import SecretStr
    from pyinfra.api import Config, Inventory, State
    from pyinfra.api.connect import connect_all, disconnect_all
    from pyinfra.api.deploy import add_deploy
    from pyinfra.api.operations import run_ops

    core = import_module("ops_deploy.services._mail_database")

    def ensure() -> None:
        core.ensure_mail_database(
            core.MailDatabaseConfig(name="mail_web_fixture", role="mail_web_fixture"),
            role_password=SecretStr(MATERIAL["db_password"]),
        )

    state = State(Inventory(([("@local", {})], {})), Config())
    connect_all(state)
    try:
        add_deploy(state, ensure)
        run_ops(state)
    finally:
        disconnect_all(state)


def sql(statement: str) -> str:
    return run(
        "runuser",
        "-u",
        "postgres",
        "--",
        "psql",
        "-XAtq",
        "-v",
        "ON_ERROR_STOP=1",
        "-d",
        "mail_web_fixture",
        stdin=statement,
    )


def database_identity() -> str:
    # Read-only logical dump includes IDs, credential hashes, TOTP, rows, owners
    # and grants. Only its digest is exposed; never retain the dump itself.
    value = run("runuser", "-u", "postgres", "--", "pg_dump", "--no-comments", "--dbname=mail_web_fixture")
    # PostgreSQL versions may add a random restrict/unrestrict key per dump.
    value = "\n".join(line for line in value.splitlines() if not line.startswith(("\\restrict ", "\\unrestrict ")))
    return hashlib.sha256(value.encode()).hexdigest()


def synthetic_mail() -> None:
    # VM-only CA and mail account. Restrict recipients and listeners to this fixture.
    run(
        "useradd",
        "--system",
        "--home",
        "/var/lib/mail-web-fixture/mail",
        "--shell",
        "/usr/sbin/nologin",
        "mailwebfixture",
    )
    uid = run("id", "-u", "mailwebfixture")
    gid = run("id", "-g", "mailwebfixture")
    key = FIXTURE / "tls.key"
    cert = FIXTURE / "tls.crt"
    run(
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "2",
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost,IP:127.0.0.1",
        "-keyout",
        str(key),
        "-out",
        str(cert),
    )
    key.chmod(0o600)
    write("/usr/local/share/ca-certificates/mail-web-fixture.crt", cert.read_text())
    run("update-ca-certificates")
    mail = Path("/var/lib/mail-web-fixture/mail/fixture")
    mail.mkdir(parents=True)
    run("chown", "-R", "mailwebfixture:mailwebfixture", "/var/lib/mail-web-fixture/mail")
    write(
        "/etc/dovecot/mail-web-fixture-users", "fixture@example.test:{PLAIN}" + MATERIAL["mail_password"] + "\n", 0o640
    )
    run("chown", "root:dovecot", "/etc/dovecot/mail-web-fixture-users")
    write(
        "/etc/dovecot/dovecot.conf",
        f"""protocols = imap
listen = 127.0.0.1
ssl = required
ssl_cert = <{cert}
ssl_key = <{key}
mail_location = maildir:/var/lib/mail-web-fixture/mail/%n
first_valid_uid = {uid}
passdb {{
 driver = passwd-file
 args = /etc/dovecot/mail-web-fixture-users
}}
userdb {{
 driver = static
 args = uid={uid} gid={gid} home=/var/lib/mail-web-fixture/mail/%n
}}
service imap-login {{
 inet_listener imap {{
 port = 0
 }}
 inet_listener imaps {{
 port = 1993
 ssl = yes
 }}
}}
service auth {{
 unix_listener /var/spool/postfix/private/auth {{
 mode = 0660
 user = postfix
 group = postfix
 }}
}}
auth_mechanisms = plain login
""",
    )
    settings = {
        "inet_interfaces": "loopback-only",
        "myhostname": "mail-web.invalid",
        "mydestination": "",
        "relay_domains": "",
        "smtpd_sasl_type": "dovecot",
        "smtpd_sasl_path": "private/auth",
        "smtpd_sasl_auth_enable": "yes",
        "smtpd_tls_cert_file": str(cert),
        "smtpd_tls_key_file": str(key),
        "smtpd_tls_security_level": "encrypt",
        "smtpd_relay_restrictions": "reject_unauth_destination",
        "virtual_mailbox_domains": "example.test",
        "virtual_mailbox_base": "/var/lib/mail-web-fixture/mail",
        "virtual_mailbox_maps": "hash:/etc/postfix/mail-web-fixture-map",
        "virtual_uid_maps": "static:" + uid,
        "virtual_gid_maps": "static:" + gid,
    }
    for name, value in settings.items():
        run("postconf", "-e", name + "=" + value)
    write("/etc/postfix/mail-web-fixture-map", "fixture@example.test fixture/\n")
    run("postmap", "/etc/postfix/mail-web-fixture-map")
    with Path("/etc/postfix/master.cf").open("a") as f:
        f.write("\n127.0.0.1:2525 inet n - n - - smtpd\n")
    run("systemctl", "restart", "dovecot", "postfix")


class Http:
    def __init__(self, port: int):
        self.port = port
        self.cookies: dict[str, str] = {}

    def request(self, path: str, data: dict[str, Any] | None = None) -> tuple[int, str, Any]:
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args: Any, **kwargs: Any) -> None:
                return None

        headers = {"X-Forwarded-Proto": "https", "Cookie": "; ".join(k + "=" + v for k, v in self.cookies.items())}
        request = urllib.request.Request(
            "http://127.0.0.1:" + str(self.port) + path,
            headers=headers,
            data=urllib.parse.urlencode(data).encode() if data is not None else None,
        )
        try:
            response = urllib.request.build_opener(NoRedirect).open(request, timeout=30)
        except urllib.error.HTTPError as exc:
            response = exc
        for raw in response.headers.get_all("Set-Cookie", []):
            cookie = http.cookies.SimpleCookie()
            cookie.load(raw)
            self.cookies.update({k: v.value for k, v in cookie.items()})
        body = response.read().decode()
        return response.status, body, response.headers


def ui_auth() -> None:
    pfa = Http(8082)
    status, body, _ = pfa.request("/login.php")
    assert status == 200
    token = re.search(r'name="token" value="([^"]+)"', body)
    assert token
    status, _, headers = pfa.request(
        "/login.php",
        {"token": token.group(1), "fUsername": "admin@example.test", "fPassword": MATERIAL["admin_password"]},
    )
    assert status in (302, 303)
    assert "login.php" not in headers.get("Location", "login.php")
    snappy = Http(8088)
    status, body, _ = snappy.request("/?/AppData/")
    assert status == 200
    data = json.loads(body)
    assert data.get("System", {}).get("token")
    status, body, _ = snappy.request(
        "/?/Json/",
        {
            "Action": "Login",
            "Email": "fixture@example.test",
            "Password": MATERIAL["mail_password"],
            "XToken": data["System"]["token"],
        },
    )
    reply = json.loads(body)
    assert status == 200
    assert reply.get("Result")
    assert not reply.get("ErrorCode"), {
        "status": status,
        "error_code": reply.get("ErrorCode"),
    }
    admin = Http(8088)
    status, body, _ = admin.request("/?admin/AppData/")
    assert status == 200
    admin_token = json.loads(body)["System"]["token"]
    fields = {"Action": "AdminLogin", "Login": "admin", "Password": MATERIAL["admin_password"], "XToken": admin_token}
    if "totp_secret" in MATERIAL:
        digest = hmac.new(
            base64.b32decode(MATERIAL["totp_secret"]), struct.pack(">Q", int(time.time()) // 30), hashlib.sha1
        ).digest()
        offset = digest[-1] & 15
        fields["TOTP"] = str((struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1000000).zfill(6)
    status, body, _ = admin.request("/?admin/Json/", fields)
    reply = json.loads(body)
    assert status == 200
    assert reply.get("Result"), {"error_code": reply.get("ErrorCode")}
    (EVIDENCE / "ui-auth.json").write_text(
        json.dumps(
            {
                "postfixadmin_login": True,
                "snappymail_imap_login": True,
                "snappymail_admin_login": True,
                "admin_totp_used": "totp_secret" in MATERIAL,
            }
        )
    )


def local_delivery() -> None:
    context = ssl.create_default_context()
    with smtplib.SMTP("localhost", 2525, timeout=15) as smtp:
        smtp.ehlo()
        smtp.starttls(context=context)
        smtp.ehlo()
        smtp.login("fixture@example.test", MATERIAL["mail_password"])
        smtp.sendmail(
            "fixture@example.test",
            ["fixture@example.test"],
            "From: fixture@example.test\r\nTo: fixture@example.test\r\n"
            "Subject: owned fixture\r\n\r\nSynthetic local fixture only.\r\n",
        )
    for _ in range(20):
        with imaplib.IMAP4_SSL("localhost", 1993, ssl_context=context) as imap:
            imap.login("fixture@example.test", MATERIAL["mail_password"])
            status, count = imap.select("INBOX")
            if status == "OK" and count[0] is not None and int(count[0]) > 0:
                (EVIDENCE / "local-delivery.json").write_text(
                    json.dumps({"tls_verified": True, "smtp_auth": True, "local_imap_messages": int(count[0])})
                )
                return
        time.sleep(1)
    raise AssertionError("synthetic local delivery not observed")


def seed_previous(cfg: Any) -> None:
    module = import_module("ops_deploy.services._mail_web.deploy")
    from ops_deploy.core.secrets import SecretRef, SecretValues

    payload = module.render(cfg, SecretValues(SecretRef("fixture.yml"), MATERIAL))
    _, previous = module.release_records(cfg)
    payload["release"] = previous[0]
    payload["version"] = previous[0]["version"]
    namespace: dict[str, Any] = {"__name__": "fixture_host"}
    for name in ("mail_web_common.py", "mail_web_release.py"):
        exec((module.ROOT / "files" / name).read_text(), namespace)
    import tempfile

    with tempfile.TemporaryDirectory(prefix="owned-previous-") as directory:
        tree = namespace["extract_release"](payload, Path(directory))
        for path, value in namespace["code_values"](payload, tree).items():
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            namespace["replace_file"](path, value)
    run("systemctl", "restart", "php8.3-fpm")
    if cfg.service_name == "postfixadmin":
        run("php", "-r", "require '/opt/postfixadmin/vendor/autoload.php'; echo 'compatible';")
    ui_auth()
    (EVIDENCE / (cfg.service_name + "-previous.json")).write_text(
        json.dumps(
            {
                "archive_sha256": previous[0]["sha256"],
                "old_runtime_authenticated_ui": True,
                "version": previous[0]["version"],
                "php": run("php", "-r", "echo PHP_VERSION;"),
            }
        )
    )


def stable_resources() -> dict[str, Any]:
    return {
        name: {key: value for key, value in item.items() if key not in {"ctime", "mtime"}}
        for name, item in snapshot().items()
    }


def restart_failure(cfg: Any) -> None:
    # A real systemd restart fails once; the production exception handler must
    # restore owned bytes/metadata and start the previous FPM configuration.
    dropin = Path("/etc/systemd/system/php8.3-fpm.service.d/mail-web-fixture.conf")
    flag = FIXTURE / "fail-fpm-once"
    script = FIXTURE / "fail-fpm-once.sh"
    write(script, "#!/bin/sh\nif [ -f " + str(flag) + " ]; then rm -- " + str(flag) + "; exit 1; fi\n", 0o755)
    write(dropin, "[Service]\nExecStartPre=" + str(script) + "\n")
    run("systemctl", "daemon-reload")
    before = stable_resources()
    flag.touch()
    try:
        deploy(cfg.model_copy(update={"php_memory_limit": "192M"}), "restart-failure", fail=True)
        assert not flag.exists(), "real systemd failure injection was not reached"
        assert stable_resources() == before, "rollback changed owned bytes/metadata or unrelated resources"
        assert run("systemctl", "is-active", "php8.3-fpm") == "active"
        assert run("systemctl", "is-active", "nginx") == "active"
        ui_auth()
    finally:
        dropin.unlink()
        script.unlink()
        flag.unlink(missing_ok=True)
        run("systemctl", "daemon-reload")
    deploy(cfg, "restart-recovery-repeat")


def main() -> None:
    FIXTURE.mkdir(mode=0o700)
    # Synthetic VM-only material supports diagnostics; never included in artifacts.
    write(FIXTURE / "material.json", json.dumps(MATERIAL), 0o600)
    foundation()
    synthetic_mail()
    pfa_api = import_module("ops_deploy.services.postfixadmin")
    snappy_api = import_module("ops_deploy.services.snappymail")
    pfa = pfa_api.PostfixAdminConfig(
        traefik_host="admin.example.test",
        admin_email="admin@example.test",
        db_name="mail_web_fixture",
        db_user="mail_web_fixture",
        traefik_enabled=False,
        totp_exceptions=("127.0.0.0/8",),
    )
    snappy = snappy_api.SnappyMailConfig(
        traefik_host="mail.example.test",
        imap_host="localhost",
        imap_port=1993,
        smtp_host="localhost",
        smtp_port=2525,
        data_dir="/var/lib/mail-web-fixture/snappy",
        domains=("example.test",),
        traefik_enabled=False,
    )
    module = import_module("ops_deploy.services._mail_web.deploy")
    original_command = module.command
    # Reproduce the observed post-bootstrap SQL failure; the subsequent retry
    # must use this same target, never reset its newly initialized database.
    with patch.object(module, "command", lambda: partial_bootstrap_command(original_command())):
        deploy(pfa, "postfixadmin-partial-bootstrap", fail=True, trace=True)
    assert sql("SELECT value FROM config WHERE name='version';") == "1851"
    sql(
        "CREATE TABLE bootstrap_sentinel(id integer PRIMARY KEY, value text); "
        "INSERT INTO bootstrap_sentinel VALUES(42,'preserve');"
    )
    sql(
        "INSERT INTO domain(domain,description) VALUES('unowned.example.test','fixture sentinel'); "
        "INSERT INTO admin(username,password,created,modified,active,superadmin,totp_secret) "
        "VALUES('other@example.test','fixture-nonlogin-hash',NOW(),NOW(),false,false,'preserved-fixture-totp'); "
        "INSERT INTO domain_admins(username,domain,active) VALUES('other@example.test','unowned.example.test',false);"
    )
    protected_app_queries = {
        "admin": "SELECT row_to_json(t)::text FROM admin t WHERE username<>'admin@example.test' ORDER BY username;",
        "domain": "SELECT row_to_json(t)::text FROM domain t WHERE domain<>'ALL' ORDER BY domain;",
        "domain_admins": (
            "SELECT row_to_json(t)::text FROM domain_admins t WHERE username<>'admin@example.test' ORDER BY id;"
        ),
    }
    protected_app_before = {name: sql(query) for name, query in protected_app_queries.items()}
    catalog_sql = "SELECT oid,relname,relowner FROM pg_class WHERE relnamespace='public'::regnamespace ORDER BY oid;"
    catalog_before = sql(catalog_sql)
    tables_sql = (
        "SELECT tablename FROM pg_tables WHERE schemaname='public' "
        "AND tablename NOT IN ('admin','domain','domain_admins') ORDER BY tablename;"
    )
    rows_before = {
        name: sql("SELECT row_to_json(t)::text FROM public." + name + " t ORDER BY row_to_json(t)::text;")
        for name in sql(tables_sql).splitlines()
    }
    deploy(pfa, "postfixadmin-partial-retry", trace=True)
    assert sql(catalog_sql) == catalog_before
    assert {name: sql(query) for name, query in protected_app_queries.items()} == protected_app_before
    assert {
        name: sql("SELECT row_to_json(t)::text FROM public." + name + " t ORDER BY row_to_json(t)::text;")
        for name in rows_before
    } == rows_before

    def upgrade_execs(label: str) -> list[str]:
        matches = []
        for path in EVIDENCE.glob(label + "-*.strace"):
            for line in path.read_text().splitlines():
                if is_upgrader_exec(line):
                    matches.append(line)
        return matches

    first_upgrades = upgrade_execs("postfixadmin-partial-bootstrap")
    retry_upgrades = upgrade_execs("postfixadmin-partial-retry")
    assert len(first_upgrades) == 1, first_upgrades
    assert not retry_upgrades
    (EVIDENCE / "partial-bootstrap-retry.json").write_text(
        json.dumps(
            {
                "schema": "1851",
                "catalog_oids_owners_unchanged": True,
                "unowned_rows_unchanged": True,
                "upgrader_invocations_on_retry": len(retry_upgrades),
                "upgrader_invocations_on_bootstrap": len(first_upgrades),
            }
        )
    )
    deploy(pfa, "postfixadmin-fresh-repeat")
    deploy(snappy, "snappymail-fresh")
    deploy(snappy, "snappymail-fresh-repeat")
    fpm_pid = int(run("systemctl", "show", "php8.3-fpm", "-p", "MainPID", "--value"))
    fpm_executable = os.readlink(f"/proc/{fpm_pid}/exe")
    server_version = sql("SHOW server_version;")
    nginx_version = subprocess.run(["nginx", "-v"], capture_output=True, text=True, check=True).stderr.strip()
    (EVIDENCE / "runtime-versions.json").write_text(
        json.dumps(
            {
                "machine": os.uname().machine,
                "postgresql_server": server_version,
                "php_cli": run("/usr/bin/php8.3", "-r", "echo PHP_VERSION;"),
                "php_fpm_process": {"pid": fpm_pid, "executable": fpm_executable, "version": run(fpm_executable, "-v")},
                "nginx": nginx_version,
                "packages": run(
                    "dpkg-query",
                    "-W",
                    "-f=${Package}=${Version}\n",
                    "php8.3-cli",
                    "php8.3-fpm",
                    "nginx",
                    "libpq5",
                    "postgresql-" + server_version.split(".", 1)[0],
                ),
                "scope": "after successful fresh deployment, before config/update/fault phases",
            },
            indent=2,
        )
    )
    local_delivery()
    ui_auth()
    sql(
        "CREATE TABLE unrelated_web_fixture(id integer PRIMARY KEY, value text); "
        "INSERT INTO unrelated_web_fixture VALUES(42,'preserve');"
    )
    write("/opt/postfixadmin/keep-unrelated.txt", "unowned sentinel\n", 0o640)
    write("/var/lib/mail-web-fixture/snappy/_data_/_default_/domains/unrelated.json", '{"fixture":true}\n', 0o600)
    ini = Path(snappy.data_dir) / "_data_/_default_/configs/application.ini"
    MATERIAL["totp_secret"] = base64.b32encode(secrets.token_bytes(20)).decode()
    write(FIXTURE / "material.json", json.dumps(MATERIAL), 0o600)
    seeded = seed_admin_totp(ini, MATERIAL["totp_secret"])
    (EVIDENCE / "totp-fixture-seed.json").write_text(json.dumps(seeded))
    text = ini.read_text()
    text += '\n[custom]\nfixture_setting = "preserve nondefault"\n'
    ini.write_text(text)
    unowned_ini = 'admin_totp = "' + MATERIAL["totp_secret"] + '"'
    changed = pfa.model_copy(update={"php_memory_limit": "160M"})
    deploy(changed, "postfixadmin-config")
    deploy(changed, "postfixadmin-config-repeat")
    changed_snappy = snappy.model_copy(update={"php_memory_limit": "288M", "login_default_domain": "example.test"})
    deploy(changed_snappy, "snappymail-config")
    deploy(changed_snappy, "snappymail-config-repeat")
    MATERIAL["admin_password"] = secrets.token_hex(18)
    write(FIXTURE / "material.json", json.dumps(MATERIAL), 0o600)
    deploy(changed, "postfixadmin-credential")
    deploy(changed, "postfixadmin-credential-repeat")
    deploy(changed_snappy, "snappymail-credential")
    deploy(changed_snappy, "snappymail-credential-repeat")
    ui_auth()
    before = snapshot()

    def invalid(q: dict[str, Any]) -> None:
        q["files"]["/etc/nginx/sites-available/postfixadmin"] = "not valid nginx!\n"

    record = deploy(changed, "invalid-nginx", fail=True, mutate_payload=invalid)
    assert record["files_unchanged"]
    assert record["pids_unchanged"]
    assert snapshot() == before
    restart_failure(changed)
    seed_previous(changed)
    deploy(changed, "postfixadmin-update")
    deploy(changed, "postfixadmin-update-repeat")
    seed_previous(changed_snappy)
    deploy(changed_snappy, "snappymail-update")
    deploy(changed_snappy, "snappymail-update-repeat")
    ui_auth()
    assert unowned_ini in ini.read_text()
    assert 'fixture_setting = "preserve nondefault"' in ini.read_text()
    assert sql("SELECT value FROM unrelated_web_fixture WHERE id=42;") == "preserve"
    assert Path("/opt/postfixadmin/keep-unrelated.txt").read_text() == "unowned sentinel\n"
    assert (
        Path("/var/lib/mail-web-fixture/snappy/_data_/_default_/domains/unrelated.json").read_text()
        == '{"fixture":true}\n'
    )
    credential_admission(changed)
    shell_transport(changed)
    shell_transport(changed_snappy)
    phases = sorted(p.name for p in EVIDENCE.glob("*.json") if p.name not in {"summary.json"})
    (EVIDENCE / "summary.json").write_text(
        json.dumps(
            {
                "status": "passed",
                "phases": phases,
                "implementation": os.environ["IMPLEMENTATION_SHA"],
                "harness": os.environ["HARNESS_SHA"],
            }
        )
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: harness.py EVIDENCE_DIRECTORY")
    main()
