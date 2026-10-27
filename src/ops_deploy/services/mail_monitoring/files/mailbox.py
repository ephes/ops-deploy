"""Exact monitor mailbox role SQL, run as postgres; secrets arrive on stdin only."""
import json
import re
import subprocess
import sys

import psycopg2


def qualified_password_hash(value):
    # libxcrypt SHA512-CRYPT: canonical numeric cost, native salt grammar,
    # and the two meaningful bits in the final crypt-base64 character.
    if not isinstance(value, str):
        return False
    match = re.fullmatch(r"\{SHA512-CRYPT\}\$6\$(?:rounds=([1-9][0-9]{0,8})\$)?(?!rounds=)([^$:\r\n\0]{1,16})\$[./0-9A-Za-z]{85}[./01]", value)
    return bool(match and all(0x21 <= ord(char) <= 0x7e and char not in "!*:;" and ord(char) != 92 for char in match[2])
                and (match[1] is None or 1000 <= int(match[1]) <= 999999999))


def pw(arguments, password, repeat=False):
    result = subprocess.run(
        ["doveadm", "-O", "pw", *arguments],
        input=password + "\n" + (password + "\n" if repeat else ""),
        text=True, capture_output=True, timeout=30,
    )
    return result


def reconcile(request, apply):
    password = request["password"]
    if not password.strip() or password == "CHANGE_ME" or any(c in password for c in "\r\n\0"):
        raise ValueError("monitor password must be nonblank without CR/LF/NUL")
    localpart, domain = request["address"].lower().split("@")
    schema = request["schema_mode"]
    if schema not in ("postfixadmin", "legacy"):
        raise ValueError("unsupported mailbox schema")
    active = request["active"]
    with psycopg2.connect(dbname=request["database"]) as conn:
        conn.set_session(readonly=not apply)
        with conn.cursor() as cur:
            if apply:
                # Serialize monitor reconciliation, including an initially absent row.
                cur.execute("LOCK TABLE " + ("mailbox" if schema == "postfixadmin" else "mail_users") + " IN SHARE ROW EXCLUSIVE MODE")
            cur.execute(
                "SELECT domain FROM domain WHERE LOWER(domain) = LOWER(%s)" if schema == "postfixadmin"
                else "SELECT id FROM mail_domains WHERE LOWER(name) = LOWER(%s)", (domain,))
            domains = cur.fetchall()
            if len(domains) != 1:
                raise ValueError("monitor domain missing or ambiguous")
            if schema == "postfixadmin":
                cur.execute("SELECT username, password, active, maildir FROM mailbox WHERE LOWER(username) = LOWER(%s)", (request["address"],))
            else:
                cur.execute("SELECT id, password, active FROM mail_users WHERE domain_id = %s AND LOWER(localpart) = LOWER(%s)", (domains[0][0], localpart))
            rows = cur.fetchall()
            if len(rows) > 1:
                raise ValueError("monitor mailbox identity is ambiguous")
            changed = not rows
            if rows:
                if not qualified_password_hash(rows[0][1]):
                    raise ValueError("stored monitor password hash is unsupported or malformed")
                verified = pw(["-t", rows[0][1]], password)
                # Dovecot reports password mismatch with exit 75. Other errors are not rotation requests.
                if verified.returncode not in (0, 75):
                    raise ValueError("Dovecot password verification failed")
                changed = verified.returncode != 0 or bool(rows[0][2]) != active
            if changed and apply:
                generated = pw(["-s", "SHA512-CRYPT"], password, repeat=True)
                if generated.returncode or not generated.stdout.strip().startswith("{SHA512-CRYPT}"):
                    raise ValueError("Dovecot password generation failed")
                hashed = generated.stdout.strip()
                if schema == "postfixadmin":
                    if rows:
                        cur.execute("UPDATE mailbox SET password = %s, active = %s, modified = NOW() WHERE LOWER(username) = LOWER(%s)", (hashed, active, request["address"]))
                    else:
                        cur.execute("""INSERT INTO mailbox (username, password, name, maildir, quota, local_part, domain, active, created, modified)
                                       VALUES (%s, %s, '', %s, 0, %s, %s, %s, NOW(), NOW())""",
                                    (request["address"], hashed, f"{domain}/{localpart}/", localpart, domain, active))
                elif rows:
                    cur.execute("UPDATE mail_users SET password = %s, active = %s WHERE domain_id = %s AND LOWER(localpart) = LOWER(%s)", (hashed, active, domains[0][0], localpart))
                else:
                    cur.execute("INSERT INTO mail_users (domain_id, localpart, password, active) VALUES (%s, %s, %s, %s)", (domains[0][0], localpart, hashed, active))
            return changed


if __name__ == "__main__":
    try:
        if sys.argv[1:] not in (["check"], ["apply"]):
            raise ValueError("expected check or apply")
        changed = reconcile(json.load(sys.stdin), sys.argv[1] == "apply")
        print("changed=true" if changed else "changed=false")
    except ValueError as exc:
        # Only our literal diagnostics, never database exception details or request data.
        print(str(exc), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print("monitor mailbox operation failed (database or Dovecot); no secret details logged", file=sys.stderr)
        sys.exit(1)
