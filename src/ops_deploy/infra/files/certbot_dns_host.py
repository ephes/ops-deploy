#!/usr/bin/env python3
"""Host side of ``ops_deploy.infra.certbot_dns``, run as root with ``python3 -I -c``.

Subcommands:

``probe CONFIG_DIR DOMAIN INACTIVE_FILES_JSON STRAY_DIRS_JSON``
    Read-only. Prints one JSON object: the lineage ``DOMAIN`` under
    ``CONFIG_DIR`` (its renewal configuration, the live certificate's dates,
    names and key type, the live links and the archive), each inactive credentials
    file with the role's ``grep -l`` scan exit code, and which listed stray
    dirs exist. States before a first deploy (no lineage, missing files) are
    answers; any other error exits non-zero. Contacts nothing but the local
    ``openssl`` and ``grep``.
``authenticator CONF``
    Prints the lineage's authenticator the way the role reads it (empty when
    the file cannot be read).
``drop-settings CONF PROVIDER``
    When CONF's authenticator is ``dns-PROVIDER``, removes every other
    provider's ``dns_<provider>_*`` line (the role's ``lineinfile``), writing
    through a symlink and keeping owner and mode; prints ``changed`` or
    ``unchanged``.
``remove-stray``
    Reads ``certbot_stray_guard.py``'s decision on stdin and the guard's input
    from ``CERTBOT_STRAY_INPUT``; refuses (exit 1, nothing removed) unless no
    path was refused and every listed path is either removable or skipped,
    then removes the removable ones.
"""

import calendar
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

PROVIDERS = ("gandi", "rfc2136")
KINDS = ("cert", "chain", "fullchain", "privkey")
# The role's patterns (tasks/certificate.yml, tasks/cleanup.yml).
AUTHENTICATOR = re.compile(r"(?m)^authenticator\s*=\s*(\S+)")
# Top-level renewal configuration keys the deploy reads (configobj syntax).
TOP_LEVEL = ("archive_dir", "cert", "chain", "fullchain", "privkey", "renew_before_expiry")
ENTRY = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*=\s*(.*?)\s*$")
SECTION = re.compile(r"^\s*\[\s*([A-Za-z0-9_.-]+)\s*\]\s*$")


def authenticator(text):
    match = AUTHENTICATOR.search(text)
    return match.group(1) if match else ""


def settings_pattern(provider):
    # Matched per line on bytes, as lineinfile does.
    return re.compile(rb"^dns_" + provider.encode() + rb"_[A-Za-z0-9_]+\s*=")


def settings_lines(data, provider):
    """Lines of ``data`` (bytes, newlines kept) holding another provider's settings."""

    patterns = [settings_pattern(p) for p in PROVIDERS if p != provider]
    return [line for line in io.BytesIO(data).readlines() if any(p.search(line) for p in patterns)]


def plain_value(value):
    """``value`` as configobj reads it, or None for syntax this parser does not model."""

    if not value:
        return value
    if value[0] in "\"'":
        quote = value[0]
        if len(value) < 2 or value[-1] != quote or quote in value[1:-1] or value.startswith(quote * 3):
            return None
        return value[1:-1]
    return None if "#" in value else value


def parse_conf(data):
    """The values the deploy needs; ``renewalparams`` keys under their section.

    ``malformed`` is set for anything configobj (certbot's parser) might read
    differently or reject: a line that is no comment, ``[section]`` or
    ``key = value``, a quoted or commented value this parser does not model, a
    duplicate key in a section, a repeated section or a section named like a
    top-level key. certbot ignores such a
    lineage, so the deploy then leaves the decision to certonly.
    """

    text = data.decode("utf-8")
    top, params, section = {}, {}, None
    seen, sections, malformed = set(), set(), False
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        header = SECTION.match(line)
        if header:
            section = header.group(1)
            # configobj refuses a repeated section and one named like a top-level key.
            malformed = malformed or section in sections or (None, section) in seen
            sections.add(section)
            continue
        entry = ENTRY.match(line)
        value = plain_value(entry.group(2)) if entry else None
        if entry is None or value is None or (section, entry.group(1)) in seen:
            malformed = True
            continue
        key = entry.group(1)
        seen.add((section, key))
        if section is None and key in TOP_LEVEL:
            top[key] = value
        elif section == "renewalparams" and key == "autorenew":
            params[key] = value
    return {
        "authenticator": authenticator(text),
        # Providers whose dns_<provider>_* lines drop-settings for another provider removes.
        "settings": [p for p in PROVIDERS if any(settings_pattern(p).search(line) for line in io.BytesIO(data))],
        "values": top,
        "autorenew": params.get("autorenew"),
        "malformed": malformed,
    }


def openssl(path, *args):
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
    result = subprocess.run(
        ["openssl", "x509", "-in", path, "-noout", *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        env=env,
        check=True,
    )
    return result.stdout


def epoch(value):
    # openssl prints e.g. "Jan  8 12:45:34 2027 GMT" in every locale.
    return calendar.timegm(time.strptime(value.strip(), "%b %d %H:%M:%S %Y GMT"))


def certificate(path):
    # ``-dates`` and ``-text`` only: older and LibreSSL ``openssl`` lack ``-ext``.
    dates = dict(line.split("=", 1) for line in openssl(path, "-dates").splitlines() if "=" in line)
    text = openssl(path, "-text")
    names = []
    common = re.search(r"(?m)^\s*Subject:.*?\bCN\s*=\s*([^,/\s]+)", text)
    if common:
        names.append(common.group(1))
    sans = re.search(r"(?m)^\s*X509v3 Subject Alternative Name:.*\n(.*)$", text)
    for name in re.findall(r"DNS:([^,\s]+)", sans.group(1) if sans else ""):
        if name not in names:
            names.append(name)
    # certbot compares the lineage's key type with --key-type (RSA, else ECDSA);
    # read from the certificate's public key, never from the private key.
    algorithm = re.search(r"(?m)^\s*Public Key Algorithm:\s*(\S+)", text)
    return {
        "not_before": epoch(dates["notBefore"]),
        "not_after": epoch(dates["notAfter"]),
        "names": names,
        "key_type": "RSA" if algorithm and algorithm.group(1) == "rsaEncryption" else "ECDSA",
    }


def kind(path):
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        return "missing"
    if stat.S_ISLNK(mode):
        return "link"
    return "file" if stat.S_ISREG(mode) else "other"


def users_rc(path, renewal):
    # The role's scan: 0 a renewal configuration names the file, 1 none does, 2 an error.
    scan = ["sh", "-c", 'exec grep -l -F -e "$1" -- "$2"/*.conf', "sh", path, renewal]
    return subprocess.run(scan, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode


def probe(config_dir, domain, inactive, stray):
    conf_path = os.path.join(config_dir, "renewal", domain + ".conf")
    live = os.path.join(config_dir, "live", domain)
    archive = os.path.join(config_dir, "archive", domain)
    state = {"config_dir": config_dir, "now": int(time.time()), "conf": None, "cert": None, "links": {}, "archive": []}
    if os.path.exists(conf_path):
        with open(conf_path, "rb") as handle:
            state["conf"] = parse_conf(handle.read())
        cert = os.path.join(live, "cert.pem")
        if os.path.exists(cert):
            state["cert"] = certificate(cert)
        for name in KINDS:
            link = os.path.join(live, name + ".pem")
            target = os.readlink(link) if os.path.islink(link) else None
            state["links"][name] = {"target": target, "exists": os.path.exists(link)}
        if os.path.isdir(archive):
            state["archive"] = sorted(os.listdir(archive))
    renewal = os.path.join(config_dir, "renewal")
    state["inactive"] = {}
    for path in inactive:
        found = kind(path)
        state["inactive"][path] = {"kind": found, "rc": None if found == "missing" else users_rc(path, renewal)}
    state["stray"] = {path: os.path.lexists(path) for path in stray}
    return state


def read_authenticator(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return authenticator(handle.read())
    except OSError:
        return ""


def drop_settings(path, provider):
    if read_authenticator(path) != "dns-" + provider:
        return "unchanged"
    real = os.path.realpath(path)
    with open(real, "rb") as handle:
        data = handle.read()
    dropped = settings_lines(data, provider)
    if not dropped:
        return "unchanged"
    kept = [line for line in io.BytesIO(data).readlines() if line not in dropped]
    info = os.stat(real)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(real), prefix=".ops-deploy-")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(b"".join(kept))
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(tmp, info.st_uid, info.st_gid)
        os.chmod(tmp, stat.S_IMODE(info.st_mode))
        os.replace(tmp, real)
    except BaseException:
        os.unlink(tmp)
        raise
    return "changed"


def remove_stray():
    wanted = json.loads(os.environ["CERTBOT_STRAY_INPUT"])["stray"]
    decision = json.load(sys.stdin)
    if decision["refused"] or sorted(decision["remove"] + decision["skipped"]) != sorted(wanted):
        sys.exit("Refusing stray certbot dirs, nothing removed: " + json.dumps(decision["refused"]))
    for path in decision["remove"]:
        shutil.rmtree(path)
        print("removed " + path)


def main(argv):
    command, args = argv[0], argv[1:]
    if command == "probe":
        config_dir, domain, inactive, stray = args
        json.dump(probe(config_dir, domain, json.loads(inactive), json.loads(stray)), sys.stdout, sort_keys=True)
    elif command == "authenticator":
        print(read_authenticator(args[0]))
    elif command == "drop-settings":
        print(drop_settings(*args))
    elif command == "remove-stray":
        remove_stray()
    else:
        sys.exit("unknown command " + command)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
