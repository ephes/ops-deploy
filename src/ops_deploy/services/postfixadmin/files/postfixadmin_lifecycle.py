"""postfixadmin_backup / postfixadmin_restore on the host (run as root with ``python3 -I``).

The settings arrive as one JSON document on stdin (the database password among
them, so it never reaches a command line); ``psql`` gets it as PGPASSWORD in
its own environment. Only the standard library is used.

``backup``: write config.local.php, admin.json, domain_admins.json and the
optional log.json / templates_c.tar.gz into ``<root>/<stamp>.tmp``, the
manifest last, then rename the directory to ``<root>/<stamp>``; any failure
removes the ``.tmp`` directory and nothing is published (the role's rescue).
Retention runs only after a published backup.

``restore``: validate the backup directory (manifest, parts, schema version,
admin columns) before anything changes, then put back config.local.php,
templates_c (when asked) and the admin tables in one transaction.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

STAMP = re.compile(r"^[0-9]{8}T[0-9]{6}$")
REQUIRED = ("config.local.php", "admin.json", "domain_admins.json")
OPTIONAL = ("log.json", "templates_c.tar.gz")


class Failure(Exception):
    pass


def psql(cfg: dict, sql: str) -> str:
    """Run ``sql`` (on stdin: row data never reaches psql's command line)."""

    argv = ["psql", "-XAtq", "-v", "ON_ERROR_STOP=1", "-h", cfg["db_host"], "-p", str(cfg["db_port"])]
    argv += ["-U", cfg["db_user"], "-d", cfg["db_name"]]
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PGPASSWORD": cfg["db_password"], "PGCONNECT_TIMEOUT": "10", "PGCLIENTENCODING": "UTF8"}
    done = subprocess.run(argv, input=sql, capture_output=True, text=True, env=env, check=False)
    if done.returncode != 0:
        # Only psql's first error line: its LINE/DETAIL context can quote row values.
        lines = [line for line in done.stderr.splitlines() if line.strip()]
        first = next((line for line in lines if "ERROR" in line or "FATAL" in line), lines[0] if lines else "")
        raise Failure(first[:300] or f"psql exited {done.returncode}")
    return done.stdout


def rows(cfg: dict, query: str) -> list:
    """``query``'s rows as JSON objects (PostgreSQL's own JSON encoding)."""

    out = psql(cfg, f"SELECT coalesce(json_agg(t), '[]'::json) FROM ({query}) t;\n").strip()
    value = json.loads(out or "[]")
    if not isinstance(value, list):
        raise Failure("unexpected query result")
    return value


def ident(name: str) -> str:
    """A quoted SQL identifier (names come from the target's own columns)."""

    return '"' + name.replace('"', '""') + '"'


def literal(value: object) -> str:
    """``value`` as JSON in a dollar-quoted SQL literal whose tag it cannot contain."""

    text = json.dumps(value)
    while True:
        tag = "$r" + secrets.token_hex(8) + "$"
        if tag not in text:
            return f"{tag}{text}{tag}"


def nice_json(value: object) -> str:
    # Ansible's to_nice_json: indent 4, sorted keys, ASCII escapes.
    return json.dumps(value, indent=4, sort_keys=True, separators=(",", ": "))


def write(path: Path, text: str, mode: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "w") as handle:
        handle.write(text)
    os.chmod(path, mode)


def schema_version(cfg: dict) -> int:
    found = rows(cfg, "SELECT value FROM config WHERE name = 'version'")
    if len(found) != 1 or not re.fullmatch(r"[0-9]+", str(found[0].get("value"))):
        raise Failure("config.version is missing or not numeric")
    return int(found[0]["value"])


def backup(cfg: dict) -> None:
    root = Path(cfg["root"])
    stamp = cfg["stamp"]
    final, tmp = root / stamp, root / f"{stamp}.tmp"
    if cfg["retention_days"] < 1 or cfg["keep_min"] < 1:
        raise Failure("postfixadmin_backup_retention_days and postfixadmin_backup_keep_min must be at least 1")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    uid, gid = cfg.get("root_owner", (0, 0))
    info = root.stat()
    if (info.st_uid, info.st_gid) != (uid, gid):
        os.chown(root, uid, gid)
    os.chmod(root, 0o700)
    existing = [str(path) for path in (final, tmp) if path.exists() or path.is_symlink()]
    if existing:
        raise Failure(f"{', '.join(existing)} already exists; refusing to reuse it.")
    warnings: list[str] = []
    try:
        tmp.mkdir(mode=0o700)
        config = Path(cfg["install_path"]) / "config.local.php"
        if not config.is_file() or config.is_symlink():
            raise Failure(f"{config} is missing; refusing to write an incomplete backup")
        shutil.copyfile(config, tmp / "config.local.php", follow_symlinks=False)
        os.chmod(tmp / "config.local.php", 0o600)
        admins = rows(cfg, "SELECT * FROM admin ORDER BY username")
        if not admins:
            raise Failure("The admin table is empty; refusing to write a backup without an admin account")
        write(tmp / "admin.json", nice_json(admins), 0o600)
        write(tmp / "domain_admins.json", nice_json(rows(cfg, "SELECT * FROM domain_admins ORDER BY username, domain")), 0o600)
        version = schema_version(cfg)
        try:
            log = rows(cfg, 'SELECT * FROM log ORDER BY "timestamp" DESC LIMIT 10000')
            write(tmp / "log.json", nice_json(log), 0o600)
        except (Failure, OSError) as exc:
            (tmp / "log.json").unlink(missing_ok=True)
            warnings.append(f"log.json: {exc}")
        if cfg["include_templates_c"]:
            archive = tmp / "templates_c.tar.gz"
            done = subprocess.run(
                ["tar", "-czf", str(archive), "-C", cfg["install_path"], "templates_c"],
                capture_output=True,
                text=True,
                check=False,
            )
            if done.returncode == 0:
                os.chmod(archive, 0o600)
            else:
                archive.unlink(missing_ok=True)
                warnings.append("templates_c.tar.gz: " + (done.stderr.strip() or "tar failed"))
        contents = sorted(path.name for path in tmp.iterdir() if path.is_file() and path.name in REQUIRED + OPTIONAL)
        missing = [part for part in REQUIRED if part not in contents]
        if missing:
            raise Failure(f"Missing required parts: {', '.join(missing)}")
        manifest = {
            "backup_type": "postfixadmin",
            "manifest_version": 2,
            "timestamp": stamp,
            "created_at": cfg["created_at"],
            "hostname": cfg["host_name"],
            "postfixadmin_version": cfg["postfixadmin_version"],
            "db_schema_version": version,
            "contents": contents,
            "skipped": warnings,
        }
        # JSON is YAML: the role's restore (from_yaml) reads it as its own manifest.
        write(tmp / "manifest.yml", "---\n" + json.dumps(manifest, indent=2, sort_keys=True) + "\n", 0o644)
        os.rename(tmp, final)
    except BaseException as exc:
        shutil.rmtree(tmp, ignore_errors=True)
        reason = str(exc) if isinstance(exc, Failure) else type(exc).__name__
        raise Failure(f"PostfixAdmin backup failed; nothing was published and retention did not run. {reason}") from None
    for warning in warnings:
        print(f"WARNING: optional part not backed up: {warning}")
    prune(root, cfg["retention_days"], cfg["keep_min"])
    print(f"PostfixAdmin backup created at {final} ({', '.join(contents)})")


def completed(root: Path) -> list[Path]:
    return sorted(
        path for path in root.iterdir() if STAMP.match(path.name) and path.is_dir() and not path.is_symlink()
    )


def prune(root: Path, days: int, keep: int) -> None:
    """The role's retention: never the newest ``keep``; the rest only when older than ``days`` (mtime)."""

    done = completed(root)
    protected = set(sorted(done, reverse=True)[:keep])
    cutoff = time.time() - days * 86400
    for path in done:
        if path not in protected and path.stat().st_mtime < cutoff:
            shutil.rmtree(path)
            print(f"Removed expired backup {path}")


def run(argv: list[str]) -> None:
    done = subprocess.run(argv, capture_output=True, text=True, check=False)
    if done.returncode != 0:
        raise Failure(f"{argv[0]} failed: {done.stderr.strip()[:300]}")


def php_service(cfg: dict) -> str:
    version = cfg["php_version"]
    if not version:
        done = subprocess.run(
            ["php", "-r", 'printf("%s.%s", PHP_MAJOR_VERSION, PHP_MINOR_VERSION);'],
            capture_output=True,
            text=True,
            check=False,
        )
        version = done.stdout.strip() if done.returncode == 0 else ""
    if not version:
        raise Failure("PHP version detection failed and postfixadmin_php_version is not set.")
    return f"php{version}-fpm"


def restore(cfg: dict) -> None:
    root = Path(cfg["root"])
    stamp = cfg["stamp"]
    if stamp == "latest":
        found = completed(root) if root.is_dir() else []
        if not found:
            raise Failure(f"No PostfixAdmin backups found under {root}")
        stamp = found[-1].name
    if not STAMP.match(stamp):
        raise Failure("the restore timestamp must be the name of a completed backup directory (YYYYMMDDTHHMMSS)")
    directory = root / stamp
    if not directory.is_dir() or directory.is_symlink():
        raise Failure(f"Backup directory {directory} does not exist")
    if cfg["dry_run"]:
        print(f"Dry run: {directory} exists; nothing changed.")
        return
    service = php_service(cfg)
    manifest = json.loads(cfg["manifest"])
    contents = manifest.get("contents") if isinstance(manifest, dict) else None
    if isinstance(manifest, dict) and str(manifest.get("timestamp", stamp)) != stamp:
        # The controller read the manifest of another backup (one landed in between).
        raise Failure(f"{directory}/manifest.yml changed while the restore was prepared; run it again")
    if (
        not isinstance(manifest, dict)
        or manifest.get("backup_type") != "postfixadmin"
        or not isinstance(contents, list)
        or not contents
        or any(part not in REQUIRED + OPTIONAL for part in contents)
        or any(part not in contents for part in REQUIRED)
    ):
        raise Failure(f"{directory}/manifest.yml is not a usable PostfixAdmin manifest")
    missing = [part for part in contents if not (directory / part).is_file() or (directory / part).is_symlink()]
    if missing:
        raise Failure(f"The manifest lists parts that are missing from {directory}: {', '.join(missing)}")
    if cfg["restore_templates_c"] and "templates_c.tar.gz" not in contents:
        raise Failure(f"postfixadmin_restore_templates_c is set, but {stamp} has no templates_c.tar.gz")
    if "db_schema_version" in manifest:
        target = schema_version(cfg)
        # The role's ``| int``: null counts as 0; anything else must be numeric.
        version = manifest["db_schema_version"]
        if version is None:
            version = 0
        if not re.fullmatch(r"[0-9]+", str(version)):
            raise Failure(f"{directory}/manifest.yml has a non-numeric db_schema_version")
        if int(version) > target:
            raise Failure(
                f"The backup has PostfixAdmin schema version {manifest['db_schema_version']}, the target has "
                f"{target}. Upgrade the target to at least the backup's PostfixAdmin version "
                f"({manifest.get('postfixadmin_version', 'unknown')}) first."
            )
    else:
        print(f"WARNING: {stamp} records no schema version; restoring it without the version check.")
    print(
        f"Restoring PostfixAdmin backup {stamp} (created {manifest.get('created_at')}, PostfixAdmin "
        f"{manifest.get('postfixadmin_version', 'unknown')}, schema {manifest.get('db_schema_version', 'unknown')}): "
        + ", ".join(contents)
    )
    admins: list = []
    domain_admins: list = []
    if cfg["restore_admin_tables"]:
        admins = json.loads((directory / "admin.json").read_text())
        domain_admins = json.loads((directory / "domain_admins.json").read_text())
        if domain_admins == {}:
            domain_admins = []  # older backups wrote {} for an empty table
        columns = {
            row["column_name"]
            for row in rows(
                cfg,
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = current_schema() AND table_name = 'admin'",
            )
        }
        if (
            not isinstance(admins, list)
            or not admins
            or not all(isinstance(row, dict) and "username" in row and "password" in row for row in admins)
            or any(key not in columns for row in admins for key in row)
            or not isinstance(domain_admins, list)
            or not all(isinstance(row, dict) and "username" in row and "domain" in row for row in domain_admins)
        ):
            raise Failure(
                "admin.json must hold at least one admin row with username and password and only columns the "
                "target's admin table has, and domain_admins.json must hold a list."
            )
    # -- changes -------------------------------------------------------------------
    changed_config = False
    if cfg["restore_config"]:
        source = directory / "config.local.php"
        dest = Path(cfg["install_path"]) / "config.local.php"
        changed_config = not dest.is_file() or dest.read_bytes() != source.read_bytes()
        if changed_config:
            staged = dest.with_name(".config.local.php.restore")
            shutil.copyfile(source, staged)
            shutil.chown(staged, cfg.get("config_owner", "root"), cfg["web_group"])
            os.chmod(staged, 0o640)
            os.replace(staged, dest)
        else:
            shutil.chown(dest, cfg.get("config_owner", "root"), cfg["web_group"])
            os.chmod(dest, 0o640)
    if cfg["restore_templates_c"]:
        run(["tar", "-xzf", str(directory / "templates_c.tar.gz"), "-C", cfg["install_path"]])
        run(["chown", "-R", "-h", f"{cfg['web_user']}:{cfg['web_group']}", cfg["templates_c_path"]])
    if cfg["restore_admin_tables"]:
        statements = ["BEGIN;"]
        for row in admins:
            cols = sorted(row)
            quoted = ", ".join(ident(col) for col in cols)
            updates = ", ".join(f"{ident(col)} = EXCLUDED.{ident(col)}" for col in cols if col != "username")
            statements.append(
                f"INSERT INTO admin ({quoted}) SELECT {quoted} "
                f"FROM json_populate_record(NULL::admin, {literal(row)}::json)"
                " ON CONFLICT (username) DO " + (f"UPDATE SET {updates};" if updates else "NOTHING;")
            )
        for row in domain_admins:
            wanted = {"username": row.get("username"), "domain": row.get("domain"), "active": row.get("active")}
            statements.append(
                "INSERT INTO domain_admins (username, domain, active, created) "
                "SELECT r.username, r.domain, r.active, NOW() "
                f"FROM json_populate_record(NULL::domain_admins, {literal(wanted)}::json) r "
                "WHERE NOT EXISTS (SELECT 1 FROM domain_admins d WHERE d.username = r.username AND d.domain = r.domain);"
            )
        statements.append("COMMIT;")
        psql(cfg, "\n".join(statements) + "\n")
    if changed_config:
        run(["systemctl", "restart", service])
    print(f"PostfixAdmin restore completed from {directory}")


def main() -> int:
    # Everything this program creates is private until chmod/chown widen it.
    os.umask(0o077)
    cfg = json.loads(sys.stdin.read())
    try:
        {"backup": backup, "restore": restore}[cfg["action"]](cfg)
    except Failure as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
