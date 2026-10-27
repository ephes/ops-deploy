"""Mail-web admission, candidate closure, provenance and no-write boundaries."""

from __future__ import annotations

import ast
import base64
import hashlib
import json
import shlex
import shutil
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from ops_deploy.core.config import ConfigValidationError
from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services._mail_web.deploy import ROOT, command, release_records
from ops_deploy.services._mail_web.render import render
from ops_deploy.services.postfixadmin import PostfixAdminConfig
from ops_deploy.services.snappymail import SnappyMailConfig


def pfa(**kw: Any) -> PostfixAdminConfig:
    return PostfixAdminConfig(traefik_host="admin.example.test", admin_email="admin@example.test", **kw)


def snappy(**kw: Any) -> SnappyMailConfig:
    return SnappyMailConfig(
        traefik_host="mail.example.test", imap_host="imap.example.test", smtp_host="smtp.example.test", **kw
    )


def values() -> SecretValues:
    return SecretValues(
        SecretRef("fixture.yml"),
        {"db_password": "quote'\\database", "setup_password": "setup-fixture", "admin_password": "admin-fixture"},
    )


def module() -> ModuleType:
    result = ModuleType("mail_web_test_host")
    result.__dict__["CREDENTIALS_SOURCE"] = (ROOT / "files/credentials.php").read_text()
    for name in ("mail_web_common.py", "mail_web_release.py", "mail_web_candidate.py", "mail_web_host.py"):
        exec(compile((ROOT / "files" / name).read_text(), str(ROOT / "files" / name), "exec"), result.__dict__)
    return result


@pytest.mark.parametrize("cfg", [pfa(), snappy()])
def test_current_release_is_pinned_with_full_manifest(cfg: Any) -> None:
    selected, previous = release_records(cfg)
    assert selected["version"] == cfg.version
    assert selected["url"].startswith("https://github.com/")
    assert len(selected["sha256"]) == 64
    assert len(selected["files"]) > 700
    assert all(r["previous_only"] for r in previous)
    if cfg.service_name == "postfixadmin":
        assert selected["files"]["public/totp.php"] == {"link": "users/totp.php"}
        assert "public/setup.php" not in selected["files"]
        assert "php84" in selected["url"]


@pytest.mark.parametrize("cfg", [pfa(version="4.0.4"), snappy(version="2.38.0")])
def test_historical_bundle_is_admission_only_not_selected_install(cfg: Any) -> None:
    with pytest.raises(Exception, match="Unsupported selected"):
        release_records(cfg)


@pytest.mark.parametrize(
    "kwargs",
    [{"install_path": "/opt/../etc"}, {"admin_email": "bad\n@example.test"}, {"totp_exceptions": ("x\n$CONF",)}],
)
def test_invalid_php_inputs_fail_on_controller(kwargs: Any) -> None:
    base = {"traefik_host": "admin.example.test", "admin_email": "admin@example.test"}
    with pytest.raises(ConfigValidationError):
        PostfixAdminConfig(**{**base, **kwargs})


def test_secret_php_escaping_and_explicit_preload() -> None:
    result = render(pfa(traefik_sts_preload=True), values())
    config = result["files"]["/opt/postfixadmin/config.local.php"]
    assert "quote\\'\\\\database" in config
    assert "@OPS_SETUP_HASH@" in config
    assert "stsPreload: true" in result["route"]
    assert "stsPreload:" not in render(pfa(), values())["route"]
    assert "ipAllowList:" in result["route"]
    assert "tls: {}" in result["route"]


def test_domain_config_keeps_auth_and_tls() -> None:
    result = render(snappy(domains=("example.test",)), values())
    body = json.loads(result["files"]["/mnt/cryptdata/snappymail/_data_/_default_/domains/example.test.json"])
    assert body["SMTP"]["useAuth"] is True
    assert body["IMAP"]["ssl"]["verify_peer"] is True
    assert body["SMTP"]["ssl"]["allow_self_signed"] is False


def test_transport_contains_source_not_credentials() -> None:
    text = command()
    assert "python3 -I -B -c" in text
    assert "setup-fixture" not in text
    assert "admin-fixture" not in text
    loader = ast.parse(shlex.split(text)[-1])
    encoded = next(
        node.value
        for node in ast.walk(loader)
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) > 100
    )
    assert "json.load(sys.stdin)" in base64.b64decode(encoded).decode()


def test_converged_host_never_stages_or_touches_database(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    m = module()
    q = {"app": "snappymail", "php": "8.3", "root": "/opt/snappymail"}
    monkeypatch.setattr(m, "release_needed", lambda _: False)
    monkeypatch.setattr(m, "needs_seed", lambda _: False)
    monkeypatch.setattr(m, "credential_state", lambda _: {})
    monkeypatch.setattr(m, "app_grants", lambda _: False)
    monkeypatch.setattr(m, "desired_files", lambda *_: {"/owned": ("file", b"ok", 0o640, 1, 1)})
    monkeypatch.setattr(m, "file_state", lambda _: ("file", b"ok", 0o640, 1, 1))
    monkeypatch.setattr(m, "service_active", lambda _: True)
    monkeypatch.setattr(m.tempfile, "TemporaryDirectory", lambda **_: pytest.fail("no-op staging"))
    monkeypatch.setattr(m, "run", lambda *_: pytest.fail("no-op service or SQL write"))
    m.main(q)
    assert capsys.readouterr().out == "changed=false\n"


def test_candidate_redirects_absolute_relative_and_external_include_closure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    m = module()
    candidate = tmp_path / "candidate"
    nginx = candidate / "etc/nginx"
    nginx.mkdir(parents=True)
    (nginx / "nginx.conf").write_text("http {\n include sites-enabled/*;\n}\n")
    (nginx / "sites-enabled").mkdir()
    (nginx / "snippets").mkdir()
    (nginx / "sites-enabled/app").write_text("include /etc/nginx/snippets/shared.conf;\n")
    (nginx / "snippets/shared.conf").write_text("server { listen 127.0.0.1:8082; }\n")
    m.walk_includes(candidate, "/etc/nginx/nginx.conf", "nginx")
    assert str(candidate / "etc/nginx/sites-enabled/*") in (nginx / "nginx.conf").read_text()
    assert str(candidate / "etc/nginx/snippets/shared.conf") in (nginx / "sites-enabled/app").read_text()


def test_removed_site_is_not_reintroduced_from_live_include_glob(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    m = module()
    root = tmp_path / "candidate"
    (root / "etc/nginx/sites-enabled").mkdir(parents=True)
    (root / "etc/nginx/nginx.conf").write_text("include /etc/nginx/sites-enabled/*;\n")
    original = m.glob.glob

    def glob(pattern: str) -> list[str]:
        if pattern == "/etc/nginx/sites-enabled/*":
            pytest.fail("candidate must not resurrect deleted live entries")
        return list(original(pattern))

    monkeypatch.setattr(m.glob, "glob", glob)
    m.walk_includes(root, "/etc/nginx/nginx.conf", "nginx")


def test_existing_unknown_code_is_preserved(tmp_path: Path) -> None:
    m = module()
    (tmp_path / "index.php").write_text("local repair")
    desired = {"files": {"index.php": {"sha256": hashlib.sha256(b"vendor").hexdigest()}}}
    with pytest.raises(ValueError, match="preserve local repairs"):
        m.release_needed({"root": str(tmp_path), "release": desired, "previous_releases": []})
    assert (tmp_path / "index.php").read_text() == "local repair"


def test_release_internal_symlink_identity(tmp_path: Path) -> None:
    m = module()
    (tmp_path / "users").mkdir()
    (tmp_path / "users/totp.php").write_text("safe")
    (tmp_path / "totp.php").symlink_to("users/totp.php")
    release = {"files": {"totp.php": {"link": "users/totp.php"}}}
    assert m.release_matches(str(tmp_path), release)
    (tmp_path / "totp.php").unlink()
    (tmp_path / "totp.php").symlink_to("/etc/passwd")
    assert not m.release_matches(str(tmp_path), release)


def test_nginx_candidate_tokenizes_inline_quoted_and_commented_includes() -> None:
    m = module()
    text = 'http { include "snippets/one.conf"; server { include snippets/two.conf; } } # include ignored;\n'
    assert [x[0] for x in m.nginx_includes(text)] == ["snippets/one.conf", "snippets/two.conf"]
    assert list(m.nginx_includes('set $x "include not-a-directive;";')) == []


def test_real_php_snappy_hash_is_not_resalted() -> None:
    import shutil
    import subprocess

    php = shutil.which("php")
    if php is None:
        pytest.skip("PHP interpreter unavailable; native fixture runs PHP8.3")
    script = (ROOT / "files/credentials.php").read_text().removeprefix("<?php")
    request = {
        "app": "snappymail",
        "existing_hash": "",
        "hash_missing": True,
        "password": "synthetic-only-value",
        "apply": True,
    }
    first = json.loads(subprocess.check_output([php, "-r", script], input=json.dumps(request), text=True))
    request["existing_hash"] = first["snappy_hash"]
    second = json.loads(subprocess.check_output([php, "-r", script], input=json.dumps(request), text=True))
    assert not second["credential_changed"]
    assert second["snappy_hash"] == first["snappy_hash"]
    request["password"] = "different-synthetic-value"
    request["apply"] = False
    pending = json.loads(subprocess.check_output([php, "-r", script], input=json.dumps(request), text=True))
    assert pending["credential_changed"]
    assert pending["snappy_hash"] == "@NEW_HASH@"


@pytest.mark.parametrize("data", ["/opt/snappymail", "/opt/snappymail/data", "/opt"])
def test_snappy_data_is_separate_from_owned_release(data: str) -> None:
    with pytest.raises(ValueError, match="disjoint"):
        snappy(data_dir=data)


def test_snappy_domain_cannot_be_removed_and_managed() -> None:
    with pytest.raises(ValueError, match="same domain"):
        snappy(domains=("example.test",), remove_domains=("example.test",))


@pytest.mark.parametrize("mode", [0o600, 0o640])
def test_snappy_app_normalized_ini_is_exact_noop(tmp_path: Path, mode: int) -> None:
    m = module()
    path = tmp_path / "application.ini"
    body = b'; app normalized\n[security]\nforce_https = "On"\nadmin_totp = "preserve"\n[version]\ncurrent = "2.38.2"\n'
    path.write_bytes(body)
    path.chmod(mode)
    before = path.stat()
    content, desired_mode = m.snappy_ini(str(path), "[security]\nforce_https = On\n", shutil.which("php"))
    assert content == body
    assert desired_mode == mode
    assert path.stat() == before


def test_snappy_owned_change_preserves_unowned_settings(tmp_path: Path) -> None:
    import configparser

    m = module()
    path = tmp_path / "application.ini"
    path.write_text('[security]\nforce_https = Off\nadmin_totp = "keep"\n[contacts]\npdo_password = "keep-too"\n')
    path.chmod(0o600)
    content, mode = m.snappy_ini(str(path), "[security]\nforce_https = On\n", shutil.which("php"))
    parsed = configparser.ConfigParser(interpolation=None)
    parsed.read_string(content.decode())
    assert parsed["security"]["force_https"] == "On"
    assert parsed["security"]["admin_totp"] == '"keep"'
    assert parsed["contacts"]["pdo_password"] == '"keep-too"'
    assert mode == 0o600


def test_snappy_duplicate_ini_refuses_before_write(tmp_path: Path) -> None:
    import configparser

    m = module()
    path = tmp_path / "application.ini"
    body = "[security]\nforce_https=On\nforce_https=Off\n"
    path.write_text(body)
    with pytest.raises(configparser.DuplicateOptionError):
        m.snappy_ini(str(path), "[security]\nforce_https=On\n", shutil.which("php"))
    assert path.read_text() == body


@pytest.mark.parametrize(
    ("old", "wanted"),
    [
        ('"On"', "On"),
        ("true", "On"),
        ("0", "Off"),
        ('""', "Off"),
        ('"escaped\\\\path\\"quoted"', '"escaped\\\\path\\"quoted"'),
    ],
)
def test_snappy_php_ini_semantics(tmp_path: Path, old: str, wanted: str) -> None:
    m = module()
    path = tmp_path / "application.ini"
    body = "[security]\nsetting = " + old + "\n"
    path.write_text(body)
    path.chmod(0o600)
    content, mode = m.snappy_ini(str(path), "[security]\nsetting = " + wanted + "\n", shutil.which("php"))
    assert content == body.encode()
    assert mode == 0o600


def test_snappy_changed_key_retains_unowned_bytes_and_comments(tmp_path: Path) -> None:
    m = module()
    path = tmp_path / "application.ini"
    body = (
        "; keep header\n[security]\n; keep comment\nforce_https  = Off\n"
        'admin_totp = "preserve"\n\n[custom]\nCustomKey = "escaped\\\\value"\n'
    )
    path.write_text(body)
    path.chmod(0o600)
    content, _ = m.snappy_ini(str(path), "[security]\nforce_https = On\n", shutil.which("php"))
    assert content == body.replace("force_https  = Off", "force_https  = On").encode()


@pytest.mark.parametrize("shell", ["bash", "fish"])
def test_mail_web_source_and_secret_stdin_through_real_login_shell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shell: str
) -> None:
    if not shutil.which(shell):
        pytest.skip("login shell unavailable")
    from importlib import import_module

    from pyinfra.api.command import StringCommand
    from pyinfra.connectors.util import make_unix_command

    deploy_module = import_module("ops_deploy.services._mail_web.deploy")
    shutil.copytree(ROOT / "files", tmp_path / "files")
    (tmp_path / "files/mail_web_host.py").write_text(
        "print(hashlib.sha256(CREDENTIALS_SOURCE.encode()).hexdigest())\n"
        'print(hashlib.sha256(json.load(sys.stdin)["value"].encode()).hexdigest())\n'
    )
    monkeypatch.setattr(deploy_module, "ROOT", tmp_path)
    payload = "quotes'\" and backslashes\\\\ and $HOME `shell`"
    generated = deploy_module.command()
    assert payload not in generated
    wrapped = make_unix_command(StringCommand(generated)).get_raw_value()
    result = subprocess.run(
        [shell, "-c", wrapped], input=json.dumps({"value": payload}), text=True, capture_output=True
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        hashlib.sha256((ROOT / "files/credentials.php").read_bytes()).hexdigest(),
        hashlib.sha256(payload.encode()).hexdigest(),
    ]


def test_actual_php_hash_admission_refuses_malformed_encodings() -> None:
    php = shutil.which("php")
    if php is None:
        pytest.skip("PHP unavailable")
    source = (ROOT / "files/credentials.php").read_text().removeprefix("<?php")
    functions = source.split("try {\n$q = json_decode", 1)[0]
    script = (
        functions
        + r"""
$password='owned-fixture-only';
$b=password_hash($password, PASSWORD_BCRYPT, ['cost'=>4]);
if (!bcrypt_matches($password,$b) || bcrypt_matches('wrong',$b)) { exit(10); }
$bad=[$b.'x',substr($b,0,-1).'z',substr_replace($b,'03',4,2),substr_replace($b,'32',4,2)];
foreach ($bad as $stored) {
    try { bcrypt_matches($password,$stored); exit(11); } catch (RuntimeException $e) {}
}
foreach (['$6$normal-salt$', '$6$rounds=5000$./0123456789ABCD$', '$6$rounds=10000$normal-salt$'] as $setting) {
    $valid='{SHA512-CRYPT}'.crypt($password,$setting);
    if (!sha512_matches($password,$valid) || sha512_matches('wrong',$valid)) { exit(14); }
}
$s='{SHA512-CRYPT}'.crypt($password,'$6$rounds=1000$normal-salt$');
if (!sha512_matches($password,$s) || sha512_matches('wrong',$s)) { exit(12); }
$bad=[str_replace('rounds=1000','rounds=01000',$s),str_replace('rounds=1000','rounds=999',$s),
str_replace('rounds=1000','rounds=1000000000',$s),substr($s,0,-1).'z',str_replace('normal-salt','bad!salt',$s)];
foreach ($bad as $stored) {
    try { sha512_matches($password,$stored); exit(13); } catch (RuntimeException $e) {}
}
echo 'qualified';
"""
    )
    result = subprocess.run([php, "-r", script], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "qualified"


@pytest.mark.parametrize("stored", ["", "$2y$12$malformed", "$argon2id$unsupported"])
def test_existing_snappy_unknown_hash_is_not_replaced(stored: str) -> None:
    php = shutil.which("php")
    if php is None:
        pytest.skip("PHP unavailable")
    source = (ROOT / "files/credentials.php").read_text().removeprefix("<?php")
    request = {"app": "snappymail", "existing_hash": stored, "password": "synthetic", "apply": True}
    result = subprocess.run([php, "-r", source], input=json.dumps(request), capture_output=True, text=True)
    assert result.returncode != 0
    assert result.stdout == ""


@pytest.mark.parametrize("port", [8088, 18088])
def test_peer_preservation_probe_uses_actual_listener(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, port: int
) -> None:
    m = module()
    site = tmp_path / "snappymail"
    site.write_text(f"server {{\n listen 127.0.0.1:{port};\n}}\n")
    monkeypatch.setattr(m, "Path", lambda _: site)
    result = m.peer_health({"app": "postfixadmin", "healthcheck": False, "port": 99})
    assert result == {"port": port, "healthcheck": True, "healthcheck_timeout": 10, "healthcheck_retries": 3}


@pytest.mark.parametrize("listener", ["0.0.0.0:8088", "127.0.0.1:70000", "127.0.0.1:8088;\nlisten 127.0.0.1:8089"])
def test_ambiguous_peer_listener_refuses_before_activation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, listener: str
) -> None:
    m = module()
    site = tmp_path / "snappymail"
    site.write_text(f"server {{\nlisten {listener};\n}}\n")
    monkeypatch.setattr(m, "Path", lambda _: site)
    with pytest.raises(ValueError, match="peer listener"):
        m.peer_health({"app": "postfixadmin"})


@pytest.mark.parametrize("field", ["db_name", "db_user"])
@pytest.mark.parametrize("value", ["mail-db", "Mail", "mail.db"])
def test_database_identifier_matches_actual_grant_contract(field: str, value: str) -> None:
    with pytest.raises(ValueError, match="string_pattern_mismatch"):
        pfa(**{field: value})


def test_preload_requires_typed_boolean() -> None:
    with pytest.raises(ValueError, match="bool_type"):
        pfa(traefik_sts_preload="false")


def test_recovery_attempts_all_owned_files_and_units_after_restore_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    m = module()
    paths = [str(tmp_path / "one"), str(tmp_path / "two")]
    old = ("file", b"old", 0o640, 1, 1)
    new = ("file", b"new", 0o640, 1, 1)
    q = {"app": "snappymail", "php": "8.3", "root": str(tmp_path), "data": "/unused", "apply": True}
    monkeypatch.setattr(m, "release_needed", lambda _: False)
    monkeypatch.setattr(m, "needs_seed", lambda _: False)
    monkeypatch.setattr(m, "credential_state", lambda *_, **__: {})
    monkeypatch.setattr(m, "app_grants", lambda _: False)
    monkeypatch.setattr(m, "desired_files", lambda *_: dict.fromkeys(paths, new))
    monkeypatch.setattr(m, "file_state", lambda _: old)
    monkeypatch.setattr(m, "service_active", lambda _: True)
    monkeypatch.setattr(m, "peer_health", lambda _: None)
    monkeypatch.setattr(m, "stage_context", lambda *_: None)
    restored = []
    units = []

    def replace(path: str, value: Any) -> None:
        if value == old:
            restored.append(path)
            if path == paths[1]:
                raise OSError("fixture restore failure")

    def fail_activation(*_: Any) -> None:
        raise ValueError("original activation failure")

    def run(argv: list[str]) -> None:
        units.append(argv[-1])
        if argv[-1] == "php8.3-fpm":
            raise ValueError("fixture restart failure")

    monkeypatch.setattr(m, "replace_file", replace)
    monkeypatch.setattr(m, "activate", fail_activation)
    monkeypatch.setattr(m, "run", run)
    with pytest.raises(ValueError, match="original activation failure"):
        m.main(q)
    assert restored == list(reversed(paths))
    assert units == ["php8.3-fpm", "nginx"]
