"""Actual published relay and retained Python fallback against an owned TLS/AUTH sink.

Opt in with MAILGUN_FIXTURE_ARTIFACT_DIR (0.2.1 and 0.2.2 release archives)
and MAILGUN_FIXTURE_SOURCE (the Python project); never uses production secrets.
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import io
import json
import os
import shlex
import tarfile
from email import policy
from email.parser import Parser
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.mailgun_relay import MailgunRelayConfig, deploy_mailgun_relay
from ops_deploy.testing import SshRun, run_deploy_ssh
from tests.smoke.conftest import TIMINGS, SmokeHost

ROOT = "/var/lib/mailgun-fixture"
UNIT = "mailgun-fixture"
REF = SecretRef("fixture.yml")
FIXTURE_API_VALUE = "owned-fixture-only"
VALUES = SecretValues(
    REF,
    {
        "smtp_username": "fixture@example.test",
        "smtp_password": "fixture-pass",
        "envelope_sender": "fixture@example.test",
        "tokens": json.dumps(
            [
                {
                    "label": "owned-fixture",
                    "token_sha256": hashlib.sha256(FIXTURE_API_VALUE.encode()).hexdigest(),
                    "mailgun_domains": ["mg.example.test"],
                    "allowed_from_domains": ["example.test"],
                    "allowed_from_addresses": ["fixture@example.test"],
                }
            ]
        ),
    },
)


def run(host: SmokeHost, cfg: MailgunRelayConfig, label: str, *, success: bool = True) -> SshRun:
    result = run_deploy_ssh(deploy_mailgun_relay, cfg, VALUES, host_name=host.name, host_data=host.host_data)
    TIMINGS["mailgun " + label] = result.seconds
    evidence = os.environ.get("MAILGUN_FIXTURE_EVIDENCE_DIR")
    if evidence:
        with (Path(evidence) / "phases.jsonl").open("a") as output:
            output.write(
                json.dumps(
                    {
                        "phase": label,
                        "succeeded": result.succeeded,
                        "expected_success": success,
                        "seconds": result.seconds,
                        "version": cfg.rust_version,
                        "impl": cfg.impl,
                        "mutations": result.mutating_changed_ops,
                        "readonly": [op.name for op in result.ops if op.read_only and op.changed],
                        "native_process_check": not bool(os.environ.get("MAILGUN_FIXTURE_TRANSLATED")),
                    }
                )
                + "\n"
            )
    assert result.succeeded == success, (label, result.error, [op for op in result.ops if not op.succeeded])
    return result


def pid(host: SmokeHost) -> str:
    return host.out("systemctl show -p MainPID --value " + UNIT)


def snapshot(host: SmokeHost) -> str:
    code = """import pathlib,hashlib,json
r=[]
for root in ['/opt/apps/mailgun-fixture/site','/opt/apps/mailgun-fixture/.local/share/uv/python']:
 for p in sorted(pathlib.Path(root).rglob('*')):
  if '__pycache__' in p.parts:continue
  s=p.lstat(); d=[str(p),s.st_uid,s.st_gid,s.st_mode,s.st_size,s.st_mtime_ns]
  if p.is_symlink():d.append(str(p.readlink()))
  elif p.is_file():d.append(hashlib.sha256(p.read_bytes()).hexdigest())
  r.append(d)
print(hashlib.sha256(json.dumps(r).encode()).hexdigest())
"""
    return host.out(shlex.join(["python3", "-I", "-c", code]))


@pytest.fixture
def relay_fixture(smoke_host: SmokeHost) -> Any:
    artifacts = os.environ.get("MAILGUN_FIXTURE_ARTIFACT_DIR")
    source = os.environ.get("MAILGUN_FIXTURE_SOURCE")
    if not artifacts or not source:
        pytest.skip("actual relay artifacts/source not supplied")
    sink = Path(__file__).with_name("mailgun_smtp_fixture.py").read_bytes()
    smoke_host.run(
        "systemctl stop mailgun-fixture mailgun-fixture-smtp mailgun-fixture-artifacts 2>/dev/null || true; "
        "rm -rf /opt/apps/mailgun-fixture /opt/mailgun-fixture /etc/mailgun-fixture "
        f"{ROOT} /var/lib/ops-deploy/mailgun-fixture /opt/mailgun-fixture-http; "
        "rm -rf /etc/systemd/system/mailgun-fixture.service.d; "
        "rm -f /etc/systemd/system/mailgun-fixture.service /etc/traefik/dynamic/mailgun-fixture.yml; "
        f"mkdir -p {ROOT} /etc/traefik/dynamic; chmod 0755 {ROOT}; "
        f"printf %s {base64.b64encode(sink).decode()} | base64 -d > {ROOT}/smtp.py; "
        f"echo accept > {ROOT}/scenario; "
        f"openssl req -x509 -newkey rsa:2048 -nodes -keyout {ROOT}/ca-key.pem -out {ROOT}/ca.pem "
        "-days 2 -subj /CN=owned-fixture-ca -addext basicConstraints=critical,CA:TRUE "
        "-addext keyUsage=critical,keyCertSign,cRLSign >/dev/null 2>&1; "
        f"openssl req -new -newkey rsa:2048 -nodes -keyout {ROOT}/key.pem -out {ROOT}/leaf.csr "
        "-subj /CN=localhost >/dev/null 2>&1; "
        f"printf 'basicConstraints=critical,CA:FALSE\\nkeyUsage=digitalSignature,keyEncipherment\\n"
        f"extendedKeyUsage=serverAuth\\nsubjectKeyIdentifier=hash\\nauthorityKeyIdentifier=keyid,issuer\\n"
        f"subjectAltName=DNS:localhost,IP:127.0.0.1\\n' > {ROOT}/leaf.ext; "
        f"openssl x509 -req -in {ROOT}/leaf.csr -CA {ROOT}/ca.pem -CAkey {ROOT}/ca-key.pem "
        f"-CAcreateserial -days 2 -extfile {ROOT}/leaf.ext -out {ROOT}/cert.pem >/dev/null 2>&1; "
        f"chmod 0644 {ROOT}/cert.pem {ROOT}/ca.pem; systemctl daemon-reload; "
        f"systemd-run --unit=mailgun-fixture-smtp /usr/bin/python3 {ROOT}/smtp.py {ROOT} 1587"
    )
    archive = Path(artifacts) / "mailgun-relay-0.2.1-x86_64-unknown-linux-gnu.tar.gz"
    cfg = MailgunRelayConfig(
        secrets=REF,
        service_name=UNIT,
        user=UNIT,
        group=UNIT,
        home="/opt/apps/mailgun-fixture",
        site_path="/opt/apps/mailgun-fixture/site",
        env_dir="/etc/mailgun-fixture",
        python_deploy="rsync",
        source_path=Path(source),
        impl="rust",
        rust_version="0.2.1",
        rust_local_archive=archive,
        rust_install_root="/opt/mailgun-fixture",
        rust_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        bind_port=18085,
        public_host="relay.example.test",
        smtp_host="127.0.0.1",
        smtp_port=1587,
        smtp_ca_file=ROOT + "/ca.pem",
        ingress_enabled=True,
        ingress_host="relay.example.test",
        ingress_backend_url="http://127.0.0.1:18085",
        ingress_traefik_config_path="/etc/traefik/dynamic/mailgun-fixture.yml",
    )
    try:
        yield cfg, Path(artifacts)
    finally:
        smoke_host.run(
            "systemctl stop mailgun-fixture mailgun-fixture-smtp mailgun-fixture-artifacts 2>/dev/null || true"
        )


def post(host: SmokeHost, *, auth: bool = True, sender: str = "fixture@example.test") -> int:
    authorization = f"--user api:{FIXTURE_API_VALUE}" if auth else ""
    command = (
        "curl --silent --output /dev/null --write-out '%{http_code}' "
        + authorization
        + " --form-string "
        + shlex.quote("from=" + sender)
        + " --form-string to=recipient@example.test --form-string cc=copy@example.test "
        "--form-string bcc=blind@example.test --form-string subject=owned-fixture "
        "--form-string text=owned-synthetic-body --form attachment=@/var/lib/mailgun-fixture/attachment.txt "
        "http://127.0.0.1:18085/v3/mg.example.test/messages"
    )
    return int(host.out(command))


def test_actual_relay_install_update_preserve_rollback_and_failures(
    smoke_host: SmokeHost,
    relay_fixture: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = importlib.import_module("ops_deploy.services.mailgun_relay.deploy")
    if os.environ.get("MAILGUN_FIXTURE_TRANSLATED") == "rosetta":
        # Explicit fixture-only limitation: kernel exe points at Rosetta. Prove
        # its identity and exact translated argv; production code stays strict.
        translated = """
def fixture_exe(pid):
    exe = os.readlink('/proc/%s/exe' % pid)
    if exe == '/mnt/lima-rosetta/rosetta':
        argv = pathlib.Path('/proc/%s/cmdline' % pid).read_bytes().rstrip(b'\\0').split(b'\\0')
        assert argv[0] == b'/mnt/lima-rosetta/rosetta' and len(argv) == 2
        return argv[1].decode()
    return exe
"""
        script = module.SCRIPT.replace('os.readlink("/proc/%s/exe" % pid)', "fixture_exe(pid)")
        script = script.replace('if __name__ == "__main__":', translated + '\nif __name__ == "__main__":')
        monkeypatch.setattr(module, "SCRIPT", script)
    cfg, artifacts = relay_fixture
    first = run(smoke_host, cfg, "first 0.2.1 install")
    assert first.mutating_changed_ops
    initial_pid = pid(smoke_host)
    baseline = snapshot(smoke_host)
    preserved = cfg.model_copy(update={"python_deploy": "preserve"})
    assert run(smoke_host, preserved, "same version repeat").mutating_changed_ops == []
    assert pid(smoke_host) == initial_pid
    assert snapshot(smoke_host) == baseline
    archive = artifacts / "mailgun-relay-0.2.2-x86_64-unknown-linux-gnu.tar.gz"
    current = preserved.model_copy(
        update={
            "rust_version": "0.2.2",
            "rust_local_archive": archive,
            "rust_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        }
    )
    run(smoke_host, current, "actual 0.2.2 update")
    assert pid(smoke_host) != initial_pid
    assert smoke_host.out("cat /opt/mailgun-fixture/.previous-version") == "0.2.1"
    assert snapshot(smoke_host) == baseline
    assert run(smoke_host, current, "current repeat").mutating_changed_ops == []
    current_pid = pid(smoke_host)
    smoke_host.run(f"echo synthetic-attachment > {ROOT}/attachment.txt")
    assert post(smoke_host, auth=False) == 401
    assert post(smoke_host, sender="forbidden@other.test") == 403
    assert post(smoke_host) == 200
    records = json.loads(smoke_host.out(f"tail -1 {ROOT}/records.jsonl"))
    assert records["tls"] is True
    assert records["auth"] is True
    assert "fixture@example.test" in records["sender"]
    assert len(records["recipients"]) == 3
    assert "Bcc:" not in records["data"]
    message = Parser(policy=policy.default).parsestr(records["data"])
    assert [part.get_payload(decode=True) for part in message.iter_attachments()] == [b"synthetic-attachment\n"]
    limited = current.model_copy(update={"max_body_bytes": 512})
    run(smoke_host, limited, "enforced body cap")
    assert post(smoke_host) == 413
    run(smoke_host, current, "restore normal body cap")
    current_pid = pid(smoke_host)
    for scenario, expected in [("temporary", 503), ("permanent", 502)]:
        smoke_host.run(f"echo {scenario} > {ROOT}/scenario")
        assert post(smoke_host) == expected
    smoke_host.run(f"echo accept > {ROOT}/scenario")
    changed = current.model_copy(update={"smtp_max_concurrency": 3})
    # Inject a failure after runtime input writes, before the candidate/switch.
    original = module.lifecycle

    def broken(
        config: MailgunRelayConfig, mode: str, sha256: str = "", fresh: bool = False, archive_refused: bool = False
    ) -> str:
        return "false" if mode == "candidate" else original(config, mode, sha256, fresh, archive_refused)

    with monkeypatch.context() as patch:
        patch.setattr(module, "lifecycle", broken)
        run(smoke_host, changed, "interrupted config", success=False)
    assert pid(smoke_host) == current_pid
    resumed = run(smoke_host, changed, "resume config")
    assert any("Resume relay restart" in name for name in resumed.mutating_changed_ops)
    assert pid(smoke_host) != current_pid
    assert run(smoke_host, changed, "after resume repeat").mutating_changed_ops == []
    assert snapshot(smoke_host) == baseline
    # No trust override: the self-signed owned sink must be refused, never bypassed.
    untrusted = changed.model_copy(update={"smtp_ca_file": None})
    run(smoke_host, untrusted, "untrusted TLS config")
    assert post(smoke_host) in (502, 503)
    run(smoke_host, changed, "restore TLS trust")
    assert post(smoke_host) == 200
    old_pid = pid(smoke_host)
    rejected = changed.model_copy(update={"rust_version": "9.9.8"})
    run(smoke_host, rejected, "wrong reported candidate version", success=False)
    assert pid(smoke_host) == old_pid
    assert smoke_host.out("test ! -e /opt/mailgun-fixture/9.9.8 && echo removed") == "removed"
    # A valid checksum does not authorize a link member. Only owned fixture
    # paths are named even if this archive guard were to regress.
    malicious = tmp_path / "linked-release.tar.gz"
    with tarfile.open(malicious, "w:gz") as archive_stream:
        link = tarfile.TarInfo("mailgun-relay")
        link.type = tarfile.SYMTYPE
        link.linkname = ROOT + "/outside-sentinel"
        archive_stream.addfile(link)
        license_file = tarfile.TarInfo("LICENSE")
        license_file.size = 7
        archive_stream.addfile(license_file, io.BytesIO(b"fixture"))
    smoke_host.run(f"printf untouched > {ROOT}/outside-sentinel; chmod 0640 {ROOT}/outside-sentinel")
    linked = changed.model_copy(
        update={
            "rust_version": "9.9.7",
            "rust_local_archive": malicious,
            "rust_sha256": hashlib.sha256(malicious.read_bytes()).hexdigest(),
        }
    )
    run(smoke_host, linked, "native link member rejection", success=False)
    assert pid(smoke_host) == old_pid
    assert smoke_host.out(f"cat {ROOT}/outside-sentinel") == "untouched"
    assert smoke_host.out(f"stat -c %a {ROOT}/outside-sentinel") == "640"
    assert smoke_host.out("test ! -e /opt/mailgun-fixture/9.9.7 && echo removed") == "removed"
    fresh_invalid = changed.model_copy(
        update={
            "rust_install_root": Path("/opt/mailgun-fixture-reject"),
            "smtp_ca_file": ROOT + "/missing-ca.pem",
        }
    )
    smoke_host.run("rm -rf /opt/mailgun-fixture-reject")
    run(smoke_host, fresh_invalid, "fresh candidate config cleanup", success=False)
    assert pid(smoke_host) == old_pid
    assert smoke_host.out("test ! -e /opt/mailgun-fixture-reject/0.2.2 && echo removed") == "removed"
    assert (
        smoke_host.out(
            "grep -q missing-ca.pem /etc/mailgun-fixture/mailgun-relay.env "
            "&& test -e /var/lib/ops-deploy/mailgun-fixture/restart && echo rejected-config-remains"
        )
        == "rejected-config-remains"
    )
    run(smoke_host, changed, "restore after fresh config rejection")
    old_pid = pid(smoke_host)
    invalid_config = changed.model_copy(update={"smtp_ca_file": ROOT + "/missing-ca.pem"})
    run(smoke_host, invalid_config, "rejected production config", success=False)
    assert pid(smoke_host) == old_pid
    assert (
        smoke_host.out(
            "grep -q missing-ca.pem /etc/mailgun-fixture/mailgun-relay.env "
            "&& test -e /var/lib/ops-deploy/mailgun-fixture/restart && echo rejected-config-remains"
        )
        == "rejected-config-remains"
    )
    run(smoke_host, changed, "restore rejected config")
    # Exercise the complete HTTP transport → shared installer upload path using
    # the actual selected archive; all requests remain on the owned loopback.
    smoke_host.run(f"mkdir -p {ROOT}/http-artifacts")
    smoke_host.run(
        f"base64 -d > {ROOT}/http-artifacts/http-release.tar.gz",
        input=base64.b64encode(archive.read_bytes()).decode(),
    )
    smoke_host.run(
        "systemd-run --unit=mailgun-fixture-artifacts /usr/bin/python3 -m http.server "
        f"18545 --bind 127.0.0.1 --directory {ROOT}/http-artifacts"
    )
    smoke_host.run(
        "for i in $(seq 1 20); do curl --fail --silent --head --max-time 1 "
        "http://127.0.0.1:18545/http-release.tar.gz >/dev/null && exit 0; sleep 0.1; done; exit 1"
    )
    http_mirror = changed.model_copy(
        update={
            "rust_install_root": Path("/opt/mailgun-fixture-http"),
            "rust_local_archive": None,
            "rust_release_url": "http://127.0.0.1:18545/http-release.tar.gz",
        }
    )
    run(smoke_host, http_mirror, "HTTP mirror real archive success")
    assert run(smoke_host, http_mirror, "HTTP mirror repeat").mutating_changed_ops == []
    smoke_host.run("systemctl stop mailgun-fixture-artifacts")
    run(smoke_host, changed, "return from HTTP mirror root")
    smoke_host.run(
        "mkdir -p /opt/mailgun-fixture/0.0.1 /opt/mailgun-fixture/0.0.2 /opt/mailgun-fixture/unmanaged; "
        "touch -d @1 /opt/mailgun-fixture/0.0.1 /opt/mailgun-fixture/0.0.2"
    )
    compact = changed.model_copy(update={"rust_keep_versions": 1})
    pruned = run(smoke_host, compact, "prune with pin/live/previous retained")
    assert any("Prune old relay releases" in name for name in pruned.mutating_changed_ops)
    assert (
        smoke_host.out(
            "test -d /opt/mailgun-fixture/0.2.1 && test -d /opt/mailgun-fixture/0.2.2 "
            "&& test -d /opt/mailgun-fixture/unmanaged && test ! -d /opt/mailgun-fixture/0.0.1 "
            "&& test ! -d /opt/mailgun-fixture/0.0.2 && echo retained"
        )
        == "retained"
    )
    assert run(smoke_host, compact, "after prune repeat").mutating_changed_ops == []
    # Python rollback is independent of a broken/missing pinned Rust archive.
    rollback = changed.model_copy(
        update={
            "impl": "python",
            "rust_version": "9.9.9",
            "rust_local_archive": None,
            "rust_release_url": "http://127.0.0.1:1/missing",
            "rust_sha256": "a" * 64,
        }
    )
    run(smoke_host, rollback, "Python rollback with rejected Rust")
    assert post(smoke_host) == 200
    run(smoke_host, changed, "return to selected Rust")
    assert run(smoke_host, changed, "final repeat").mutating_changed_ops == []
