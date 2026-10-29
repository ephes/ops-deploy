"""mail_relay with postsrsd 1.x (tcp: tables) and 2.x (postsrsd.conf + socketmap: tables)."""

from __future__ import annotations

import base64
import hashlib
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any

import pytest
from pyinfra.api import DeployError

from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.services.mail_relay import deploy as relay
from ops_deploy.services.mail_relay.config import MailRelayConfig
from ops_deploy.services.mail_relay.postsrsd import (
    _SOCKETMAP_CHECK,
    candidate_version,
    postsrsd_major,
    probe_sender,
)
from ops_deploy.services.mail_relay.render import render_role
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

PROBE_SENDER = "ops-deploy-srs-probe@srs-probe.invalid"

SECRETS = SecretValues(SecretRef("fixture.yml"), {"sasl_password": "fixture-sasl", "srs_secret": "fixture-srs-secret"})
SRS: dict[str, Any] = dict(
    domains=("example.test", "example.org"),
    srs_enabled=True,
    srs_domain="example.test",
    srs_exclude_domains=("example.test", "example.org"),
    recipient_rewrites=({"from": "@b.example.test", "to": "@example.test"},),
)
V1, V2 = "1.10-2.1build1", "2.0.11-1"
P = "Deploy native mail edge relay | "


def config(**changes: Any) -> MailRelayConfig:
    return MailRelayConfig.model_validate({**SRS, **changes})


# sha256 of the renders before postsrsd 2.x support (ops-deploy 0d74681).
PRE_2X = {
    ("srs", "main.cf.j2"): "fced7f92ff2431f0723e7f18d8ab13a61cc1ab2431a529fe6d5e751b43ae2eea",
    ("srs", "postsrsd.default.j2"): "d58873cddd428a408129fc6cb54e8e48618e6ead0fd2acdea050ba9df32c6c05",
    ("srs-tcp", "main.cf.j2"): "af462097a7df9751563da5e5a535fed07ffc4ac0eae441223a19e29c88b79594",
    ("srs-tcp", "postsrsd.default.j2"): "6ce41e8766e1ec78a5367856abe209974bdbc629f2b331a8123fbe1df972400a",
    ("plain", "main.cf.j2"): "f83ff643b3986134aa81e5a1aa63ca963653afe58a9b93e8329ee17038ec5a7c",
}
CASES: dict[str, dict[str, Any]] = {
    "srs": SRS,
    "srs-tcp": dict(
        domains=("example.test",),
        srs_enabled=True,
        srs_domain="example.test",
        srs_listen_addr="127.0.0.2",
        srs_forward_port=11001,
        srs_reverse_port=11002,
    ),
    "plain": dict(domains=("example.test",)),
}


@pytest.mark.parametrize(("case", "template"), sorted(PRE_2X))
def test_postsrsd_1x_renders_keep_their_bytes(case: str, template: str) -> None:
    cfg = MailRelayConfig.model_validate(CASES[case])
    for body in (render_role(template, cfg, SECRETS), render_role(template, cfg, SECRETS, postsrsd_major=1)):
        assert hashlib.sha256(body.encode()).hexdigest() == PRE_2X[(case, template)]


@pytest.mark.parametrize(
    ("version", "major"),
    [("1.10-2.1build1", 1), ("1.10-2", 1), ("2.0.11-1", 2), ("1:2.0.11-1", 2), ("2.1~rc1-1ubuntu1", 2)],
)
def test_postsrsd_major(version: str, major: int) -> None:
    assert postsrsd_major(version) == major


@pytest.mark.parametrize("version", ["3.0-1", "0.9-1", "", "2", "x2.0"])
def test_unknown_postsrsd_major_refused(version: str) -> None:
    with pytest.raises(DeployError, match=r"neither 1\.x nor 2\.x"):
        postsrsd_major(version)


def test_candidate_version() -> None:
    policy = "postsrsd:\n  Installed: (none)\n  Candidate: 2.0.11-1\n  Version table:\n     2.0.11-1 500\n"
    assert candidate_version(policy) == "2.0.11-1"
    assert candidate_version("postsrsd:\n  Installed: (none)\n  Candidate: (none)\n") is None
    assert candidate_version("") is None


def test_2x_renders_postsrsd_conf_and_socketmap_maps() -> None:
    cfg = config()
    main = render_role("main.cf.j2", cfg, SECRETS, postsrsd_major=2)
    assert "recipient_canonical_maps = socketmap:unix:srs:reverse, hash:/etc/postfix/recipient_canonical\n" in main
    assert "sender_canonical_maps = socketmap:unix:srs:forward\nsender_canonical_classes = envelope_sender\n" in main
    assert "tcp:" not in main
    # Everything else in main.cf is the 1.x render.
    old = render_role("main.cf.j2", cfg, SECRETS).replace("tcp:127.0.0.1:10002", "socketmap:unix:srs:reverse")
    assert old.replace("tcp:127.0.0.1:10001", "socketmap:unix:srs:forward") == main
    conf = render_role("postsrsd.conf.j2", cfg, SECRETS, postsrsd_major=2)
    settings = [line for line in conf.splitlines() if line and not line.startswith("#")]
    assert settings == [
        'srs-domain = "example.test"',
        'domains = { ".example.test", ".example.org", "example.test", "example.org" }',
        'secrets-file = "/etc/postsrsd.secret"',
        'separator = "="',
        "hash-length = 4",
        "hash-minimum = 4",
        "original-envelope = embedded",
        "always-rewrite = off",
        "socketmap = unix:/var/spool/postfix/srs",
        "keep-alive = 30",
        'unprivileged-user = "postsrsd"',
        'chroot-dir = "/var/lib/postsrsd"',
        "syslog = off",
        "debug = off",
    ]
    assert "fixture-srs-secret" not in conf


def test_srs_off_renders_the_same_for_both_majors() -> None:
    cfg = config(srs_enabled=False)
    assert render_role("main.cf.j2", cfg, SECRETS, postsrsd_major=2) == render_role("main.cf.j2", cfg, SECRETS)


def host(version: str | None, *, candidate: str | None = None, files: dict[str, str] | None = None) -> dict[str, Any]:
    packages = ["postfix", "postgrey", "libsasl2-modules", "sasl2-bin", "ca-certificates"]
    dpkg = [f"ii  {name}  1.0  all  {name}" for name in packages]
    if version is not None:
        dpkg.append(f"ii  postsrsd  {version}  arm64  postsrsd")
    responses: dict[str, Any] = {
        **fakehost.LINUX,
        "dpkg -l": dpkg,
        "' check )": ["current"],
        "apt-cache policy postsrsd": ["postsrsd:", "  Installed: (none)", f"  Candidate: {candidate or '(none)'}"],
        **fakehost.apt_cache_fresh(),
    }
    for unit in ("postfix", "postgrey", "postsrsd", "systemd-resolved"):
        responses.update(fakehost.service(f"{unit}.service"))
    for path, content in (files or {}).items():
        responses.update(fakehost.file(path, content))
    return responses


def run(cfg: MailRelayConfig, responses: dict[str, Any]) -> Any:
    result = run_deploy_fake(relay.deploy_mail_relay, cfg, SECRETS, responses=responses)
    assert result.succeeded, result.error
    return result


def names(result: Any) -> list[str]:
    return [op.name.removeprefix(P) for op in result.ops]


def test_2x_switches_postsrsd_before_postfix_maps() -> None:
    cfg = config()
    files = {"/etc/default/postsrsd": render_role("postsrsd.default.j2", cfg, SECRETS)}
    result = run(cfg, host(V2, files=files))
    order = names(result)
    uploads = [path for path, _ in result.uploads]
    # Secret, postsrsd.conf, 1.x file removal, postsrsd restart and the
    # socketmap round trip all come before main.cf names the socketmap.
    sequence = [
        "Remember postsrsd restart owed",
        "Retain configured SRS signing secret",
        "Install relay configuration",
        "Remove the postsrsd 1.x defaults file",
        "Enable postsrsd.service",
        "Start postsrsd.service",
        "Restart postsrsd.service",
        "Verify relay SRS socketmap round trip",
    ]
    positions = [order.index(name) for name in sequence]
    assert positions == sorted(positions)
    assert uploads.index("/etc/postsrsd.conf") < uploads.index("/etc/postfix/main.cf")
    restart = next(op for op in result.ops if op.name == P + "Restart postsrsd.service")
    assert restart.changed
    assert "rm -f /etc/default/postsrsd" in " ".join(result.executed_commands)
    main = dict(result.uploads)["/etc/postfix/main.cf"].decode()
    assert "socketmap:unix:srs:forward" in main
    assert "tcp:" not in main
    # No 1.x leftovers: tcp listener waits, defaults validation or upload.
    assert "Verify relay SRS forward listener" not in order
    assert "Validate relay postsrsd defaults" not in order
    assert "/etc/default/postsrsd" not in uploads
    assert "Verify the installed postsrsd major version" not in order
    assert not any("apt-cache policy" in command for command in result.fact_commands)


def test_2x_keeps_the_1x_secret_file() -> None:
    cfg = config()
    one, two = run(cfg, host(V1)), run(cfg, host(V2))

    def secret(result: Any) -> list[tuple[str, bytes]]:
        # secret_file sends the bytes base64-encoded on stdin, never as an upload.
        return [(key, base64.b64decode(data)) for key, data in result.stdin if " postsrsd.secret " in key]

    assert secret(one) == secret(two)
    assert [data for _, data in secret(two)] == [b"fixture-srs-secret\n"]
    assert "/etc/postsrsd.secret" not in [path for path, _ in two.uploads]
    assert all("fixture-srs-secret" not in command for command in two.executed_commands)


def test_1x_keeps_tcp_listeners_and_defaults_file() -> None:
    result = run(config(), host(V1))
    order = names(result)
    assert "Validate relay postsrsd defaults" in order
    assert "Verify relay SRS forward listener" in order
    assert "Verify relay SRS reverse listener" in order
    assert "Verify relay SRS socketmap round trip" not in order
    uploads = [path for path, _ in result.uploads]
    assert "/etc/default/postsrsd" in uploads
    assert "/etc/postsrsd.conf" not in uploads
    assert uploads.index("/etc/postfix/main.cf") < uploads.index("/etc/default/postsrsd")


@pytest.mark.parametrize(("candidate", "major"), [(V2, "2"), (V1, "1"), (None, "1")])
def test_not_installed_follows_apt_candidate_and_checks_after_install(candidate: str | None, major: str) -> None:
    result = run(config(), host(None, candidate=candidate))
    order = names(result)
    check = order.index("Verify the installed postsrsd major version")
    assert order.index("Install mail relay packages") < check < order.index("Remember postfix restart owed")
    assert any(command.endswith(f" {major}") and "dpkg-query" in command for command in result.executed_commands)
    uploads = [path for path, _ in result.uploads]
    assert ("/etc/postsrsd.conf" in uploads) == (major == "2")
    assert ("/etc/default/postsrsd" in uploads) == (major == "1")


def test_srs_off_never_asks_for_postsrsd() -> None:
    result = run(config(srs_enabled=False), host(None, candidate=V2))
    assert not any("apt-cache policy" in command for command in result.fact_commands)
    assert not any("postsrsd" in name.lower() for name in names(result))


@pytest.mark.parametrize(
    "change",
    [
        {"srs_listen_addr": "127.0.0.2"},
        {"srs_forward_port": 11001},
        {"srs_reverse_port": 11002},
        {"srs_exclude_domains": ('example.test", "evil.test',)},
        {"srs_secret_file": "/etc/postsrsd secret"},
    ],
)
def test_2x_refuses_settings_it_cannot_express(change: dict[str, Any]) -> None:
    cfg = config(**change)
    with pytest.raises(ValueError, match=r"postsrsd 2\.x"):
        run_deploy_fake(relay.deploy_mail_relay, cfg, SECRETS, responses=host(V2))
    # postsrsd 1.x keeps accepting them as before.
    assert run_deploy_fake(relay.deploy_mail_relay, cfg, SECRETS, responses=host(V1)).succeeded


def test_mixed_installed_majors_refused() -> None:
    responses = host(V1)
    responses["dpkg -l"] = [*responses["dpkg -l"], f"ii  postsrsd  {V2}  amd64  postsrsd"]
    result = run_deploy_fake(relay.deploy_mail_relay, config(), SECRETS, responses=responses)
    assert isinstance(result.error, DeployError)
    assert "more than one major" in str(result.error)
    assert not result.uploads
    assert not result.executed_commands


@pytest.mark.parametrize(
    ("excluded", "sender"),
    [
        (("example.test",), "ops-deploy-srs-probe@srs-probe.invalid"),
        (("example.test", "invalid"), "ops-deploy-srs-probe@srs-probe.example"),
        (("example.test", "srs-probe.invalid", ".example"), "ops-deploy-srs-probe@srs-probe.test"),
        (("example.test", "INVALID", "example", "test"), "ops-deploy-srs-probe@srs-probe.localhost"),
    ],
)
def test_probe_sender_avoids_every_exclusion(excluded: tuple[str, ...], sender: str) -> None:
    assert probe_sender(config(srs_exclude_domains=excluded), excluded) == sender


def test_2x_socketmap_check_probes_outside_the_exclusions() -> None:
    result = run(config(srs_exclude_domains=("example.test", "example.org", "invalid")), host(V2))
    check = [command for command in result.executed_commands if "/var/spool/postfix/srs" in command]
    assert len(check) == 1
    assert "ops-deploy-srs-probe@srs-probe.example" in check[0]
    assert "srs-probe.invalid" not in check[0]


def test_2x_refuses_when_no_probe_domain_is_left() -> None:
    cfg = config(srs_exclude_domains=("example.test", "invalid", "example", "test", "localhost"))
    with pytest.raises(ValueError, match="probe domain"):
        run_deploy_fake(relay.deploy_mail_relay, cfg, SECRETS, responses=host(V2))
    # postsrsd 1.x has no such check and keeps accepting it.
    assert run_deploy_fake(relay.deploy_mail_relay, cfg, SECRETS, responses=host(V1)).succeeded


class SocketmapServer:
    """A postsrsd-like socketmap peer: netstring replies, connection kept open."""

    def __init__(self, path: str, srs_domain: str, own: str) -> None:
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(path)
        self.server.listen()
        self.srs_domain, self.own = srs_domain, own
        threading.Thread(target=self.serve, daemon=True).start()

    def answer(self, request: str) -> str:
        name, _, key = request.partition(" ")
        local, _, domain = key.rpartition("@")
        if name == "forward" and not (domain == self.own or domain.endswith("." + self.own)):
            return f"OK SRS0=abcd=XY={domain}={local}@{self.srs_domain}"
        if name == "reverse" and key.startswith("SRS0=abcd=XY="):
            original_domain, _, original_local = key.split("@")[0].removeprefix("SRS0=abcd=XY=").partition("=")
            return f"OK {original_local}@{original_domain}"
        return "NOTFOUND "

    def serve(self) -> None:
        while True:
            connection, _ = self.server.accept()
            data = connection.recv(4096).decode()
            length, _, rest = data.partition(":")
            reply = self.answer(rest[: int(length)]).encode()
            connection.sendall(str(len(reply)).encode() + b":" + reply + b",")
            # keep-alive: the connection stays open; the client must not wait for EOF.


@pytest.mark.parametrize(("srs_domain", "ok"), [("example.test", True), ("other.test", False)])
def test_socketmap_check_round_trip(srs_domain: str, ok: bool) -> None:
    with tempfile.TemporaryDirectory(prefix="srs") as directory:
        path = str(Path(directory) / "s")
        SocketmapServer(path, "example.test", "example.org")
        argv = [sys.executable, "-I", "-c", _SOCKETMAP_CHECK, path, PROBE_SENDER, srs_domain, "example.org"]
        done = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    assert (done.returncode == 0) == ok, done.stderr
    assert ("round trip failed" in done.stderr) != ok


def test_socketmap_check_refuses_rewriting_own_domain() -> None:
    with tempfile.TemporaryDirectory(prefix="srs") as directory:
        path = str(Path(directory) / "s")
        SocketmapServer(path, "example.test", "unrelated.test")
        argv = [sys.executable, "-I", "-c", _SOCKETMAP_CHECK, path, PROBE_SENDER, "example.test", "example.org"]
        done = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    assert done.returncode == 1
    assert "round trip failed" in done.stderr
