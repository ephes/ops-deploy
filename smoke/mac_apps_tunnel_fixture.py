"""Owned GUI tunnel with real high-port SSH, TLS/SNI, identity repair and repeats."""

from __future__ import annotations

import grp
import hashlib
import json
import os
import pwd
import shutil
import ssl
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any

from mac_apps_owned import OwnedMac, command, port

from ops_deploy.services.macos_ssh_tunnel import MacosSshTunnelConfig, deploy_macos_ssh_tunnel
from ops_deploy.testing import run_deploy_ssh


def snapshot(root: Path) -> dict[str, tuple[int, ...]]:
    return {
        str(path.relative_to(root)): (
            s.st_dev,
            s.st_ino,
            s.st_mode,
            s.st_uid,
            s.st_gid,
            s.st_size,
            s.st_mtime_ns,
            s.st_ctime_ns,
        )
        for path in (root, *root.rglob("*"))
        for s in [path.lstat()]
    }


def owner_main(path: Path) -> None:
    data = json.loads(path.read_text())
    assert os.geteuid() == pwd.getpwnam("runner").pw_uid
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    home = Path.home()
    root = home / (".ops-mac-tunnel-" + data["suffix"])
    assert not root.exists()
    root.mkdir(mode=0o700)
    known = root / "known-hosts"
    known.write_text(data["known_host"])
    label = "com.example.ops-mac-apps.tunnel." + data["suffix"]
    cfg = MacosSshTunnelConfig(
        owner="runner",
        home=PurePosixPath(home),
        host="127.0.0.1",
        user=data["relay_user"],
        target="localhost",
        target_port=data["https_port"],
        local_port=port(),
        ssh_port=data["ssh_port"],
        label=label,
        directory=PurePosixPath(root / "application"),
        plist=PurePosixPath(root / "agent.plist"),
        log_directory=PurePosixPath(root / "logs"),
        identity=PurePosixPath(root / "identity"),
        known_hosts=PurePosixPath(known),
        python=PurePosixPath("/usr/bin/python3"),
        manage_identity=True,
        identity_group=grp.getgrgid(os.getgid()).gr_name,
        identity_comment="owned-mac-tunnel-fixture",
        relay_home=PurePosixPath(data["relay_home"]),
        ignore_ssl_errors=False,
        ca_file=PurePosixPath(data["ca_file"]),
    )
    directory, identity, plist = cfg.directory, cfg.identity, cfg.plist
    assert directory is not None
    assert identity is not None
    assert plist is not None
    service = "gui/" + str(os.getuid()) + "/" + label
    proof: dict[str, Any] = {
        "status": "failed",
        "repeats": {},
        "fixture": "tunnel-owner",
        "implementation": os.environ["IMPLEMENTATION_SHA"],
    }
    failure: BaseException | None = None

    def deploy(config: MacosSshTunnelConfig, *, succeeds: bool = True) -> list[str]:
        result = run_deploy_ssh(deploy_macos_ssh_tunnel, config, host_name="@local", host_data={})
        assert result.succeeded is succeeds, str(result.error)
        return result.mutating_changed_ops

    def lifecycle(action: str, *arguments: str) -> None:
        command(
            "/usr/bin/python3",
            str(directory / "tunnel_control.py"),
            "--config",
            str(directory / "config.json"),
            action,
            *arguments,
        )

    def no_op(config: MacosSshTunnelConfig, name: str) -> None:
        before = snapshot(root)
        changes = deploy(config)
        assert changes == []
        assert snapshot(root) == before
        proof["repeats"][name] = changes

    try:
        command("/bin/launchctl", "print", "gui/" + str(os.getuid()))
        proof["first_changes"] = deploy(cfg)
        assert proof["first_changes"]
        assert command("/bin/launchctl", "print", service, check=False).returncode != 0
        assert (
            '"' + label + '" => disabled'
            in command("/bin/launchctl", "print-disabled", "gui/" + str(os.getuid())).stdout
        )
        effective = command("/usr/bin/ssh", "-G", "-F", str(directory / "ssh_config"), "managed-tunnel").stdout
        assert "\nport " + str(data["ssh_port"]) + "\n" in "\n" + effective
        proof["effective_ssh_port"] = data["ssh_port"]
        no_op(cfg, "fresh-stopped")
        lifecycle("start")
        for _ in range(100):
            try:
                lifecycle("check", "--transport-only")
                break
            except subprocess.CalledProcessError:
                time.sleep(0.2)
        else:
            raise AssertionError("owned GUI tunnel did not carry verified HTTPS")
        status = command("/bin/launchctl", "print", service).stdout
        import re

        match = re.search(r"^\s*pid = ([1-9][0-9]*)$", status, re.M)
        assert match is not None
        first_pid = match[1]
        # A genuine unsafe identity remains a refusal, and must not stop the
        # already running owned tunnel or rotate its private key.
        key = Path(identity)
        key_before = hashlib.sha256(key.read_bytes()).hexdigest()
        key.chmod(0o644)
        protected = snapshot(root)
        deploy(cfg, succeeds=False)
        assert snapshot(root) == protected
        assert "pid = " + first_pid in command("/bin/launchctl", "print", service).stdout
        key.chmod(0o600)
        assert hashlib.sha256(key.read_bytes()).hexdigest() == key_before
        proof["unsafe_identity_refused_running_job_preserved"] = True
        proof["loaded_enabled_install_stopped_changes"] = deploy(cfg)
        assert proof["loaded_enabled_install_stopped_changes"]
        assert command("/bin/launchctl", "print", service, check=False).returncode != 0
        no_op(cfg, "after-legitimate-stop")
        root.chmod(0o750)
        proof["safe_parent_mode_repair_changes"] = deploy(cfg)
        assert proof["safe_parent_mode_repair_changes"]
        assert root.stat().st_mode & 0o777 == 0o700
        assert hashlib.sha256(key.read_bytes()).hexdigest() == key_before
        no_op(cfg, "parent-mode-repair")
        absent = cfg.model_copy(update={"state": "absent"})
        proof["absent_changes"] = deploy(absent)
        assert key.exists()
        assert key.with_suffix(".pub").exists()
        assert not Path(plist).exists()
        no_op(absent, "absent-retention")
        proof["status"] = "passed"
    except BaseException as error:
        failure = error
        proof["failure_type"] = type(error).__name__
    finally:
        command("/bin/launchctl", "disable", service, check=False)
        command("/bin/launchctl", "bootout", service, check=False)
        proof["job_unloaded"] = command("/bin/launchctl", "print", service, check=False).returncode != 0
        try:
            shutil.rmtree(root)
        except OSError as error:
            proof["cleanup_error_type"] = type(error).__name__
        proof["cleanup"] = proof["job_unloaded"] and not root.exists()
        proof["limitations"] = ["The unique disabled GUI-label override remains until this disposable VM is destroyed."]
        if failure is not None or not proof["cleanup"]:
            proof["status"] = "failed"
        Path(data["owner_proof"]).write_text(json.dumps(proof, indent=2) + "\n")
    if failure is not None:
        raise failure
    assert proof["cleanup"]


def main() -> None:
    if len(sys.argv) == 3 and sys.argv[1] == "--owner":
        owner_main(Path(sys.argv[2]))
        return
    owned = OwnedMac("tunnel")
    failure: BaseException | None = None
    backend: ThreadingHTTPServer | None = None
    server_thread: threading.Thread | None = None
    try:
        owned.verify_implementation()
        relay, relay_home = owned.create_existing_user("relay")
        ssh_dir = relay_home / ".ssh"
        ssh_dir.mkdir(mode=0o700)
        relay_uid = pwd.getpwnam(relay).pw_uid
        os.chown(ssh_dir, relay_uid, 20)
        actor = pwd.getpwnam("runner")
        control_key, host_key = owned.root / "control-key", owned.root / "host-key"
        for key in [control_key, host_key]:
            command("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key))
        os.chown(control_key, actor.pw_uid, actor.pw_gid)
        authorized = ssh_dir / "authorized_keys"
        original = "restrict " + control_key.with_suffix(".pub").read_text()
        authorized.write_text(original)
        authorized.chmod(0o600)
        os.chown(authorized, relay_uid, 20)
        ssh_port = port()
        ssh_config = owned.root / "relay-sshd.conf"
        ssh_config.write_text(
            f"Port {ssh_port}\nListenAddress 127.0.0.1\nHostKey {host_key}\n"
            f"PidFile {owned.root}/relay-sshd.pid\nAuthorizedKeysFile {authorized}\n"
            f"AllowUsers {relay}\nPermitRootLogin no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n"
            "UsePAM no\nAllowTcpForwarding local\nStrictModes yes\nLogLevel ERROR\n"
        )
        command("/usr/sbin/sshd", "-t", "-f", str(ssh_config))
        owned.spawn(["/usr/sbin/sshd", "-D", "-e", "-f", str(ssh_config)], owned.evidence / "tunnel-owned-sshd.log")
        agent_dir = owned.root / "agent"
        agent_dir.mkdir(mode=0o700)
        os.chown(agent_dir, actor.pw_uid, actor.pw_gid)
        agent_socket = agent_dir / "socket"
        owned.spawn(["/usr/bin/sudo", "-H", "-u", "runner", "--", "/usr/bin/ssh-agent", "-D", "-a", str(agent_socket)])
        for _ in range(50):
            if agent_socket.exists():
                break
            time.sleep(0.1)
        assert agent_socket.exists()
        command(
            "/usr/bin/sudo",
            "-H",
            "-u",
            "runner",
            "--",
            "/usr/bin/env",
            "SSH_AUTH_SOCK=" + str(agent_socket),
            "/usr/bin/ssh-add",
            str(control_key),
        )
        certificate, tls_key, openssl_config = (
            owned.root / "localhost.pem",
            owned.root / "localhost.key",
            owned.root / "certificate.cnf",
        )
        openssl_config.write_text(
            "[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=v3\n[dn]\nCN=localhost\n[v3]\nsubjectAltName=DNS:localhost\nbasicConstraints=critical,CA:true\nkeyUsage=critical,digitalSignature,keyEncipherment,keyCertSign\n"
        )
        command(
            "/usr/bin/openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-keyout",
            str(tls_key),
            "-out",
            str(certificate),
            "-config",
            str(openssl_config),
        )
        certificate.chmod(0o644)
        sni: list[str | None] = []

        class Health(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"owned TLS fixture")

            def log_message(self, *args: Any) -> None:
                pass

        backend = ThreadingHTTPServer(("127.0.0.1", 0), Health)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, tls_key)
        context.set_servername_callback(lambda _socket, name, _context: sni.append(name))
        backend.socket = context.wrap_socket(backend.socket, server_side=True)
        server_thread = threading.Thread(target=backend.serve_forever, daemon=True)
        server_thread.start()
        # The unprivileged owner child creates and removes this GUI job; the
        # root fixture also boots it out if the child dies before its cleanup.
        owned.adopt_gui_label(actor.pw_uid, "com.example.ops-mac-apps.tunnel." + owned.suffix)
        child_proof = owned.evidence / "tunnel-owner-proof.json"
        os.chown(owned.evidence, actor.pw_uid, actor.pw_gid)
        config_file = owned.root / "owner-input.json"
        config_file.write_text(
            json.dumps(
                {
                    "suffix": owned.suffix,
                    "relay_user": relay,
                    "relay_home": str(relay_home),
                    "ssh_port": ssh_port,
                    "https_port": backend.server_port,
                    "ca_file": str(certificate),
                    "owner_proof": str(child_proof),
                    "known_host": "[127.0.0.1]:"
                    + str(ssh_port)
                    + " "
                    + " ".join(host_key.with_suffix(".pub").read_text().split()[:2])
                    + "\n",
                }
            )
        )
        result = command(
            "/usr/bin/sudo",
            "-H",
            "-u",
            "runner",
            "--",
            "/usr/bin/env",
            "SSH_AUTH_SOCK=" + str(agent_socket),
            "IMPLEMENTATION_SHA=" + os.environ["IMPLEMENTATION_SHA"],
            "GITHUB_ACTIONS=true",
            "PYTHONDONTWRITEBYTECODE=1",
            sys.executable,
            str(Path(__file__).resolve()),
            "--owner",
            str(config_file),
            check=False,
        )
        owned.report["owner_process_returncode"] = result.returncode
        (owned.evidence / "tunnel-owner-process.log").write_text(result.stdout + result.stderr)
        assert child_proof.exists()
        owned.report["owner"] = json.loads(child_proof.read_text())
        assert result.returncode == 0
        assert owned.report["owner"]["status"] == "passed"
        assert "localhost" in sni
        lines = authorized.read_text().splitlines()
        assert lines[0] == original.strip()
        assert len(lines) == 2
        assert lines[1].startswith(
            'restrict,port-forwarding,permitopen="localhost:'
            + str(backend.server_port)
            + '",command="/usr/bin/false" ssh-ed25519 '
        )
        owned.report["actual_tls_sni"] = "localhost"
        owned.report["relay_scope"] = (
            "original unprivileged owner; original control line retained; one restricted public line added"
        )
        owned.report["status"] = "passed"
    except BaseException as error:
        failure = error
    finally:
        if backend is not None:
            backend.shutdown()
            backend.server_close()
        if server_thread is not None:
            server_thread.join(timeout=5)
        failure = owned.finish(failure)
    if failure is not None:
        raise failure
    print("owned ARM GUI/high-port SSH/TLS/identity/stop/fault/repeat passed; fixture removed")


if __name__ == "__main__":
    main()
