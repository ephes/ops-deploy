#!/usr/bin/python3
"""Read-only ingress and static-policy acceptance for a proxy-only update."""

import argparse
import concurrent.futures
import hashlib
import json
import socket
import ssl
import subprocess
import time
import tomllib
from pathlib import Path


def observe(probe):
    args = [
        "curl",
        "--silent",
        "--show-error",
        "--output",
        "/dev/null",
        "--write-out",
        "%{http_code}",
        "--max-time",
        "10",
        "--resolve",
        f"{probe['host']}:{probe['port']}:{probe['address']}",
        f"{probe['scheme']}://{probe['host']}:{probe['port']}{probe.get('path', '/')}",
    ]
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=12, check=False
        )
    except subprocess.TimeoutExpired:
        return {"status": "", "exit": 28}
    return {"status": result.stdout, "exit": result.returncode}


def fingerprint(probe):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with (
        socket.create_connection(
            (probe["address"], probe["port"]), timeout=10
        ) as connection,
        context.wrap_socket(
            connection, server_hostname=probe["host"]
        ) as connection_tls,
    ):
        certificate = connection_tls.getpeercert(binary_form=True)
        if not certificate:
            raise RuntimeError("Missing TLS certificate")
        return hashlib.sha256(certificate).hexdigest()


def observe_with_fingerprint(probe):
    result = observe(probe)
    if probe["scheme"] == "https":
        try:
            result["tls_sha256"] = fingerprint(probe)
        except (OSError, RuntimeError) as exc:
            result.update(tls_sha256=None, tls_error=type(exc).__name__)
    return result


def acceptable(before, after):
    if before.get("tls_sha256") != after.get("tls_sha256"):
        return False
    if before == after:
        return True
    # A formerly unavailable backend recovering is not an ingress regression.
    # Authentication failures and redirects retain their exact expected status.
    return (
        before["exit"] == after["exit"] == 0
        and before["status"].startswith("5")
        and after["status"].startswith("2")
    )


def tree(root):
    return {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def validate_static_policy(static, expected_entrypoints, mode):
    entries = static["entryPoints"]
    if set(entries) != set(expected_entrypoints) or any(
        entry.get("http", {}).get("aliasHeadersStrategy") != "delete"
        for entry in entries.values()
    ):
        raise RuntimeError("Incomplete header-alias policy")
    if mode == "metrics_bind" and (
        entries.get("traefik", {}).get("address") != "127.0.0.1:8080"
        or static.get("metrics", {}).get("prometheus", {}).get("entryPoint")
        != "traefik"
    ):
        raise RuntimeError("Metrics entrypoint is not bound to loopback")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode", choices=["capture", "health", "alias", "metrics_bind", "cleanup"]
    )
    parser.add_argument("config", type=Path)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    if not isinstance(config.get("probes"), list) or not config["probes"]:
        raise ValueError("At least one explicit ingress probe is required")
    observer = (
        observe_with_fingerprint if config.get("tls_fingerprints") is True else observe
    )
    if (
        config.get("tls_fingerprints") is True
        and args.mode
        not in {
            "capture",
            "cleanup",
        }
        and any(
            p["scheme"] == "https" and "tls_sha256" not in b
            for p, b in zip(config["probes"], config["observations"], strict=True)
        )
    ):
        raise ValueError("Missing captured TLS fingerprint baseline")
    dynamic = Path("/etc/traefik/dynamic")
    if args.mode == "capture":
        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            observed = list(pool.map(observer, config["probes"]))
        print(json.dumps({"observations": observed, "dynamic": tree(dynamic)}))
        return
    if tree(dynamic) != config["dynamic"]:
        raise RuntimeError("Permanent routing changed during the update")
    if args.mode == "cleanup":
        # This probe creates no live route, backend, unit or timer to remove.
        print(
            json.dumps({"cleanup": "no temporary resources", "dynamic_verified": True})
        )
        return
    if args.mode in {"alias", "metrics_bind"}:
        static = tomllib.loads(Path("/etc/traefik/traefik.toml").read_text())
        validate_static_policy(static, config["entrypoints"], args.mode)
    for attempt in range(5):
        with concurrent.futures.ThreadPoolExecutor(8) as pool:
            actual = list(pool.map(observer, config["probes"]))
        failures = [
            p["host"]
            for p, before, after in zip(
                config["probes"], config["observations"], actual, strict=True
            )
            if not acceptable(before, after)
        ]
        if not failures:
            print(
                json.dumps({"ingress_checks": len(actual), "baseline_preserved": True})
            )
            return
        if attempt < 4:
            time.sleep(2)
    raise RuntimeError("Ingress changed for: " + ", ".join(failures))


if __name__ == "__main__":
    main()
