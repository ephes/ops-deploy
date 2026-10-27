#!/usr/bin/env python3
"""Dynamic DNS updater with pluggable provider backends.

Deployed by the ops-library ``dns_deploy`` role. Reads non-secret settings from a
JSON config file (``--config``) and credentials from the environment.

For every configured record (name x A/AAAA) it compares the provider's current
value with the detected WAN address, writes it when it differs and reads it back.
Any non-2xx API answer, an unreadable address or a read-back mismatch fails the
run (exit 1). After the provider step it asks the zone's authoritative
nameservers what the public sees and records that, plus how long a mismatch has
lasted, in a status JSON file for monitoring.

Several providers can be written in one run (``providers`` list), e.g. the old
and the new DNS host while a delegation moves; the run fails if any of them fails.

Secrets are never logged: request headers and bodies are not written anywhere,
and the RFC 2136 TSIG secret reaches nsupdate on stdin, never in argv or a file.

Adding a backend: subclass ``Backend``, implement ``get(name, rtype)`` (returns a
sorted list of values, empty when the record does not exist) and
``set(name, rtype, values)``, then register it in ``BACKENDS``.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, Optional

HttpFunc = Callable[[str, str, dict, Optional[bytes]], "tuple[int, bytes]"]
# (argv, stdin text) -> (exit code, combined output)
CommandFunc = Callable[[list, Optional[str]], "tuple[int, str]"]
ResolveFunc = Callable[[str, str, Optional[str]], "Optional[list[str]]"]

USER_AGENT = "ops-library-ddns/2"
HTTP_TIMEOUT = 20


class DdnsError(Exception):
    """A failure that must fail the run."""


def http_request(method: str, url: str, headers: dict, body: Optional[bytes]) -> tuple[int, bytes]:
    request = urllib.request.Request(url, data=body, method=method)
    for key, value in headers.items():
        request.add_header(key, value)
    request.add_header("User-Agent", USER_AGENT)
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as err:
        return err.code, err.read()
    except (urllib.error.URLError, OSError) as err:
        raise DdnsError(f"{method} {redact_url(url)} failed: {err}") from None


def redact_url(url: str) -> str:
    """URLs never carry credentials here; drop any query string anyway."""
    return url.split("?", 1)[0]


def short_body(body: bytes) -> str:
    text = body.decode("utf-8", "replace").strip().replace("\n", " ")
    return text[:300]


def idna_zone(zone: str) -> str:
    return ".".join(
        label if label.isascii() else label.encode("idna").decode("ascii")
        for label in zone.rstrip(".").split(".")
    ).lower()


def fqdn(name: str, zone: str) -> str:
    return zone if name in ("", "@") else f"{name}.{zone}"


class Backend:
    provider = "base"

    def __init__(self, zone: str, ttl: int, settings: dict, env: dict, http: HttpFunc):
        self.zone = zone
        self.ttl = ttl
        self.settings = settings
        self.env = env
        self.http = http

    def get(self, name: str, rtype: str) -> list[str]:
        raise NotImplementedError

    def set(self, name: str, rtype: str, values: list[str]) -> None:
        raise NotImplementedError

    def _require_env(self, key: str) -> str:
        value = self.env.get(key, "").strip()
        if not value:
            raise DdnsError(f"credential {key} is not set in the environment")
        return value


class GandiBackend(Backend):
    """Gandi LiveDNS v5. Auth: Personal Access Token (Bearer) or legacy API key (Apikey)."""

    provider = "gandi"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        scheme = str(self.settings.get("auth_scheme", "bearer")).lower()
        if scheme not in ("bearer", "apikey"):
            raise DdnsError(f"unsupported Gandi auth_scheme {scheme!r} (bearer|apikey)")
        self.scheme = "Bearer" if scheme == "bearer" else "Apikey"
        self.token = self._require_env("GANDI_API_TOKEN")
        self.base = self.settings.get("api_base", "https://api.gandi.net/v5/livedns").rstrip("/")

    def _url(self, name: str, rtype: str) -> str:
        return (
            f"{self.base}/domains/{urllib.parse.quote(self.zone)}/records/"
            f"{urllib.parse.quote(name, safe='*.@')}/{rtype}"
        )

    def _headers(self) -> dict:
        return {"Authorization": f"{self.scheme} {self.token}", "Accept": "application/json"}

    def get(self, name: str, rtype: str) -> list[str]:
        status, body = self.http("GET", self._url(name, rtype), self._headers(), None)
        if status == 404:
            return []
        if not 200 <= status < 300:
            raise DdnsError(f"gandi GET {name} {rtype}: HTTP {status} {short_body(body)}")
        try:
            values = json.loads(body).get("rrset_values", [])
        except (ValueError, AttributeError):
            raise DdnsError(f"gandi GET {name} {rtype}: unparseable answer") from None
        return sorted(str(v) for v in values)

    def set(self, name: str, rtype: str, values: list[str]) -> None:
        headers = dict(self._headers(), **{"Content-Type": "application/json"})
        payload = json.dumps({"rrset_ttl": self.ttl, "rrset_values": values}).encode()
        status, body = self.http("PUT", self._url(name, rtype), headers, payload)
        if not 200 <= status < 300:
            raise DdnsError(f"gandi PUT {name} {rtype}: HTTP {status} {short_body(body)}")


def run_command(argv: list, stdin: Optional[str]) -> tuple[int, str]:
    try:
        result = subprocess.run(argv, input=stdin, capture_output=True, text=True,
                                timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired) as err:
        return 127, str(err)
    return result.returncode, (result.stdout + result.stderr).strip()


class Rfc2136Backend(Backend):
    """RFC 2136 DNS UPDATE signed with TSIG (nsupdate), read back from the same server.

    Settings: server (address or name of the primary), port (53), key_name,
    key_algorithm (hmac-sha256), update_zone (optional; nsupdate finds the zone by
    SOA otherwise). Credential: DDNS_TSIG_SECRET (base64) in the environment.
    """

    provider = "rfc2136"
    algorithms = ("hmac-sha256", "hmac-sha384", "hmac-sha512")
    command: CommandFunc = staticmethod(run_command)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.server = str(self.settings.get("server", "")).strip()
        self.port = int(self.settings.get("port", 53))
        self.key_name = str(self.settings.get("key_name", "")).strip()
        self.algorithm = str(self.settings.get("key_algorithm", "hmac-sha256")).lower()
        self.update_zone = str(self.settings.get("update_zone", "") or "").strip()
        if not self.server or not self.key_name:
            raise DdnsError("rfc2136: settings server and key_name are required")
        if self.algorithm not in self.algorithms:
            raise DdnsError(f"rfc2136: unsupported key_algorithm {self.algorithm!r}")
        for value in (self.server, self.key_name, self.update_zone):
            if any(ch.isspace() for ch in value):
                raise DdnsError("rfc2136: settings must not contain whitespace")
        self.secret = self._require_env("DDNS_TSIG_SECRET")
        if any(ch.isspace() for ch in self.secret):
            raise DdnsError("rfc2136: DDNS_TSIG_SECRET must be a single base64 token")

    def _fqdn(self, name: str) -> str:
        return fqdn(name, self.zone) + "."

    def get(self, name: str, rtype: str) -> list[str]:
        argv = ["dig", "+norecurse", "+short", "+time=3", "+tries=2", "-p", str(self.port),
                f"@{self.server}", self._fqdn(name), rtype]
        code, output = self.command(argv, None)
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        if code != 0 or any(line.startswith(";") for line in lines):
            raise DdnsError(f"rfc2136 query {name} {rtype} @{self.server}: {short_body(output.encode())}")
        # A wildcard owner is queried literally and answers with its own record set.
        return sorted(line.rstrip(".") for line in lines if line.split()[0] != "CNAME")

    def set(self, name: str, rtype: str, values: list[str]) -> None:
        owner = self._fqdn(name)
        script = [f"server {self.server} {self.port}"]
        if self.update_zone:
            script.append(f"zone {self.update_zone}")
        script.append(f"key {self.algorithm}:{self.key_name} {self.secret}")
        script.append(f"update delete {owner} {rtype}")
        script += [f"update add {owner} {self.ttl} {rtype} {value}" for value in values]
        script.append("send")
        code, output = self.command(["nsupdate", "-v"], "\n".join(script) + "\n")
        if code != 0:
            output = output.replace(self.secret, "<redacted>")
            raise DdnsError(f"rfc2136 update {name} {rtype}: nsupdate exit {code}: "
                            f"{short_body(output.encode())}")


BACKENDS = {GandiBackend.provider: GandiBackend, Rfc2136Backend.provider: Rfc2136Backend}


def detect_ip(url: str, version: int, http: HttpFunc) -> str:
    status, body = http("GET", url, {}, None)
    if not 200 <= status < 300:
        raise DdnsError(f"IPv{version} detection via {url}: HTTP {status}")
    text = body.decode("ascii", "replace").strip()
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        raise DdnsError(f"IPv{version} detection via {url}: not an address") from None
    if address.version != version or not address.is_global:
        raise DdnsError(f"IPv{version} detection via {url}: unusable address {address}")
    return str(address)


def dig(name: str, rtype: str, server: Optional[str]) -> Optional[list[str]]:
    """Query with dig. Returns sorted answers, or None when the query failed."""
    cmd = ["dig", "+short", "+time=3", "+tries=2"]
    if server:
        cmd += ["+norecurse", f"@{server}"]
    cmd += [name, rtype]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if any(line.startswith(";") for line in lines):
        return None
    return sorted(line.rstrip(".") for line in lines)


class Logger:
    def __init__(self, path: Optional[str], max_bytes: int):
        self.path = path
        self.max_bytes = max_bytes

    def __call__(self, message: str) -> None:
        line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}"
        print(line, flush=True)
        if not self.path:
            return
        try:
            if os.path.exists(self.path) and os.path.getsize(self.path) > self.max_bytes:
                os.replace(self.path, self.path + ".old")
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        except OSError as err:
            print(f"log file {self.path} not writable: {err}", file=sys.stderr)


def load_previous_status(path: Optional[str]) -> dict:
    if not path:
        return {}
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def write_status(path: Optional[str], status: dict) -> None:
    if not path:
        return
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(status, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def run(config: dict, env: dict, http: HttpFunc = http_request, resolve: ResolveFunc = dig,
        log: Callable[[str], None] = print, now: Callable[[], float] = time.time) -> tuple[int, dict]:
    providers = list(config.get("providers") or [config.get("provider", "gandi")])
    provider = providers[0]
    zone = idna_zone(config["zone"])
    names = list(config.get("names", []))
    ttl = int(config.get("ttl", 300))
    families = {4: bool(config.get("ipv4", True)), 6: bool(config.get("ipv6", True))}
    errors: list[str] = []
    records: dict[str, dict] = {}
    wan: dict[str, Optional[str]] = {"ipv4": None, "ipv6": None}

    provider_label = (f"provider={provider}" if len(providers) == 1
                      else f"providers={','.join(providers)}")
    log(f"DDNS run: {provider_label} zone={zone} names={','.join(names)}")

    backends: dict[str, Optional[Backend]] = {}
    for name_ in providers:
        backends[name_] = None
        try:
            backend_cls = BACKENDS.get(name_)
            if backend_cls is None:
                raise DdnsError(f"unknown provider {name_!r} (known: {', '.join(sorted(BACKENDS))})")
            backends[name_] = backend_cls(zone, ttl, config.get(name_, {}), env, http)
        except DdnsError as err:
            errors.append(str(err))
            log(f"ERROR: {err}")

    sources = config.get("ip_sources", {})
    for version, enabled in families.items():
        if not enabled:
            continue
        try:
            wan[f"ipv{version}"] = detect_ip(
                sources.get(f"ipv{version}", f"https://ipv{version}.icanhazip.com"), version, http
            )
            log(f"WAN IPv{version}: {wan[f'ipv{version}']}")
        except DdnsError as err:
            errors.append(str(err))
            log(f"ERROR: {err}")

    targets = [(4, "A"), (6, "AAAA")]
    for name in names:
        for version, rtype in targets:
            if not families[version]:
                continue
            key = f"{name}_{rtype}"
            desired = wan[f"ipv{version}"]
            record = {"name": fqdn(name, zone), "type": rtype, "desired": desired,
                      "provider_values": None, "action": "skipped", "public_values": None,
                      "public_ok": False, "providers": {}}
            records[key] = record
            for provider_name, backend in backends.items():
                tag = f"{provider_name} " if len(backends) > 1 else ""
                result = {"values": None, "action": "skipped"}
                record["providers"][provider_name] = result
                if backend is None or desired is None:
                    continue
                try:
                    current = backend.get(name, rtype)
                    result["values"] = current
                    if current == [desired]:
                        result["action"] = "unchanged"
                        log(f"unchanged {tag}{rtype} {record['name']} = {desired}")
                    else:
                        backend.set(name, rtype, [desired])
                        after = backend.get(name, rtype)
                        result["values"] = after
                        if after != [desired]:
                            raise DdnsError(
                                f"{tag}{rtype} {record['name']}: read-back {after} != [{desired}]"
                            )
                        result["action"] = "updated"
                        log(f"updated {tag}{rtype} {record['name']}: "
                            f"{current or '[]'} -> {desired}")
                except DdnsError as err:
                    result["action"] = "failed"
                    errors.append(str(err))
                    log(f"ERROR: {err}")
            # Summary fields keep their single-provider meaning: the first provider's
            # values, and the worst action across providers.
            actions = [r["action"] for r in record["providers"].values()]
            record["provider_values"] = record["providers"][provider]["values"]
            for action in ("failed", "skipped", "updated", "unchanged"):
                if action in actions:
                    record["action"] = action
                    break

    # Public view: ask the authoritative nameservers directly. Without an explicit
    # list, use the NS set of the closest enclosing zone that has one, so a record
    # in a delegated child zone (home.example.com) is checked at the child's servers
    # once the delegation exists, and at the parent's servers before that.
    configured = list(config.get("verify_nameservers") or [])
    ns_cache: dict[str, list[str]] = {}

    def nameservers_for(owner: str) -> list[str]:
        if configured:
            return configured
        labels = owner.split(".")
        if labels[0] == "*":
            labels = labels[1:]
        candidates = [".".join(labels[i:]) for i in range(len(labels))]
        candidates = [c for c in candidates if c == zone or c.endswith("." + zone)] or [zone]
        for candidate in candidates:
            if candidate not in ns_cache:
                ns_cache[candidate] = resolve(candidate, "NS", None) or []
            if ns_cache[candidate]:
                return ns_cache[candidate]
        return []

    used_nameservers: list[str] = []
    for record in records.values():
        if record["desired"] is None:
            continue
        nameservers = nameservers_for(record["name"])
        used_nameservers += [ns for ns in nameservers if ns not in used_nameservers]
        answers = [resolve(record["name"], record["type"], ns) for ns in nameservers]
        seen = [a for a in answers if a is not None]
        record["public_values"] = seen[0] if seen else None
        record["public_ok"] = bool(seen) and len(seen) == len(answers) and all(
            a == [record["desired"]] for a in seen
        )
        if not record["public_ok"]:
            log(f"public {record['type']} {record['name']} = {seen or 'no answer'}"
                f" (want {record['desired']}) via {','.join(nameservers) or 'no nameservers'}")

    timestamp = int(now())
    previous = load_previous_status(config.get("status_path"))
    prev_summary = previous.get("summary", {}) if isinstance(previous.get("summary"), dict) else {}
    public_ok = bool(records) and all(r["public_ok"] for r in records.values())
    if public_ok:
        mismatch_since = None
    else:
        mismatch_since = prev_summary.get("public_mismatch_since_epoch") or timestamp
    run_ok = not errors
    consecutive = 0 if run_ok else int(prev_summary.get("consecutive_failures", 0)) + 1
    last_success = timestamp if run_ok else prev_summary.get("last_success_epoch")

    status = {
        "provider": provider,
        "providers": providers,
        "zone": zone,
        "wan": wan,
        "records": records,
        "errors": errors,
        "nameservers": used_nameservers or configured or nameservers_for(zone),
        "summary": {
            "run_ok": run_ok,
            "finished_at_epoch": timestamp,
            "last_success_epoch": last_success,
            "consecutive_failures": consecutive,
            "records_total": len(records),
            "records_updated": sum(1 for r in records.values() if r["action"] == "updated"),
            "records_public_ok": sum(1 for r in records.values() if r["public_ok"]),
            "public_ok": public_ok,
            "public_mismatch_since_epoch": mismatch_since,
            "public_mismatch_seconds": 0 if mismatch_since is None else timestamp - int(mismatch_since),
        },
    }
    summary = status["summary"]
    log(
        f"DDNS result: run_ok={run_ok} updated={summary['records_updated']} "
        f"public_ok={summary['records_public_ok']}/{summary['records_total']} errors={len(errors)}"
    )
    return (0 if run_ok else 1), status


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", required=True, help="JSON settings file")
    args = parser.parse_args(argv)
    with open(args.config, encoding="utf-8") as handle:
        config = json.load(handle)
    log = Logger(config.get("log_file"), int(config.get("log_max_bytes", 10 * 1048576)))
    try:
        code, status = run(config, dict(os.environ), http=http_request, resolve=dig, log=log)
    except Exception as err:  # noqa: BLE001 - any crash must fail the unit loudly
        log(f"ERROR: unexpected {type(err).__name__}: {err}")
        return 1
    try:
        write_status(config.get("status_path"), status)
    except OSError as err:
        log(f"ERROR: cannot write status file: {err}")
        return 1
    return code


if __name__ == "__main__":
    sys.exit(main())
