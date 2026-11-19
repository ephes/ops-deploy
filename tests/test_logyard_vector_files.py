"""The Logyard Vector file pipelines, run through ``vector test``.

Covers the line parsers (Traefik JSON and common log format, PostgreSQL,
fail2ban, Echoport, plain), what each one leaves out, which Traefik requests
skip sampling, the redaction of query values, token-like path segments,
bearer tokens and URL passwords (also on journald lines), configured drop
patterns and floors. Skipped where no ``vector`` binary is installed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.services.logyard import vector
from tests.logyard_fixtures import vector_config

VECTOR = shutil.which("vector")

pytestmark = pytest.mark.skipif(VECTOR is None, reason="no vector binary")

SOURCES: list[dict[str, Any]] = [
    {"service": "traefik-access", "paths": ["/var/log/traefik/access.log"], "kind": "traefik", "sample_rate": 100},
    {"service": "traefik-clf", "paths": ["/var/log/traefik/clf.log"], "kind": "traefik", "slow_ms": 2000},
    {"service": "postgresql", "paths": ["/var/log/postgresql/postgresql-17-main.log"], "kind": "postgres"},
    {"service": "fail2ban", "paths": ["/var/log/fail2ban.log"], "kind": "fail2ban"},
    {"service": "echoport-scheduler", "paths": ["/home/echoport/logs/scheduler.log"], "kind": "echoport"},
    {
        "service": "voxhelm",
        "paths": ["/private/var/log/voxhelm/voxhelm.log", "/private/var/log/voxhelm/voxhelm.err.log"],
        "drop": [r'"POST /v1/internal/(?:workers/heartbeat|work/claim) HTTP/1\.1" (?:200|204) ', r"^tick$"],
        "fingerprint": "checksum",
    },
    {"service": "quiet-agent", "paths": ["/Users/example/Library/Logs/quiet-agent.log"], "min_level": "warning"},
]
IDS = {source["service"]: vector.source_id(source["service"]) for source in SOURCES}


def fragment() -> str:
    assert VECTOR is not None
    version = subprocess.run([VECTOR, "--version"], capture_output=True, text=True, timeout=30, check=False).stdout
    return vector.render_fragment(vector_config(files=SOURCES), vector.supports_confinement(version, True))


def parse(service: str) -> str:
    return f"logyard_file_{IDS[service]}_parse"


def vrl_checks(expected: dict[str, Any], absent: tuple[str, ...] = ()) -> str:
    checks = [f"assert_eq!(.{key}, {json.dumps(value)})" for key, value in expected.items()]
    checks += [f"assert!(!exists(.{key}))" for key in absent]
    checks += [f"assert!(!contains(encode_json(.), {json.dumps(text)}))" for text in SECRETS]
    return "; ".join(checks)


SECRETS = ("s3cr3t-value", "abcdefghijkl", "hunter2", "aHVudGVyMg", "0123456789abcdefABCDEF")


def kept(name: str, service: str, line: str, expected: dict[str, Any], absent: tuple[str, ...] = ()) -> dict[str, Any]:
    return {
        "name": name,
        "inputs": [
            {"insert_at": parse(service), "type": "log", "log_fields": {"message": line, "file": "/var/log/x.log"}}
        ],
        "outputs": [
            {"extract_from": parse(service), "conditions": [{"type": "vrl", "source": vrl_checks(expected, absent)}]}
        ],
    }


def dropped(name: str, service: str, line: str) -> dict[str, Any]:
    return {
        "name": name,
        "inputs": [{"insert_at": parse(service), "type": "log", "log_fields": {"message": line}}],
        "no_outputs_from": [parse(service)],
    }


def traefik_json(**fields: Any) -> str:
    base: dict[str, Any] = {
        "ClientHost": "192.0.2.10",
        "ClientUsername": "-",
        "DownstreamStatus": 200,
        "Duration": 3_000_000,
        "RequestHost": "rustfs.example.invalid",
        "RequestMethod": "GET",
        "RequestPath": "/bucket/object",
        "RequestProtocol": "HTTP/1.1",
        "RouterName": "rustfs-api-int@file",
        "StartUTC": "2026-11-19T10:00:00Z",
    }
    base.update(fields)
    return json.dumps({key: value for key, value in base.items() if value is not None})


def clf(path: str, status: str = "404", router: str = "-", ms: int = 0) -> str:
    return (
        f'198.51.100.7 - - [19/Nov/2026:17:02:16 +0000] "GET {path} HTTP/1.1" {status} 19 '
        f'"https://ref.example.invalid/?token=s3cr3t-value" "curl/8.9" 12 "{router}" "-" {ms}ms'
    )


TRAEFIK = "traefik-access"
PG = "2026-11-19 17:57:04.249 CET [2964] app@db "
CASES: list[dict[str, Any]] = [
    # Traefik JSON: what skips sampling.
    kept(
        "ordinary rustfs 200 is sampled",
        TRAEFIK,
        traefik_json(),
        {
            "logyard_keep": False,
            "level": "info",
            "http_status": 200,
            "duration_ms": 3,
            "router": "rustfs-api-int@file",
            "service": "traefik-access",
            "source_type": "file",
            "host": "macmini",
            "message": "200 GET rustfs.example.invalid/bucket/object 3ms router=rustfs-api-int@file",
        },
    ),
    kept(
        "routed 404 is kept",
        TRAEFIK,
        traefik_json(DownstreamStatus=404, RouterName="paperless@file"),
        {"logyard_keep": True, "level": "warning"},
    ),
    kept(
        "unrouted 404 is sampled",
        TRAEFIK,
        traefik_json(DownstreamStatus=404, RouterName=None),
        {"logyard_keep": False, "level": "warning", "router": "-"},
    ),
    kept(
        "unrouted 401 is kept",
        TRAEFIK,
        traefik_json(DownstreamStatus=401, RouterName=None),
        {"logyard_keep": True, "level": "warning"},
    ),
    kept("429 is kept", TRAEFIK, traefik_json(DownstreamStatus=429), {"logyard_keep": True}),
    kept("502 is kept", TRAEFIK, traefik_json(DownstreamStatus=502), {"logyard_keep": True, "level": "error"}),
    kept("no response is kept", TRAEFIK, traefik_json(DownstreamStatus=0), {"logyard_keep": True, "level": "error"}),
    kept(
        "client abort of a long poll is sampled",
        TRAEFIK,
        traefik_json(DownstreamStatus=499, Duration=90_000_000_000),
        {"logyard_keep": False, "level": "info", "duration_ms": 90000},
    ),
    kept(
        "slow 200 is kept", TRAEFIK, traefik_json(Duration=1_500_000_000), {"logyard_keep": True, "duration_ms": 1500}
    ),
    # Redaction.
    kept(
        "query values are dropped, names kept",
        TRAEFIK,
        traefik_json(RequestPath="/notifications/hub?access_token=s3cr3t-value&cursor=5&flag"),
        {"http_path": "/notifications/hub", "http_query_keys": ["access_token", "cursor"]},
    ),
    kept(
        "token-like path segments are replaced, slugs and uuids are not",
        TRAEFIK,
        traefik_json(
            RequestPath="/share/0123456789abcdefABCDEF/2026-11-19-logyard-levels-and-tank-wakes/"
            "0f8fad5b-d9cb-469f-a165-70867728950e/internationalization"
        ),
        {
            "http_path": "/share/REDACTED/2026-11-19-logyard-levels-and-tank-wakes/"
            "0f8fad5b-d9cb-469f-a165-70867728950e/internationalization"
        },
    ),
    kept(
        "percent-encoded webhook routes are decoded before the check",
        TRAEFIK,
        traefik_json(RequestPath="/api/%77ebhook/hunter2"),
        {"http_path": "/api/webhook/REDACTED"},
    ),
    kept(
        "a webhook route inside a masked segment still counts",
        TRAEFIK,
        traefik_json(RequestPath="/api%2Fwebhook%2Fx%3Fy=1/abc"),
        {"http_path": "/api/webhook/REDACTED"},
    ),
    kept(
        "a URL password inside the path is redacted in http_path",
        TRAEFIK,
        traefik_json(RequestPath="/go/https://user:hunter2@x.invalid/"),
        {"http_path": "/go/https://REDACTED/"},
    ),
    kept(
        "an encoded URL with a password inside the path is masked",
        TRAEFIK,
        traefik_json(RequestPath="/go/https%3A%2F%2Fuser%3Ahunter2%40x.invalid/"),
        {"http_path": "/go/REDACTED/"},
    ),
    kept(
        "a password-only URL is redacted",
        "voxhelm",
        "connect redis://:hunter2@x.invalid/0",
        {"message": "connect redis://REDACTED@x.invalid/0"},
    ),
    kept(
        "a URL password with & and = is redacted before the pair rule",
        "voxhelm",
        "connect redis://:hunter2&x=y@cache.invalid/0",
        {"message": "connect redis://REDACTED@cache.invalid/0"},
    ),
    kept(
        "an @ in a query after a path keeps the whole query redacted",
        "voxhelm",
        "GET https://example.invalid/?token=prefix@hunter2 x",
        {"message": "GET https://example.invalid/?REDACTED x"},
    ),
    kept(
        "a long user agent is redacted before it is shortened",
        "traefik-clf",
        clf("/", status="200", router="homepage@file").replace(
            '"curl/8.9"', '"' + "a" * 150 + " https://u:hunter2" + "b" * 60 + '@x.invalid/"'
        ),
        {"user_agent": "a" * 150 + " https://REDACTED@x.invalid/"},
    ),
    kept(
        "an @ inside a password is covered",
        "voxhelm",
        "GET https://user:@hunter2@example.invalid/x",
        {"message": "GET https://REDACTED@example.invalid/x"},
    ),
    kept(
        "libpq passwords with # and ? are covered",
        "voxhelm",
        "dsn postgresql://app:pa#hunter2?x@db.invalid/app",
        {"message": "dsn postgresql://REDACTED@db.invalid/app"},
    ),
    kept(
        "a user-only token URL is covered",
        "voxhelm",
        "clone https://hunter2@git.invalid/repo",
        {"message": "clone https://REDACTED@git.invalid/repo"},
    ),
    kept(
        "remote account paths keep their @",
        TRAEFIK,
        traefik_json(RequestPath="/@user@example.invalid"),
        {"http_path": "/@user@example.invalid"},
    ),
    kept(
        "an encoded slash in the webhook route still counts",
        TRAEFIK,
        traefik_json(RequestPath="/api/webhook%2Fhunter2"),
        {"http_path": "/api/webhook/REDACTED"},
    ),
    kept(
        "an encoded slash does not split a webhook id",
        TRAEFIK,
        traefik_json(RequestPath="/api/webhook/prefix%2Fhunter2"),
        {"http_path": "/api/webhook/REDACTED"},
    ),
    kept(
        "an encoded query inside a segment is replaced",
        TRAEFIK,
        traefik_json(RequestPath="/proxy/https%3A%2F%2Fx.invalid%3Ftoken%3Dhunter2"),
        {"http_path": "/proxy/REDACTED"},
    ),
    kept(
        "home assistant webhook ids are replaced",
        TRAEFIK,
        traefik_json(RequestPath="/api/webhook/short-id"),
        {"http_path": "/api/webhook/REDACTED"},
    ),
    # Traefik common log format (production).
    kept(
        "clf unrouted 404 is sampled, query and referer dropped",
        "traefik-clf",
        clf("/.well-known/x?token=s3cr3t-value"),
        {
            "logyard_keep": False,
            "http_path": "/.well-known/x",
            "http_query_keys": ["token"],
            "http_status": 404,
            "router": "-",
            "user_agent": "curl/8.9",
            "client": "198.51.100.7",
        },
    ),
    kept(
        "the user agent is redacted too",
        "traefik-clf",
        clf("/").replace('"curl/8.9"', '"bot (+https://x.invalid/?token=s3cr3t-value)"'),
        {"user_agent": "bot (+https://x.invalid/?REDACTED"},
    ),
    kept(
        "clf routed 401 is kept",
        "traefik-clf",
        clf("/admin", status="401", router="mastodon-web@file"),
        {"logyard_keep": True, "level": "warning"},
    ),
    kept(
        "clf slow threshold follows slow_ms",
        "traefik-clf",
        clf("/", status="200", router="homepage-secure@file", ms=1500),
        {"logyard_keep": False, "duration_ms": 1500},
    ),
    kept(
        "a garbled line ships only its length",
        "traefik-clf",
        "garbage GET /login?password=hunter2 HTTP/1.0",
        {"level": "warning", "logyard_keep": False, "message": "unparsed access log line (44 bytes)"},
    ),
    kept(
        "a quote inside a header value makes the line unparsed, not leaked",
        "traefik-clf",
        clf("/x").replace('"curl/8.9"', '"curl \\"8.9\\" s3cr3t-value"'),
        {"level": "warning", "logyard_keep": False},
    ),
    # PostgreSQL.
    dropped(
        "checkpoint chatter",
        "postgresql",
        "2026-11-19 17:57:04.249 CET [2960] LOG:  checkpoint starting: time",
    ),
    dropped(
        "autovacuum chatter",
        "postgresql",
        "2026-11-19 17:57:04.249 CET [2960] LOG:  automatic vacuum of table x.y.z: index scans: 0",
    ),
    dropped(
        "statements are not shipped",
        "postgresql",
        "2026-11-19 17:57:04.249 CET [2961] app@db STATEMENT:  insert into t values ('hunter2')",
    ),
    dropped(
        "details are not shipped",
        "postgresql",
        "2026-11-19 17:57:04.249 CET [2961] app@db DETAIL:  Key (email)=(a@b.invalid) already exists.",
    ),
    dropped("continuation lines are not shipped", "postgresql", "\tand more of a statement"),
    kept(
        "failed authentication is critical",
        "postgresql",
        '2026-11-19 17:57:04.249 CET [2962] app@db FATAL:  password authentication failed for user "app"',
        {"level": "critical", "service": "postgresql"},
    ),
    kept(
        "warnings",
        "postgresql",
        '2026-11-19 17:57:04.249 CET [2963] app@lead WARNING:  database "lead" has a collation version mismatch',
        {"level": "warning"},
    ),
    kept(
        "server start",
        "postgresql",
        "2026-11-19 17:57:04.249 CET [1] LOG:  starting PostgreSQL 17.12",
        {"level": "info"},
    ),
    kept(
        "statements in duration lines are omitted",
        "postgresql",
        "2026-11-19 17:57:04.249 CET [2964] app@db LOG:  duration: 1234.5 ms  statement: UPDATE u SET pw='hunter2'",
        {
            "level": "info",
            "message": "2026-11-19 17:57:04.249 CET [2964] app@db LOG:  duration: 1234.5 ms  statement [omitted]",
        },
    ),
    kept(
        "logged statements are omitted",
        "postgresql",
        "2026-11-19 17:57:04.249 CET [2964] app@db LOG:  execute S_1: select 'hunter2'",
        {"message": "2026-11-19 17:57:04.249 CET [2964] app@db LOG:  execute [omitted]"},
    ),
    kept(
        "statement names with colons do not hide the SQL",
        "postgresql",
        "2026-11-19 17:57:04.249 CET [2964] app@db LOG:  duration: 3 ms  execute a:b:c: select 1 where pw = x",
        {"message": "2026-11-19 17:57:04.249 CET [2964] app@db LOG:  duration: 3 ms  execute [omitted]"},
    ),
    kept(
        "input values in errors are omitted",
        "postgresql",
        '2026-11-19 17:57:04.249 CET [2964] app@db ERROR:  invalid input syntax for type integer: "hunter2"',
        {"level": "error", "message": PG + "ERROR:  invalid input syntax for type integer: [omitted]"},
    ),
    kept(
        "an embedded quote in an echoed value does not end the omission",
        "postgresql",
        '2026-11-19 17:57:04.249 CET [2964] app@db ERROR:  invalid input syntax for type integer: "1" or hunter2"',
        {"message": PG + "ERROR:  invalid input syntax for type integer: [omitted]"},
    ),
    kept(
        "single-quoted text is cut at the first quote",
        "postgresql",
        "2026-11-19 17:57:04.249 CET [2964] app@db ERROR:  syntax error at or near 'a'' hunter2'",
        {"message": "2026-11-19 17:57:04.249 CET [2964] app@db ERROR:  syntax error at or near [omitted]"},
    ),
    kept(
        "identifiers after object words are kept",
        "postgresql",
        '2026-11-19 17:57:04.249 CET [2964] app@db ERROR:  relation "events" does not exist',
        {"message": '2026-11-19 17:57:04.249 CET [2964] app@db ERROR:  relation "events" does not exist'},
    ),
    kept(
        "a quoted value after an identifier is omitted",
        "postgresql",
        PG + 'ERROR:  date/time field value out of range: "hunter2" in relation "events"',
        {"message": "2026-11-19 17:57:04.249 CET [2964] app@db ERROR:  date/time field value out of range: [omitted]"},
    ),
    # fail2ban.
    dropped(
        "per-attempt Found lines",
        "fail2ban",
        "2026-11-19 17:30:21,047 fail2ban.filter         [1206]: INFO    [sshd] Found 203.0.113.9 - 2026-11-19",
    ),
    dropped(
        "already banned",
        "fail2ban",
        "2026-11-19 17:30:21,047 fail2ban.actions        [1206]: NOTICE  [sshd] 203.0.113.9 already banned",
    ),
    kept(
        "a ban",
        "fail2ban",
        "2026-11-19 17:30:22,019 fail2ban.actions        [1206]: NOTICE  [sshd] Ban 203.0.113.9",
        {"level": "notice", "jail": "sshd"},
    ),
    kept(
        "a warning",
        "fail2ban",
        "2026-11-19 17:39:46,029 fail2ban.ipdns          [888]: WARNING Unable to find a corresponding IP address",
        {"level": "warning"},
    ),
    # Echoport.
    dropped("debug lines", "echoport-scheduler", "DEBUG 2026-11-19 17:55:01,463 run_scheduled_backups not due"),
    dropped("idle tick start", "echoport-scheduler", "Checking 38 scheduled targets..."),
    dropped("idle tick end", "echoport-scheduler", "Complete: 0 triggered, 38 skipped"),
    kept("a tick that triggers", "echoport-scheduler", "Complete: 1 triggered, 37 skipped", {"level": "info"}),
    kept(
        "errors",
        "echoport-scheduler",
        "ERROR 2026-11-19 03:00:06,872 minio_client Failed to delete object",
        {"level": "error"},
    ),
    kept("plain lines", "echoport-scheduler", "  Deleted 'x' backup: x/1.tar.gz (rustfs)", {"level": "info"}),
    # Plain files, drop patterns, floors.
    dropped(
        "configured drop: heartbeats",
        "voxhelm",
        'INFO:     127.0.0.1:56321 - "POST /v1/internal/workers/heartbeat HTTP/1.1" 200 OK',
    ),
    dropped("configured drop anchored with $", "voxhelm", "tick"),
    kept(
        "uvicorn level prefix",
        "voxhelm",
        'INFO:     127.0.0.1:56321 - "GET /v1/jobs HTTP/1.1" 200 OK',
        {"level": "info", "service": "voxhelm", "file": "/var/log/x.log"},
    ),
    kept(
        "python logging level after a timestamp",
        "voxhelm",
        "2026-11-19 16:58:46,374 WARNING httpx retry",
        {"level": "warning"},
    ),
    kept("bracketed level", "voxhelm", "[ERROR] boom", {"level": "error"}),
    kept("emergency words", "voxhelm", "[EMERG] panic", {"level": "emerg"}),
    kept("alert words", "voxhelm", "ALERT: disk", {"level": "alert"}),
    kept(
        "short bearer tokens are replaced",
        "voxhelm",
        "Authorization: Bearer hunter2",
        {"message": "Authorization: Bearer REDACTED"},
    ),
    kept(
        "basic credentials are replaced",
        "voxhelm",
        "Authorization: Basic aHVudGVyMg==",
        {"message": "Authorization: Basic REDACTED"},
    ),
    kept(
        "percent-encoded parameter names do not hide values",
        "voxhelm",
        "GET /x?access%5Ftoken=hunter2&page=2",
        {"message": "GET /x?REDACTED"},
    ),
    kept(
        "a hash inside a form value does not end the redaction",
        "voxhelm",
        "body a=1&token=prefix#hunter2 end",
        {"message": "body a=1&token=REDACTED end"},
    ),
    kept(
        "fragment parameters are replaced",
        "voxhelm",
        "callback /cb#access_token=hunter2&state=x",
        {"message": "callback /cb#access_token=REDACTED&state=REDACTED"},
    ),
    kept(
        "an apostrophe inside a query does not end the redaction",
        "voxhelm",
        "GET /x?token=a'hunter2 done",
        {"message": "GET /x?REDACTED done"},
    ),
    kept(
        "a semicolon inside a query value does not end the redaction",
        "voxhelm",
        "GET /x?token=prefix;hunter2 done",
        {"message": "GET /x?REDACTED done"},
    ),
    kept(
        "empty and long parameter names do not hide values",
        "voxhelm",
        "body a=1&=hunter2&" + "n" * 200 + "=s3cr3t-value end",
        {"message": "body a=1&=REDACTED&" + "n" * 200 + "=REDACTED end"},
    ),
    kept(
        "basic credentials inside JSON are replaced",
        "voxhelm",
        '{"headers": {"Authorization": "Basic aHVudGVyMg=="}}',
        {"message": '{"headers": {"Authorization": "Basic REDACTED"}}'},
    ),
    kept("no level word", "voxhelm", "usage-stale\tusage-stale\twork usage status", {"level": "info"}),
    kept(
        "bearer tokens are replaced",
        "voxhelm",
        "request failed: Authorization: Bearer abcdefghijkl.mnop",
        {"message": "request failed: Authorization: Bearer REDACTED"},
    ),
    kept(
        "url passwords are replaced",
        "voxhelm",
        "fetch https://user:hunter2@example.invalid/x failed",
        {"message": "fetch https://REDACTED@example.invalid/x failed"},
    ),
    dropped("below the floor", "quiet-agent", "2026-11-19 10:00:00 INFO all good"),
    kept("at the floor", "quiet-agent", "2026-11-19 10:00:00 WARNING look", {"level": "warning"}),
    # The sample stage passes kept requests through; the output stage drops the marker.
    {
        "name": "kept requests pass the sampler without the marker",
        "inputs": [
            {
                "insert_at": parse(TRAEFIK),
                "type": "log",
                "log_fields": {"message": traefik_json(DownstreamStatus=503)},
            }
        ],
        "outputs": [
            {
                "extract_from": "logyard_files_out",
                "conditions": [
                    {"type": "vrl", "source": "assert!(!exists(.logyard_keep)); assert_eq!(.http_status, 503)"}
                ],
            }
        ],
    },
    # Journald lines get the same redaction.
    {
        "name": "journald query tokens are replaced",
        "inputs": [
            {
                "insert_at": "normalize_logs",
                "type": "log",
                "log_fields": {
                    "message": "[2026-11-19][request][INFO] GET /notifications/hub?access_token=s3cr3t-value&x=1",
                    "_SYSTEMD_UNIT": "vaultwarden.service",
                    "PRIORITY": "6",
                },
            }
        ],
        "outputs": [
            {
                "extract_from": "normalize_logs",
                "conditions": [
                    {
                        "type": "vrl",
                        "source": 'assert_eq!(.message, "[2026-11-19][request][INFO] GET /notifications/hub?REDACTED")',
                    }
                ],
            }
        ],
    },
]


def run_vector_test(tmp_path: Path, text: str, cases: list[dict[str, Any]]) -> subprocess.CompletedProcess[str]:
    config = tmp_path / "logyard.yaml"
    config.write_text(text)
    tests = tmp_path / "tests.yaml"
    tests.write_text(json.dumps({"tests": cases}))
    assert VECTOR is not None
    return subprocess.run(
        [VECTOR, "test", str(config), str(tests)], capture_output=True, text=True, timeout=180, check=False
    )


def test_file_pipelines(tmp_path: Path) -> None:
    result = run_vector_test(tmp_path, fragment(), CASES)

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert output.count("... passed") == len(CASES), output


def test_files_only_fragment_validates(tmp_path: Path) -> None:
    """A Darwin producer: no journald source, transform or sink."""

    cfg = vector_config(journald=False, darwin={}, files=SOURCES[-2:])
    text = vector.render_fragment(cfg, True)
    assert "journald_logs" not in text
    assert "normalize_logs" not in text
    (tmp_path / "data").mkdir()
    (tmp_path / "00-global.yaml").write_text(f'data_dir: "{tmp_path / "data"}"\n')
    (tmp_path / "30-logyard.yaml").write_text(text)
    assert VECTOR is not None
    result = subprocess.run(
        [VECTOR, "validate", "--no-environment", "--config-dir", str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
