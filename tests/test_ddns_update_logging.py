"""ddns_update.py log volume: a run that changes nothing logs one line."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

SCRIPT = Path(__file__).resolve().parents[1] / "src/ops_deploy/services/dns/files/ddns_update.py"
_spec = importlib.util.spec_from_file_location("ddns_update_logging_under_test", SCRIPT)
assert _spec is not None
assert _spec.loader is not None
ddns: Any = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ddns)

ZONE = "xn--wersdrfer-47a.de"
BASE = f"https://api.gandi.net/v5/livedns/domains/{ZONE}/records"
NEW4, NEW6 = "2.243.94.187", "2a02:3100:41eb:df00:6afe:f7ff:fe0c:fc3"
OLD4, OLD6 = "80.171.217.153", "2a02:3100:3f53:1500:6afe:f7ff:fe0c:fc3"


class FakeGandi:
    def __init__(self, records: dict[tuple[str, str], list[str]]) -> None:
        self.records = dict(records)

    def __call__(self, method: str, url: str, headers: dict[str, str], body: bytes | None) -> tuple[int, bytes]:
        if url == "https://ipv4.icanhazip.com":
            return 200, f"{NEW4}\n".encode()
        if url == "https://ipv6.icanhazip.com":
            return 200, f"{NEW6}\n".encode()
        name, rtype = url[len(BASE) + 1 :].rsplit("/", 1)
        if method == "GET":
            if (name, rtype) not in self.records:
                return 404, b"{}"
            return 200, json.dumps({"rrset_values": self.records[(name, rtype)]}).encode()
        assert body is not None
        self.records[(name, rtype)] = json.loads(body)["rrset_values"]
        return 201, b"{}"


def public(v4: str, v6: str) -> dict[tuple[str, str], list[str]]:
    return {(f"{n}.{ZONE}", t): [v] for n in ("home", "*.home") for t, v in (("A", v4), ("AAAA", v6))}


def run(records: dict[tuple[str, str], list[str]], seen: dict[tuple[str, str], list[str]]) -> tuple[int, list[str]]:
    def resolve(name: str, rtype: str, server: str | None) -> list[str] | None:
        return ["ns-a.example.", "ns-b.example."] if rtype == "NS" else seen.get((name, rtype))

    config = {"provider": "gandi", "zone": "wersdörfer.de", "names": ["home", "*.home"], "ttl": 60,
              "gandi": {"auth_scheme": "apikey"}}  # fmt: skip
    lines: list[str] = []
    code, _status = ddns.run(config, {"GANDI_API_TOKEN": "t"}, http=FakeGandi(records), resolve=resolve,
                             log=lines.append, now=lambda: 1_000_000)  # fmt: skip
    return code, lines


def current() -> dict[tuple[str, str], list[str]]:
    return {(n, t): [v] for n in ("home", "*.home") for t, v in (("A", NEW4), ("AAAA", NEW6))}


def test_a_run_without_changes_logs_only_its_result() -> None:
    code, lines = run(current(), public(NEW4, NEW6))

    assert code == 0
    assert lines == [f"DDNS result: run_ok=True updated=0 public_ok=4/4 errors=0 wan={NEW4},{NEW6}"]


def test_an_update_logs_every_detail_line_in_order() -> None:
    records = current()
    records[("home", "A")] = [OLD4]
    code, lines = run(records, public(NEW4, NEW6))

    assert code == 0
    assert lines[0].startswith("DDNS run: provider=gandi")
    assert lines[1:3] == [f"WAN IPv4: {NEW4}", f"WAN IPv6: {NEW6}"]
    # Detail lines after the first line that matters are logged as they come.
    assert lines[3:7] == [
        f"updated A home.{ZONE}: ['{OLD4}'] -> {NEW4}",
        f"unchanged AAAA home.{ZONE} = {NEW6}",
        f"unchanged A *.home.{ZONE} = {NEW4}",
        f"unchanged AAAA *.home.{ZONE} = {NEW6}",
    ]
    assert lines[7].startswith("DDNS result: run_ok=True updated=1 public_ok=4/4")
    assert len(lines) == 8


def test_a_public_mismatch_logs_the_details_before_it() -> None:
    code, lines = run(current(), public(OLD4, NEW6))

    assert code == 0
    assert lines[0].startswith("DDNS run: ")
    assert f"unchanged A home.{ZONE} = {NEW4}" in lines
    assert any(line.startswith(f"public A home.{ZONE} = [['{OLD4}']") for line in lines)
    assert lines[-1].startswith("DDNS result: run_ok=True updated=0 public_ok=2/4")


def test_main_writes_the_held_lines_before_its_own_error(tmp_path: Path, monkeypatch: Any, capsys: Any) -> None:
    def resolve(name: str, rtype: str, server: str | None) -> list[str] | None:
        return ["ns-a.example."] if rtype == "NS" else public(NEW4, NEW6).get((name, rtype))

    real_run = ddns.run

    def fake_run(config: Any, env: Any, http: Any, resolve: Any, log: Any) -> Any:
        return real_run(config, env, FakeGandi(current()), fake_resolve, log)

    fake_resolve = resolve
    monkeypatch.setattr(ddns, "run", fake_run)
    monkeypatch.setenv("GANDI_API_TOKEN", "t")
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"provider": "gandi", "zone": "wersdörfer.de", "names": ["home", "*.home"],
                                  "gandi": {"auth_scheme": "apikey"},
                                  "status_path": str(tmp_path / "missing" / "status.json")}))  # fmt: skip

    assert ddns.main(["--config", str(config)]) == 1
    lines = [line.split("] ", 1)[1] for line in capsys.readouterr().out.splitlines()]
    assert lines[0].startswith("DDNS result: run_ok=True updated=0 public_ok=4/4")
    assert lines[1].startswith("DDNS run: provider=gandi")
    assert f"unchanged AAAA *.home.{ZONE} = {NEW6}" in lines
    assert lines[-1].startswith("ERROR: cannot write status file:")
