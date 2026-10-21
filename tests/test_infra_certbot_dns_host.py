"""``files/certbot_dns_host.py`` and the vendored stray guard, run for real on temp trees.

The scripts run as the deploy runs them (``python3 -I -c <source> ...``)
against a certbot-shaped tree in a temp directory with certificates made by
the local ``openssl``. Nothing here talks to an ACME server or needs root.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest

from ops_deploy.infra import CertbotDnsConfig
from ops_deploy.infra.certbot_dns import HOST_SCRIPT, STRAY_GUARD, Lineage, renewal_due

DOMAIN = "home.example.org"
KINDS = ("cert", "chain", "fullchain", "privkey")
needs_openssl = pytest.mark.skipif(not shutil.which("openssl"), reason="needs openssl")


def host(*args: str, stdin: str | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["python3", "-I", "-c", HOST_SCRIPT, *args],
        input=stdin,
        capture_output=True,
        text=True,
        env={"PATH": os.environ["PATH"], **(env or {})},
        timeout=60,
    )


def make_cert(path: Path, days: int, names: tuple[str, ...]) -> None:
    san = ",".join(f"DNS:{name}" for name in names)
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-keyout",
            str(path.with_name(path.name + ".key")),
            "-out",
            str(path),
            "-days",
            str(days),
            "-subj",
            f"/CN={names[0]}",
            "-addext",
            f"subjectAltName={san}",
        ],
        check=True,
        capture_output=True,
        timeout=60,
    )


def make_lineage(
    root: Path,
    *,
    days: int = 80,
    names: tuple[str, ...] = (DOMAIN, f"*.{DOMAIN}"),
    authenticator: str = "dns-rfc2136",
    extra: str = "",
) -> Path:
    """``root`` as a config dir holding one lineage on version 1 (version 2 for ``cert`` only)."""

    archive = root / "archive" / DOMAIN
    live = root / "live" / DOMAIN
    archive.mkdir(parents=True)
    live.mkdir(parents=True)
    (root / "renewal").mkdir()
    for kind in KINDS:
        if kind == "cert":
            make_cert(archive / "cert1.pem", days, names)
        else:
            (archive / f"{kind}1.pem").write_text(f"{kind}\n")
        (live / f"{kind}.pem").symlink_to(f"../../archive/{DOMAIN}/{kind}1.pem")
    conf = root / "renewal" / f"{DOMAIN}.conf"
    conf.write_text(
        "# renew_before_expiry = 30 days\n"
        "version = 2.9.0\n"
        f"archive_dir = {archive}\n"
        + "".join(f"{kind} = {live}/{kind}.pem\n" for kind in KINDS)
        + "\n# Options used in the renewal process\n[renewalparams]\n"
        f"account = 0123456789abcdef\nauthenticator = {authenticator}\n"
        f"dns_rfc2136_credentials = {root}/dns-rfc2136-credentials.ini\n"
        "dns_rfc2136_propagation_seconds = 120\n"
        "server = https://acme-v02.api.letsencrypt.org/directory\nkey_type = ecdsa\n" + extra
    )
    return conf


def probe(root: Path, inactive: list[str] = (), stray: list[str] = ()) -> dict[str, Any]:  # type: ignore[assignment]
    result = host("probe", str(root), DOMAIN, json.dumps(list(inactive)), json.dumps(list(stray)))
    assert result.returncode == 0, result.stderr
    data: dict[str, Any] = json.loads(result.stdout)
    return data


def config(root: Path, **changes: Any) -> CertbotDnsConfig:
    # The probe reports the tree it read; renewal_due checks paths against that.
    return CertbotDnsConfig(
        provider="rfc2136",
        domain=DOMAIN,
        email="admin@example.org",
        rfc2136_server="192.0.2.53",
        rfc2136_key_name="acme-key",
        **changes,
    )


def test_probe_without_a_lineage(tmp_path: Path) -> None:
    state = probe(tmp_path, [str(tmp_path / "gone.ini")], ["/nonexistent-stray"])

    assert state["conf"] is None
    assert state["cert"] is None
    assert state["inactive"] == {str(tmp_path / "gone.ini"): {"kind": "missing", "rc": None}}
    assert state["stray"] == {"/nonexistent-stray": False}
    assert renewal_due(config(tmp_path), Lineage.parse(json.dumps(state))) == "no lineage yet"


@needs_openssl
def test_probe_reads_the_lineage_and_finds_it_not_due(tmp_path: Path) -> None:
    make_lineage(tmp_path)

    state = probe(tmp_path)

    assert state["config_dir"] == str(tmp_path)
    assert state["conf"]["malformed"] is False
    assert state["conf"]["authenticator"] == "dns-rfc2136"
    assert state["conf"]["settings"] == ["rfc2136"]
    assert state["conf"]["autorenew"] is None
    # The commented default is not a setting.
    assert "renew_before_expiry" not in state["conf"]["values"]
    assert state["cert"]["names"] == [DOMAIN, f"*.{DOMAIN}"]
    assert state["cert"]["key_type"] == "ECDSA"
    assert 79 * 86400 < state["cert"]["not_after"] - state["now"] <= 80 * 86400
    assert state["links"]["cert"] == {"target": f"../../archive/{DOMAIN}/cert1.pem", "exists": True}
    assert renewal_due(config(tmp_path), Lineage.parse(json.dumps(state))) is None


@needs_openssl
def test_probe_sees_an_expiring_or_renamed_certificate(tmp_path: Path) -> None:
    make_lineage(tmp_path / "a", days=20)
    make_lineage(tmp_path / "b", names=(DOMAIN,))

    for name, reason in (("a", "renewal window"), ("b", "names differ")):
        state = Lineage.parse(json.dumps(probe(tmp_path / name)))
        assert reason in (renewal_due(config(tmp_path / name), state) or "")


@needs_openssl
def test_probe_sees_a_pending_deployment(tmp_path: Path) -> None:
    make_lineage(tmp_path)
    archive = tmp_path / "archive" / DOMAIN
    for kind in KINDS:
        shutil.copy(archive / f"{kind}1.pem", archive / f"{kind}2.pem")

    reason = renewal_due(config(tmp_path), Lineage.parse(json.dumps(probe(tmp_path))))

    assert reason == "the live links are not on the latest certificate"


@needs_openssl
def test_probe_runs_the_roles_scan_on_inactive_files(tmp_path: Path) -> None:
    make_lineage(tmp_path)
    used = tmp_path / "dns-rfc2136-credentials.ini"
    unused = tmp_path / "dns-credentials.ini"
    for path in (used, unused):
        path.write_text("x\n")
    link = tmp_path / "link.ini"
    link.symlink_to(unused)

    state = probe(tmp_path, [str(used), str(unused), str(link)])

    assert state["inactive"] == {
        str(used): {"kind": "file", "rc": 0},
        str(unused): {"kind": "file", "rc": 1},
        str(link): {"kind": "link", "rc": 1},
    }
    (tmp_path / "renewal" / f"{DOMAIN}.conf").unlink()
    assert probe(tmp_path, [str(unused)])["inactive"][str(unused)] == {"kind": "file", "rc": 2}


def test_probe_fails_on_an_unreadable_configuration(tmp_path: Path) -> None:
    (tmp_path / "renewal").mkdir()
    (tmp_path / "renewal" / f"{DOMAIN}.conf").write_bytes(b"\xff\xfe broken")

    result = host("probe", str(tmp_path), DOMAIN, "[]", "[]")

    assert result.returncode != 0
    assert result.stdout == ""


@needs_openssl
@pytest.mark.parametrize(
    "extra",
    [
        "authenticator = dns-gandi\n",
        "[renewalparams]\nserver = x\n",
        "not a setting\n",
        "key_type = ecdsa # comment\n",
        "key_type = 'ecdsa\n",
        'key_type = """ecdsa"""\n',
        "[[nested]]\nx = 1\n",
    ],
    ids=["duplicate-key", "duplicate-section", "stray-line", "inline-comment", "open-quote", "triple-quote", "nested"],
)
def test_configuration_certbot_might_read_otherwise_is_due(tmp_path: Path, extra: str) -> None:
    make_lineage(tmp_path, extra=extra)

    state = probe(tmp_path)

    assert state["conf"]["malformed"] is True
    assert "not plain configobj" in (renewal_due(config(tmp_path), Lineage.parse(json.dumps(state))) or "")


@needs_openssl
def test_section_named_like_a_top_level_key_is_due(tmp_path: Path) -> None:
    conf = make_lineage(tmp_path)
    conf.write_text("renewalparams = unused\n" + conf.read_text())

    state = probe(tmp_path)

    assert state["conf"]["malformed"] is True
    assert "not plain configobj" in (renewal_due(config(tmp_path), Lineage.parse(json.dumps(state))) or "")


@needs_openssl
def test_empty_values_are_plain(tmp_path: Path) -> None:
    make_lineage(tmp_path, extra="pre_hook =\nempty = ''\n")

    state = probe(tmp_path)

    assert state["conf"]["malformed"] is False
    assert renewal_due(config(tmp_path), Lineage.parse(json.dumps(state))) is None


@needs_openssl
def test_quoted_values_and_comments_are_plain(tmp_path: Path) -> None:
    make_lineage(tmp_path, extra='key_type_note = "two words"\n# a comment = x\n')

    state = probe(tmp_path)

    assert state["conf"]["malformed"] is False
    assert renewal_due(config(tmp_path), Lineage.parse(json.dumps(state))) is None


def test_authenticator_is_read_like_the_role(tmp_path: Path) -> None:
    conf = tmp_path / "x.conf"
    conf.write_text("[renewalparams]\nauthenticator = dns-gandi\nauthenticator = dns-rfc2136\n")

    assert host("authenticator", str(conf)).stdout == "dns-gandi\n"
    assert host("authenticator", str(tmp_path / "missing.conf")).stdout == "\n"


def test_drop_settings_removes_other_providers_lines_only_after_the_switch(tmp_path: Path) -> None:
    real = tmp_path / "real.conf"
    text = (
        "[renewalparams]\nauthenticator = dns-rfc2136\n"
        "dns_gandi_credentials = /etc/letsencrypt/dns-credentials.ini\n"
        "dns_gandi_propagation_seconds=120\n"
        "dns_rfc2136_credentials = /etc/letsencrypt/dns-rfc2136-credentials.ini\n"
        "# dns_gandi_comment = kept\n"
    )
    real.write_text(text)
    real.chmod(0o640)
    link = tmp_path / "link.conf"
    link.symlink_to(real)

    assert host("drop-settings", str(link), "gandi").stdout == "unchanged\n"
    assert real.read_text() == text
    assert host("drop-settings", str(link), "rfc2136").stdout == "changed\n"

    assert link.is_symlink()
    assert real.read_text() == (
        "[renewalparams]\nauthenticator = dns-rfc2136\n"
        "dns_rfc2136_credentials = /etc/letsencrypt/dns-rfc2136-credentials.ini\n"
        "# dns_gandi_comment = kept\n"
    )
    assert stat.S_IMODE(real.stat().st_mode) == 0o640
    assert host("drop-settings", str(link), "rfc2136").stdout == "unchanged\n"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["link.conf", "real.conf"]


def guard(root: Path, stray: list[str]) -> subprocess.CompletedProcess[str]:
    data = {"stray": stray, "protected": [str(root)], "config_dir": str(root)}
    return subprocess.run(
        ["python3", "-I", "-c", STRAY_GUARD],
        capture_output=True,
        text=True,
        env={"PATH": os.environ["PATH"], "CERTBOT_STRAY_INPUT": json.dumps(data)},
        timeout=60,
        check=True,
    )


@needs_openssl
def test_guard_and_removal_take_only_a_real_stray_tree(tmp_path: Path) -> None:
    root = tmp_path / "etc"
    make_lineage(root)
    stray = tmp_path / "stray"
    (stray / "renewal").mkdir(parents=True)
    (stray / "renewal" / "old.conf").write_text("x\n")
    missing = str(tmp_path / "gone")
    data = {"stray": [str(stray), missing], "protected": [str(root)], "config_dir": str(root)}

    decision = guard(root, [str(stray), missing]).stdout
    assert json.loads(decision) == {"remove": [str(stray)], "skipped": [missing], "refused": []}
    result = host("remove-stray", stdin=decision, env={"CERTBOT_STRAY_INPUT": json.dumps(data)})

    assert result.returncode == 0, result.stderr
    assert result.stdout == f"removed {stray}\n"
    assert not stray.exists()
    assert root.is_dir()


@needs_openssl
def test_removal_refuses_a_guard_refusal(tmp_path: Path) -> None:
    root = tmp_path / "etc"
    make_lineage(root)
    (root / "unexpected").symlink_to("/tmp")
    stray = tmp_path / "stray"
    (stray / "renewal").mkdir(parents=True)
    data = {"stray": [str(stray)], "protected": [str(root)], "config_dir": str(root)}

    decision = guard(root, [str(stray)]).stdout
    assert json.loads(decision)["refused"]
    result = host("remove-stray", stdin=decision, env={"CERTBOT_STRAY_INPUT": json.dumps(data)})

    assert result.returncode == 1
    assert "Refusing stray certbot dirs, nothing removed" in result.stderr
    assert stray.is_dir()


def test_removal_refuses_a_decision_for_other_paths(tmp_path: Path) -> None:
    stray = tmp_path / "stray"
    stray.mkdir()
    data = {"stray": [str(stray), "/other"], "protected": [], "config_dir": "/x"}
    decision = json.dumps({"remove": [str(stray)], "skipped": [], "refused": []})

    result = host("remove-stray", stdin=decision, env={"CERTBOT_STRAY_INPUT": json.dumps(data)})

    assert result.returncode == 1
    assert stray.is_dir()
