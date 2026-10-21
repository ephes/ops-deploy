"""``certbot_dns`` against real certbot, openssl and systemd in an owned Docker fixture.

Skipped unless ``CERTBOT_DNS_DOCKER_CONTAINER`` names the full ID of a running
fixture container (see ``docs/infra.md``, "certbot_dns"). The container has
no network, so nothing can reach an ACME server. Lineages are made with
self-signed certificates in certbot's layout. The test checks what the fake
connector cannot: the probe's "due" decision agrees with certbot 2.9's own
(``_find_lineage_for_domains_and_certname`` and ``has_pending_deployment``
on the same tree), a converged run invokes no certbot at all (certbot writes
its log on every start), the exec-time cleanup and stray removal work on the
real files, and the guard refuses before any change.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr
from pyinfra.api import Config, Inventory, State
from pyinfra.api.connect import connect_all, disconnect_all
from pyinfra.api.deploy import add_deploy
from pyinfra.api.exceptions import PyinfraError
from pyinfra.api.operations import run_ops
from pyinfra.connectors.docker import DockerConnector

from ops_deploy.infra import CertbotDnsConfig, deploy_certbot_dns
from ops_deploy.infra.certbot_dns import render_credentials, render_hook
from ops_deploy.testing.harness import OpResult, collect_ops

pytestmark = pytest.mark.skipif(
    not os.environ.get("CERTBOT_DNS_DOCKER_CONTAINER"), reason="no explicitly owned certbot Docker fixture"
)

NAME = "/ops-deploy-certbot-dns-20261020"
RUN_LABEL = "pyinfra-certbot-dns-20261020"
DOMAIN = "home.example.org"
SECRET = SecretStr("Zml4dHVyZS10c2lnLWtleQ==")
CFG = CertbotDnsConfig(
    provider="rfc2136",
    domain=DOMAIN,
    email="admin@example.org",
    rfc2136_server="192.0.2.53",
    rfc2136_key_name="acme-fixture",
    renewal_hooks=("systemctl restart systemd-journald",),
    stray_config_dirs=("/letsencrypt",),
    single_lineage=True,
    consumer_units=("systemd-journald",),
)
P = "certbot DNS | "
GANDI = "/etc/letsencrypt/dns-credentials.ini"
RFC2136 = "/etc/letsencrypt/dns-rfc2136-credentials.ini"
HOOK = "/etc/letsencrypt/renewal-hooks/deploy/reload-services.sh"
LOG = "/var/log/letsencrypt/letsencrypt.log"
READ_ONLY = {
    P + "Check the renewal hook",
    P + "Check the lineage is the only one",
    P + "Check systemd-journald is loaded and active",
}

# A lineage as certbot lays it out: archive/<name>/<kind>N.pem, live links,
# renewal/<name>.conf (certbot 2.9's keys). Args: days, names (comma list),
# key type (ec|rsa), version, renewal extras (may be empty).
MAKE_LINEAGE = r"""
set -eu
days=$1 names=$2 key=$3 version=$4 extra=$5
d=/etc/letsencrypt; name=home.example.org
rm -rf "$d/archive/$name" "$d/live/$name" "$d/renewal"
mkdir -p "$d/archive/$name" "$d/live/$name" "$d/renewal"
san=$(printf '%s' "$names" | sed 's/^/DNS:/; s/,/,DNS:/g')
cn=${names%%,*}
for n in $(seq 1 "$version"); do
  if [ "$key" = rsa ]; then newkey="rsa:2048"; else newkey="ec -pkeyopt ec_paramgen_curve:prime256v1"; fi
  openssl req -x509 -newkey $newkey -nodes -keyout "$d/archive/$name/privkey$n.pem" \
    -out "$d/archive/$name/cert$n.pem" -days "$days" -subj "/CN=$cn" -addext "subjectAltName=$san" 2>/dev/null
  cp "$d/archive/$name/cert$n.pem" "$d/archive/$name/chain$n.pem"
  cat "$d/archive/$name/cert$n.pem" "$d/archive/$name/chain$n.pem" > "$d/archive/$name/fullchain$n.pem"
done
for kind in cert chain fullchain privkey; do
  ln -s "../../archive/$name/$kind$version.pem" "$d/live/$name/$kind.pem"
done
{
  echo "# renew_before_expiry = 30 days"
  echo "version = 2.9.0"
  echo "archive_dir = $d/archive/$name"
  for kind in cert privkey chain fullchain; do echo "$kind = $d/live/$name/$kind.pem"; done
  echo
  echo "# Options used in the renewal process"
  echo "[renewalparams]"
  echo "account = 0123456789abcdef0123456789abcdef"
  echo "authenticator = dns-rfc2136"
  echo "dns_rfc2136_credentials = $d/dns-rfc2136-credentials.ini"
  echo "dns_rfc2136_propagation_seconds = 120"
  echo "server = https://acme-v02.api.letsencrypt.org/directory"
  if [ "$key" = rsa ]; then echo "key_type = rsa"; else echo "key_type = ecdsa"; fi
  if [ -n "$extra" ]; then printf '%s\n' "$extra"; fi
} > "$d/renewal/$name.conf"
"""

# certbot 2.9's own answer for the role's certonly argv on the current tree.
ORACLE = r"""
import json, sys
from certbot._internal import cert_manager, cli, main
from certbot._internal.display import obj as display_obj
from certbot._internal.plugins import disco
argv = json.loads(sys.argv[1])
display_obj.set_display(display_obj.NoninteractiveDisplay(open("/dev/null", "w")))
# As certbot's main: a NamespaceConfig that knows which options the command line set.
config = cli.prepare_and_parse_args(disco.PluginsRegistry.find_all(), argv)
lineage = cert_manager.lineage_for_certname(config, config.certname)
pending = bool(lineage and lineage.has_pending_deployment())
action, _ = main._find_lineage_for_domains_and_certname(config, config.domains, config.certname)
print(json.dumps({"action": action, "pending": pending}))
"""


class Fixture:
    def __init__(self) -> None:
        binary = shutil.which("docker")
        assert binary is not None
        self.binary = binary
        self.identifier = os.environ["CERTBOT_DNS_DOCKER_CONTAINER"]
        assert re.fullmatch(r"[0-9a-f]{64}", self.identifier)
        info = json.loads(self.docker("container", "inspect", self.identifier).stdout)[0]
        # Only the owned, isolated fixture: no network, mounts, ports or devices.
        assert info["Name"] == NAME
        assert info["State"]["Running"]
        assert info["Config"]["Labels"]["ops-deploy.fixture"] == "certbot-dns"
        assert info["Config"]["Labels"]["ops-deploy.run"] == RUN_LABEL
        cfg = info["HostConfig"]
        assert cfg["NetworkMode"] == "none"
        assert cfg["Privileged"] is False
        assert cfg["CgroupnsMode"] == "private"
        assert not cfg["Binds"]
        assert not cfg.get("Mounts")
        assert not cfg["PortBindings"]
        assert not cfg["Devices"]
        assert [name.removeprefix("CAP_") for name in cfg["CapAdd"]] == ["SYS_ADMIN"]
        assert self.sh("cat /proc/1/comm") == "systemd"
        assert self.sh("certbot --version").startswith("certbot 2.")

    def docker(self, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [self.binary, *args], input=stdin, capture_output=True, text=True, check=True, timeout=180
        )

    def sh(self, command: str) -> str:
        return self.docker("exec", "-i", self.identifier, "sh", "-c", command).stdout.strip()

    def exists(self, path: str) -> bool:
        return self.sh(f"test -e {shlex.quote(path)} || test -L {shlex.quote(path)} && echo yes || echo no") == "yes"

    def lineage(
        self, days: int = 80, names: str = f"{DOMAIN},*.{DOMAIN}", key: str = "ec", version: int = 1, extra: str = ""
    ) -> None:
        self.docker(
            "exec",
            "-i",
            self.identifier,
            "sh",
            "-s",
            "--",
            str(days),
            names,
            key,
            str(version),
            extra,
            stdin=MAKE_LINEAGE,
        )

    def certbot_says(self, cfg: CertbotDnsConfig) -> dict[str, Any]:
        from ops_deploy.infra.certbot_dns import certonly_argv

        argv = certonly_argv(cfg)[1:]
        out = self.docker("exec", "-i", self.identifier, "python3", "-c", ORACLE, json.dumps(argv)).stdout
        result: dict[str, Any] = json.loads(out.strip().splitlines()[-1])
        return result

    def guard_connector(self, tmp: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        # pyinfra may only inspect, exec in and copy into the container: never start, commit or remove it.
        wrapper = tmp / "docker-transport"
        wrapper.write_text(
            '#!/bin/sh\ncase "$1:$2" in container:inspect|exec:*|cp:*) ;; *) exit 97 ;; esac\nexec '
            + shlex.quote(self.binary)
            + ' "$@"\n'
        )
        wrapper.chmod(0o700)
        monkeypatch.setattr(DockerConnector, "docker_cmd", shlex.quote(str(wrapper)))

    def _state(self) -> tuple[State, str]:
        name = f"@docker/{self.identifier}"
        state = State(Inventory(([(name, {})], {})), Config())
        connect_all(state)
        assert state.activated_hosts
        return state, name

    def plan(self, cfg: CertbotDnsConfig) -> list[str]:
        """Names of the operations the deploy plans; nothing is executed."""

        state, name = self._state()
        try:
            add_deploy(state, deploy_certbot_dns, cfg, SECRET)
            return [op.name for op in collect_ops(state, name)]
        finally:
            disconnect_all(state)

    def deploy(self, cfg: CertbotDnsConfig) -> list[OpResult]:
        state, name = self._state()
        try:
            add_deploy(state, deploy_certbot_dns, cfg, SECRET)
            run_ops(state)
            ops = collect_ops(state, name)
        finally:
            disconnect_all(state)
        assert all(op.succeeded for op in ops), ops
        return ops

    def reset(self) -> None:
        """As the package leaves it (no hook directory), no credentials, stray tree or
        certbot log; a fresh not-due lineage."""

        self.sh(
            f"rm -rf /letsencrypt {GANDI} {RFC2136} /etc/letsencrypt/renewal-hooks /etc/letsencrypt/unexpected "
            "/var/log/letsencrypt "
            "&& systemctl reset-failed systemd-journald"
        )
        self.lineage()


def mutating(ops: list[OpResult]) -> list[str]:
    return [op.name for op in ops if op.changed and not op.read_only]


@pytest.fixture
def fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Fixture:
    fx = Fixture()
    fx.guard_connector(tmp_path, monkeypatch)
    fx.reset()
    return fx


@pytest.mark.parametrize(
    ("lineage", "cfg_changes", "due"),
    [
        ({}, {}, False),
        ({"days": 31}, {}, False),
        ({"days": 29}, {}, True),
        ({"names": DOMAIN}, {}, True),
        ({"key": "rsa"}, {}, True),
        ({"key": "rsa"}, {"key_type": "rsa"}, False),
        ({"version": 2}, {}, False),
        ({"days": 50, "extra": ""}, {"additional_domains": ("www.example.org",)}, True),
        ({"days": 10, "extra": "autorenew = False"}, {}, False),
    ],
    ids=["80d", "31d", "29d", "names", "key-type", "rsa-kept", "v2", "new-name", "autorenew-off"],
)
def test_probe_agrees_with_certbot(
    fixture: Fixture, lineage: dict[str, Any], cfg_changes: dict[str, Any], due: bool
) -> None:
    cfg = CertbotDnsConfig.model_validate({**CFG.model_dump(), "stray_config_dirs": (), **cfg_changes})
    fixture.lineage(**lineage)

    planned = P + "Request or renew the certificate" in fixture.plan(cfg)
    certbot = fixture.certbot_says(cfg)

    assert planned is due
    assert (certbot["action"] != "reinstall" or certbot["pending"]) is due, certbot


def test_pending_deployment_is_due_like_certbot_relinks(fixture: Fixture) -> None:
    fixture.lineage(version=2)
    fixture.sh("cd /etc/letsencrypt/live/home.example.org && ln -sfn ../../archive/home.example.org/cert1.pem cert.pem")
    cfg = CertbotDnsConfig.model_validate({**CFG.model_dump(), "stray_config_dirs": ()})

    assert P + "Request or renew the certificate" in fixture.plan(cfg)
    assert fixture.certbot_says(cfg) == {"action": "reinstall", "pending": True}


def test_first_run_writes_then_a_second_run_changes_nothing_and_runs_no_certbot(fixture: Fixture) -> None:
    fixture.sh(f"mkdir -p /letsencrypt/renewal && echo old > /letsencrypt/renewal/old.conf && echo x > {GANDI}")

    first = fixture.deploy(CFG)

    assert mutating(first) == [
        P + f"Write {RFC2136}",
        P + f"Remove {GANDI} once no lineage uses it",
        P + "Remove listed stray certbot dirs",
        # The packaged certbot ships no deploy-hook directory.
        P + "Ensure /etc/letsencrypt/renewal-hooks/deploy",
        P + "Clear special mode bits on /etc/letsencrypt/renewal-hooks/deploy",
        P + f"Write {HOOK}",
    ]
    assert not fixture.exists("/letsencrypt")
    assert not fixture.exists(GANDI)
    assert fixture.sh(f"stat -c '%U:%G %a' {RFC2136}") == "root:root 600"
    assert fixture.sh(f"cat {RFC2136}") + "\n" == render_credentials(CFG, SECRET)
    assert fixture.sh(f"stat -c '%U:%G %a' {HOOK}") == "root:root 755"
    assert fixture.sh(f"cat {HOOK}") + "\n" == render_hook(CFG)
    assert fixture.sh("systemctl is-active certbot.timer") == "active"

    second = fixture.deploy(CFG)

    assert mutating(second) == []
    assert {op.name for op in second if op.changed} == READ_ONLY
    # certbot logs every start; none happened in either run.
    assert not fixture.exists(LOG)


def test_leftover_settings_and_old_file_go_in_one_run(fixture: Fixture) -> None:
    # After an earlier switch: the lineage uses rfc2136 but still names the Gandi file.
    fixture.lineage(extra=f"dns_gandi_credentials = {GANDI}\ndns_gandi_propagation_seconds = 120")
    fixture.sh(f"echo x > {GANDI}")
    conf = f"/etc/letsencrypt/renewal/{DOMAIN}.conf"
    before = fixture.sh(f"stat -c '%U:%G %a' {conf}")
    cfg = CertbotDnsConfig.model_validate({**CFG.model_dump(), "stray_config_dirs": ()})

    ops = fixture.deploy(cfg)

    assert P + "Drop the other providers' settings from the lineage" in mutating(ops)
    assert P + f"Remove {GANDI} once no lineage uses it" in mutating(ops)
    assert "dns_gandi" not in fixture.sh(f"cat {conf}")
    assert "dns_rfc2136_credentials" in fixture.sh(f"cat {conf}")
    assert fixture.sh(f"stat -c '%U:%G %a' {conf}") == before
    assert not fixture.exists(GANDI)
    assert mutating(fixture.deploy(cfg)) == []


def test_old_file_in_use_by_another_lineage_is_kept(fixture: Fixture) -> None:
    fixture.sh(
        f"echo x > {GANDI} && printf 'authenticator = dns-gandi\\ndns_gandi_credentials = {GANDI}\\n' "
        "> /etc/letsencrypt/renewal/other.conf"
    )
    cfg = CertbotDnsConfig.model_validate({**CFG.model_dump(), "stray_config_dirs": (), "single_lineage": False})

    ops = fixture.deploy(cfg)

    assert P + f"Remove {GANDI} once no lineage uses it" not in mutating(ops)
    assert fixture.exists(GANDI)


def test_guard_refusal_stops_before_any_change(fixture: Fixture) -> None:
    fixture.sh("mkdir -p /letsencrypt/renewal && ln -s /tmp /etc/letsencrypt/unexpected")

    with pytest.raises(PyinfraError, match="Refusing stray certbot dirs, nothing removed"):
        fixture.plan(CFG)

    assert fixture.exists("/letsencrypt/renewal")
    assert not fixture.exists(RFC2136)
    assert not fixture.exists(HOOK)


def test_final_checks_fail_on_a_second_lineage_or_a_stopped_consumer(fixture: Fixture) -> None:
    cfg = CertbotDnsConfig.model_validate({**CFG.model_dump(), "stray_config_dirs": ()})
    fixture.deploy(cfg)
    fixture.sh("echo x > /etc/letsencrypt/renewal/second.conf")

    with pytest.raises((AssertionError, PyinfraError)):
        fixture.deploy(cfg)

    fixture.sh("rm /etc/letsencrypt/renewal/second.conf")
    # certbot's renewal/*.conf glob also takes a symlinked configuration.
    fixture.sh(f"ln -s {DOMAIN}.conf /etc/letsencrypt/renewal/other.conf")
    with pytest.raises((AssertionError, PyinfraError)):
        fixture.deploy(cfg)
    fixture.sh("rm /etc/letsencrypt/renewal/other.conf")
    bad = CertbotDnsConfig.model_validate({**cfg.model_dump(), "consumer_units": ("ops-deploy-missing.service",)})
    with pytest.raises((AssertionError, PyinfraError)):
        fixture.deploy(bad)
    assert mutating(fixture.deploy(cfg)) == []
