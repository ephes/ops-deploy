"""``dns_metrics_endpoint``: the role's checks, templates and convergence, on the fake host."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jinja2
import pytest

from ops_deploy.core import ConfigValidationError
from ops_deploy.core.secrets import SecretRef, SecretValues
from ops_deploy.helpers.traefik import hash_password
from ops_deploy.services._metrics_httpd import problems
from ops_deploy.services.dns_metrics_endpoint import DnsMetricsEndpointConfig, deploy_dns_metrics_endpoint
from ops_deploy.services.dns_metrics_endpoint import deploy as dns
from ops_deploy.testing import run_deploy_fake
from tests import fakehost

VALUE = "fixture-endpoint-password"
SECRETS = SecretValues(SecretRef("secrets/fixture.yml"), {"endpoint_password": VALUE})
BIND = "100.64.0.7"
TEMPLATES = Path(__file__).parents[1] / "src/ops_deploy/services/dns_metrics_endpoint/templates"
# RFC 5737 / RFC 3849 documentation addresses, as in the role's defaults.
NAMESERVERS: list[dict[str, Any]] = [
    {"id": "ns1", "label": "ns1.example.com", "role": "primary", "ipv4": "192.0.2.53", "ipv6": "2001:db8:1::53"},
    {"id": "ns2", "label": "ns2.example.com", "role": "secondary", "ipv4": "198.51.100.53", "ipv6": "2001:db8:2::53"},
]
# dns_metrics_endpoint/defaults/main.yml, the derived paths resolved (written out, not from role_vars()).
ROLE_DEFAULTS: dict[str, Any] = {
    "dns_metrics_endpoint_user": "metrics",
    "dns_metrics_endpoint_group": "metrics",
    "dns_metrics_endpoint_bind": BIND,
    "dns_metrics_endpoint_port": 9107,
    "dns_metrics_endpoint_request_timeout": 15,
    "dns_metrics_endpoint_path": "/.well-known/dns",
    "dns_metrics_endpoint_data_dir": "/var/lib/dns-metrics",
    "dns_metrics_endpoint_json_path": "/var/lib/dns-metrics/dns.json",
    "dns_metrics_endpoint_server_path": "/usr/local/bin/dns_metrics_httpd.py",
    "dns_metrics_endpoint_collector_path": "/usr/local/bin/dns_metrics_collector.py",
    "dns_metrics_endpoint_htpasswd_path": "/etc/dns-metrics-endpoint/htpasswd",
    "dns_metrics_endpoint_timer_interval": 300,
    "dns_metrics_endpoint_timer_on_boot_sec": 30,
    "dns_metrics_endpoint_timer_accuracy_sec": 10,
    "dns_metrics_endpoint_timer_randomized_delay_sec": 15,
    "dns_metrics_endpoint_nameservers": NAMESERVERS,
    "dns_metrics_endpoint_zones": ["example.com"],
    "dns_metrics_endpoint_families": ["ipv4", "ipv6"],
    "dns_metrics_endpoint_transports": ["udp", "tcp"],
    "dns_metrics_endpoint_vantage_point_limitations": [],
    "dns_metrics_endpoint_foreign_name": "example.net",
    "dns_metrics_endpoint_foreign_qtype": "A",
    "dns_metrics_endpoint_open_resolver_transport": "udp",
    "dns_metrics_endpoint_dig_timeout": 3,
    "dns_metrics_endpoint_dig_tries": 2,
    "dns_metrics_endpoint_dig_subprocess_timeout": 15,
    "dns_metrics_endpoint_max_workers": 8,
    "dns_metrics_endpoint_ipv6_probe_address": "2001:4860:4860::8888",
}
LIMITATION = {"id": "ns2-ipv6-tcp", "reason": "no TCP to that prefix from here"}


def config(**changes: Any) -> DnsMetricsEndpointConfig:
    fields = {
        "auth_user": "nyxmon",
        "bind": BIND,
        "secrets": "secrets/fixture.yml",
        "nameservers": NAMESERVERS,
        "zones": ["example.com"],
    }
    return DnsMetricsEndpointConfig.model_validate({**fields, **changes})


def render_ansible(template: str, variables: dict[str, Any]) -> str:
    # ansible.builtin.template: trim_blocks on, lstrip_blocks off; to_json is json.dumps.
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(TEMPLATES),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["to_json"] = json.dumps
    return env.get_template(template).render(**variables)


# (config changes, role variables overriding ROLE_DEFAULTS)
VARIANTS: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {
    "defaults": ({}, {}),
    "the monitoring play": (
        {"port": 9108, "zones": ["example.com", "example.org"], "foreign_name": "example.net"},
        {"dns_metrics_endpoint_port": 9108, "dns_metrics_endpoint_zones": ["example.com", "example.org"]},
    ),
    "everything": (
        {
            "user": "dnsmon",
            "group": "dnsgrp",
            "service_name": "dns-x",
            "port": 9200,
            "request_timeout": 7,
            "path": "/x/dns",
            "site_path": "/srv/dns",
            "json_file": "/srv/other.json",
            "server_path": "/opt/dns/httpd.py",
            "collector_path": "/opt/dns/collect.py",
            "htpasswd_dir": "/etc/dns-x",
            "timer_name": "dns-x-collector",
            "timer_interval": 120,
            "timer_on_boot_sec": 5,
            "timer_accuracy_sec": 1,
            "timer_randomized_delay_sec": 0,
            "nameservers": [{"id": "ns1", "ipv4": "192.0.2.53", "transports": ["udp"]}, NAMESERVERS[1]],
            "transports": ["udp", "tcp"],
            "vantage_point_limitations": [LIMITATION],
            "foreign_name": "example.net.",
            "foreign_qtype": "TXT",
            "open_resolver_transport": "tcp",
            "dig_timeout": 2,
            "dig_tries": 3,
            "dig_subprocess_timeout": 9,
            "max_workers": 4,
            "ipv6_probe_address": "2001:db8::1",
        },
        {
            "dns_metrics_endpoint_user": "dnsmon",
            "dns_metrics_endpoint_group": "dnsgrp",
            "dns_metrics_endpoint_port": 9200,
            "dns_metrics_endpoint_request_timeout": 7,
            "dns_metrics_endpoint_path": "/x/dns",
            "dns_metrics_endpoint_data_dir": "/srv/dns",
            "dns_metrics_endpoint_json_path": "/srv/other.json",
            "dns_metrics_endpoint_server_path": "/opt/dns/httpd.py",
            "dns_metrics_endpoint_collector_path": "/opt/dns/collect.py",
            "dns_metrics_endpoint_htpasswd_path": "/etc/dns-x/htpasswd",
            "dns_metrics_endpoint_timer_interval": 120,
            "dns_metrics_endpoint_timer_on_boot_sec": 5,
            "dns_metrics_endpoint_timer_accuracy_sec": 1,
            "dns_metrics_endpoint_timer_randomized_delay_sec": 0,
            "dns_metrics_endpoint_nameservers": [
                {"id": "ns1", "ipv4": "192.0.2.53", "transports": ["udp"]},
                NAMESERVERS[1],
            ],
            "dns_metrics_endpoint_vantage_point_limitations": [LIMITATION],
            "dns_metrics_endpoint_foreign_name": "example.net.",
            "dns_metrics_endpoint_foreign_qtype": "TXT",
            "dns_metrics_endpoint_open_resolver_transport": "tcp",
            "dns_metrics_endpoint_dig_timeout": 2,
            "dns_metrics_endpoint_dig_tries": 3,
            "dns_metrics_endpoint_dig_subprocess_timeout": 9,
            "dns_metrics_endpoint_max_workers": 4,
            "dns_metrics_endpoint_ipv6_probe_address": "2001:db8::1",
        },
    ),
}


@pytest.mark.parametrize("variant", VARIANTS)
@pytest.mark.parametrize("template", sorted(p.name for p in TEMPLATES.glob("*.j2")))
def test_files_are_the_roles_templates_rendered(template: str, variant: str) -> None:
    changes, overrides = VARIANTS[variant]
    expected = render_ansible(template, {**ROLE_DEFAULTS, **overrides})

    assert dns.render_role(template, config(**changes), BIND) == expected


def test_every_role_template_is_shipped() -> None:
    assert sorted(p.name for p in TEMPLATES.iterdir()) == [
        "dns-metrics-collector.service.j2",
        "dns-metrics-collector.timer.j2",
        "dns-metrics-endpoint.service.j2",
        "dns_metrics_collector.py.j2",
        "dns_metrics_httpd.py.j2",
    ]


def test_the_collector_reads_back_its_inputs_with_their_types() -> None:
    cfg = config(vantage_point_limitations=[LIMITATION], zones=["example.com", "home.example.com"])
    namespace: dict[str, Any] = {"__name__": "dns_metrics_collector"}

    exec(compile(dns.render_role("dns_metrics_collector.py.j2", cfg, BIND), "collector", "exec"), namespace)

    assert namespace["NAMESERVERS"] == NAMESERVERS
    assert namespace["ZONES"] == ["example.com", "home.example.com"]
    assert namespace["LIMITATIONS"] == [LIMITATION]
    assert namespace["FOREIGN_NAME"] == "example.net"
    assert namespace["DIG_SUBPROCESS_TIMEOUT"] == 15
    assert namespace["IPV6_PROBE_ADDRESS"] == "2001:4860:4860::8888"


def test_unset_nameserver_fields_stay_out_of_the_collector_json() -> None:
    cfg = config(nameservers=[{"id": "ns1", "ipv4": "192.0.2.53"}])

    assert dns.role_vars(cfg, BIND)["dns_metrics_endpoint_nameservers"] == [{"id": "ns1", "ipv4": "192.0.2.53"}]


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"nameservers": []}, "non-empty"),
        ({"nameservers": [NAMESERVERS[0], NAMESERVERS[0]]}, "unique"),
        ({"nameservers": [{**NAMESERVERS[0], "id": "ns.1"}]}, "id"),
        ({"nameservers": [{**NAMESERVERS[0], "id": "NS1"}]}, "id"),
        ({"nameservers": [{"id": "ns1"}]}, "at least one non-empty"),
        ({"nameservers": [{"id": "ns1", "ipv4": "", "ipv6": ""}]}, "at least one non-empty"),
        ({"nameservers": [{"id": "ns1", "ipv4": "999.999.999.999"}]}, "not a literal IP"),
        ({"nameservers": [{"id": "ns1", "ipv4": "1..2.3"}]}, "not a literal IP"),
        ({"nameservers": [{"id": "ns1", "ipv6": "1::2::3"}]}, "not a literal IP"),
        ({"nameservers": [{"id": "ns1", "ipv4": "2001:db8::53"}]}, "is IPv6, not IPv4"),
        ({"nameservers": [{"id": "ns1", "ipv6": "192.0.2.53"}]}, "is IPv4, not IPv6"),
        ({"nameservers": [{"id": "ns1", "ipv6": "::ffff:192.0.2.53"}]}, "IPv4-mapped"),
        ({"nameservers": [{"id": "ns1", "ipv6": "::ffff:c000:235"}]}, "IPv4-mapped"),
        ({"nameservers": [{"id": "ns1", "ipv4": "192.0.2.53", "families": ["ipv6"]}]}, "no usable address"),
        ({"nameservers": [{"id": "ns1", "ipv4": "192.0.2.53"}], "families": ["ipv6"]}, "no usable address"),
        ({"nameservers": [{**NAMESERVERS[0], "families": []}]}, "non-empty subset"),
        ({"nameservers": [{**NAMESERVERS[0], "transports": ["tcp"]}], "transports": ["udp"]}, "subset"),
        ({"zones": []}, "non-empty"),
        ({"families": []}, "non-empty"),
        ({"families": ["ipv5"]}, "families"),
        ({"transports": ["quic"]}, "transports"),
        ({"transports": ["tcp"]}, "open_resolver_transport"),
        ({"dig_timeout": 0}, "dig_timeout"),
        ({"dig_tries": 0}, "dig_tries"),
        ({"max_workers": 0}, "max_workers"),
        ({"dig_subprocess_timeout": 6}, "must exceed"),
        ({"vantage_point_limitations": [{"id": "ns3-ipv6-tcp", "reason": "x"}]}, "matches no configured"),
        ({"vantage_point_limitations": [{"id": "ns2-ipv6-tcp", "reason": ""}]}, "reason"),
        ({"vantage_point_limitations": ["ns2-ipv6-tcp"]}, "vantage_point_limitations"),
        ({"foreign_name": "example.com"}, "inside the monitored zone"),
        ({"foreign_name": "Example.COM."}, "inside the monitored zone"),
        ({"foreign_name": "www.example.com"}, "inside the monitored zone"),
        ({"foreign_name": ""}, "foreign_name"),
        ({"foreign_name": "x;reboot"}, "foreign_name"),
        ({"zones": ["example.com'''"]}, "zones"),
        ({"nameservers": [{**NAMESERVERS[0], "label": "a'''b"}]}, "label"),
        ({"ipv6_probe_address": "192.0.2.1"}, "ipv6_probe_address"),
        ({"auth_user": "CHANGE_ME"}, "placeholder"),
    ],
)
def test_the_roles_validation_refuses_before_any_host(change: dict[str, Any], message: str) -> None:
    with pytest.raises(ConfigValidationError, match=message):
        config(**change)


def test_a_valid_limitation_and_a_foreign_name_outside_the_zones_pass() -> None:
    cfg = config(vantage_point_limitations=[LIMITATION], foreign_name="example.net.")

    assert cfg.vantage_point_limitations[0].id == "ns2-ipv6-tcp"


def test_httpd_switch_inputs_fit_the_role_contract() -> None:
    endpoint = dns.httpd_endpoint(config(), BIND)

    assert problems(endpoint) == []
    assert endpoint.probe_realm == "dns-metrics"
    assert endpoint.ip_address_allow == ("localhost", "100.64.0.0/10", "fd7a:115c:a1e0::/48")
    # The role's metrics_httpd_switch_argv (tasks/main.yml).
    assert endpoint.argv == (
        *("json-file", "--bind", BIND, "--port", "9107", "--path", "/.well-known/dns"),
        *("--json-path", "/var/lib/dns-metrics/dns.json"),
        *("--htpasswd-file", "/etc/dns-metrics-endpoint/htpasswd"),
        *("--realm", "dns-metrics", "--server-name", "dns-metrics-httpd/0.1"),
        *("--meta", "merge", "--request-timeout", "15"),
    )
    assert endpoint.sandbox == ("NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes")


def converged(**changes: Any) -> tuple[DnsMetricsEndpointConfig, dict[str, Any]]:
    cfg = config(**changes)
    contents = {p.name: dns.render_role(p.name, cfg, BIND) for p in TEMPLATES.glob("*.j2")}
    responses: dict[str, Any] = {
        **fakehost.UBUNTU,
        **fakehost.accounts({"metrics": "/home/metrics"}),
        **fakehost.deb_installed(*cfg.packages),
        **fakehost.directory("/usr/local/bin"),
        **fakehost.directory("/etc/systemd/system"),
        **fakehost.stat(str(cfg.site_path), group="metrics", mode="drwxr-x---"),
        **fakehost.stat(str(cfg.htpasswd_dir), group="metrics", mode="drwxr-x---"),
        **fakehost.file(str(cfg.htpasswd_path), f"nyxmon:{hash_password(VALUE)}\n"),
        **fakehost.stat(str(cfg.htpasswd_path), group="metrics", mode="-rw-r-----"),
        **fakehost.file(str(cfg.json_path), "{}", mode="-rw-r-----"),
        **fakehost.service(cfg.service_name + ".service"),
        **fakehost.service(cfg.timer_name + ".timer"),
    }
    paths = {
        "dns_metrics_collector.py.j2": str(cfg.collector_path),
        "dns_metrics_httpd.py.j2": str(cfg.server_path),
        "dns-metrics-collector.service.j2": f"/etc/systemd/system/{cfg.timer_name}.service",
        "dns-metrics-collector.timer.j2": f"/etc/systemd/system/{cfg.timer_name}.timer",
        "dns-metrics-endpoint.service.j2": f"/etc/systemd/system/{cfg.service_name}.service",
    }
    for template, path in paths.items():
        mode = "-rwxr-xr-x" if not path.startswith("/etc/systemd/") else "-rw-r--r--"
        responses.update(fakehost.file(path, contents[template], mode=mode))
    return cfg, responses


def test_converged_deploy_performs_no_mutations() -> None:
    cfg, responses = converged()
    result = run_deploy_fake(deploy_dns_metrics_endpoint, cfg, SECRETS, responses=responses)

    assert result.succeeded, result.error
    assert result.mutating_changed_ops == []
    assert not any("systemctl start" in c or "systemctl restart" in c for c in result.executed_commands)
    assert "dig -v" in result.executed_commands


def test_missing_metrics_file_runs_the_collector_once() -> None:
    cfg, responses = converged()
    responses.pop(f"test -e {cfg.json_path} ||")
    result = run_deploy_fake(deploy_dns_metrics_endpoint, cfg, SECRETS, responses=responses)

    assert result.succeeded, result.error
    assert result.mutating_changed_ops == [
        "Deploy DNS metrics endpoint | Run collector once to create initial metrics file"
    ]
    assert "systemctl start dns-metrics-collector.service" in result.executed_commands


def test_collector_change_recollects_without_restarting_the_endpoint_or_timer() -> None:
    cfg, responses = converged()
    responses.update(fakehost.file(str(cfg.collector_path), "old collector", mode="-rwxr-xr-x"))
    result = run_deploy_fake(deploy_dns_metrics_endpoint, cfg, SECRETS, responses=responses)

    assert result.succeeded, result.error
    names = result.mutating_changed_ops
    assert any("Run collector once" in name for name in names)
    assert not any("Restart" in name for name in names)


def test_timer_unit_change_reloads_and_restarts_the_timer_only() -> None:
    cfg, responses = converged()
    timer = f"/etc/systemd/system/{cfg.timer_name}.timer"
    responses.update(fakehost.file(timer, "[Timer]\nOnActiveSec=1\n"))
    result = run_deploy_fake(deploy_dns_metrics_endpoint, cfg, SECRETS, responses=responses)

    assert result.succeeded, result.error
    names = result.mutating_changed_ops
    assert any("Reload systemd for DNS metrics" in name for name in names)
    assert any("Restart dns-metrics-collector.timer" in name for name in names)
    assert not any("Restart dns-metrics-endpoint.service" in name for name in names)
    assert not any("Run collector once" in name for name in names)


def test_endpoint_script_change_restarts_the_endpoint() -> None:
    cfg, responses = converged()
    responses.update(fakehost.file(str(cfg.server_path), "old server", mode="-rwxr-xr-x"))
    result = run_deploy_fake(deploy_dns_metrics_endpoint, cfg, SECRETS, responses=responses)

    assert result.succeeded, result.error
    assert any("Restart dns-metrics-endpoint.service" in name for name in result.mutating_changed_ops)


def test_placeholder_password_never_reaches_the_host() -> None:
    cfg, responses = converged()
    secrets = SecretValues(SecretRef("secrets/fixture.yml"), {"endpoint_password": "CHANGE_ME"})
    result = run_deploy_fake(deploy_dns_metrics_endpoint, cfg, secrets, responses=responses)

    assert not result.succeeded
    assert result.executed_commands == []


def test_first_deploy_follows_the_roles_order() -> None:
    responses = {
        **fakehost.UBUNTU,
        **fakehost.directory("/usr/local/bin"),
        **fakehost.directory("/etc/systemd/system"),
    }
    result = run_deploy_fake(deploy_dns_metrics_endpoint, config(), SECRETS, responses=responses)

    assert result.succeeded, result.error
    systemctl = [c for c in result.executed_commands if c.startswith(("systemctl", "dig"))]
    assert systemctl == [
        "dig -v",
        "systemctl daemon-reload",
        "systemctl start dns-metrics-collector.service",
        "systemctl enable dns-metrics-collector.timer",
        "systemctl start dns-metrics-collector.timer",
        "systemctl enable dns-metrics-endpoint.service",
        "systemctl start dns-metrics-endpoint.service",
    ]
    for path, mode in (
        ("/usr/local/bin/dns_metrics_collector.py", "755"),
        ("/usr/local/bin/dns_metrics_httpd.py", "755"),
        ("/etc/systemd/system/dns-metrics-endpoint.service", "644"),
    ):
        assert f"chmod {mode} {path}" in result.executed_commands
    for directory in ("/var/lib/dns-metrics", "/etc/dns-metrics-endpoint"):
        assert f"chmod 750 {directory}" in result.executed_commands
        assert f"chown root:metrics {directory}" in result.executed_commands
    assert VALUE not in " ".join(result.executed_commands)
