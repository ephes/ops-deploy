"""Original Python/Rust endpoint contract with bounded cached-report refresh."""

from __future__ import annotations

import re
import shlex
from pathlib import PurePosixPath

from pydantic import SecretStr
from pyinfra import host
from pyinfra.api import DeployError, deploy
from pyinfra.facts.server import KernelVersion, LinuxDistribution
from pyinfra.operations import files, server, systemd
from pyinfra.operations.util import any_changed

from ops_deploy.helpers.checks import mark_read_only
from ops_deploy.helpers.probes import verify_probe
from ops_deploy.infra._monitoring import prerequisites
from ops_deploy.services import _metrics_httpd as metrics_httpd
from ops_deploy.services.fractal_monitoring.config import SchemaRule
from ops_deploy.services.fractal_monitoring.deploy import (
    admit_paths,
    endpoint_account,
    finish_endpoint,
    path_row,
    reconcile_endpoint,
)

from .metrics_config import TailscaleMetricsConfig
from .render import render


def endpoint(cfg: TailscaleMetricsConfig) -> metrics_httpd.Endpoint:
    return metrics_httpd.Endpoint(
        service_name=cfg.service_name,
        user=cfg.user,
        group=cfg.group,
        argv=(
            "json-file",
            "--bind",
            cfg.bind,
            "--port",
            str(cfg.port),
            "--path",
            cfg.path,
            "--json-path",
            cfg.json_path,
            "--htpasswd-file",
            cfg.htpasswd_path,
            "--realm",
            "tailscale-metrics",
            "--server-name",
            "tailscale-metrics-httpd/0.1",
            "--path-match",
            "path-only",
        ),
        sandbox=(
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "PrivateTmp=yes",
            f"ReadOnlyPaths={cfg.data_dir}",
        ),
        python_script=cfg.server_path,
        probe_bind=cfg.bind,
        probe_port=cfg.port,
        probe_path=cfg.path,
        probe_realm="tailscale-metrics",
        ip_address_allow=cfg.ip_address_allow,
    )


def schema() -> tuple[SchemaRule, ...]:
    # False health results are valid fresh telemetry; deploying must not hide
    # them by collecting again or claiming they are a schema error.
    return (
        SchemaRule(path=("summary",), kind="mapping"),
        *[
            SchemaRule(path=("summary", key), kind="boolean")
            for key in (
                "backend_running",
                "self_online",
                "key_expiry_warning_ok",
                "key_expiry_critical_ok",
                "overall_ok",
            )
        ],
        SchemaRule(path=("meta", "age_seconds"), kind="number"),
    )


@deploy("Deploy cached Tailscale metrics endpoint")
def deploy_tailscale_metrics(cfg: TailscaleMetricsConfig, credential: SecretStr) -> None:
    if not cfg.enabled:
        return
    value = credential.get_secret_value()
    if (
        not value
        or value.lower() in {"change_me", "changeme", "placeholder", "example"}
        or re.search(r"[\x00-\x1f\x7f]", value)
        or len(value.encode()) > 72
    ):
        raise DeployError("Tailscale endpoint requires a bounded non-placeholder bcrypt credential")
    debt = f"/var/lib/ops-deploy/tailscale/{cfg.service_name}-rollout.json"
    paths = [path_row(p, "directory") for p in (cfg.data_dir, cfg.htpasswd_dir, str(PurePosixPath(debt).parent))]
    paths += [
        path_row(p)
        for p in (
            cfg.server_path,
            cfg.exporter_path,
            cfg.htpasswd_path,
            cfg.json_path,
            cfg.json_path + ".tmp",
            debt,
            str(PurePosixPath(debt).parent / "lock"),
            f"/etc/systemd/system/{cfg.service_name}.service",
            f"/etc/systemd/system/{cfg.timer_name}.service",
            f"/etc/systemd/system/{cfg.timer_name}.timer",
        )
    ]
    # Native distribution tools may legitimately be usr-merge symlinks. They
    # are execution prerequisites, never managed configuration/file targets.
    verify_probe("test -x " + shlex.quote(cfg.tailscale_bin), name="Native Tailscale collector binary")
    if cfg.require_default_ipv4_route:
        verify_probe("test -x " + shlex.quote(cfg.ip_bin), name="Native configured route probe")
    admit_paths(paths)
    prerequisites(cfg.packages)
    if cfg.require_effective_ip_filter:
        distribution = host.get_fact(LinuxDistribution)
        kernel = host.get_fact(KernelVersion)
        packages = (
            ("linux-tools-common", "linux-tools-generic", "linux-tools-" + kernel)
            if distribution["name"] == "Ubuntu"
            else ("bpftool",)
        )
        prerequisites(packages)
        verify_probe(cfg.bpftool_bin + " version", name="Native endpoint cgroup-BPF tooling")
    endpoint_account(
        name="Ensure metadata-only endpoint account, no home or verifier fact", user=cfg.user, group=cfg.group
    )
    for directory in (cfg.data_dir, cfg.htpasswd_dir):
        files.directory(
            name="Ensure original Tailscale metrics directory",
            path=directory,
            user="root",
            group=cfg.group,
            mode="0750",
        )
    resources = [
        (cfg.exporter_path, "tailscale_metrics_exporter.py", 0o755, dict(refresh=True)),
        (cfg.server_path, "tailscale_metrics_httpd.py", 0o755, dict(restart=True)),
        (
            f"/etc/systemd/system/{cfg.service_name}.service",
            "tailscale-metrics-endpoint.service",
            0o644,
            dict(restart=True),
        ),
        (
            f"/etc/systemd/system/{cfg.timer_name}.service",
            "tailscale-metrics-collector.service",
            0o644,
            dict(refresh=True),
        ),
        (
            f"/etc/systemd/system/{cfg.timer_name}.timer",
            "tailscale-metrics-collector.timer",
            0o644,
            dict(refresh=True, timer=True),
        ),
    ]
    data = dict(
        files=[
            dict(path=path, content=render(cfg, resource), mode=mode, **flags)
            for path, resource, mode, flags in resources
        ],
        paths=paths,
        group=cfg.group,
        auth_user=cfg.auth_user,
        htpasswd_path=cfg.htpasswd_path,
        json_path=cfg.json_path,
        freshness_sec=cfg.freshness_sec,
        schema=[rule.model_dump() for rule in schema()],
        service=cfg.service_name + ".service",
        timer=cfg.timer_name + ".timer",
        collector=cfg.timer_name + ".service",
        collector_timeout=120,
        debt=debt,
    )
    reconciliation = reconcile_endpoint(
        name="Reconcile Tailscale resources/auth and refresh only actual debt/staleness",
        payload=data,
        credential=credential,
    )
    selection = metrics_httpd.select(
        endpoint(cfg), cfg, check_when=lambda: reconciliation.did_change(), transient_check_is_mutation=True
    )
    systemd.daemon_reload(
        name="Reload only selected endpoint implementation changes", _if=any_changed(selection.dropin)
    )
    finish_endpoint(
        name="Converge selected Tailscale endpoint without redundant restart",
        payload=data,
        credential=credential,
        dropin=selection.dropin,
        inputs=reconciliation,
    )
    metrics_httpd.verify(selection)
    if cfg.require_effective_ip_filter:
        script = (
            "control=$(systemctl show "
            + shlex.quote(cfg.service_name + ".service")
            + ' --property=ControlGroup --value) && test -n "$control" && filters=$('
            + shlex.quote(cfg.bpftool_bin)
            + ' cgroup show /sys/fs/cgroup"$control")'
            + ' && printf %s "$filters" | grep -q cgroup_inet_ingress'
            + ' && printf %s "$filters" | grep -q cgroup_inet_egress'
        )
        mark_read_only(
            server.shell(name="Verify actual endpoint ingress and egress cgroup-BPF attachment", commands=[script])
        )
