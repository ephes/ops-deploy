"""Read-only checks: the port preflight before any change, the rollout checks after it (2.9).

Each is one shell operation tagged read-only (``helpers.mark_read_only``), so
a converged run reports no mutating change.
"""

from __future__ import annotations

import shlex

from pyinfra.api.operation import OperationMeta
from pyinfra.operations import server

from ops_deploy.helpers import http_check, mark_read_only
from ops_deploy.services.compose_app.config import ComposeAppConfig


def _check(name: str, script: str) -> OperationMeta:
    return mark_read_only(server.shell(name=name, commands=[f"sh -c {shlex.quote(script)}"]))


def _project(cfg: ComposeAppConfig) -> str:
    return shlex.quote(f"label=com.docker.compose.project={cfg.project}")


def port_preflight(cfg: ComposeAppConfig) -> OperationMeta | None:
    """Every published port is free, or held by a container of this project.

    A listener on the port's address (or a wildcard address) that is not one
    of the project's published ports aborts the run before any change and
    names the port and the process holding it. The project's ports come from
    ``docker ps`` (``<ip>:<port>->``), so the check needs no list of owners.
    """

    if not cfg.published_ports:
        return None
    # One line per container: "127.0.0.1:18080->8080/tcp, ..."; joined into one space-separated line.
    ports = f"docker ps --filter {_project(cfg)} --format '{{{{.Ports}}}}' 2>/dev/null | tr ',\\n' '  '"
    lines = [f"ours=$({ports})", "bad=0"]
    for port in cfg.published_ports:
        flag = "-Hltnp" if port.protocol == "tcp" else "-Hlunp"
        wildcard = "0.0.0.0" if ":" not in port.host_ip else "[::]"
        address = f"[{port.host_ip}]" if ":" in port.host_ip else port.host_ip
        # Compared as strings (awk ==, grep -F): IPv6 addresses carry brackets.
        candidates = " ".join(f"{a}:{port.published}" for a in dict.fromkeys((address, wildcard, "[::]", "*")))
        lines.append(
            f"held=$(ss {flag} 'sport = :{port.published}' | awk -v c={shlex.quote(candidates)} "
            "'BEGIN {n = split(c, w, \" \")} {for (i = 1; i <= n; i++) if ($4 == w[i]) print $4, $6}')"
        )
        lines.append(
            f'if [ -n "$held" ] && ! printf "%s" " $ours " | grep -qF " {address}:{port.published}->"; then '
            f'echo "port {port.protocol}/{port.published} is in use: $held" >&2; bad=1; fi'
        )
    lines.append('[ "$bad" = 0 ]')
    return _check("Port preflight", "; ".join(lines))


def compose_state(cfg: ComposeAppConfig) -> OperationMeta:
    """Every service without a profile runs, and is healthy if it has a healthcheck."""

    wanted = []
    for service in cfg.running_services:
        wanted.append(f"{service.name}:running:{'healthy' if service.healthcheck else 'none'}")
    fmt = (
        '{{index .Config.Labels "com.docker.compose.service"}}:{{.State.Status}}:'
        "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}"
    )
    script = (
        f"wanted={shlex.quote(' '.join(sorted(wanted)))}; "
        f"for i in $(seq 1 {cfg.checks.timeout}); do "
        f"ids=$(docker ps -aq --filter {_project(cfg)} --filter label=com.docker.compose.oneoff=False); "
        f'now=$([ -n "$ids" ] && docker inspect --format {shlex.quote(fmt)} $ids | tr "\\n" " "); '
        'missing=""; for item in $wanted; do '
        'case " $now " in *" $item "*) ;; *) missing="$missing $item" ;; esac; done; '
        '[ -z "$missing" ] && exit 0; sleep 1; done; '
        'echo "services not running (and healthy):$missing" >&2; exit 1'
    )
    return _check(f"Check the {cfg.project} services run", script)


def namespaces(cfg: ComposeAppConfig) -> list[OperationMeta]:
    """Each ``network_mode: service:X`` container shares X's network namespace."""

    ops = []
    for provider in cfg.providers:
        for dependent in cfg.dependents(provider):

            def ids(service: str) -> str:
                label = shlex.quote(f"label=com.docker.compose.service={service}")
                return f"docker ps -q --no-trunc --filter {_project(cfg)} --filter {label}"

            script = (
                f"x=$({ids(provider)}); d=$({ids(dependent)}); "
                '[ -n "$x" ] && [ -n "$d" ] && '
                'mode=$(docker inspect --format "{{.HostConfig.NetworkMode}}" "$d") && '
                '[ "$mode" = "container:$x" ] || '
                f"{{ echo '{dependent} does not share the network namespace of {provider}' >&2; exit 1; }}"
            )
            ops.append(_check(f"Check {dependent} runs in the network namespace of {provider}", script))
    return ops


def listen(cfg: ComposeAppConfig) -> list[OperationMeta]:
    """Each published TCP port listens on its address only."""

    ops = []
    for port in cfg.published_ports:
        if port.protocol != "tcp":
            continue
        address = f"[{port.host_ip}]" if ":" in port.host_ip else port.host_ip
        script = (
            f"out=$(ss -Hltn 'sport = :{port.published}' | awk '{{print $4}}'); "
            f'[ -n "$out" ] || {{ echo "nothing listens on port {port.published}" >&2; exit 1; }}; '
            f'other=$(printf "%s\\n" "$out" | grep -vxF "{address}:{port.published}" || true); '
            f'[ -z "$other" ] || {{ echo "port {port.published} also listens on $other" >&2; exit 1; }}'
        )
        ops.append(_check(f"Check port {port.published} listens on {port.host_ip} only", script))
    return ops


def rollout_checks(cfg: ComposeAppConfig) -> None:
    compose_state(cfg)
    namespaces(cfg)
    listen(cfg)
    for check in cfg.checks.http:
        http_check(check.url, status=check.statuses, host_header=check.host_header)
