"""Nyxmon json-metrics rules for OS lifecycle reports.

Nyxmon only compares a value at a JSON path with a constant (``< <= > >= ==
!=``, ``warning`` or ``critical``); a missing or ``null`` value fails the
rule. The report therefore carries every age and remaining time as a number,
and each rule below states what must hold. Critical is reserved for a broken
mechanism (no fresh report, unattended-upgrades off or failing for a week)
and hard deadlines; everything that can be planned is a warning.

Two shapes:

- :func:`endpoint_rules`: a host's own endpoint (``$`` is its report;
  ``$.meta.age_seconds`` is the endpoint's age of the file);
- :func:`remote_rules`: one host inside the pull file of the monitoring host
  (``$.hosts.<name>``: the pull's state and the last report it got).
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator

from ops_deploy.services._nyxmon_json_metrics import JsonMetricsCheck

Positive = Annotated[StrictInt, Field(ge=1)]
# Host names inside JSONPath dot notation: no dots, dashes or quoting.
HostKey = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_]{0,62}$")]
Severity = Literal["warning", "critical"]
CHECK_DATA: dict[str, Any] = {"timeout": 15.0, "retries": 1, "retry_delay": 5.0}


class Thresholds(BaseModel):
    """The rules' limits; the defaults are the design's (owner decision D4: design defaults)."""

    model_config = ConfigDict(extra="forbid", frozen=True, validate_default=True, hide_input_in_errors=True)

    # The collector runs hourly (plus up to 10 min jitter).
    report_max_age_seconds: Positive = 7200
    # Remote hosts: the pull runs hourly; one missed pull is tolerated.
    pull_max_age_hours: Positive = 3
    uu_success_warning_hours: Positive = 48
    uu_success_critical_hours: Positive = 168
    security_index_warning_hours: Positive = 48
    security_index_critical_hours: Positive = 168
    pending_security_warning_hours: Positive = 72
    pending_security_critical_hours: Positive = 168
    # Hosts rebooted by hand (classes A and B, and C until its window exists).
    reboot_warning_hours: Positive = 168
    reboot_critical_hours: Positive = 504
    # Hosts with an automatic reboot window (class C): a missed window, then two.
    reboot_window_warning_hours: Positive = 192
    reboot_window_critical_hours: Positive = 360
    uptime_warning_days: Positive = 120
    uptime_critical_days: Positive = 240
    support_warning_days: Positive = 365
    eol_warning_days: Positive = 180
    eol_critical_days: Positive = 60
    lifecycle_data_max_age_days: Positive = 120

    @model_validator(mode="after")
    def _ordered(self) -> Thresholds:
        pairs = [
            ("uu_success", self.uu_success_warning_hours, self.uu_success_critical_hours),
            ("security_index", self.security_index_warning_hours, self.security_index_critical_hours),
            ("pending_security", self.pending_security_warning_hours, self.pending_security_critical_hours),
            ("reboot", self.reboot_warning_hours, self.reboot_critical_hours),
            ("reboot_window", self.reboot_window_warning_hours, self.reboot_window_critical_hours),
            ("uptime", self.uptime_warning_days, self.uptime_critical_days),
        ]
        for name, warning, critical in pairs:
            if warning >= critical:
                raise ValueError(f"{name}: the warning limit must be below the critical limit")
        if self.eol_critical_days >= self.eol_warning_days:
            raise ValueError("eol: the critical limit must be below the warning limit")
        return self


def _rule(path: str, op: str, value: Any, severity: Severity) -> dict[str, Any]:
    return {"path": path, "op": op, "value": value, "severity": severity}


def report_rules(
    t: Thresholds,
    *,
    prefix: str = "$",
    unattended_upgrades: bool = True,
    security_index: bool = True,
    reboot_window: bool = False,
) -> list[dict[str, Any]]:
    """The rules on one report under ``prefix``.

    ``unattended_upgrades``: the host is expected to run unattended-upgrades
    (off until the policy is rolled out there). ``security_index``: also
    watch the age of the security index (left out where ``software_live``
    already does). ``reboot_window``: the host reboots itself in a window.
    """

    p = prefix
    rules = []
    if unattended_upgrades:
        rules += [
            _rule(f"{p}.uu.enabled", "==", True, "critical"),
            _rule(f"{p}.uu.last_success_age_hours", "<=", t.uu_success_warning_hours, "warning"),
            _rule(f"{p}.uu.last_success_age_hours", "<=", t.uu_success_critical_hours, "critical"),
        ]
    if security_index:
        rules += [
            _rule(f"{p}.apt.security_index_age_hours", "<=", t.security_index_warning_hours, "warning"),
            _rule(f"{p}.apt.security_index_age_hours", "<=", t.security_index_critical_hours, "critical"),
        ]
    reboot = (
        (t.reboot_window_warning_hours, t.reboot_window_critical_hours)
        if reboot_window
        else (t.reboot_warning_hours, t.reboot_critical_hours)
    )
    rules += [
        _rule(f"{p}.apt.pending_security_max_age_hours", "<=", t.pending_security_warning_hours, "warning"),
        _rule(f"{p}.apt.pending_security_max_age_hours", "<=", t.pending_security_critical_hours, "critical"),
        _rule(f"{p}.reboot.required_age_hours", "<=", reboot[0], "warning"),
        _rule(f"{p}.reboot.required_age_hours", "<=", reboot[1], "critical"),
        _rule(f"{p}.reboot.uptime_days", "<=", t.uptime_warning_days, "warning"),
        _rule(f"{p}.reboot.uptime_days", "<=", t.uptime_critical_days, "critical"),
        _rule(f"{p}.os.upgrade_due", "==", False, "warning"),
        _rule(f"{p}.os.support_days_remaining", ">=", t.support_warning_days, "warning"),
        _rule(f"{p}.os.eol_days_remaining", ">=", t.eol_warning_days, "warning"),
        _rule(f"{p}.os.eol_days_remaining", ">=", t.eol_critical_days, "critical"),
        _rule(f"{p}.os.lifecycle_sources_agree", "==", True, "warning"),
        _rule(f"{p}.os.lifecycle_data_age_days", "<=", t.lifecycle_data_max_age_days, "warning"),
    ]
    return rules


def endpoint_rules(
    t: Thresholds, *, unattended_upgrades: bool = True, security_index: bool = True, reboot_window: bool = False
) -> list[dict[str, Any]]:
    """A host's own endpoint: a fresh report, then :func:`report_rules` on it."""

    rules = report_rules(
        t, unattended_upgrades=unattended_upgrades, security_index=security_index, reboot_window=reboot_window
    )
    return [_rule("$.meta.age_seconds", "<", t.report_max_age_seconds, "critical"), *rules]


def remote_rules(
    t: Thresholds,
    host: str,
    *,
    unattended_upgrades: bool = True,
    security_index: bool = True,
    reboot_window: bool = False,
) -> list[dict[str, Any]]:
    """One host in the pull file: the pull ran, reached the host, and the report is fresh."""

    p = f"$.hosts.{host}"
    return [
        _rule("$.meta.age_seconds", "<", t.report_max_age_seconds, "critical"),
        _rule(f"{p}.pull_ok", "==", True, "warning"),
        _rule(f"{p}.last_pull_success_age_hours", "<=", t.pull_max_age_hours, "critical"),
        _rule(f"{p}.report_age_hours", "<=", t.pull_max_age_hours, "critical"),
        *report_rules(
            t,
            prefix=f"{p}.report",
            unattended_upgrades=unattended_upgrades,
            security_index=security_index,
            reboot_window=reboot_window,
        ),
    ]


def lifecycle_check(
    *,
    service_name: str,
    name: str,
    url: str,
    rules: list[dict[str, Any]],
    auth_username: str | None,
    check_interval: int = 1800,
) -> JsonMetricsCheck:
    """One json-metrics check of an endpoint with ``rules``."""

    return JsonMetricsCheck.model_validate(
        {
            "service_name": service_name,
            "name": name,
            "check_interval": check_interval,
            "auth_username": auth_username,
            "data": {"url": url, **CHECK_DATA, "checks": rules},
        }
    )


__all__ = [
    "CHECK_DATA",
    "HostKey",
    "Thresholds",
    "endpoint_rules",
    "lifecycle_check",
    "remote_rules",
    "report_rules",
]
