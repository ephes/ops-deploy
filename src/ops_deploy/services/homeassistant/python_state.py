"""Prepared original Python/Matter decisions; no host probes or effects here."""

from __future__ import annotations

from dataclasses import dataclass

from .runtime_config import HomeAssistantRuntimeConfig


@dataclass(frozen=True)
class EnvironmentState:
    python_exists: bool
    python_stdout: str = ""
    pip_status: int = 0
    application_exists: bool = False
    installed_version: str = ""
    legacy_matter_status: int = 1
    chip_status: int = 0


@dataclass(frozen=True)
class EnvironmentDecision:
    replace: bool
    install_application: bool
    stop_services: tuple[str, ...]


def _version_mismatch(spec: str, installed: str) -> bool:
    # The original treats only an exact == spec as an installation drift target.
    desired = spec.split("==")[1].strip() if "==" in spec else ""
    return bool(desired) and installed != desired


def _python_mismatch(state: EnvironmentState, desired: str) -> bool:
    if not state.python_exists:
        return False
    parts = state.python_stdout.split()
    if len(parts) < 2:
        # Original split()[1] also aborts rather than silently rebuilding on an
        # unrecognised interpreter response. Do not hide a failed probe.
        raise ValueError("existing virtualenv returned no Python version")
    return parts[1] != desired


def homeassistant_application_required(
    cfg: HomeAssistantRuntimeConfig, state: EnvironmentState, *, llama_cpp_rebuild: bool = False
) -> bool:
    return (
        cfg.force_reinstall
        or llama_cpp_rebuild
        or not state.application_exists
        or _version_mismatch(cfg.package_spec, state.installed_version)
    )


def matter_application_required(cfg: HomeAssistantRuntimeConfig, state: EnvironmentState) -> bool:
    return (
        cfg.force_reinstall
        or not state.application_exists
        or _version_mismatch(cfg.matter_server_package_spec, state.installed_version)
        or state.chip_status != 0
    )


def homeassistant_decision(
    cfg: HomeAssistantRuntimeConfig,
    state: EnvironmentState,
    *,
    llama_cpp_rebuild: bool = False,
    unit_exists: bool = False,
    matter_unit_exists: bool = False,
) -> EnvironmentDecision:
    mismatch = _python_mismatch(state, cfg.python_version)
    replace = (
        cfg.force_reinstall
        or llama_cpp_rebuild
        or not state.python_exists
        or mismatch
        or state.pip_status != 0
        or state.legacy_matter_status == 0
    )
    stops: list[str] = []
    if replace and state.python_exists:
        # This original stop is deliberately not gated by manage_matter_server:
        # a legacy shared environment may still have an existing Matter unit.
        if matter_unit_exists:
            stops.append(cfg.matter_server_service_name)
        if unit_exists:
            stops.append(cfg.service_name)
    install = homeassistant_application_required(cfg, state, llama_cpp_rebuild=llama_cpp_rebuild)
    # Replacement removes the old application binary before its subsequent stat.
    return EnvironmentDecision(replace, replace or install, tuple(stops))


def matter_decision(
    cfg: HomeAssistantRuntimeConfig,
    state: EnvironmentState,
    *,
    unit_exists: bool = False,
) -> EnvironmentDecision:
    mismatch = _python_mismatch(state, cfg.python_version)
    replace = cfg.force_reinstall or not state.python_exists or mismatch or state.pip_status != 0
    stops = (cfg.matter_server_service_name,) if replace and state.python_exists and unit_exists else ()
    install = matter_application_required(cfg, state)
    return EnvironmentDecision(replace, replace or install, stops)
