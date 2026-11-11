"""Pinned chip-ota-provider-app release (inputs only; installation in ``ota_provider``)."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import AfterValidator

OTA_PROVIDER_VERSION = "2025.9.0"
# The release python-matter-server's own Dockerfile pins.
OTA_PROVIDER_URL_TEMPLATE = (
    "https://github.com/home-assistant-libs/matter-linux-ota-provider/releases/download/"
    "{version}/chip-ota-provider-app-{arch}"
)
OtaArch = Literal["x86-64", "aarch64"]

OTA_PROVIDER_CHECKSUMS: dict[OtaArch, str] = {
    "x86-64": "4550df7af6529e4620463d1c0127f830ec2404c817ad4c6343b29e32cec0144e",
    "aarch64": "e068ab6c4050e23eaa6ccda9bf7eccdc4b792a2514e1098cbc12b414cd64aa7e",
}
# ``uname -m`` -> the release asset's architecture name.
OTA_ARCHES = {"x86_64": "x86-64", "amd64": "x86-64", "aarch64": "aarch64", "arm64": "aarch64"}


def _url_template(value: str) -> str:
    if not value.startswith("https://") or any(c.isspace() or ord(c) < 32 for c in value):
        raise ValueError("OTA provider URL template must be an https URL without whitespace")
    try:
        value.format(version="0", arch="x86-64")
    except (KeyError, IndexError, ValueError):
        raise ValueError("OTA provider URL template may only use {version} and {arch}") from None
    return value


OtaUrlTemplate = Annotated[str, AfterValidator(_url_template)]

# python-matter-server looks the program up by this name on the Matter unit's
# PATH (matter-server.service.j2: <venv>/bin:/usr/local/bin:/usr/bin:/bin).
OTA_PROVIDER_NAME = "chip-ota-provider-app"
OTA_PROVIDER_DIRS = ("/usr/local/bin", "/usr/bin", "/bin")


def _provider_path(value: str) -> str:
    parent, _, name = value.rpartition("/")
    if name != OTA_PROVIDER_NAME or parent not in OTA_PROVIDER_DIRS:
        raise ValueError(
            "OTA provider path must be chip-ota-provider-app in a directory on the Matter unit's PATH: "
            + ", ".join(OTA_PROVIDER_DIRS)
        )
    return value


OtaProviderPath = Annotated[str, AfterValidator(_provider_path)]


def ota_provider_url(template: str, version: str, arch: str) -> str:
    return template.format(version=version, arch=arch)
