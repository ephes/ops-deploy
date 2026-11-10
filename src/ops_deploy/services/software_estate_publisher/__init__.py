"""The software inventory publisher of the ops-library roles ``software_estate_publisher`` (macOS)
and ``software_estate_publisher_linux``."""

from .config import SoftwareEstatePublisherConfig
from .deploy import deploy_software_estate_publisher
from .render import release_id

__all__ = ["SoftwareEstatePublisherConfig", "deploy_software_estate_publisher", "release_id"]
