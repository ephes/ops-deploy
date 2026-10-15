"""static_site: generated read-only site behind Traefik (port of the static_site_deploy role)."""

from ops_deploy.services.static_site.deploy import (
    StaticSiteConfig,
    StaticSiteSourceError,
    deploy_static_site,
    validate_source,
)

__all__ = ["StaticSiteConfig", "StaticSiteSourceError", "deploy_static_site", "validate_source"]
