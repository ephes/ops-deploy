"""Unbound split DNS and its DDNS/monitoring services."""

from ops_deploy.services.dns.config import DdnsEndpointConfig, DdnsStaticRecord, DnsConfig
from ops_deploy.services.dns.deploy import deploy_dns
from ops_deploy.services.dns.remove import DnsRemoveConfig, deploy_dns_remove

__all__ = ["DdnsEndpointConfig", "DdnsStaticRecord", "DnsConfig", "DnsRemoveConfig", "deploy_dns", "deploy_dns_remove"]
