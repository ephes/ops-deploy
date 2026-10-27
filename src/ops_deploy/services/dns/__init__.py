"""Unbound split DNS and its DDNS/monitoring services."""

from ops_deploy.services.dns.config import DdnsEndpointConfig, DnsConfig
from ops_deploy.services.dns.deploy import deploy_dns

__all__ = ["DdnsEndpointConfig", "DnsConfig", "deploy_dns"]
