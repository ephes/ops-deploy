"""Authoritative-DNS health endpoint: root collector/timer and authenticated HTTP endpoint."""

from ops_deploy.services.dns_metrics_endpoint.deploy import (
    DnsMetricsEndpointConfig,
    Limitation,
    Nameserver,
    deploy_dns_metrics_endpoint,
)
from ops_deploy.services.metrics_endpoint.common import CREDENTIAL_FIELD

__all__ = [
    "CREDENTIAL_FIELD",
    "DnsMetricsEndpointConfig",
    "Limitation",
    "Nameserver",
    "deploy_dns_metrics_endpoint",
]
