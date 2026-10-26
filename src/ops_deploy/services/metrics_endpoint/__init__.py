"""Authenticated mail metrics endpoint, ported from the metrics_endpoint role."""

from ops_deploy.services.metrics_endpoint.common import CREDENTIAL_FIELD
from ops_deploy.services.metrics_endpoint.deploy import MetricsEndpointConfig, ProbeState, deploy_metrics_endpoint

__all__ = ["CREDENTIAL_FIELD", "MetricsEndpointConfig", "ProbeState", "deploy_metrics_endpoint"]
