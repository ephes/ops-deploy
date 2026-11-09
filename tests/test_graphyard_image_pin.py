"""The shipped Grafana default must use a release tag and registry digest."""

import re

from ops_deploy.services.graphyard.core import Grafana


def test_grafana_default_is_pinned() -> None:
    assert re.fullmatch(r"grafana/grafana-oss:[0-9]+\.[0-9]+\.[0-9]+@sha256:[0-9a-f]{64}", Grafana().image)
