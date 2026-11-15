"""Configuration renderer input guards; the renders themselves are golden (test_homeassistant_golden)."""

from __future__ import annotations

import jinja2
import pytest
from pydantic import ValidationError

from ops_deploy.services.homeassistant.configuration_render import (
    ConfigurationValues,
    render_configuration,
    render_include,
)
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig


def test_unknown_template_and_input_are_not_silently_ignored() -> None:
    with pytest.raises(jinja2.TemplateNotFound):
        render_include("missing.yaml")
    with pytest.raises(ValidationError) as error:
        ConfigurationValues.model_validate({"unrecognized": "synthetic-private"})
    assert "synthetic-private" not in str(error.value)


@pytest.mark.parametrize(("latitude", "longitude"), [(51, 7), (0, -1), (51.2, -1.4), (51, 7.0)])
def test_coordinate_original_input_types_are_preserved(latitude: int | float, longitude: int | float) -> None:
    values = ConfigurationValues(latitude=latitude, longitude=longitude)
    assert type(values.latitude) is type(latitude)
    assert type(values.longitude) is type(longitude)
    rendered = render_configuration(HomeAssistantRuntimeConfig(), values).get_secret_value()
    assert rendered.count(f"latitude: {latitude}\n") == 2
    assert rendered.count(f"longitude: {longitude}\n") == 2


@pytest.mark.parametrize("value", [True, "51"])
def test_coordinate_bad_types_do_not_silently_coerce(value: object) -> None:
    with pytest.raises(ValidationError):
        ConfigurationValues.model_validate({"latitude": value})
