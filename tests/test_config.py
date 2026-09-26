import pytest
from pydantic import ValidationError

from kali_ops_agent.config import EngagementConfig


def test_defaults_are_finite_and_positive():
    config = EngagementConfig(engagement_id="eng-1", scope=["lab.internal"])
    assert config.rate_capacity == 10.0
    assert config.rate_refill_per_sec == 1.0
    assert config.operator_id == "operator"


def test_non_finite_rate_values_rejected():
    # Pydantic v2 accepts inf/NaN in float fields by default; allow_inf_nan=False
    # must reject them so a non-finite rate cannot disable the safety budget.
    for bad in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValidationError):
            EngagementConfig(engagement_id="eng-1", rate_capacity=bad)
        with pytest.raises(ValidationError):
            EngagementConfig(engagement_id="eng-1", rate_refill_per_sec=bad)


def test_non_positive_rate_values_rejected():
    with pytest.raises(ValidationError):
        EngagementConfig(engagement_id="eng-1", rate_capacity=0)
    with pytest.raises(ValidationError):
        EngagementConfig(engagement_id="eng-1", rate_refill_per_sec=-1)
