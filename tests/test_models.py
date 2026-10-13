from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from cti_automator.models import Indicator, IndicatorType, IntelligenceSource


def test_indicator_normalizes_value_and_tags() -> None:
    indicator = Indicator(
        value="  evil.example  ",
        indicator_type=IndicatorType.DOMAIN,
        source=IntelligenceSource.OTX,
        tags=(" malware ", "", "malware"),
    )

    assert indicator.value == "evil.example"
    assert indicator.tags == ("malware",)


def test_indicator_rejects_invalid_confidence() -> None:
    with pytest.raises(ValidationError):
        Indicator(
            value="192.0.2.1",
            indicator_type=IndicatorType.IPV4,
            source=IntelligenceSource.OTX,
            confidence=101,
        )


def test_indicator_accepts_timestamps() -> None:
    indicator = Indicator(
        value="https://example.test/a",
        indicator_type=IndicatorType.URL,
        source=IntelligenceSource.THREATFOX,
        first_seen=datetime(2026, 1, 1, tzinfo=UTC),
    )

    assert indicator.first_seen is not None
