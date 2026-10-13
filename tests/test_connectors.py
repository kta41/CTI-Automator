from typing import Any

import pytest
import requests

from cti_automator.config import Settings
from cti_automator.connectors.abusech import ThreatFoxClient
from cti_automator.connectors.otx import OTXClient
from cti_automator.exceptions import ConnectorError
from cti_automator.models import IndicatorType


class FakeResponse:
    def __init__(self, payload: object) -> None:
        self.payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> object:
        return self.payload


class FakeSession:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append({"method": method, "url": url, **kwargs})
        return self.response


def test_otx_client_normalizes_pulse_indicators() -> None:
    session = FakeSession(
        FakeResponse(
            {
                "results": [
                    {
                        "id": "pulse-1",
                        "name": "Example pulse",
                        "indicators": [
                            {
                                "id": "indicator-1",
                                "indicator": "evil.test",
                                "type": "domain",
                            }
                        ],
                    }
                ]
            }
        )
    )
    client = OTXClient(Settings(otx_api_key="secret"), session=session)  # type: ignore[arg-type]

    pulses = client.get_pulses(modified_since="2026-01-01")

    assert pulses[0].indicators[0].indicator_type is IndicatorType.DOMAIN
    assert session.calls[0]["headers"]["X-OTX-API-KEY"] == "secret"
    assert session.calls[0]["params"] == {"modified_since": "2026-01-01"}


def test_threatfox_client_parses_ioc_metadata() -> None:
    session = FakeSession(
        FakeResponse(
            {
                "query_status": "ok",
                "data": [
                    {
                        "id": 42,
                        "ioc": "https://evil.test/payload",
                        "ioc_type": "url",
                        "confidence_level": "95",
                        "first_seen": "2026-01-01 12:00:00",
                        "tags": ["malware"],
                    }
                ],
            }
        )
    )
    client = ThreatFoxClient(
        Settings(abusech_api_key="secret"),
        session=session,  # type: ignore[arg-type]
    )

    result = client.get_recent_iocs(days=7)

    assert result.indicators[0].confidence == 95
    assert result.indicators[0].source_id == "42"
    assert session.calls[0]["json"] == {"query": "get_iocs", "days": 7}


def test_connector_requires_credentials_before_network_call() -> None:
    session = FakeSession(FakeResponse({}))

    with pytest.raises(ValueError, match="OTX_API_KEY"):
        OTXClient(Settings(), session=session).get_pulses()
    assert not session.calls


def test_http_errors_are_domain_errors() -> None:
    class FailingSession:
        def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
            raise requests.Timeout("timed out")

    client = OTXClient(Settings(otx_api_key="secret"), session=FailingSession())  # type: ignore[arg-type]

    with pytest.raises(ConnectorError, match="failed"):
        client.get_pulses()


@pytest.mark.parametrize(
    "value,expected,kind",
    [
        ("8.8.8.8:443", "8.8.8.8", IndicatorType.IPV4),
        ("[2001:4860:4860::8888]:443", "2001:4860:4860::8888", IndicatorType.IPV6),
    ],
)
def test_threatfox_ip_ports_export_as_valid_addresses(value, expected, kind):
    result = ThreatFoxClient._parse_result(
        {
            "query_status": "ok",
            "data": [{"ioc": value, "ioc_type": "ip:port"}],
        }
    )
    assert result.indicators[0].value == expected
    assert result.indicators[0].indicator_type == kind
    assert result.indicators[0].raw_data["ioc"] == value


def test_threatfox_no_result_and_rejected_queries_differ():
    assert (
        ThreatFoxClient._parse_result(
            {"query_status": "no_result", "data": None}
        ).indicators
        == ()
    )
    with pytest.raises(ConnectorError, match="rejected"):
        ThreatFoxClient._parse_result({"query_status": "illegal_days", "data": []})


def test_otx_pagination_fetches_all_pages_and_rejects_cross_origin():
    from unittest.mock import Mock

    session = Mock(spec=requests.Session)
    session.request.side_effect = [
        FakeResponse(
            {
                "results": [{"id": "one", "name": "first"}],
                "next": "https://otx.alienvault.com/api/v1/pulses/subscribed?page=2",
            }
        ),
        FakeResponse({"results": [{"id": "two", "name": "second"}], "next": None}),
    ]
    result = OTXClient(Settings(otx_api_key="secret"), session=session).get_pulses()
    assert [pulse.id for pulse in result] == ["one", "two"]
    session.request.side_effect = [
        FakeResponse({"results": [], "next": "https://attacker.example/"})
    ]
    with pytest.raises(ConnectorError, match="pagination"):
        OTXClient(Settings(otx_api_key="secret"), session=session).get_pulses()
