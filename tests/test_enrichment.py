from datetime import UTC, datetime
from unittest.mock import Mock

import pytest
import requests

from cti_automator.config import Settings
from cti_automator.enrichment import EnrichmentService, QuotaError
from cti_automator.exceptions import ConnectorError
from cti_automator.exporters.stix import STIXExporter
from cti_automator.models import Indicator, IndicatorType, IntelligenceSource


def indicator(value="8.8.8.8", kind=IndicatorType.IPV4):
    return Indicator(value=value, indicator_type=kind, source=IntelligenceSource.OTX)


def response(status=200, payload=None):
    result = Mock(spec=requests.Response)
    result.status_code = status
    result.json.return_value = payload or {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 2,
                    "suspicious": 0,
                    "harmless": 1,
                    "undetected": 1,
                }
            }
        }
    }
    return result


def test_disabled_enrichment_does_not_require_keys_or_call_network():
    session = Mock(spec=requests.Session)
    item = indicator("10.0.0.1")
    assert EnrichmentService(Settings(), session=session).enrich([item]) == (item,)
    session.get.assert_not_called()


@pytest.mark.parametrize(
    "value,kind",
    [
        ("10.0.0.1", IndicatorType.IPV4),
        ("127.0.0.1", IndicatorType.IPV4),
        ("169.254.169.254", IndicatorType.IPV4),
        ("fd00::1", IndicatorType.IPV6),
        ("::ffff:10.0.0.1", IndicatorType.IPV6),
        ("corp.internal", IndicatorType.DOMAIN),
        ("person@company.com", IndicatorType.EMAIL),
        ("https://public.com/private?token=secret", IndicatorType.URL),
        ("not-a-hash", IndicatorType.FILE_HASH_MD5),
        ("a.corp.com", IndicatorType.DOMAIN),
        ("a.example.com", IndicatorType.DOMAIN),
        ("bad.invalid", IndicatorType.DOMAIN),
        ("2001:4860:4860::8888", IndicatorType.IPV4),
    ],
)
def test_private_or_invalid_values_rejected_before_any_request(value, kind):
    session = Mock(spec=requests.Session)
    service = EnrichmentService(
        Settings(virustotal_api_key="secret", restricted_domains=("corp.com",)),
        session=session,
    )
    with pytest.raises(ValueError):
        service.enrich([indicator("8.8.8.8"), indicator(value, kind)], ["virustotal"])
    session.get.assert_not_called()


def test_cache_deduplication_expiration_and_traceability():
    clock = Mock(return_value=0)
    session = Mock(spec=requests.Session)
    session.get.return_value = response()
    service = EnrichmentService(
        Settings(virustotal_api_key="secret", enrichment_cache_ttl=10),
        session=session,
        clock=clock,
    )
    result = service.enrich([indicator(), indicator()], ["virustotal", "virustotal"])
    assert session.get.call_count == 1
    assert result[0].enrichments[0].confidence == 50
    assert result[0].enrichments[0].retrieved_at <= datetime.now(UTC)
    serialized = STIXExporter().export_indicators(result).serialize()
    assert "virustotal" in serialized
    assert "secret" not in serialized
    clock.return_value = 10
    service.enrich([indicator()], ["virustotal"])
    assert session.get.call_count == 2


@pytest.mark.parametrize("status,exception", [(429, QuotaError), (302, ConnectorError)])
def test_remote_limits_and_redirects_are_errors(status, exception):
    session = Mock(spec=requests.Session)
    session.get.return_value = response(status)
    service = EnrichmentService(Settings(virustotal_api_key="secret"), session=session)
    with pytest.raises(exception):
        service.enrich([indicator()], ["virustotal"])


def test_no_result_is_distinct_from_failure_and_cached():
    session = Mock(spec=requests.Session)
    session.get.return_value = response(404)
    service = EnrichmentService(Settings(virustotal_api_key="secret"), session=session)
    assert (
        service.enrich([indicator()], ["virustotal"])[0].enrichments[0].status
        == "not-found"
    )
    service.enrich([indicator()], ["virustotal"])
    assert session.get.call_count == 1


def test_local_budget_resets_after_one_minute():
    clock = Mock(return_value=0)
    session = Mock(spec=requests.Session)
    session.get.return_value = response()
    service = EnrichmentService(
        Settings(
            virustotal_api_key="secret",
            enrichment_requests_per_minute=1,
        ),
        session=session,
        clock=clock,
    )
    service.enrich([indicator()], ["virustotal"])
    with pytest.raises(QuotaError):
        service.enrich([indicator("1.1.1.1")], ["virustotal"])
    assert session.get.call_count == 1
    clock.return_value = 60
    service.enrich([indicator("1.1.1.1")], ["virustotal"])
    assert session.get.call_count == 2


@pytest.mark.parametrize("failure", [requests.Timeout("secret"), {"bad": "payload"}])
def test_transport_and_malformed_responses_do_not_cache_success(failure):
    session = Mock(spec=requests.Session)
    if isinstance(failure, Exception):
        session.get.side_effect = failure
    else:
        session.get.return_value = response(payload=failure)
    service = EnrichmentService(Settings(virustotal_api_key="secret"), session=session)
    with pytest.raises(ConnectorError):
        service.enrich([indicator()], ["virustotal"])
    assert not service.cache


def test_missing_keys_and_unsupported_shodan_type_are_explicit():
    session = Mock(spec=requests.Session)
    with pytest.raises(ValueError, match="VIRUSTOTAL"):
        EnrichmentService(Settings(), session=session).enrich(
            [indicator()], ["virustotal"]
        )
    with pytest.raises(ValueError, match="only IP"):
        EnrichmentService(Settings(shodan_api_key="secret"), session=session).enrich(
            [indicator("public.com", IndicatorType.DOMAIN)],
            ["shodan"],
        )
    session.get.assert_not_called()


def test_shodan_uses_ip_endpoint_and_sanitized_metadata():
    session = Mock(spec=requests.Session)
    session.get.return_value = response(
        payload={"ip_str": "8.8.8.8", "tags": ["dns"], "raw_secret": "private"}
    )
    result = EnrichmentService(
        Settings(shodan_api_key="secret"), session=session
    ).enrich(
        [indicator()],
        ["shodan"],
    )
    assert result[0].enrichments[0].tags == ("dns",)
    assert "private" not in result[0].model_dump_json()
