import hashlib
import hmac
import json
from unittest.mock import Mock

import pytest
import requests

from cti_automator.config import Settings
from cti_automator.exceptions import NotificationError, SecOpsError
from cti_automator.models import (
    Indicator,
    IndicatorType,
    IntelligenceSource,
    PDFAnalysis,
    TTPMapping,
)
from cti_automator.secops import (
    CortexXSOARAdapter,
    TheHiveAdapter,
    WebhookNotifier,
    build_case,
    derive_severity,
)


def analysis() -> PDFAnalysis:
    return PDFAnalysis(
        summary="Full report summary text.",
        source_document="report.pdf",
        indicators=(
            Indicator(
                value="evil.example",
                indicator_type=IndicatorType.DOMAIN,
                source=IntelligenceSource.PDF_REPORT,
                confidence=90,
            ),
            Indicator(
                value="8.8.4.4",
                indicator_type=IndicatorType.IPV4,
                source=IntelligenceSource.PDF_REPORT,
            ),
        ),
        ttps=(
            TTPMapping(
                technique_id="T1566",
                technique_name="Phishing",
                tactic="Initial Access",
                rationale="Spearphishing attachment",
                evidence="email attachment",
                confidence=60,
            ),
        ),
    )


def response(status=200, payload=None):
    result = Mock(spec=requests.Response)
    result.status_code = status
    result.json.return_value = payload if payload is not None else {}
    return result


def test_severity_is_derived_deterministically() -> None:
    assert derive_severity(analysis()) == "high"
    base = analysis()
    few = base.model_copy(
        update={
            "indicators": (base.indicators[0].model_copy(update={"confidence": 10}),)
        }
    )
    assert derive_severity(few) == "low"
    extra = base.indicators[0].model_copy(
        update={"value": "second.example", "confidence": 20}
    )
    third = base.indicators[0].model_copy(
        update={"value": "third.example", "confidence": 20}
    )
    many = base.model_copy(
        update={
            "indicators": (few.indicators[0], extra, third),
        }
    )
    assert derive_severity(many) == "medium"


def test_build_case_is_idempotent_and_filters_payload() -> None:
    first = build_case(analysis())
    second = build_case(analysis(), severity="critical")
    assert first.idempotency_key == second.idempotency_key
    assert second.severity == "critical"
    summary = first.payload_summary()
    assert summary["indicators"] == 2
    assert "Full report summary text." not in json.dumps(summary)


def thehive_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "thehive_url": "https://thehive.internal.example",
        "thehive_token": "token",
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def test_thehive_dry_run_makes_no_network_calls() -> None:
    session = Mock(spec=requests.Session)
    adapter = TheHiveAdapter(thehive_settings(), session=session)
    result = adapter.deliver(build_case(analysis()), dry_run=True)
    assert result.status == "dry-run"
    session.request.assert_not_called()


def test_thehive_returns_existing_case_without_recreating() -> None:
    session = Mock(spec=requests.Session)
    session.request.return_value = response(payload=[{"_id": "case-1"}])
    adapter = TheHiveAdapter(thehive_settings(), session=session)
    result = adapter.deliver(build_case(analysis()))
    assert result.status == "existing"
    assert result.reference == "case-1"
    assert result.attempts == 1
    create_calls = [
        call
        for call in session.request.call_args_list
        if call.args[1].endswith("/api/v1/case") and call.args[0] == "POST"
    ]
    assert not create_calls


def test_thehive_reconciles_ambiguous_create_without_duplicates() -> None:
    session = Mock(spec=requests.Session)
    session.request.side_effect = [
        response(payload=[]),
        requests.exceptions.ConnectTimeout(),
        response(payload=[{"_id": "case-created-anyway"}]),
        response(payload=[{"_id": "case-created-anyway"}]),
    ]
    adapter = TheHiveAdapter(thehive_settings(), session=session)
    result = adapter.deliver(build_case(analysis()))
    assert result.status == "existing"
    assert result.reference == "case-created-anyway"


def test_thehive_fails_after_bounded_retries() -> None:
    session = Mock(spec=requests.Session)
    session.request.side_effect = [
        response(payload=[]),
        requests.exceptions.ConnectTimeout(),
        response(payload=[]),
        response(payload=[]),
        requests.exceptions.ConnectTimeout(),
    ]
    adapter = TheHiveAdapter(thehive_settings(secops_retry_attempts=1), session=session)
    with pytest.raises(SecOpsError):
        adapter.deliver(build_case(analysis()))
    # search, create, reconciled search, retry search, retry create
    assert session.request.call_count == 5


def xsoar_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "xsoar_url": "https://xsoar.internal.example",
        "xsoar_token": "token",
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def test_xsoar_creates_incident_once() -> None:
    session = Mock(spec=requests.Session)
    session.request.side_effect = [
        response(payload={"total": 0}),
        response(status=200, payload={"id": "incident-9"}),
    ]
    adapter = CortexXSOARAdapter(xsoar_settings(), session=session)
    result = adapter.deliver(build_case(analysis(), severity="high"))
    assert result.status == "created"
    assert result.reference == "incident-9"
    create_call = session.request.call_args_list[1]
    body = create_call.kwargs["json"]
    assert body["severity"] == 3
    assert body["customFields"]["ctiidempotencykey"]


def test_xsoar_rejects_invalid_search_metadata() -> None:
    session = Mock(spec=requests.Session)
    session.request.return_value = response(payload={})
    adapter = CortexXSOARAdapter(xsoar_settings(), session=session)
    with pytest.raises(SecOpsError):
        adapter.deliver(build_case(analysis()))


def chatops_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "chatops_webhooks": (("soc", "https://hooks.example/abcd"),),
        "chatops_signing_secrets": (("soc", "signing-secret"),),
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def test_notifier_dry_run_never_touches_the_network() -> None:
    session = Mock(spec=requests.Session)
    notifier = WebhookNotifier(chatops_settings(), session=session)
    result = notifier.notify("soc", "new case", dry_run=True)
    assert result.status == "dry-run"
    assert result.signed
    session.post.assert_not_called()


def test_notifier_rejects_unknown_destination() -> None:
    notifier = WebhookNotifier(chatops_settings())
    with pytest.raises(ValueError, match="ChatOps destination"):
        notifier.notify("missing", "message")


@pytest.mark.parametrize(
    "url",
    [
        "http://hooks.example/abcd",
        "https://127.0.0.1/hook",
        "https://user:pass@hooks.example/abcd",
        "ftp://hooks.example/abcd",
    ],
)
def test_notifier_blocks_unsafe_destinations(url: str) -> None:
    session = Mock(spec=requests.Session)
    settings = Settings(chatops_webhooks=(("bad", url),))
    notifier = WebhookNotifier(settings, session=session)
    with pytest.raises(NotificationError):
        notifier.notify("bad", "message")
    session.post.assert_not_called()


def test_notifier_allows_internal_http_only_when_authorized() -> None:
    session = Mock(spec=requests.Session)
    session.post.return_value = response(status=200)
    settings = Settings(
        chatops_webhooks=(("mattermost", "http://mattermost.internal:8065/hook"),),
        secops_allowed_hosts=("mattermost.internal",),
    )
    result = WebhookNotifier(settings, session=session).notify(
        "mattermost", "message one"
    )
    assert result.status == "sent"
    assert result.signed is False


def test_notifier_sends_signed_payload_and_verifies_hmac() -> None:
    session = Mock(spec=requests.Session)
    session.post.return_value = response(status=200)
    notifier = WebhookNotifier(chatops_settings(), session=session)
    result = notifier.notify("soc", "case update")
    assert result.status == "sent"
    headers = session.post.call_args.kwargs["headers"]
    body = session.post.call_args.kwargs["data"]
    expected = hmac.new(b"signing-secret", body, hashlib.sha256).hexdigest()
    assert headers["X-CTI-Signature"] == f"sha256={expected}"
    assert b"signing-secret" not in body


def test_notifier_deduplicates_identical_messages_within_ttl() -> None:
    session = Mock(spec=requests.Session)
    session.post.return_value = response(status=200)
    clock = Mock(return_value=1000.0)
    notifier = WebhookNotifier(chatops_settings(), session=session, clock=clock)
    first = notifier.notify("soc", "same message")
    second = notifier.notify("soc", "same message")
    assert first.status == "sent"
    assert second.status == "duplicate"
    session.post.assert_called_once()


def test_notifier_distinguishes_new_messages_after_ttl() -> None:
    session = Mock(spec=requests.Session)
    session.post.return_value = response(status=200)
    clock = Mock(return_value=1000.0)
    notifier = WebhookNotifier(chatops_settings(), session=session, clock=clock)
    notifier.notify("soc", "same message")
    clock.return_value = 1400.0
    result = notifier.notify("soc", "same message")
    assert result.status == "sent"
    assert session.post.call_count == 2


def test_notifier_maps_rate_limit_and_rejection() -> None:
    session = Mock(spec=requests.Session)
    session.post.side_effect = [response(status=429), response(status=500)]
    notifier = WebhookNotifier(chatops_settings(), session=session)
    with pytest.raises(NotificationError):
        notifier.notify("soc", "m1")
    with pytest.raises(NotificationError):
        notifier.notify("soc", "m2")


def test_notifier_enforces_local_frequency_limit() -> None:
    session = Mock(spec=requests.Session)
    session.post.return_value = response(status=200)
    clock = Mock(return_value=1000.0)
    notifier = WebhookNotifier(chatops_settings(), session=session, clock=clock)
    for index in range(6):
        notifier.notify("soc", f"message {index}")
    with pytest.raises(NotificationError, match="frequency"):
        notifier.notify("soc", "message 7")
    assert session.post.call_count == 6


def test_missing_case_credentials_fail_before_network() -> None:
    with pytest.raises(ValueError, match="CTI_THEHIVE_URL"):
        TheHiveAdapter(Settings())
    with pytest.raises(ValueError, match="CTI_XSOAR_URL"):
        CortexXSOARAdapter(Settings())
