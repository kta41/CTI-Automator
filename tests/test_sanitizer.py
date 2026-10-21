from unittest.mock import Mock

import pytest

import cti_automator.sanitizer as sanitizer_module
from cti_automator.analyzer import PDFAnalyzer
from cti_automator.config import Settings
from cti_automator.exceptions import SanitizationError

SanitizationPolicy = sanitizer_module.SanitizationPolicy
Sanitizer = sanitizer_module.Sanitizer
audit_protected_values = sanitizer_module.audit_protected_values

POLICY = SanitizationPolicy(
    email_domains=("corp.example",),
    internal_networks=("10.0.0.0/8", "192.168.0.0/16"),
    names=("Alice Smith",),
    allowed_values=frozenset({"10.0.0.9"}),
)


def test_disabled_sanitizer_is_a_noop() -> None:
    sanitizer = Sanitizer(SanitizationPolicy(), enabled=False)
    text = "alice@corp.example from 10.1.2.3"
    assert sanitizer.sanitize(text).text == text
    assert sanitizer.sanitize(text).total == 0


def test_sanitizer_redacts_emails_ips_and_names_with_stable_tokens() -> None:
    sanitizer = Sanitizer(POLICY)
    text = (
        "Alice Smith wrote to bob@corp.example twice (bob@corp.example) "
        "from 10.1.2.3 and 10.1.2.3 plus 192.168.5.5."
    )
    result = sanitizer.sanitize(text)
    assert "corp.example" not in result.text
    assert "10.1.2.3" not in result.text
    assert "192.168.5.5" not in result.text
    assert "Alice Smith" not in result.text
    assert result.counts == {"email": 2, "ip": 3, "name": 1}
    assert result.text.count("<CTI_EMAIL_1>") == 2
    assert result.text.count("<CTI_IP_1>") == 2
    assert "<CTI_NAME_1>" in result.text


def test_allowed_values_and_public_indicators_are_preserved() -> None:
    sanitizer = Sanitizer(POLICY)
    text = (
        "Attacker 8.8.8.8 and allowed internal host 10.0.0.9 and "
        "public attacker@threat.example stayed."
    )
    result = sanitizer.sanitize(text)
    assert "8.8.8.8" in result.text
    assert "10.0.0.9" in result.text
    assert "attacker@threat.example" in result.text
    assert result.total == 0


def test_ipv6_internal_addresses_are_redacted() -> None:
    sanitizer = Sanitizer(SanitizationPolicy(internal_networks=("fd00::/8",)))
    result = sanitizer.sanitize("beacon fd00:dead:beef::1 active")
    assert "fd00" not in result.text
    assert result.counts["ip"] == 1


def test_short_names_are_ignored_to_avoid_ambiguous_redaction() -> None:
    from_settings = SanitizationPolicy(
        names=("Al", "Alice Smith"),
    )
    sanitizer = Sanitizer(from_settings)
    result = sanitizer.sanitize("Al and Alice Smith")
    assert result.text.startswith("Al")
    assert "Alice Smith" not in result.text


def test_sanitization_failure_blocks_and_never_leaks_originals(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sanitizer = Sanitizer(POLICY)

    def explode(text: str) -> object:
        raise RuntimeError("engine failure")

    monkeypatch.setattr(sanitizer, "_redact", explode)
    with pytest.raises(SanitizationError):
        sanitizer.sanitize("Alice Smith at 10.0.0.1")
    assert "Alice Smith" not in capsys.readouterr().out


def test_analyzer_applies_sanitizer_before_the_llm_prompt() -> None:
    captured: dict[str, str] = {}

    class FakeLLM:
        def generate_json(self, prompt: str) -> dict[str, object]:
            captured["prompt"] = prompt
            return {"summary": "ok summary"}

    analyzer = PDFAnalyzer(
        Settings(),
        ollama=FakeLLM(),  # type: ignore[arg-type]
        sanitizer=Sanitizer(POLICY),
    )
    analysis = analyzer.analyze_text(
        "Alice Smith reported bob@corp.example from 10.1.2.3", "report.pdf"
    )
    assert analysis.summary == "ok summary"
    assert "bob@corp.example" not in captured["prompt"]
    assert "10.1.2.3" not in captured["prompt"]
    assert "<CTI_EMAIL_1>" in captured["prompt"]


def test_audit_protected_values_detects_leftovers() -> None:
    dirty = "bob@corp.example 10.1.2.3 Alice Smith"
    assert audit_protected_values(dirty, POLICY) == {
        "email": 1,
        "ip": 1,
        "name": 1,
    }
    clean = "<CTI_EMAIL_1> <CTI_IP_1> <CTI_NAME_1> 8.8.8.8"
    assert audit_protected_values(clean, POLICY) == {"email": 0, "ip": 0, "name": 0}


def test_redaction_metric_records_categories_without_values(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from cti_automator.observability import REDACTIONS, configure_logging

    configure_logging("INFO")
    before = REDACTIONS.labels("email")._value.get()
    Sanitizer(POLICY).sanitize("bob@corp.example")
    assert REDACTIONS.labels("email")._value.get() == before + 1
    assert "bob@corp.example" not in capsys.readouterr().err


def test_settings_build_sanitizer_from_environment_policy() -> None:
    sanitizer = Sanitizer.from_settings(
        Settings(
            dlp_enabled=True,
            dlp_email_domains=("corp.example",),
            dlp_internal_cidrs=("10.0.0.0/8",),
        )
    )
    assert sanitizer.enabled
    assert Sanitizer.from_settings(Settings()).enabled is False


def test_invalid_cidr_policy_is_rejected_at_construction() -> None:
    with pytest.raises(SanitizationError):
        Sanitizer(SanitizationPolicy(internal_networks=("10.0.0.0/99",)))


def test_mock_session_never_touched_by_sanitizer() -> None:
    session = Mock()
    Sanitizer(POLICY).sanitize("bob@corp.example from 10.1.2.3")
    session.assert_not_called()
