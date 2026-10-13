from pathlib import Path
from typing import Any

import pytest

from cti_automator.analyzer import PDFAnalyzer, build_analysis_prompt
from cti_automator.config import Settings
from cti_automator.exceptions import DocumentExtractionError, LLMResponseError
from cti_automator.llm import (
    OllamaClient,
    OpenAICompatibleClient,
    create_llm_client,
)
from cti_automator.models import PDFAnalysis
from cti_automator.parsers.pdf import PDFTextExtractor


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

    def post(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append({"url": url, **kwargs})
        return self.response


def test_pdf_extractor_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(DocumentExtractionError, match="does not exist"):
        PDFTextExtractor().extract(tmp_path / "missing.pdf")


def test_prompt_contains_contract_and_report_text() -> None:
    prompt = build_analysis_prompt("The actor used PowerShell.", "report.pdf")

    assert "MITRE ATT&CK" in prompt
    assert "report.pdf" in prompt
    assert "The actor used PowerShell." in prompt


def test_ollama_client_requests_json() -> None:
    session = FakeSession(
        FakeResponse({"response": '{"summary": "ok", "indicators": [], "ttps": []}'})
    )
    client = OllamaClient(Settings(), session=session)  # type: ignore[arg-type]

    result = client.generate_json("Analyze this.")

    assert result["summary"] == "ok"
    assert session.calls[0]["json"]["format"] == "json"
    assert session.calls[0]["json"]["stream"] is False


def test_ollama_client_rejects_invalid_generated_json() -> None:
    session = FakeSession(FakeResponse({"response": "not-json"}))
    client = OllamaClient(Settings(), session=session)  # type: ignore[arg-type]

    with pytest.raises(LLMResponseError, match="invalid JSON"):
        client.generate_json("Analyze this.")


def test_openai_compatible_client_supports_groq_style_response() -> None:
    session = FakeSession(
        FakeResponse(
            {
                "choices": [
                    {
                        "message": {
                            "content": '{"summary": "ok", "indicators": [], "ttps": []}'
                        }
                    }
                ]
            }
        )
    )
    settings = Settings(
        ai_provider="groq",
        ai_api_key="secret",
        ai_base_url="https://api.groq.com/openai/v1",
        ai_model="llama-3.3-70b-versatile",
    )
    client = OpenAICompatibleClient(settings, session=session)  # type: ignore[arg-type]

    result = client.generate_json("Analyze this.")

    assert result["summary"] == "ok"
    assert session.calls[0]["url"].endswith("/chat/completions")
    assert session.calls[0]["headers"]["Authorization"] == "Bearer secret"
    assert session.calls[0]["json"]["model"] == "llama-3.3-70b-versatile"


def test_factory_selects_hosted_provider() -> None:
    client = create_llm_client(
        Settings(ai_provider="openai", ai_api_key="secret")
    )

    assert isinstance(client, OpenAICompatibleClient)


def test_analyzer_validates_structured_result() -> None:
    class FakeExtractor:
        def extract(self, path: Path) -> str:
            return "An attacker used PowerShell."

    class FakeOllama:
        def generate_json(self, prompt: str) -> dict[str, Any]:
            return {
                "summary": "PowerShell execution",
                "indicators": [],
                "ttps": [
                    {
                        "technique_id": "T1059.001",
                        "technique_name": "PowerShell",
                        "tactic": "Execution",
                        "rationale": "The report describes PowerShell.",
                        "evidence": "used PowerShell",
                        "confidence": 90,
                    }
                ],
            }

    analysis = PDFAnalyzer(
        Settings(),
        extractor=FakeExtractor(),  # type: ignore[arg-type]
        ollama=FakeOllama(),  # type: ignore[arg-type]
    ).analyze(Path("report.pdf"))

    assert isinstance(analysis, PDFAnalysis)
    assert analysis.source_document == "report.pdf"
    assert analysis.ttps[0].technique_id == "T1059.001"
