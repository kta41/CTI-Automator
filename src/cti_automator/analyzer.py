"""Semantic analysis pipeline for technical PDF reports."""

from __future__ import annotations

import json
from pathlib import Path

from cti_automator.config import Settings
from cti_automator.llm import OllamaClient
from cti_automator.models import PDFAnalysis
from cti_automator.parsers.pdf import PDFTextExtractor


class PDFAnalyzer:
    """Extract a report and obtain a validated MITRE-aware analysis from Ollama."""

    def __init__(
        self,
        settings: Settings,
        *,
        extractor: PDFTextExtractor | None = None,
        ollama: OllamaClient | None = None,
    ) -> None:
        self._extractor = extractor or PDFTextExtractor()
        self._ollama = ollama or OllamaClient(settings)

    def analyze(self, path: Path) -> PDFAnalysis:
        """Analyze one PDF without sending data to any remote service."""
        text = self._extractor.extract(path)
        prompt = build_analysis_prompt(text, path.name)
        result = self._ollama.generate_json(prompt)
        result["source_document"] = path.name
        return PDFAnalysis.model_validate(result)


def build_analysis_prompt(text: str, document_name: str) -> str:
    """Build a constrained prompt with a machine-validatable output contract."""
    schema = {
        "summary": "string",
        "indicators": [
            {
                "value": "string",
                "indicator_type": "domain-name|email-addr|file-hash-md5|"
                "file-hash-sha1|file-hash-sha256|ipv4-addr|ipv6-addr|url|unknown",
                "source": "pdf-report",
                "confidence": 0,
                "tags": [],
                "raw_data": {},
            }
        ],
        "ttps": [
            {
                "technique_id": "T1059",
                "technique_name": "string",
                "tactic": "string",
                "rationale": "string",
                "evidence": "verbatim short evidence from report",
                "confidence": 0,
            }
        ],
    }
    return (
        "You are a cyber threat intelligence analyst. Analyze the following "
        "technical report locally. Return JSON only, matching this contract:\n"
        f"{json.dumps(schema, ensure_ascii=True)}\n"
        "Rules: extract only indicators supported by the report; use "
        "source='pdf-report'; map only justified MITRE ATT&CK techniques; "
        "include concise evidence and rationale; confidence is an integer "
        "from 0 to 100. Do not invent facts.\n"
        f"Document: {document_name}\n"
        "Report text:\n"
        f"{text}"
    )
