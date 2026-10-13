"""Ollama client for private, local semantic analysis."""

from __future__ import annotations

from typing import Any

import requests

from cti_automator.config import Settings
from cti_automator.exceptions import LLMResponseError


class OllamaClient:
    """Call Ollama's local JSON generation endpoint."""

    def __init__(
        self,
        settings: Settings,
        session: requests.Session | None = None,
    ) -> None:
        self._settings = settings
        self._session = session or requests.Session()

    def generate_json(self, prompt: str) -> dict[str, Any]:
        """Generate and validate an object response without leaking report text."""
        if not prompt.strip():
            raise ValueError("prompt cannot be empty")
        try:
            response = self._session.post(
                f"{self._settings.ollama_base_url}/api/generate",
                json={
                    "model": self._settings.ollama_model,
                    "prompt": prompt,
                    "format": "json",
                    "stream": False,
                },
                timeout=self._settings.request_timeout,
                verify=self._settings.verify_tls,
            )
            response.raise_for_status()
            payload = response.json()
            generated = payload.get("response") if isinstance(payload, dict) else None
            if not isinstance(generated, str):
                raise LLMResponseError("Ollama response is missing generated JSON")
            result = _decode_json(generated)
            if not isinstance(result, dict):
                raise LLMResponseError("Ollama generated JSON must be an object")
            return result
        except requests.exceptions.RequestException as exc:
            raise LLMResponseError("Ollama request failed") from exc
        except ValueError as exc:
            raise LLMResponseError("Ollama returned invalid JSON") from exc


def _decode_json(value: str) -> object:
    import json

    cleaned = value.strip()
    if cleaned.startswith("```") and cleaned.endswith("```"):
        cleaned = cleaned.split("\n", 1)[1].rsplit("\n", 1)[0]
    return json.loads(cleaned)
