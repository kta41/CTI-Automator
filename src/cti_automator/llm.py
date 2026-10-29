"""Ollama client for private, local semantic analysis."""

from __future__ import annotations

import json
from typing import Any, Protocol

import requests

from cti_automator.config import Settings
from cti_automator.exceptions import LLMResponseError


class LLMClient(Protocol):
    """Common contract implemented by local and hosted AI providers."""

    def generate_json(self, prompt: str) -> dict[str, Any]:
        """Generate one JSON object from a prompt."""


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
                    "options": {"temperature": 0},
                },
                timeout=self._settings.request_timeout,
                verify=self._settings.verify_tls,
                allow_redirects=False,
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
    cleaned = value.strip()
    if cleaned.startswith("```") and cleaned.endswith("```"):
        cleaned = cleaned.split("\n", 1)[1].rsplit("\n", 1)[0]
    return json.loads(cleaned)


class OpenAICompatibleClient:
    """Client for OpenAI Chat Completions compatible APIs.

    This adapter works with OpenAI, Groq, and compatible gateways by changing
    only the base URL, API key, and model in Settings.
    """

    def __init__(
        self,
        settings: Settings,
        session: requests.Session | None = None,
    ) -> None:
        self._settings = settings
        self._session = session or requests.Session()

    def generate_json(self, prompt: str) -> dict[str, Any]:
        """Generate one JSON object using response_format json_object."""
        if not prompt.strip():
            raise ValueError("prompt cannot be empty")
        try:
            response = self._session.post(
                f"{self._settings.ai_base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self._settings.require_ai_api_key()}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self._settings.ai_model,
                    "messages": [
                        {
                            "role": "system",
                            "content": (
                                "Return only a valid JSON object. Do not use "
                                "markdown fences."
                            ),
                        },
                        {"role": "user", "content": prompt},
                    ],
                    "response_format": {"type": "json_object"},
                    "temperature": 0,
                },
                timeout=self._settings.request_timeout,
                verify=self._settings.verify_tls,
                allow_redirects=False,
            )
            response.raise_for_status()
            payload = response.json()
            generated = _extract_chat_content(payload)
            result = _decode_json(generated)
            if not isinstance(result, dict):
                raise LLMResponseError(
                    "OpenAI-compatible response must contain a JSON object"
                )
            return result
        except requests.exceptions.RequestException as exc:
            raise LLMResponseError("OpenAI-compatible request failed") from exc
        except ValueError as exc:
            raise LLMResponseError(
                "OpenAI-compatible provider returned invalid JSON"
            ) from exc


def _extract_chat_content(payload: object) -> str:
    if not isinstance(payload, dict):
        raise LLMResponseError("AI provider returned an invalid response")
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise LLMResponseError("AI provider response is missing choices")
    first = choices[0]
    if not isinstance(first, dict):
        raise LLMResponseError("AI provider returned an invalid choice")
    message = first.get("message")
    if not isinstance(message, dict):
        raise LLMResponseError("AI provider response is missing message content")
    content = message.get("content")
    if not isinstance(content, str):
        raise LLMResponseError("AI provider response is missing message content")
    return content


def create_llm_client(
    settings: Settings,
    session: requests.Session | None = None,
) -> LLMClient:
    """Create the configured provider adapter."""
    if settings.ai_provider == "ollama":
        return OllamaClient(settings, session=session)
    return OpenAICompatibleClient(settings, session=session)
