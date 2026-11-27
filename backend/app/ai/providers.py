"""Model providers. The model gets text in and returns text out. It has no tools."""

from typing import Protocol

import httpx2

from ..config import Settings

MAX_RESPONSE_CHARS = 20_000


class AiProviderError(RuntimeError):
    """The model backend is unreachable or returned something unusable."""


class Provider(Protocol):
    name: str
    model: str

    def complete(self, messages: list[dict], schema: dict) -> str:
        """Return the model's reply as a JSON string that should match `schema`."""
        ...


class OllamaProvider:
    """A model running locally through Ollama, so scan data never leaves the network."""

    name = "ollama"

    def __init__(
        self,
        base_url: str,
        model: str,
        timeout: float = 180.0,
        client: httpx2.Client | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self._timeout = timeout
        self._client = client

    def complete(self, messages: list[dict], schema: dict) -> str:
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "format": schema,  # constrains decoding to this JSON schema
            "options": {"temperature": 0},
        }
        client = self._client or httpx2.Client(timeout=self._timeout)
        try:
            response = client.post(f"{self.base_url}/api/chat", json=payload)
            response.raise_for_status()
            content = response.json()["message"]["content"]
        except httpx2.HTTPError as exc:
            raise AiProviderError(
                f"Could not reach Ollama at {self.base_url}. Is it running, and is the model "
                f"'{self.model}' pulled? ({exc})"
            ) from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise AiProviderError("Ollama returned an unexpected response.") from exc
        finally:
            if self._client is None:
                client.close()

        if not isinstance(content, str) or len(content) > MAX_RESPONSE_CHARS:
            raise AiProviderError("Ollama returned an unexpected response.")
        return content


def get_provider(settings: Settings) -> Provider | None:
    """Return the configured provider, or None when AI triage is switched off."""
    if settings.ai_provider == "ollama" and settings.ollama_model.strip():
        return OllamaProvider(
            settings.ollama_url, settings.ollama_model.strip(), settings.ai_timeout_seconds
        )
    return None
