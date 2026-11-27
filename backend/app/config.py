"""Runtime settings. Every value can be overridden with an environment variable."""

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    # SQLite is the fallback for local development and tests. Compose sets PostgreSQL.
    database_url: str = "sqlite:///./vulndash.db"

    # Host headers the app will answer to. Blocks DNS-rebinding attacks on a local tool.
    allowed_hosts: str = "localhost,127.0.0.1"

    max_upload_mb: int = 200

    # Swagger UI at /api/docs. Off by default because it pulls scripts from a CDN.
    enable_api_docs: bool = False

    # Threat-intel feeds (both public, no API key).
    kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    epss_url: str = "https://api.first.org/data/v1/epss"

    # AI triage is off unless a provider is configured.
    ai_provider: str = "none"  # "none" or "ollama"
    ollama_url: str = "http://host.docker.internal:11434"
    ollama_model: str = ""
    ai_timeout_seconds: float = 180.0

    @field_validator("ai_provider")
    @classmethod
    def _known_provider(cls, value: str) -> str:
        value = value.strip().lower()
        if value not in {"none", "ollama"}:
            raise ValueError("AI_PROVIDER must be 'none' or 'ollama'")
        return value

    @property
    def allowed_host_list(self) -> list[str]:
        return [h.strip() for h in self.allowed_hosts.split(",") if h.strip()]

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024
