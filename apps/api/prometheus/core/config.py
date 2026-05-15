from functools import lru_cache
from pathlib import Path

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


CONFIG_FILE = Path(__file__).resolve()
API_DIR = CONFIG_FILE.parents[2]
ROOT_DIR = API_DIR.parents[1]
DEFAULT_CORS_ALLOWED_ORIGINS = (
    "http://localhost:3000",
    "http://localhost:3001",
    "http://localhost:3002",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:3001",
    "http://127.0.0.1:3002",
    "http://192.168.56.1:3000",
    "http://192.168.56.1:3001",
    "http://192.168.56.1:3002",
)


def default_env_files() -> tuple[Path, Path]:
    return (ROOT_DIR / ".env", API_DIR / ".env")


class Settings(BaseSettings):
    app_name: str = "PROMETHEUS API"
    app_version: str = "0.4.0"
    tenant_label: str = "Acme Global Bank - AI Operations Control Plane"
    gemini_api_key: str | None = None
    gemini_reasoning_model: str = "gemini-3.1-pro-preview"
    gemini_fast_model: str = "gemini-3-flash-preview"
    gemini_lite_model: str = "gemini-3.1-flash-lite-preview"
    lobstertrap_enabled: bool = False
    lobstertrap_bin: str = ""
    lobstertrap_policy_path: str = "../../infra/lobstertrap/prometheus_policy.yaml"
    lobstertrap_timeout_seconds: int = 5
    database_path: str = "prometheus/data/prometheus.db"
    cors_allowed_origins: str = Field(
        default=",".join(DEFAULT_CORS_ALLOWED_ORIGINS),
        validation_alias=AliasChoices("CORS_ALLOWED_ORIGINS", "CORS_ORIGINS"),
    )
    default_demo_duration_seconds: int = 90
    sponsor_status: str = "Built on Veea Lobster Trap DPI + Gemini"

    model_config = SettingsConfigDict(
        env_file=default_env_files(),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    def resolved_cors_allowed_origins(self) -> list[str]:
        origins = list(DEFAULT_CORS_ALLOWED_ORIGINS)
        for origin in self.cors_allowed_origins.split(","):
            normalized = origin.strip()
            if normalized and normalized not in origins:
                origins.append(normalized)
        return origins


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
