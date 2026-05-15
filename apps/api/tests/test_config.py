from pathlib import Path

from prometheus.core.config import (
    API_DIR,
    DEFAULT_CORS_ALLOWED_ORIGINS,
    ROOT_DIR,
    Settings,
    default_env_files,
)


def test_default_env_files_resolve_absolute_paths() -> None:
    root_env, api_env = default_env_files()

    assert root_env == ROOT_DIR / ".env"
    assert api_env == API_DIR / ".env"
    assert root_env.is_absolute()
    assert api_env.is_absolute()


def test_api_env_overrides_root_env(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_REASONING_MODEL", raising=False)

    root_env = tmp_path / "root.env"
    api_env = tmp_path / "api.env"
    root_env.write_text(
        "GEMINI_API_KEY=root-key\nGEMINI_REASONING_MODEL=root-model\n",
        encoding="utf-8",
    )
    api_env.write_text(
        "GEMINI_API_KEY=api-key\nGEMINI_REASONING_MODEL=api-model\n",
        encoding="utf-8",
    )

    settings = Settings(_env_file=(root_env, api_env))

    assert settings.gemini_api_key == "api-key"
    assert settings.gemini_reasoning_model == "api-model"


def test_default_cors_allowed_origins_include_dev_hosts(monkeypatch) -> None:
    monkeypatch.delenv("CORS_ALLOWED_ORIGINS", raising=False)
    monkeypatch.delenv("CORS_ORIGINS", raising=False)
    settings = Settings(_env_file=None)

    assert settings.resolved_cors_allowed_origins() == list(DEFAULT_CORS_ALLOWED_ORIGINS)


def test_cors_allowed_origins_env_var_extends_defaults(monkeypatch) -> None:
    monkeypatch.setenv(
        "CORS_ALLOWED_ORIGINS",
        "http://localhost:3001,http://10.0.0.7:3001",
    )

    settings = Settings(_env_file=None)
    origins = settings.resolved_cors_allowed_origins()

    assert "http://localhost:3001" in origins
    assert "http://10.0.0.7:3001" in origins
    assert origins.count("http://localhost:3001") == 1


def test_cors_allowed_origin_regex_env_var(monkeypatch) -> None:
    monkeypatch.setenv("CORS_ALLOWED_ORIGIN_REGEX", r"https://.*\.vercel\.app")

    settings = Settings(_env_file=None)

    assert settings.resolved_cors_allowed_origin_regex() == r"https://.*\.vercel\.app"


def test_resolve_repo_path_prefers_root_but_falls_back_to_api_dir() -> None:
    settings = Settings(_env_file=None)

    policy_path = settings.resolve_repo_path("infra/lobstertrap/prometheus_policy.yaml")
    legacy_relative_policy_path = settings.resolve_repo_path(
        "../../infra/lobstertrap/prometheus_policy.yaml"
    )

    assert policy_path == (ROOT_DIR / "infra/lobstertrap/prometheus_policy.yaml").resolve()
    assert legacy_relative_policy_path == (
        API_DIR / "../../infra/lobstertrap/prometheus_policy.yaml"
    ).resolve()
