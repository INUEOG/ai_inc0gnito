from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class GuarditConfig:
    max_candidate_files: int = 80
    max_file_bytes: int = 300_000
    sandbox_mode: str = "docker"
    sandbox_timeout_sec: int = 8
    sandbox_image: str = "guardit-sandbox:latest"
    results_dir: Path = Path("results")
    logs_dir: Path = Path("logs")
    github_token: str | None = None
    llm_provider: str = "gemini-api"
    llm_model: str = "gemini-2.5-flash"
    llm_required: bool = False
    llm_max_retries: int = 3
    llm_backoff_seconds: float = 1.0
    llm_strict_json: bool = False
    llm_provider_priority: str = "gemini-api,openai,local-degraded"
    llm_lightweight_mode: bool = True
    llm_enable_cache: bool = False


def load_config() -> GuarditConfig:
    load_env_files()
    return GuarditConfig(
        max_candidate_files=int(os.environ.get("GUARDIT_MAX_CANDIDATE_FILES", "80")),
        max_file_bytes=int(os.environ.get("GUARDIT_MAX_FILE_BYTES", "300000")),
        sandbox_mode=_sandbox_mode(os.environ.get("GUARDIT_SANDBOX_MODE", "docker")),
        sandbox_timeout_sec=int(os.environ.get("GUARDIT_SANDBOX_TIMEOUT_SEC", "8")),
        sandbox_image=os.environ.get("GUARDIT_SANDBOX_IMAGE", "guardit-sandbox:latest"),
        github_token=os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"),
        llm_provider=os.environ.get("GUARDIT_LLM_PROVIDER", "gemini-api"),
        llm_model=os.environ.get("GUARDIT_LLM_MODEL", "gemini-2.5-flash"),
        llm_required=_env_bool("GUARDIT_LLM_REQUIRED", False),
        llm_max_retries=max(1, int(os.environ.get("GUARDIT_LLM_MAX_RETRIES", "3"))),
        llm_backoff_seconds=max(0.0, float(os.environ.get("GUARDIT_LLM_BACKOFF_SECONDS", "1"))),
        llm_strict_json=_env_bool("GUARDIT_LLM_STRICT_JSON", False),
        llm_provider_priority=os.environ.get("GUARDIT_LLM_PROVIDER_PRIORITY", "gemini-api,openai,local-degraded"),
        llm_lightweight_mode=_env_bool("GUARDIT_LLM_LIGHTWEIGHT_MODE", True),
        llm_enable_cache=_env_bool("GUARDIT_LLM_ENABLE_CACHE", False),
    )


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _sandbox_mode(value: str) -> str:
    normalized = value.strip().lower()
    return "docker" if normalized in {"always", "docker", "static", "off"} else "docker"


def load_env_files() -> None:
    for env_path in _env_file_candidates():
        if not env_path.exists():
            continue
        if not _load_with_python_dotenv(env_path):
            _load_with_builtin_parser(env_path)


def env_file_status() -> dict[str, bool]:
    project_env, cwd_env = _env_file_candidates()
    return {
        "project_env": project_env.exists(),
        "cwd_env": cwd_env.exists(),
    }


def _env_file_candidates() -> tuple[Path, Path]:
    return (_project_root() / ".env", Path.cwd() / ".env")


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_with_python_dotenv(env_path: Path) -> bool:
    try:
        from dotenv import load_dotenv
    except ImportError:
        return False
    load_dotenv(env_path, override=False)
    return True


def _load_with_builtin_parser(env_path: Path) -> None:
    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        if not key or key in os.environ:
            continue
        os.environ[key] = value.strip().strip('"').strip("'")
