from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class GuarditConfig:
    max_candidate_files: int = 80
    max_file_bytes: int = 300_000
    sandbox_threshold: int = 30
    sandbox_mode: str = "static"
    sandbox_timeout_sec: int = 8
    sandbox_image: str = "guardit-sandbox:latest"
    results_dir: Path = Path("results")
    logs_dir: Path = Path("logs")
    github_token: str | None = None
    llm_provider: str = "gemini-api"
    llm_model: str = "gemini-2.5-flash"


def load_config() -> GuarditConfig:
    return GuarditConfig(
        max_candidate_files=int(os.environ.get("GUARDIT_MAX_CANDIDATE_FILES", "80")),
        max_file_bytes=int(os.environ.get("GUARDIT_MAX_FILE_BYTES", "300000")),
        sandbox_threshold=int(os.environ.get("GUARDIT_SANDBOX_THRESHOLD", "30")),
        sandbox_mode=os.environ.get("GUARDIT_SANDBOX_MODE", "static"),
        sandbox_timeout_sec=int(os.environ.get("GUARDIT_SANDBOX_TIMEOUT_SEC", "8")),
        sandbox_image=os.environ.get("GUARDIT_SANDBOX_IMAGE", "guardit-sandbox:latest"),
        github_token=os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"),
        llm_provider=os.environ.get("GUARDIT_LLM_PROVIDER", "gemini-api"),
        llm_model=os.environ.get("GUARDIT_LLM_MODEL", "gemini-2.5-flash"),
    )
