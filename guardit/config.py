from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class GuarditConfig:
    max_candidate_files: int = 80
    max_file_bytes: int = 300_000
    sandbox_threshold: int = 30
    results_dir: Path = Path("results")
    logs_dir: Path = Path("logs")
    github_token: str | None = None
    llm_provider: str = "off"
    llm_model: str = "offline"


def load_config() -> GuarditConfig:
    return GuarditConfig(
        max_candidate_files=int(os.environ.get("GUARDIT_MAX_CANDIDATE_FILES", "80")),
        max_file_bytes=int(os.environ.get("GUARDIT_MAX_FILE_BYTES", "300000")),
        sandbox_threshold=int(os.environ.get("GUARDIT_SANDBOX_THRESHOLD", "30")),
        github_token=os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"),
        llm_provider=os.environ.get("GUARDIT_LLM_PROVIDER", "off"),
        llm_model=os.environ.get("GUARDIT_LLM_MODEL", "offline"),
    )
