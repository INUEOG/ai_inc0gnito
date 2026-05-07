from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: int
    file: str
    line: int
    evidence: str
    category: str
    description: str


@dataclass
class RepoProfile:
    source: str
    local_path: Path
    author_trust_score: int = 50
    author_signals: list[str] = field(default_factory=list)
    files_scanned: int = 0
    executable_files: list[str] = field(default_factory=list)


@dataclass
class SandboxEvent:
    kind: str
    file: str
    line: int
    detail: str
    risk: int


@dataclass
class ScanReport:
    profile: RepoProfile
    findings: list[Finding]
    sandbox_events: list[SandboxEvent]
    risk_score: int
    verdict: str
    recommendation: str
    exfiltration_targets: list[str]
    ai_judgement: str
    elapsed_ms: float
    ai_provider: str = "offline-heuristic"
    ai_model: str = "rules+ast+sandbox"
    ai_used: bool = False
    ai_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.profile.source,
            "files_scanned": self.profile.files_scanned,
            "author_trust_score": self.profile.author_trust_score,
            "author_signals": self.profile.author_signals,
            "executable_files": self.profile.executable_files,
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "recommendation": self.recommendation,
            "exfiltration_targets": self.exfiltration_targets,
            "ai_judgement": self.ai_judgement,
            "ai_provider": self.ai_provider,
            "ai_model": self.ai_model,
            "ai_used": self.ai_used,
            "ai_error": self.ai_error,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "findings": [finding.__dict__ for finding in self.findings],
            "sandbox_events": [event.__dict__ for event in self.sandbox_events],
        }
