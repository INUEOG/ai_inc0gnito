from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


RiskLevel = Literal["SAFE", "WATCH", "SUSPICIOUS", "MALICIOUS"]
Severity = Literal["low", "medium", "high", "critical"]


@dataclass
class RepositoryRef:
    owner: str
    repo: str
    url: str


@dataclass
class AuthorTrust:
    score: int = 50
    signals: list[str] = field(default_factory=list)


@dataclass
class RepoMetadata:
    source: str
    owner: str | None = None
    repo: str | None = None
    default_branch: str | None = None
    stars: int = 0
    forks: int = 0
    created_at: str | None = None
    pushed_at: str | None = None
    owner_created_at: str | None = None
    owner_public_repos: int = 0
    owner_followers: int = 0
    author_trust: AuthorTrust = field(default_factory=AuthorTrust)
    collection_mode: str = "local"


@dataclass
class RepoFile:
    path: str
    size: int = 0
    sha: str | None = None
    download_url: str | None = None


@dataclass
class CandidateFile:
    path: str
    content: str
    size: int
    sha: str | None = None
    reason: str = ""


@dataclass
class Evidence:
    file: str
    line: int
    type: str
    severity: Severity
    evidence: str
    score: int
    category: str
    description: str = ""


@dataclass
class SandboxLog:
    file: str
    line: int
    action: str
    detail: str
    score: int


@dataclass
class LLMJudgement:
    verdict: RiskLevel
    confidence: float
    reason: str
    risk_adjustment: int = 0
    evidence: list[str] = field(default_factory=list)
    provider: str = "offline-fallback"
    used: bool = False
    error: str | None = None


@dataclass
class ScoreBreakdown:
    base_score: int
    final_score: int
    risk_level: RiskLevel
    forced_malicious: bool
    has_auto_trigger: bool
    has_secret_access: bool
    has_external_sink: bool
    notes: list[str] = field(default_factory=list)


@dataclass
class ScanReport:
    metadata: RepoMetadata
    candidates: list[str]
    evidence: list[Evidence]
    sandbox_logs: list[SandboxLog]
    llm: LLMJudgement
    score: ScoreBreakdown
    elapsed_ms: float
    suspected_secrets: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": asdict(self.metadata),
            "candidates": self.candidates,
            "evidence": [asdict(item) for item in self.evidence],
            "sandbox_logs": [asdict(item) for item in self.sandbox_logs],
            "llm": asdict(self.llm),
            "score": asdict(self.score),
            "elapsed_ms": round(self.elapsed_ms, 2),
            "suspected_secrets": self.suspected_secrets,
        }
