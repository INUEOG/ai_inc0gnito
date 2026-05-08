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
class CandidateSummary:
    path: str
    reason: str
    size: int


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
class ScanWarning:
    file: str
    line: int
    type: str
    message: str
    severity: Severity = "medium"


@dataclass
class SandboxLog:
    file: str
    line: int
    action: str
    detail: str
    score: int
    origin: str = "inferred"
    syscall: str | None = None


@dataclass
class SandboxSummary:
    mode: str = "static-behavior-inference"
    is_real_sandbox: bool = False
    fallback_used: bool = False
    fallback_reason: str | None = None
    inferred_opened_files: list[str] = field(default_factory=list)
    inferred_network_attempts: list[str] = field(default_factory=list)
    inferred_processes: list[str] = field(default_factory=list)
    observed_opened_files: list[str] = field(default_factory=list)
    observed_network_attempts: list[str] = field(default_factory=list)
    observed_processes: list[str] = field(default_factory=list)
    dummy_credentials_accessed: bool = False


@dataclass
class ExecutionFlow:
    trigger_file: str
    executed_file: str | None
    secret_sources: list[str] = field(default_factory=list)
    external_sinks: list[str] = field(default_factory=list)
    process_steps: list[str] = field(default_factory=list)
    risk: str = "unknown"


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
    has_command_execution: bool
    notes: list[str] = field(default_factory=list)


@dataclass
class ScanReport:
    metadata: RepoMetadata
    candidates: list[CandidateSummary]
    evidence: list[Evidence]
    sandbox_logs: list[SandboxLog]
    sandbox_summary: SandboxSummary
    execution_flows: list[ExecutionFlow]
    warnings: list[ScanWarning]
    llm: LLMJudgement
    score: ScoreBreakdown
    elapsed_ms: float
    suspected_secrets: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": asdict(self.metadata),
            "candidates": [asdict(item) for item in self.candidates],
            "evidence": [asdict(item) for item in self.evidence],
            "sandbox_logs": [asdict(item) for item in self.sandbox_logs],
            "sandbox_summary": asdict(self.sandbox_summary),
            "execution_flows": [asdict(item) for item in self.execution_flows],
            "warnings": [asdict(item) for item in self.warnings],
            "llm": asdict(self.llm),
            "score": asdict(self.score),
            "elapsed_ms": round(self.elapsed_ms, 2),
            "suspected_secrets": self.suspected_secrets,
        }
