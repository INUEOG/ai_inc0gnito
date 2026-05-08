from __future__ import annotations

import time
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from .ai import LLMJudge
from .config import GuarditConfig
from .file_filter import filter_candidate_files, is_candidate_path, looks_binary
from .flow import build_execution_flows
from .github_client import GitHubClient
from .models import AuthorTrust, CandidateFile, CandidateSummary, Evidence, RepoFile, RepoMetadata, ScanReport, ScanWarning
from .sandbox import DockerSandboxRunner
from .scoring import score_report
from .static_analyzer import analyze_candidate


ProgressCallback = Callable[[str, int, str], None]


def scan_source(source: str, config: GuarditConfig, progress: ProgressCallback | None = None) -> ScanReport:
    started = time.perf_counter()
    _progress(progress, "start", 1, "GitHub/로컬 정보 수집")
    if _is_github_url(source):
        metadata, candidates = _collect_github(source, config)
    else:
        metadata, candidates = _collect_local(Path(source), config)
    _progress(progress, "done", 1, "GitHub/로컬 정보 수집")
    _progress(progress, "start", 2, "자동 실행 파일 탐지")
    _progress(progress, "done", 2, "자동 실행 파일 탐지")

    _progress(progress, "start", 3, "정적 개인정보 유출 분석")
    evidence = []
    for candidate in candidates:
        evidence.extend(analyze_candidate(candidate))

    execution_flows = build_execution_flows(candidates, evidence)
    _progress(progress, "done", 3, "정적 개인정보 유출 분석")
    _progress(progress, "start", 4, "샌드박스 행동 분석")
    sandbox_logs, sandbox_summary = DockerSandboxRunner(
        image=config.sandbox_image,
        timeout_sec=config.sandbox_timeout_sec,
    ).analyze(candidates, evidence, execution_flows)
    _progress(progress, "done", 4, "샌드박스 행동 분석")

    _progress(progress, "start", 5, "AI 보조 판단")
    base_after_sandbox = score_report(metadata, evidence, sandbox_logs, None)
    warnings = _build_warnings(evidence)
    llm = LLMJudge(
        provider=config.llm_provider,
        model=config.llm_model,
        max_retries=config.llm_max_retries,
        backoff_seconds=config.llm_backoff_seconds,
        strict_json=config.llm_strict_json,
    ).judge(
        suspicious_files=[candidate.path for candidate in candidates],
        evidence=evidence,
        sandbox_logs=sandbox_logs,
        metadata=metadata,
        rule_score=base_after_sandbox.base_score,
    )
    _progress(progress, "done", 5, "AI 보조 판단")
    score = score_report(metadata, evidence, sandbox_logs, llm)
    if config.llm_required and not llm.used:
        score.risk_level = "UNKNOWN"
        score.notes.append("LLM required: 최종 LLM 분석 실패로 판정을 보류")
    elapsed_ms = (time.perf_counter() - started) * 1000
    return ScanReport(
        metadata=metadata,
        candidates=[CandidateSummary(candidate.path, candidate.reason, candidate.size) for candidate in candidates],
        evidence=evidence,
        sandbox_logs=sandbox_logs,
        sandbox_summary=sandbox_summary,
        execution_flows=execution_flows,
        warnings=warnings,
        llm=llm,
        score=score,
        elapsed_ms=elapsed_ms,
        suspected_secrets=_suspected_secrets(evidence),
    )


def _progress(progress: ProgressCallback | None, event: str, index: int, title: str) -> None:
    if progress:
        progress(event, index, title)


def _build_warnings(evidence: list[Evidence]) -> list[ScanWarning]:
    has_secret = any(item.category == "secret_access" for item in evidence)
    has_sink = any(item.category == "external_sink" for item in evidence)
    warnings: list[ScanWarning] = []
    for item in evidence:
        if item.category != "auto_trigger":
            continue
        if item.type == "auto_trigger" and not has_secret and not has_sink:
            warnings.append(
                ScanWarning(
                    file=item.file,
                    line=item.line,
                    type="auto_run_without_exfiltration",
                    message=(
                        "자동 실행 설정이 있습니다. 현재 개인정보 접근 또는 외부 전송 흐름은 탐지되지 않았지만 "
                        "폴더를 열거나 설치 단계에서 실행될 수 있으므로 검토가 필요합니다."
                    ),
                    severity="medium",
                )
            )
    return _dedupe_warnings(warnings)


def _dedupe_warnings(warnings: list[ScanWarning]) -> list[ScanWarning]:
    seen: set[tuple[str, int, str]] = set()
    result: list[ScanWarning] = []
    for warning in warnings:
        key = (warning.file, warning.line, warning.type)
        if key in seen:
            continue
        seen.add(key)
        result.append(warning)
    return result


def _collect_github(source: str, config: GuarditConfig) -> tuple[RepoMetadata, list[CandidateFile]]:
    client = GitHubClient(token=config.github_token)
    ref = client.parse_repo_url(source)
    metadata = client.fetch_metadata(ref)
    tree = client.fetch_tree(ref, metadata.default_branch or "main")
    candidate_files = filter_candidate_files(tree, config.max_file_bytes, config.max_candidate_files)
    candidates: list[CandidateFile] = []
    for file in candidate_files:
        candidate = client.fetch_blob(ref, file)
        if candidate is None:
            continue
        matched, reason = is_candidate_path(candidate.path)
        candidate.reason = reason if matched else ""
        candidates.append(candidate)
    return metadata, candidates


def _collect_local(path: Path, config: GuarditConfig) -> tuple[RepoMetadata, list[CandidateFile]]:
    root = path.resolve()
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"분석할 경로를 찾을 수 없습니다: {path}")
    files: list[RepoFile] = []
    for item in root.rglob("*"):
        if not item.is_file() or _is_ignored(item, root):
            continue
        rel = item.relative_to(root).as_posix()
        try:
            size = item.stat().st_size
        except OSError:
            continue
        files.append(RepoFile(path=rel, size=size))
    candidate_files = filter_candidate_files(files, config.max_file_bytes, config.max_candidate_files)
    candidates: list[CandidateFile] = []
    for file in candidate_files:
        raw_path = root / file.path
        try:
            raw = raw_path.read_bytes()
        except OSError:
            continue
        if looks_binary(raw):
            continue
        matched, reason = is_candidate_path(file.path)
        candidates.append(CandidateFile(file.path, raw.decode("utf-8", errors="replace"), len(raw), reason=reason if matched else ""))
    metadata = RepoMetadata(
        source=str(root),
        collection_mode="local",
        author_trust=AuthorTrust(score=65, signals=["로컬 경로 분석: 작성자 신뢰도는 보조 점수에서 제외 수준으로 설정"]),
    )
    return metadata, candidates


def _is_github_url(source: str) -> bool:
    parsed = urlparse(source)
    return parsed.scheme in {"http", "https"} and parsed.netloc in {"github.com", "www.github.com"}


def _is_ignored(path: Path, root: Path) -> bool:
    ignored = {".git", "node_modules", ".venv", "__pycache__", "dist", "build", ".pytest_cache"}
    rel_parts = path.relative_to(root).parts
    return any(part in ignored for part in rel_parts)


def _suspected_secrets(evidence: list) -> list[str]:
    result: set[str] = set()
    for item in evidence:
        text = f"{item.type} {item.evidence}".lower()
        if "aws" in text:
            result.add("AWS credentials")
        if "ssh" in text or "id_rsa" in text:
            result.add("SSH private key")
        if ".env" in text or "dotenv" in text:
            result.add(".env token")
        if "github" in text or "ghp_" in text:
            result.add("GitHub token")
        if "npm" in text:
            result.add("npm token")
        if "login data" in text or "cookies" in text or "browser" in text:
            result.add("browser credential")
        if "client_secret" in text or "access_key" in text:
            result.add("cloud credential")
    return sorted(result)
