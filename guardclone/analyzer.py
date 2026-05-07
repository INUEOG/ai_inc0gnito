from __future__ import annotations

import ast
import json
import time
from pathlib import Path

from .models import Finding, RepoProfile, ScanReport
from .rules import RULES, SENSITIVE_TARGETS, is_auto_exec_path
from .sandbox import infer_sandbox_events

MAX_FILE_BYTES = 300_000


def scan_profile(profile: RepoProfile) -> ScanReport:
    started = time.perf_counter()
    files = _iter_files(profile.local_path)
    profile.files_scanned = len(files)
    executable = [path for path in files if is_auto_exec_path(_rel(profile.local_path, path))]
    profile.executable_files = [_rel(profile.local_path, path) for path in executable]

    findings: list[Finding] = []
    if not executable:
        elapsed = (time.perf_counter() - started) * 1000
        return ScanReport(
            profile=profile,
            findings=[],
            sandbox_events=[],
            risk_score=max(0, 15 - profile.author_trust_score // 10),
            verdict="SAFE",
            recommendation="자동 실행 위험 파일이 없어 clone 진행 가능",
            exfiltration_targets=[],
            ai_judgement="자동 실행 진입점이 발견되지 않아 개인정보 탈취 가능성이 낮습니다.",
            elapsed_ms=elapsed,
        )

    for path in executable:
        findings.extend(_scan_file(profile.local_path, path))

    sandbox_events = infer_sandbox_events(profile.local_path, executable)
    targets = sorted(_extract_targets(findings))
    risk_score = _score(profile, findings, sandbox_events)
    verdict, recommendation = _verdict(risk_score)
    ai_judgement = _judge_intent(risk_score, findings, sandbox_events, targets, profile)
    elapsed = (time.perf_counter() - started) * 1000

    return ScanReport(
        profile=profile,
        findings=findings,
        sandbox_events=sandbox_events,
        risk_score=risk_score,
        verdict=verdict,
        recommendation=recommendation,
        exfiltration_targets=targets,
        ai_judgement=ai_judgement,
        elapsed_ms=elapsed,
    )


def _iter_files(root: Path) -> list[Path]:
    ignored = {".git", "node_modules", ".venv", "__pycache__", "dist", "build"}
    files: list[Path] = []
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if any(part in ignored for part in path.parts):
            continue
        try:
            if path.stat().st_size <= MAX_FILE_BYTES:
                files.append(path)
        except OSError:
            continue
    return files


def _scan_file(root: Path, path: Path) -> list[Finding]:
    rel = _rel(root, path)
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    findings: list[Finding] = []
    lines = text.splitlines() or [""]
    if rel.startswith(".git/hooks/"):
        findings.append(_finding("HOOK001", rel, 1, rel))

    for index, line in enumerate(lines, start=1):
        for rule in RULES:
            if rule.rule_id == "HOOK001":
                continue
            if rule.pattern.search(line):
                findings.append(_finding(rule.rule_id, rel, index, line.strip()[:180]))

        for target, patterns in SENSITIVE_TARGETS.items():
            if any(__import__("re").search(pattern, line, __import__("re").I) for pattern in patterns):
                findings.append(
                    Finding(
                        rule_id="DATA001",
                        title=f"{target} 접근",
                        severity=24,
                        file=rel,
                        line=index,
                        evidence=line.strip()[:180],
                        category="data-access",
                        description=f"{target}로 분류되는 개인정보 또는 인증정보 경로를 참조합니다.",
                    )
                )

    if path.suffix == ".py":
        findings.extend(_scan_python_ast(rel, text))
    if path.name == "package.json":
        findings.extend(_scan_package_json(rel, text))

    return _dedupe(findings)


def _scan_python_ast(rel: str, text: str) -> list[Finding]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []

    assignments: dict[str, str] = {}
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments[target.id] = node.value.value
        if isinstance(node, ast.Call):
            name = _call_name(node.func)
            if name in {"requests.post", "subprocess.run", "os.system"}:
                joined_args = " ".join(_literal_or_name(arg, assignments) for arg in node.args)
                if any(marker in joined_args for marker in [".aws", ".ssh", "Login Data", ".env", "http"]):
                    findings.append(
                        Finding(
                            rule_id="AST001",
                            title="AST 변수 흐름상 민감정보 전송 가능",
                            severity=28,
                            file=rel,
                            line=getattr(node, "lineno", 1),
                            evidence=joined_args[:180],
                            category="data-flow",
                            description="문자열 변수에 저장된 민감 경로나 URL이 실행 호출로 전달됩니다.",
                        )
                    )
    return findings


def _scan_package_json(rel: str, text: str) -> list[Finding]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return []
    scripts = payload.get("scripts", {})
    findings: list[Finding] = []
    for name, command in scripts.items():
        if name in {"preinstall", "postinstall", "prepare", "prestart"}:
            findings.append(
                Finding(
                    rule_id="PKG001",
                    title=f"package.json 자동 실행 스크립트: {name}",
                    severity=16,
                    file=rel,
                    line=1,
                    evidence=str(command)[:180],
                    category="auto-exec",
                    description="패키지 설치 또는 준비 단계에서 사용자 의도 없이 실행될 수 있습니다.",
                )
            )
    return findings


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _literal_or_name(node: ast.AST, assignments: dict[str, str]) -> str:
    if isinstance(node, ast.Constant):
        return str(node.value)
    if isinstance(node, ast.Name):
        return assignments.get(node.id, node.id)
    return ""


def _finding(rule_id: str, rel: str, line: int, evidence: str) -> Finding:
    rule = next(rule for rule in RULES if rule.rule_id == rule_id)
    return Finding(rule.rule_id, rule.title, rule.severity, rel, line, evidence, rule.category, rule.description)


def _extract_targets(findings: list[Finding]) -> set[str]:
    targets: set[str] = set()
    for finding in findings:
        if finding.rule_id == "DATA001":
            targets.add(finding.title.removesuffix(" 접근"))
        if ".aws" in finding.evidence:
            targets.add("AWS credentials")
        if ".ssh" in finding.evidence:
            targets.add("SSH keys")
        if "Login Data" in finding.evidence or "Cookies" in finding.evidence:
            targets.add("Browser passwords")
    return targets


def _score(profile: RepoProfile, findings: list[Finding], events: list) -> int:
    score = sum(finding.severity for finding in findings)
    score += sum(event.risk for event in events)
    score += max(0, 60 - profile.author_trust_score) // 2
    if any(f.category == "network" for f in findings) and any(f.category == "data-access" for f in findings):
        score += 22
    if any(f.category == "auto-exec" for f in findings) and any(f.category == "obfuscation" for f in findings):
        score += 12
    if not any(f.category == "data-access" for f in findings):
        score = min(score, 70)
    return max(0, min(100, score))


def _verdict(score: int) -> tuple[str, str]:
    if score >= 75:
        return "BLOCK", "clone 차단 권장"
    if score >= 45:
        return "QUARANTINE", "위험 파일 제외 후 clone 권장"
    if score >= 20:
        return "WARN", "주의 메시지 표시 후 사용자 확인 권장"
    return "SAFE", "clone 진행 가능"


def _judge_intent(score: int, findings: list[Finding], events: list, targets: list[str], profile: RepoProfile) -> str:
    if score >= 75:
        return (
            "자동 실행 진입점에서 민감 경로 접근과 외부 전송이 함께 나타납니다. "
            f"탈취 가능 정보는 {', '.join(targets) if targets else '인증정보'}이며 개인정보 유출 의도가 높습니다."
        )
    if score >= 45:
        return "자동 실행 스크립트에 위험 행동이 포함되어 있어 격리 clone이 적합합니다."
    if findings or events:
        return "일부 위험 신호가 있으나 개인정보 탈취로 단정할 근거는 부족합니다."
    return "자동 실행 위험과 개인정보 접근 정황이 낮습니다."


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen = set()
    result = []
    for finding in findings:
        key = (finding.rule_id, finding.file, finding.line, finding.evidence)
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return result


def _rel(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()
