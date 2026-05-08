from __future__ import annotations

import re
import shlex
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from guardit.flow import execution_commands
from guardit.models import CandidateFile, Evidence, ExecutionFlow, SandboxLog, SandboxSummary
from guardit.sandbox.strace_parser import parse_strace


SECRET_RE = re.compile(r"(\.aws[/\\]credentials|\.ssh[/\\]id_rsa|\.env|NPM_TOKEN|GITHUB_TOKEN|ghp_|github_pat_)", re.I)
NETWORK_RE = re.compile(r"(https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)|curl|wget|fetch|axios\.post|requests\.post|nc\s+)", re.I)
PROCESS_RE = re.compile(r"(child_process|subprocess|os\.system|bash\s+-c|node\s+-e|eval|exec|\b(node|python|python3|bash|sh|pwsh|powershell)\s+[\w./-]+)", re.I)


@dataclass
class StaticBehaviorAnalyzer:
    """실행 없는 static behavior inference.

    실제 Docker/strace가 아니라 후보 파일 문자열과 evidence를 기반으로 행동 가능성을 추정한다.
    """

    def analyze(self, candidates: list[CandidateFile], evidence: list[Evidence]) -> list[SandboxLog]:
        logs: list[SandboxLog] = []
        for candidate in candidates:
            for line_no, line in enumerate(candidate.content.splitlines(), start=1):
                stripped = line.strip()
                if SECRET_RE.search(line):
                    logs.append(SandboxLog(candidate.path, line_no, "dummy_credential_access", _secret_target(line) or stripped[:220], 15, origin="inferred"))
                if NETWORK_RE.search(line):
                    logs.append(SandboxLog(candidate.path, line_no, "network_connect_attempt", stripped[:220], 15, origin="inferred"))
                if PROCESS_RE.search(line):
                    logs.append(SandboxLog(candidate.path, line_no, "process_spawn", stripped[:220], 8, origin="inferred"))
        return _dedupe(logs)

    def summarize(self, logs: list[SandboxLog], fallback_used: bool = False, fallback_reason: str | None = None) -> SandboxSummary:
        return summarize_sandbox_logs(
            "static-behavior-inference",
            logs,
            is_real_sandbox=False,
            fallback_used=fallback_used,
            fallback_reason=fallback_reason,
        )


@dataclass
class DockerSandboxRunner:
    image: str = "python:3.12-slim"
    timeout_sec: int = 8
    memory_limit: str = "256m"
    cpu_limit: str = "0.5"

    def analyze(
        self,
        candidates: list[CandidateFile],
        evidence: list[Evidence],
        flows: list[ExecutionFlow],
    ) -> tuple[list[SandboxLog], SandboxSummary]:
        docker_path = shutil.which("docker")
        if docker_path is None:
            return self._fallback(candidates, evidence, "Docker CLI를 찾지 못해 static behavior inference로 fallback했습니다.")

        commands = execution_commands(flows)
        if not commands:
            return self._fallback(candidates, evidence, "제한 실행 가능한 자동 실행 command를 찾지 못해 static behavior inference로 fallback했습니다.")

        with tempfile.TemporaryDirectory(prefix="guardit_sandbox_") as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            home = root / "sandbox-home"
            trace_dir = root / "trace"
            workspace.mkdir()
            trace_dir.mkdir(mode=0o777)
            trace_dir.chmod(0o777)
            self._materialize_candidates(workspace, candidates)
            self._write_dummy_home(home)

            command = self._docker_command(docker_path, workspace, home, trace_dir, commands)
            try:
                completed = subprocess.run(command, capture_output=True, text=True, timeout=self.timeout_sec + 3, check=False)
            except subprocess.TimeoutExpired:
                return self._fallback(candidates, evidence, f"Docker sandbox timed out after {self.timeout_sec + 3}s.")
            except OSError as exc:
                return self._fallback(candidates, evidence, f"Docker sandbox 실행 실패: {exc}")
            trace_path = trace_dir / "strace.log"
            trace_text = trace_path.read_text(encoding="utf-8", errors="replace") if trace_path.exists() else ""
            logs = parse_strace(trace_text, file_hint="docker-sandbox")
            if completed.returncode != 0 and not logs:
                reason = (completed.stderr or completed.stdout or f"Docker sandbox exited with {completed.returncode}").strip()[:400]
                return self._fallback(candidates, evidence, reason)

        summary = summarize_sandbox_logs("docker-sandbox", logs, is_real_sandbox=True)
        return logs, summary

    def security_profile(self) -> list[str]:
        return [
            "--rm",
            "--network=none",
            "--read-only",
            f"--memory={self.memory_limit}",
            f"--cpus={self.cpu_limit}",
            "--cap-drop=ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            "65534:65534",
        ]

    def _docker_command(self, docker_path: str, workspace: Path, home: Path, trace_dir: Path, commands: list[str]) -> list[str]:
        joined = " ; ".join(f"({command})" for command in commands[:3])
        traced = (
            "export HOME=/sandbox-home; "
            f"timeout {self.timeout_sec}s strace -f -qq -e trace=file,network,process "
            f"-o /trace/strace.log sh -c {shlex.quote(joined)}"
        )
        return [
            docker_path,
            "run",
            *self.security_profile(),
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,noexec,size=16m",
            "-v",
            f"{workspace}:/workspace:ro",
            "-v",
            f"{home}:/sandbox-home:ro",
            "-v",
            f"{trace_dir}:/trace:rw",
            "-w",
            "/workspace",
            self.image,
            "sh",
            "-c",
            traced,
        ]

    def _materialize_candidates(self, workspace: Path, candidates: list[CandidateFile]) -> None:
        for candidate in candidates:
            target = workspace / candidate.path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(candidate.content, encoding="utf-8")

    def _write_dummy_home(self, home: Path) -> None:
        (home / ".aws").mkdir(parents=True)
        (home / ".ssh").mkdir(parents=True)
        (home / ".aws" / "credentials").write_text("[default]\naws_access_key_id=FAKE_AWS_KEY\naws_secret_access_key=FAKE_AWS_SECRET\n", encoding="utf-8")
        (home / ".ssh" / "id_rsa").write_text("FAKE_SSH_KEY\n", encoding="utf-8")
        (home / ".env").write_text("FAKE_TOKEN=guardit_dummy\n", encoding="utf-8")

    def _fallback(self, candidates: list[CandidateFile], evidence: list[Evidence], reason: str) -> tuple[list[SandboxLog], SandboxSummary]:
        static = StaticBehaviorAnalyzer()
        logs = static.analyze(candidates, evidence)
        return logs, static.summarize(logs, fallback_used=True, fallback_reason=reason)


SandboxRunner = StaticBehaviorAnalyzer


def summarize_sandbox_logs(
    mode: str,
    logs: list[SandboxLog],
    is_real_sandbox: bool,
    fallback_used: bool = False,
    fallback_reason: str | None = None,
) -> SandboxSummary:
    inferred = [log for log in logs if log.origin == "inferred"]
    observed = [log for log in logs if log.origin == "observed"]
    return SandboxSummary(
        mode=mode,
        is_real_sandbox=is_real_sandbox,
        fallback_used=fallback_used,
        fallback_reason=fallback_reason,
        inferred_opened_files=sorted({log.detail for log in inferred if log.action == "dummy_credential_access"}),
        inferred_network_attempts=sorted({log.detail for log in inferred if log.action == "network_connect_attempt"}),
        inferred_processes=sorted({log.detail for log in inferred if log.action == "process_spawn"}),
        observed_opened_files=sorted({log.detail for log in observed if log.action in {"dummy_credential_access", "dummy_credential_io"}}),
        observed_network_attempts=sorted({log.detail for log in observed if log.action == "network_connect_attempt"}),
        observed_processes=sorted({log.detail for log in observed if log.action == "process_spawn"}),
        dummy_credentials_accessed=any(log.action in {"dummy_credential_access", "dummy_credential_io"} for log in logs),
    )


def _dedupe(logs: list[SandboxLog]) -> list[SandboxLog]:
    seen: set[tuple[str, int, str, str, str]] = set()
    result: list[SandboxLog] = []
    for log in logs:
        key = (log.file, log.line, log.action, log.detail, log.origin)
        if key in seen:
            continue
        seen.add(key)
        result.append(log)
    return result


def _secret_target(line: str) -> str | None:
    for pattern in [
        r"\$HOME/\.aws/credentials",
        r"~/\.aws/credentials",
        r"\.aws[/\\]credentials",
        r"\$HOME/\.ssh/id_rsa",
        r"~/\.ssh/id_rsa",
        r"\.ssh[/\\]id_rsa",
        r"\$HOME/\.env",
        r"~/\.env",
        r"\.env",
    ]:
        match = re.search(pattern, line, flags=re.I)
        if match:
            return match.group(0)
    return None
