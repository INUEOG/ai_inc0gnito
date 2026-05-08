from __future__ import annotations

import re
from typing import Any


PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}", re.I),
    re.compile(r"ghp_[A-Za-z0-9_]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]+"),
    re.compile(r"npm_[A-Za-z0-9_]+"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"Bearer\s+[A-Za-z0-9._\-]+", re.I),
    re.compile(r"(password|secret|access_key|refresh_token|client_secret)\s*=\s*[^&\s'\"`]+", re.I),
]


def redact_sensitive_text(text: str) -> str:
    redacted = text
    for pattern in PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def redact_obj(value: Any) -> Any:
    if isinstance(value, str):
        return redact_sensitive_text(value)
    if isinstance(value, list):
        return [redact_obj(item) for item in value]
    if isinstance(value, dict):
        return {key: redact_obj(item) for key, item in value.items()}
    return value
