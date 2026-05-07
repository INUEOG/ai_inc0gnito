from __future__ import annotations

import json
import statistics
import time
from pathlib import Path

from .analyzer import scan_profile
from .collector import collect_source


BLOCKING = {"BLOCK", "QUARANTINE"}


def evaluate_dataset(root: Path) -> dict:
    labels_path = root / "labels.json"
    if not labels_path.exists():
        raise FileNotFoundError("labels.json이 있는 데모 데이터셋 경로가 필요합니다.")
    labels = json.loads(labels_path.read_text(encoding="utf-8"))

    rows = []
    durations = []
    for name, expected in labels.items():
        source = root / name
        started = time.perf_counter()
        report = scan_profile(collect_source(str(source)))
        durations.append((time.perf_counter() - started) * 1000)
        rows.append(
            {
                "repo": name,
                "expected": expected,
                "actual": report.verdict,
                "risk_score": report.risk_score,
                "correct": _same_class(expected, report.verdict),
                "elapsed_ms": round(report.elapsed_ms, 2),
            }
        )

    tp = sum(1 for row in rows if row["expected"] in BLOCKING and row["actual"] in BLOCKING)
    tn = sum(1 for row in rows if row["expected"] == "SAFE" and row["actual"] == "SAFE")
    fp = sum(1 for row in rows if row["expected"] == "SAFE" and row["actual"] in BLOCKING)
    fn = sum(1 for row in rows if row["expected"] in BLOCKING and row["actual"] == "SAFE")
    total = len(rows)

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    false_positive_rate = fp / (fp + tn) if fp + tn else 0.0

    return {
        "total_repos": total,
        "accuracy": round(sum(row["correct"] for row in rows) / total, 3),
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "false_positive_rate": round(false_positive_rate, 3),
        "avg_elapsed_ms": round(statistics.mean(durations), 2),
        "p95_elapsed_ms": round(max(durations), 2),
        "rows": rows,
        "limits": [
            "데모 데이터셋은 작기 때문에 실제 성능 수치가 아니라 지표 산정 방식 검증용입니다.",
            "실서비스에서는 공개 악성 레포, 정상 오픈소스, 사내 정책 위반 샘플을 분리해 평가해야 합니다.",
        ],
    }


def _same_class(expected: str, actual: str) -> bool:
    if expected == actual:
        return True
    return expected in BLOCKING and actual in BLOCKING
