from __future__ import annotations

import json
import statistics
import time
from pathlib import Path

from guardit.config import load_config
from guardit.scanner import scan_source


BLOCKING = {"SUSPICIOUS", "MALICIOUS"}


def evaluate_dataset(dataset: Path, output: Path = Path("results/evaluation-report.json")) -> dict:
    labels_path = dataset / "labels.json"
    if not labels_path.exists():
        raise FileNotFoundError(f"labels.json을 찾을 수 없습니다: {labels_path}")
    labels = json.loads(labels_path.read_text(encoding="utf-8"))
    config = load_config()
    config = config.__class__(
        max_candidate_files=config.max_candidate_files,
        max_file_bytes=config.max_file_bytes,
        sandbox_threshold=config.sandbox_threshold,
        results_dir=config.results_dir,
        logs_dir=config.logs_dir,
        github_token=config.github_token,
        llm_provider="off",
        llm_model=config.llm_model,
    )

    rows = []
    durations: list[float] = []
    for repo_name, expected in labels.items():
        source = dataset / repo_name
        started = time.perf_counter()
        report = scan_source(str(source), config)
        elapsed = (time.perf_counter() - started) * 1000
        durations.append(elapsed)
        actual = report.score.risk_level
        rows.append(
            {
                "repo": repo_name,
                "expected": expected,
                "actual": actual,
                "risk_score": report.score.final_score,
                "correct": _same_class(str(expected), actual),
                "elapsed_ms": round(elapsed, 2),
            }
        )

    total = len(rows)
    tp = sum(1 for row in rows if row["expected"] in BLOCKING and row["actual"] in BLOCKING)
    tn = sum(1 for row in rows if row["expected"] not in BLOCKING and row["actual"] not in BLOCKING)
    fp = sum(1 for row in rows if row["expected"] not in BLOCKING and row["actual"] in BLOCKING)
    fn = sum(1 for row in rows if row["expected"] in BLOCKING and row["actual"] not in BLOCKING)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    false_positive_rate = fp / (fp + tn) if fp + tn else 0.0
    false_negative_rate = fn / (fn + tp) if fn + tp else 0.0
    result = {
        "total": total,
        "accuracy": round(sum(1 for row in rows if row["expected"] == row["actual"]) / total, 3) if total else 0.0,
        "blocking_accuracy": round(sum(1 for row in rows if row["correct"]) / total, 3) if total else 0.0,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "false_positive_rate": round(false_positive_rate, 3),
        "false_negative_rate": round(false_negative_rate, 3),
        "average_elapsed_ms": round(statistics.mean(durations), 2) if durations else 0.0,
        "p95_elapsed_ms": round(_p95(durations), 2) if durations else 0.0,
        "rows": rows,
        "limits": [
            "데모 데이터셋은 지표 계산 구조 검증용입니다.",
            "운영 평가는 정상 오픈소스, 악성 샘플, 사내 정책 위반 샘플을 분리해야 합니다.",
        ],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def _same_class(expected: str, actual: str) -> bool:
    if expected == actual:
        return True
    return expected in BLOCKING and actual in BLOCKING


def _p95(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round((len(ordered) - 1) * 0.95)))
    return ordered[index]
