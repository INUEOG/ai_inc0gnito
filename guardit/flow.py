from __future__ import annotations

import json
import re
from pathlib import PurePosixPath

from .models import CandidateFile, Evidence, ExecutionFlow


SCRIPT_REF_RE = re.compile(r"([\w./-]+\.(?:js|mjs|cjs|py|sh|bash|zsh))")


def build_execution_flows(candidates: list[CandidateFile], evidence: list[Evidence]) -> list[ExecutionFlow]:
    by_path = {candidate.path: candidate for candidate in candidates}
    flows: list[ExecutionFlow] = []

    for candidate in candidates:
        if candidate.path == ".vscode/tasks.json":
            flows.extend(_flows_from_tasks(candidate, by_path, evidence))
        elif candidate.path == "package.json":
            flows.extend(_flows_from_package(candidate, by_path, evidence))
        elif candidate.path.endswith((".sh", ".bash", ".zsh")):
            flows.extend(_flows_from_shell(candidate, by_path, evidence))

    if not flows:
        flows.extend(_fallback_flows(candidates, evidence))
    return _dedupe(flows)


def _flows_from_tasks(candidate: CandidateFile, by_path: dict[str, CandidateFile], evidence: list[Evidence]) -> list[ExecutionFlow]:
    flows: list[ExecutionFlow] = []
    try:
        payload = json.loads(candidate.content)
    except json.JSONDecodeError:
        return flows
    tasks = payload.get("tasks", []) if isinstance(payload, dict) else []
    if not isinstance(tasks, list):
        return flows
    for task in tasks:
        if not isinstance(task, dict):
            continue
        command = str(task.get("command", ""))
        for ref in _extract_script_refs(command):
            target = _normalize_ref(ref)
            flows.append(_flow(candidate.path, target if target in by_path else ref, evidence, [command]))
    return flows


def _flows_from_package(candidate: CandidateFile, by_path: dict[str, CandidateFile], evidence: list[Evidence]) -> list[ExecutionFlow]:
    flows: list[ExecutionFlow] = []
    try:
        payload = json.loads(candidate.content)
    except json.JSONDecodeError:
        return flows
    scripts = payload.get("scripts", {}) if isinstance(payload, dict) else {}
    if not isinstance(scripts, dict):
        return flows
    for name, command in scripts.items():
        if name not in {"preinstall", "install", "postinstall", "prepare"}:
            continue
        command_text = str(command)
        refs = _extract_script_refs(command_text)
        if refs:
            for ref in refs:
                target = _normalize_ref(ref)
                flows.append(_flow(candidate.path, target if target in by_path else ref, evidence, [f"{name}: {command_text}"]))
        else:
            flows.append(_flow(candidate.path, None, evidence, [f"{name}: {command_text}"]))
    return flows


def _flows_from_shell(candidate: CandidateFile, by_path: dict[str, CandidateFile], evidence: list[Evidence]) -> list[ExecutionFlow]:
    flows: list[ExecutionFlow] = []
    for line in candidate.content.splitlines():
        refs = _extract_script_refs(line)
        for ref in refs:
            target = _normalize_ref(ref)
            flows.append(_flow(candidate.path, target if target in by_path else ref, evidence, [line.strip()]))
    return flows


def _fallback_flows(candidates: list[CandidateFile], evidence: list[Evidence]) -> list[ExecutionFlow]:
    paths = {candidate.path for candidate in candidates}
    flows: list[ExecutionFlow] = []
    trigger_paths = {item.file for item in evidence if item.category == "auto_trigger"}
    for trigger in sorted(trigger_paths):
        if trigger in paths:
            flows.append(_flow(trigger, trigger, evidence, []))
    return flows


def _flow(trigger: str, executed: str | None, evidence: list[Evidence], process_steps: list[str]) -> ExecutionFlow:
    relevant_files = {trigger}
    if executed:
        relevant_files.add(executed)
    related = [item for item in evidence if item.file in relevant_files]
    secrets = _unique([item.evidence for item in related if item.category == "secret_access"])[:5]
    sinks = _unique([item.evidence for item in related if item.category == "external_sink"])[:5]
    processes = _unique([*process_steps, *[item.evidence for item in related if item.category in {"remote_execution", "process_execution", "obfuscation"}]])[:5]
    if secrets and sinks:
        risk = "credential_exfiltration_flow"
    elif sinks or processes:
        risk = "auto_execution_with_external_or_process_behavior"
    else:
        risk = "auto_execution_candidate"
    return ExecutionFlow(trigger_file=trigger, executed_file=executed, secret_sources=secrets, external_sinks=sinks, process_steps=processes, risk=risk)


def _extract_script_refs(command: str) -> list[str]:
    refs = [match.group(1).strip("'\"") for match in SCRIPT_REF_RE.finditer(command)]
    return [ref for ref in refs if "://" not in ref and not ref.startswith("//")]


def _normalize_ref(ref: str) -> str:
    normalized = ref.replace("\\", "/").lstrip("./")
    parts = PurePosixPath(normalized).parts
    return PurePosixPath(*parts).as_posix() if parts else normalized


def _dedupe(flows: list[ExecutionFlow]) -> list[ExecutionFlow]:
    seen: set[tuple[str, str | None, str]] = set()
    result: list[ExecutionFlow] = []
    for flow in flows:
        key = (flow.trigger_file, flow.executed_file, flow.risk)
        if key in seen:
            continue
        seen.add(key)
        result.append(flow)
    return result


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
