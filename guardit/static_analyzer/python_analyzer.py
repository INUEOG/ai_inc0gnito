from __future__ import annotations

import ast

from guardit.models import CandidateFile, Evidence


SOURCE_CALLS = {"open", "os.getenv", "pathlib.Path.read_text", "Path.read_text"}
SINK_CALLS = {"requests.post", "subprocess.run", "os.system", "exec", "eval"}
DECODE_CALLS = {"base64.b64decode"}
SECRET_MARKERS = (".aws", ".ssh", ".env", "TOKEN", "SECRET", "credentials", "id_rsa", "client_secret")


def analyze_python(candidate: CandidateFile) -> list[Evidence]:
    try:
        tree = ast.parse(candidate.content)
    except SyntaxError:
        return []
    visitor = _PythonVisitor(candidate.path)
    visitor.visit(tree)
    return visitor.evidence


class _PythonVisitor(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.source_vars: set[str] = set()
        self.constants: dict[str, str] = {}
        self.evidence: list[Evidence] = []

    def visit_Assign(self, node: ast.Assign) -> None:
        value_text = self._expr_text(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    self.constants[target.id] = node.value.value
                if self._is_source(node.value, value_text):
                    self.source_vars.add(target.id)
                    self.evidence.append(_ev(self.path, node.lineno, "py_secret_source", "high", value_text[:220], 20, "secret_access", "Python source 값이 변수에 저장됩니다."))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        call_name = _call_name(node.func)
        text = self._expr_text(node)
        if call_name in SOURCE_CALLS or call_name.endswith(".read_text"):
            score = 25 if _contains_secret(text) else 12
            self.evidence.append(_ev(self.path, getattr(node, "lineno", 1), "py_secret_access", "high", text[:220], score, "secret_access", "Python 파일/환경변수 접근입니다."))
        if call_name in SINK_CALLS:
            category = "external_sink" if call_name == "requests.post" else "process_execution"
            self.evidence.append(_ev(self.path, getattr(node, "lineno", 1), "py_sink", "high", text[:220], 15, category, "Python sink 또는 동적 실행 호출입니다."))
            if self._uses_source_var(node):
                self.evidence.append(_ev(self.path, getattr(node, "lineno", 1), "source_to_sink", "critical", text[:220], 20, "data_flow", "민감정보 source 변수가 sink로 전달됩니다."))
        if call_name in DECODE_CALLS:
            self.evidence.append(_ev(self.path, getattr(node, "lineno", 1), "base64_decode", "medium", text[:220], 10, "obfuscation", "base64 디코딩 호출입니다."))
        self.generic_visit(node)

    def _is_source(self, node: ast.AST, text: str) -> bool:
        if isinstance(node, ast.Call):
            call_name = _call_name(node.func)
            return call_name in SOURCE_CALLS or call_name.endswith(".read_text") or _contains_secret(text)
        return _contains_secret(text)

    def _uses_source_var(self, node: ast.AST) -> bool:
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in self.source_vars:
                return True
        return False

    def _expr_text(self, node: ast.AST) -> str:
        try:
            return ast.unparse(node)
        except Exception:
            return node.__class__.__name__


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _contains_secret(text: str) -> bool:
    return any(marker.lower() in text.lower() for marker in SECRET_MARKERS)


def _ev(path: str, line: int, type_: str, severity: str, evidence: str, score: int, category: str, description: str) -> Evidence:
    return Evidence(path, line, type_, severity, evidence, score, category, description)
