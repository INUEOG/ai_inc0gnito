# Guardit

Guardit은 GitHub 레포지토리를 `git clone`하기 전에 개발자 개인정보 탈취 위험을 분석하는 pre-clone 보안 CLI입니다.

핵심 공식은 다음과 같습니다.

```text
자동 실행 트리거 + 민감정보 접근 + 외부 전송 = MALICIOUS
```

LLM은 최종 탐지 엔진이 아니라 의도 분석과 설명 생성을 돕는 보조 계층입니다. 기본 동작은 룰 기반 evidence, 경량 AST/흐름 분석, 샌드박스형 행동 추정, 정량 점수 시스템으로 수행됩니다.

## 빠른 실행

```bash
python -m guardit scan demo_repos/malicious
python -m guardit clone https://github.com/owner/repo
python -m guardit clone https://github.com/owner/repo safe-repo --choice clean
python -m guardit eval demo_repos
python -m guardit doctor
```

패키지로 설치하면 다음처럼 실행할 수 있습니다.

```bash
pip install -e .
guardit clone https://github.com/owner/repo
```

## 분석 대상

1차 MVP 필수 대상:

- `.vscode/tasks.json`
- `package.json`
- `scripts/*.js`
- `scripts/*.sh`

확장 후보:

- `.vscode/launch.json`
- `.devcontainer/devcontainer.json`
- `setup.py`
- `pyproject.toml`
- `Makefile`
- `.husky/*`
- `.githooks/*`
- `pre-commit-config.yaml`

## 결과

스캔 결과는 터미널에 출력되고 JSON 리포트가 저장됩니다.

```text
results/guardit-report.json
```

평가 결과는 다음 파일에 저장됩니다.

```text
results/evaluation-report.json
```

## LLM 사용

기본값은 LLM 미사용입니다.

```bash
OPENAI_API_KEY=... python -m guardit scan demo_repos/malicious --llm-provider openai
```

LLM 입력 전 evidence 문자열은 `guardit/ai/redact.py`에서 마스킹됩니다. `risk_adjustment`는 `-10~+10`으로 제한되며 최종 점수를 직접 결정하지 않습니다.

## Clean Clone

위험 파일 제외 clone은 GitHub zipball을 다운로드해 위험 파일을 제외하고 압축 해제합니다. 이 방식은 신뢰하지 않는 레포를 전체 clone하지 않는 장점이 있지만, git history를 보존하지 못할 수 있습니다.

## 문서

설계와 한계는 `docs/`에 정리되어 있습니다.

- `docs/project_plan.md`
- `docs/architecture.md`
- `docs/threat_model.md`
- `docs/scoring_system.md`
- `docs/test_plan.md`
- `docs/evaluation_metrics.md`
- `docs/checklist.md`
- `docs/implementation_log.md`
