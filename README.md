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
python -m guardit scan demo_repos/malicious --sandbox static
python -m guardit scan demo_repos/malicious --sandbox docker
python -m guardit clone https://github.com/owner/repo
python -m guardit clone https://github.com/owner/repo safe-repo --choice clean
python -m guardit clone demo_repos/malicious /tmp/guardit-clean --clean-clone
python -m guardit eval demo_repos
python -m guardit report results/guardit-report.json
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

리포트에는 다음 항목이 포함됩니다.

- verdict
- risk score
- 위험 후보 파일과 선별 이유
- evidence
- 탈취 가능 개인정보
- 실행 흐름
- sandbox mode
- inferred evidence
- observed evidence
- warning
- 권장 조치

평가 결과는 다음 파일에 저장됩니다.

```text
results/eval_result.json
results/eval_report.md
```

## LLM 사용

기본 LLM provider는 Gemini API입니다. `GEMINI_API_KEY` 또는 `GOOGLE_API_KEY`가 없으면 LLM 호출 없이 offline fallback으로 동작합니다.

```bash
GEMINI_API_KEY=... python -m guardit scan demo_repos/malicious
GEMINI_API_KEY=... python -m guardit clone https://github.com/owner/repo --llm-provider gemini-api
```

LLM은 핵심 탐지 엔진이 아니라 evidence 기반 보조 판단기입니다. 파일 필터링, 정규식 탐지, source-to-sink 분석, scoring은 LLM 없이 동작합니다. LLM 입력 전 evidence 문자열은 `guardit/ai/redact.py`에서 마스킹됩니다. `risk_adjustment`는 `-10~+10`으로 제한되며 최종 점수를 직접 결정하지 않습니다.

필요하면 `--llm-provider off`로 LLM을 끄거나, 호환용 `--llm-provider openai`를 사용할 수 있습니다.

## Sandbox Mode

Guardit은 sandbox 관련 분석을 세 가지 모드로 제공합니다.

```bash
python -m guardit scan <repo> --sandbox off
python -m guardit scan <repo> --sandbox static
python -m guardit scan <repo> --sandbox docker
```

- `off`: sandbox 관련 분석을 사용하지 않습니다.
- `static`: 기본값입니다. 실제 실행 없이 후보 파일 문자열과 evidence로 행동 가능성을 추정합니다.
- `docker`: Docker 컨테이너 안에서 제한된 자동 실행 command를 strace로 관찰합니다.

`static`은 실제 sandbox가 아닙니다. 리포트에서는 `static-behavior-inference`와 `[inferred]`로 표시됩니다.

`docker`는 실제 Docker/strace 기반 관찰 기능입니다. 리포트에서는 `docker-sandbox`, `is_real_sandbox: true`, `[observed]`로 구분됩니다. 단, Docker CLI, Docker daemon 권한, strace가 포함된 sandbox image가 필요합니다.

Sandbox image 예시:

```bash
docker build -f docker/sandbox.Dockerfile -t guardit-sandbox:latest .
```

Docker sandbox는 다음 제한을 적용합니다.

- `--network=none`
- `--read-only`
- `--memory=256m`
- `--cpus=0.5`
- `--cap-drop=ALL`
- `--security-opt no-new-privileges`
- non-root user
- timeout

실제 사용자 HOME이나 실제 credential은 절대 마운트하지 않습니다. Docker sandbox는 임시 HOME에 dummy 파일만 생성합니다.

```text
/sandbox-home/.aws/credentials
/sandbox-home/.ssh/id_rsa
/sandbox-home/.env
```

Docker가 없거나 권한이 없거나 image에 strace가 없으면 Guardit은 실패하지 않고 static behavior inference로 fallback합니다. 리포트에는 fallback 여부와 이유가 표시됩니다.

현재 Docker sandbox는 production-grade malware sandbox가 아닙니다. 제한된 자동 실행 command만 실행하며, dependency install이나 전체 레포 실행은 하지 않습니다.

## 평가 데이터셋

`demo_repos`는 교육용 mock 데이터셋 15개를 포함합니다.

- benign 5개
- suspicious 5개
- malicious 5개

평가 명령은 accuracy, TPR, FPR, precision, recall, confusion matrix, evidence count, average/p95 elapsed time을 계산합니다.

```bash
python -m guardit eval demo_repos --output results/eval_result.json
```

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
- `docs/2/PROJECT_PLAN.md`
- `docs/2/IMPLEMENTATION_REPORT.md`
- `docs/2/EVALUATION_PLAN.md`
- `docs/2/DEMO_SCENARIO.md`
- `docs/3/PROJECT_PLAN.md`
- `docs/3/SANDBOX_DESIGN.md`
- `docs/3/IMPLEMENTATION_REPORT.md`
- `docs/3/TEST_REPORT.md`
- `docs/3/DEMO_SCENARIO.md`
