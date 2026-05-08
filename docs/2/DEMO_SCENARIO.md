# Guardit 데모 시나리오

## 1. 악성 레포 scan

```bash
python3 -m guardit scan demo_repos/malicious
```

기대 결과:

- `.vscode/tasks.json`의 `runOn: folderOpen`
- `node scripts/init.js`
- `~/.aws/credentials` 접근 정황
- 외부 POST 전송
- MALICIOUS 판정

## 2. 위험 흐름 확인

출력의 `[위험 흐름]`에서 다음 연결을 확인한다.

```text
.vscode/tasks.json
  -> scripts/init.js
  -> AWS credentials 접근
  -> POST 시도
```

## 3. 저장된 리포트 재출력

```bash
python3 -m guardit report results/guardit-report.json
```

발표에서는 JSON을 직접 읽는 대신 이 명령으로 핵심 evidence와 흐름을 보여준다.

## 4. clean clone

```bash
python3 -m guardit clone demo_repos/malicious /tmp/guardit-clean-demo --clean-clone
```

기대 결과:

- 위험 후보 파일 제외
- `guardit-report.json` 생성
- `README_GUARDIT_WARNING.md` 생성

## 5. 평가 지표

```bash
python3 -m guardit eval demo_repos --output results/eval_result.json
```

기대 결과:

- confusion matrix 출력
- TPR/FPR/precision/recall 출력
- evidence count와 처리 시간 출력
- `results/eval_report.md` 생성

## 6. 발표 포인트

- Guardit은 clone 이후 악성코드를 찾는 도구가 아니라 clone 이전 위험 차단 도구다.
- LLM 없이도 핵심 탐지가 동작한다.
- LLM은 evidence 기반 보조 판단기다.
- 실제 credential은 읽지 않는다.
- sandbox-like 로그는 실제 실행 로그가 아니라 정적 추정임을 명확히 표시한다.
