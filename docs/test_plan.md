# 테스트 계획

## 테스트 목표

Guardit 테스트는 악성코드 전체 탐지가 아니라 pre-clone 개인정보 탈취 차단 흐름을 검증한다.

## 테스트 범위

- GitHub URL 파싱
- 위험 후보 파일 필터링
- `.vscode/tasks.json`의 `runOn: folderOpen`
- `package.json`의 `preinstall`, `install`, `postinstall`, `prepare`
- `curl | bash`, `wget | sh`, `node -e`, `bash -c`
- 민감정보 접근 evidence 생성
- 외부 전송 evidence 생성
- source -> sink 흐름 점수 반영
- LLM API key가 없을 때 fallback
- 결과 JSON 저장
- safe clone에서 위험 파일 제외
- 평가 지표 계산

## 샘플 데이터

`demo_repos/benign`, `demo_repos/suspicious`, `demo_repos/malicious`에 정상, 애매, 악성 샘플을 둔다. 악성 샘플은 folderOpen -> AWS credentials -> fetch POST, postinstall -> .env -> curl POST, base64 + eval, curl | bash를 포함한다.

## 한계

MVP 테스트는 실제 Docker sandbox 실행을 요구하지 않는다. 샌드박스형 행동 추정이 기대 로그를 생성하는지 확인한다.
