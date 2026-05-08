# Guardit 프로젝트 계획서

## 목표

Guardit은 `git clone` 이전에 GitHub 레포지토리의 위험 후보 파일만 선별 분석해, 개발자 환경에서 자동 실행될 수 있는 개인정보 탈취 흐름을 사전에 차단하는 CLI 보안 서비스다.

핵심 탐지 대상은 단순 악성코드 문자열이 아니라 다음 조합이다.

```text
자동 실행 트리거 + 민감정보 접근 + 외부 전송 = HIGH RISK
```

이 공식은 룰 기반 분석, AST 분석, 샌드박스형 행동 추정, 위험 점수 계산에 직접 반영한다.

## 해결하려는 문제

개발자는 외부 레포를 clone한 뒤 VSCode, Cursor, npm install, make, hook 도구를 자연스럽게 실행한다. 공격자는 이 흐름에 `.vscode/tasks.json`, `package.json`, `.husky/*`, `scripts/*.sh` 같은 자동 실행 지점을 심어 개인 토큰, 클라우드 credential, SSH key, `.env`를 탈취할 수 있다.

기존 SAST나 백신은 파일 하나의 악성 패턴은 찾더라도 “개발환경 자동 실행 지점에서 민감정보를 읽고 외부로 전송한다”는 흐름을 clone 이전에 사용자 선택으로 연결하는 데 약하다. Guardit은 이 간극을 CLI UX와 정량 점수로 메운다.

## 구현 단계

1. 문서 초안 생성
2. 기본 프로젝트 구조 생성
3. CLI 기본 명령 구현
4. GitHub URL 파싱 및 repo metadata 수집
5. 파일 tree 수집
6. 위험 후보 파일 필터링
7. 후보 파일 blob 다운로드
8. 정규식 기반 evidence 탐지
9. 위험 점수 계산
10. 리포트 출력 및 JSON 저장
11. `package.json` / `tasks.json` 전용 룰 고도화
12. JS AST 성격의 흐름 분석 추가
13. Python/Shell 분석 추가
14. 샌드박스 모듈 skeleton 구현
15. LLM judge skeleton 및 fallback 구현
16. 개인정보 마스킹 구현
17. safe clone 구현
18. demo repos / test fixture 작성
19. 평가 metrics 구현
20. README 및 docs 업데이트

## MVP 범위

1차 MVP는 `.vscode/tasks.json`, `package.json`, `scripts/*.js`, `scripts/*.sh`를 필수 분석 대상으로 삼는다. 확장 대상으로 `.vscode/launch.json`, `.devcontainer/devcontainer.json`, `setup.py`, `pyproject.toml`, `Makefile`, `.husky/*`, `.githooks/*`, `pre-commit-config.yaml`도 후보 필터에 포함한다.

분석은 public GitHub 레포와 로컬 fixture를 지원한다. GitHub API token은 선택 사항이며, API key가 없어도 LLM 없이 룰 기반으로 동작한다.

## 보안 의도

Guardit은 실제 사용자 홈 디렉터리나 credential을 분석 대상 코드에 제공하지 않는다. LLM으로 전달되는 문자열은 마스킹한다. safe clone은 위험 파일을 제외한 zipball 기반 추출을 우선하며, git history가 보존되지 않는 한계를 명확히 표시한다.

## 현재 한계

MVP의 JS 분석은 외부 npm AST 파서 없이 Python 표준 라이브러리와 정규식 기반 경량 흐름 추적으로 구현한다. 샌드박스는 실제 악성코드 실행 대신 행동 추정 로그를 기본으로 사용하고, Docker/strace 확장을 위한 인터페이스를 둔다.
