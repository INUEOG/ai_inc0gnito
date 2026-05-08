# Guardit 아키텍처

## 전체 흐름

```text
CLI
  -> GitHubClient
  -> FileFilter
  -> StaticAnalyzer(regex/js/python/shell)
  -> RiskScorer
  -> SandboxRunner(조건부)
  -> LLMJudge(선택)
  -> Reporter
  -> SafeClone
```

이 구조는 clone 이전 분석과 clone 수행을 분리한다. 분석 단계는 GitHub API tree와 blob만 사용하고, 사용자 선택 후에만 clone 또는 zipball 추출을 수행한다.

## 모듈 책임

- `guardit/cli.py`: 명령 파싱, 단계별 UX, 사용자 선택 처리
- `guardit/github_client.py`: GitHub URL 파싱, metadata/tree/blob/zipball 수집
- `guardit/file_filter.py`: 위험 후보 파일 선별, 크기와 binary 제한
- `guardit/static_analyzer/*`: evidence 생성 중심의 정적 분석
- `guardit/scoring/risk_score.py`: 0~100 점수와 판정 산출
- `guardit/sandbox/*`: 행동 추정 및 향후 Docker/strace 확장 지점
- `guardit/ai/*`: 개인정보 마스킹, LLM JSON judge, fallback
- `guardit/clone/safe_clone.py`: 위험 파일 제외 zipball 추출
- `guardit/evaluation/metrics.py`: 라벨 기반 정량 평가
- `guardit/reporter.py`: 터미널/JSON 리포트

## 설계 이유

LLM을 탐지 엔진으로 두면 재현성과 비용, 개인정보 전송 위험이 커진다. 따라서 핵심 판단은 evidence와 점수 시스템이 담당하고, LLM은 오탐 감소와 설명 생성을 돕는 보조 계층으로 제한한다.

GitHub 수집은 대형 레포 대응을 위해 tree만 먼저 가져온 뒤 후보 파일 blob만 다운로드한다. 이 방식은 전체 clone보다 빠르고, 사용자가 신뢰하지 않는 코드를 로컬 개발환경에 배치하기 전에 판단할 수 있다.

## 확장성

Private repo는 GitHub token header를 이미 주입할 수 있는 구조로 둔다. Docker sandbox는 `SandboxRunner` 인터페이스에 실제 실행 구현을 추가하면 된다. LLM provider는 `LLMJudge` 내부의 provider 분기로 OpenAI/Gemini/Claude를 붙일 수 있다.

## 한계

GitHub API rate limit, archive 다운로드 실패, 초대형 파일, 동적 코드 생성, 난독화된 다단계 payload는 MVP에서 완전하게 분석하지 못한다. 위험 점수는 보수적으로 설계하되 근거 기반으로 출력해 사용자가 판단할 수 있게 한다.
