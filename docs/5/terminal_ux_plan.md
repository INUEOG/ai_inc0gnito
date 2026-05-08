# Terminal UX/UI 전면 개선 계획서

## 1. 현재 UX 문제점 분석

### 1.1 정보 중복
- `reporter.py`의 `render_text()`와 `terminal_ui.py`의 `render_security_report()`가 거의 같은 정보를 다른 포맷으로 출력
- execution_flows, evidence, sandbox 정보가 여러 패널에 걸쳐 반복 등장

### 1.2 과도한 영어 레이블
- "Repository Summary", "Suspicious Files", "Evidence", "Sandbox Behavior", "AI Security Analysis", "Final Risk Report"
- 한국어 기반 보안 도구인데 핵심 레이블이 전부 영어 → 발표 시 직관성 저하

### 1.3 패널 남발
- 한 번의 scan에 6개 패널(Repository Summary, Suspicious Files, Evidence, Sandbox, AI, Final Risk)
- 모든 패널이 동일한 box-drawing 스타일 → 중요도 구분 불가
- 시각적 피로감, "터미널 꾸미기" 느낌

### 1.4 badge 남발
- `[ static ]`, `[ 3 ]`, `[ MALICIOUS ]`, `[ auto_trigger ]`, `[ WATCH ]` 등
- badge가 너무 많으면 오히려 핵심 정보가 묻힘

### 1.5 색상 산만
- cyan, magenta, blue, green, yellow, red, bright_red, bright_black → 8색 이상 사용
- 특히 cyan이 기본 border에 사용되어 해커 영화 느낌 강화

### 1.6 정보 우선순위 부재
- 최종 판정이 6번째(가장 마지막) 패널에 위치
- 가장 중요한 "이 레포가 위험한가?"가 스크롤해야 보임
- evidence가 중간에 나와서 전체 맥락 파악 전에 세부사항을 봐야 함

### 1.7 SAFE 케이스 허전
- 안전할 때 "위험 evidence 없음" 한 줄만 출력
- 왜 안전한지에 대한 근거가 부족

### 1.8 sandbox skipped 표현
- "LLM 보정 전 점수 22가 sandbox threshold 30 미만입니다" → 기계적 로그

### 1.9 발표/데모 약점
- 정보가 평면적이라 발표자가 "여기가 핵심입니다"를 가리키기 어려움
- 긴 출력 → 터미널 스크롤 필요 → 발표 흐름 끊김

---

## 2. 목표 UX 방향

| 항목 | 현재 | 개선 후 |
|------|------|---------|
| 레이블 | 영어 중심 | 한국어 기반 (기술어만 영어) |
| 패널 수 | 6개 | 3~4개 핵심 섹션 |
| 색상 | 8색+ | 3색 (녹/노/적) + 기본 흰/회 |
| 정보 순서 | 세부→판정 | 판정→근거→세부 |
| badge | 과다 | 최소화, 인라인 텍스트 |
| 테두리 | box-drawing 6중 | 얇은 구분선 |
| 배너 | 대형 패널 | 1~2줄 심플 |
| 느낌 | RGB 해커 감성 | 정제된 보안 제품 |

참고 UX: Claude Code, GitHub CLI, OpenCode, Warp Terminal

---

## 3. 정보 구조 개선 방향

### 출력 순서 (위→아래)

```
1. 헤더 (1~2줄: 도구명 + 대상)
2. 진행 단계 ([1/5] ~ [5/5])
3. ──── 최종 판정 ────
   판정: MALICIOUS / 위험도: 87/100
4. ──── 탐지 요약 ────
   위험 흐름, 의심 파일, 핵심 evidence
5. ──── AI 분석 ────
   판정/신뢰도/근거
6. ──── 세부 정보 ────
   sandbox, score driver 등 (기본 숨김, verbose시 표시)
```

---

## 4. 출력 우선순위 재정리

| 순위 | 정보 | 기본 출력 | verbose |
|------|------|-----------|---------|
| 1순위 | 최종 판정, 위험도, 개인정보 탈취 가능성 | ✓ | ✓ |
| 2순위 | 왜 위험한지, 어떤 파일, 어떤 행위 | ✓ | ✓ |
| 3순위 | evidence 세부, line number, sandbox 상세 | 요약만 | ✓ |
| 4순위 | LLM 시도 기록, 점수 근거 전체 | X | ✓ |

---

## 5. 색상 정책

```
기본 텍스트:     흰색 (default) / 보조: dim(회색)
SAFE:           FG_GREEN  (#00ff00 계열)
WATCH/WARNING:  FG_YELLOW (#ffff00 계열)
SUSPICIOUS:     FG_RED    (#ff0000 계열)
MALICIOUS:      FG_BRIGHT_RED (#ff5555 계열)

금지:
- FG_CYAN (해커 감성)
- FG_MAGENTA (과도한 강조)
- FG_BLUE (패널 테두리)
```

---

## 6. Typography 정책

- 구분선: `────────────────` (단순 dash line)
- 제목: BOLD만 사용, 색상은 위험도에 따라
- 본문: 기본 흰색, 보조 정보는 DIM
- secret/credential 키워드: 해당 위험도 색상으로 인라인 강조
- badge: `[ ]` → 인라인 색 텍스트. 정말 필요한 경우만 뱃지 유지 (MALICIOUS, SAFE 등 등급)

---

## 7. Panel 구조

### Before (6개 패널)
```
┌──────────────────────────────┐
│ Repository Summary           │
├──────────────────────────────┤
│ ...                          │
└──────────────────────────────┘

┌──────────────────────────────┐
│ Suspicious Files             │
...
(x6 반복)
```

### After (섹션 구분선 방식)
```
guardit · 분석 대상: https://github.com/user/repo

✓ [1/5] GitHub 정보 수집
✓ [2/5] 자동 실행 파일 탐지
✓ [3/5] 정적 분석
✓ [4/5] sandbox 분석
✓ [5/5] AI 의도 분석

──── 최종 판정 ─────────────────────────

  판정: MALICIOUS
  위험도: ████████░░ 87/100
  개인정보 탈취: AWS credentials, SSH key

──── 탐지 요약 ─────────────────────────

  의심 파일 3개
  - package.json (postinstall 자동 실행)
  - scripts/setup.js (외부 전송)
  - .vscode/tasks.json (폴더 열기 시 실행)

  위험 흐름
  - package.json → scripts/setup.js
    → ~/.aws/credentials 접근
    → https://evil.com POST 전송

  [inferred]
  - package.json lifecycle script
  - credential 파일 접근 시도

  [observed]
  - ~/.aws 디렉토리 접근
  - 외부 POST 연결 시도

──── AI 분석 ────────────────────────────

  판정: MALICIOUS
  신뢰도: ████████████████████░░░░ 97%

  근거:
  - 자동 실행 스크립트 존재
  - AWS credentials 접근 시도
  - 외부 서버 POST 요청 탐지

──── 상세 정보 ──────────────────────────

  처리 시간: 2340.52ms
  JSON 리포트: results/guardit-report.json
```

---

## 8. 위험도 표현 방식

```
판정: MALICIOUS
위험도: ████████░░ 87/100
```

- 게이지 bar는 10칸 고정
- 숫자/100 형태 유지
- 등급은 BOLD + 등급 색상으로 표시
- 과도한 이모지/아이콘 금지

---

## 9. AI 분석 결과 표현

```
──── AI 분석 ────────────────────────────

  판정: MALICIOUS
  신뢰도: 97%

  근거:
  - 자동 실행 스크립트 존재
  - AWS credentials 접근 시도
  - 외부 서버 POST 요청 탐지
```

- 일반 로그가 아닌 "보안 리포트" 느낌
- provider/attempts 등 기술 세부사항은 verbose에서만
- 핵심: 판정 → 신뢰도 → 근거 순서

---

## 10. Inferred / Observed 구분 방식

```
  [inferred] 정적 추론
  - package.json lifecycle script
  - credential 파일 접근 패턴

  [observed] 실제 행위
  - ~/.aws 디렉토리 접근
  - 외부 POST 연결 시도
```

- `[inferred]`는 DIM 또는 YELLOW으로 표시
- `[observed]`는 RED로 표시 (실제 관측이므로 더 위험)
- 각각 2~3줄 요약. 전체는 verbose 또는 JSON export

---

## 11. 발표/데모 최적화 방향

1. 전체 출력이 터미널 한 화면에 들어오도록 정보 압축
2. 최종 판정이 가장 먼저 보이므로 "결론" 즉시 확인 가능
3. 진행 단계가 실시간으로 보이므로 "분석 과정"이 시각적으로 전달
4. SAFE 결과도 "왜 안전한지" 보여서 도구의 가치 입증
5. 한국어 메시지로 발표자가 별도 설명 불필요

---

## 12. 구현 라이브러리 선정

현재 프로젝트 정책: **Python 표준 라이브러리만 사용** (`requirements.txt` 참고)

따라서:
- ANSI escape code 직접 사용 유지 (현재 방식)
- `rich` 라이브러리는 도입하지 않음 (외부 의존성 금지 정책)
- `shutil.get_terminal_size()` 활용한 터미널 너비 대응 유지

> 향후 rich 도입 시 마이그레이션이 쉽도록, 출력 함수를 모듈화하여 구성

---

## 13. 성능 영향 여부

- 출력 레이어만 변경하므로 스캔/분석 성능에 영향 없음
- spinner 스레드는 기존과 동일 (0.08초 간격)
- 패널 렌더링은 문자열 조립이므로 무시 가능한 수준
- terminal_width() 호출 횟수는 동일하거나 감소
