# Terminal UX/UI 개선 결과

## 수정 파일

| 파일 | 변경 내용 |
|------|-----------|
| `guardit/terminal_ui.py` | 전면 리팩토링 (409→330줄) |
| `guardit/reporter.py` | 출력 구조 개선 + 한국어 전환 |
| `guardit/cli.py` | 액션 메시지 한국어화 + doctor 정리 |

## 핵심 변경 사항

### 1. 색상 정책 변경
- **Before**: 8색+ (cyan, magenta, blue, green, yellow, red, bright_red, bright_black)
- **After**: 3색 (녹/노/적) + 흰/회

`FG_CYAN`, `FG_MAGENTA`, `FG_BLUE` 전부 제거. 위험도에 따른 3색 + 기본 텍스트(흰) + 보조(DIM) 만 사용.

### 2. 패널 → 섹션 구분선
- **Before**: box-drawing 패널 6개 (`┌─┐`, `│ │`, `└─┘`)
- **After**: 얇은 구분선 (`──── 제목 ────`) 4개 섹션

### 3. 정보 구조 순서 변경
- **Before**: Repository → Files → Evidence → Sandbox → AI → Final (판정이 마지막)
- **After**: 최종 판정 → 탐지 요약 → AI 분석 → 상세 정보 (판정이 최상단)

### 4. 한국어 메시지 통일
- **Before**: "Repository Summary", "Suspicious Files", "Evidence", "Clone Gate: Blocked"
- **After**: "최종 판정", "탐지 요약", "AI 분석", "Clone 차단"

### 5. 배너 단순화
- **Before**: `GUARDIT AI SECURITY GATE` 대형 패널 (5줄+)
- **After**: `guardit · 분석 대상: ...` (2줄)

### 6. 스피너 차분화
- **Before**: `⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏` (0.08초 간격, 10프레임)
- **After**: `· ·· ···` (0.25초 간격, 3프레임)

### 7. SAFE 케이스 체크리스트
```
✓ 자동 실행 파일 없음
✓ 개인정보 접근 패턴 없음
✓ 외부 전송 시도 없음
```

### 8. inferred/observed 구분
- `[inferred]` 정적 추론 → 노란색
- `[observed]` 실제 행위 → 빨간색

### 9. sandbox 생략 인간화
- **Before**: `LLM 보정 전 점수 22가 sandbox threshold 30 미만입니다`
- **After**: `위험 점수 22점 — sandbox 실행 기준(30점) 미만으로 생략`

### 10. badge 축소
- **Before**: `[ static ]`, `[ 3 ]`, `[ MALICIOUS ]` 등 박스 배지 남발
- **After**: 인라인 bold+color 텍스트. 등급 표시만 유지.

### 11. doctor 정리
- ✓/✗ 아이콘으로 설정 상태 시각화
- 불필요한 내부 config 정보 제거

## 테스트 결과

- `test_candidate_path_detects_required_files` — OK
- `test_malicious_demo_forces_malicious` — OK
- `test_llm_required_holds_final_verdict_when_llm_fails` — OK

## 데모 시 고려사항

1. 터미널 너비 80칸 이상 권장 (60칸까지 대응)
2. `NO_COLOR` 환경변수 설정 시 색상 비활성화
3. malicious demo는 exit code 1 반환 (정상)
4. `--llm off` 옵션으로 AI 분석 없이 빠르게 시연 가능
5. 최종 판정이 최상단에 위치하므로 스크롤 없이 결론 확인 가능
