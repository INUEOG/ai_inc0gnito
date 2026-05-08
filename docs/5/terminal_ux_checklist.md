# Terminal UX/UI 개선 체크리스트

## 분석 단계

- [x] 현재 reporter 구조 분석 (`reporter.py`, `terminal_ui.py`)
- [x] 현재 출력 구조 분석 (패널 6개, badge 과다, 영어 레이블)
- [x] 색상 사용 현황 분석 (8색+, cyan 기본)
- [x] 발표/데모 관점 약점 분석

## 설계 단계

- [ ] 출력 정보 우선순위 정리
- [ ] panel 레이아웃 설계 (섹션 구분선 방식)
- [ ] severity 색상 정책 정의 (3색: 녹/노/적)
- [ ] inferred/observed 구분 시각 설계

## 구현 단계

### terminal_ui.py
- [ ] 색상 상수 정리 (사용하지 않는 색상 제거)
- [ ] `panel()` → `section()` 구분선 스타일로 변경
- [ ] `badge()` 축소 (등급 표시만 유지)
- [ ] `banner()` 단순화 (1~2줄 헤더)
- [ ] `render_security_report()` 출력 순서 변경 (판정→요약→세부)
- [ ] `_repository_panel()` → 제거 또는 1줄 요약
- [ ] `_suspicious_files_panel()` → 탐지 요약에 통합
- [ ] `_evidence_panel()` → 탐지 요약에 통합
- [ ] `_sandbox_panel()` → 탐지 요약 내 inferred/observed로 통합
- [ ] `_ai_panel()` → 핵심 정보만 (판정/신뢰도/근거)
- [ ] `_final_panel()` → 최상단 이동, 핵심 판정 섹션으로
- [ ] SAFE 케이스 체크리스트 스타일 출력
- [ ] sandbox skipped 사람 읽기 쉬운 표현
- [ ] 한국어 메시지 통일

### reporter.py
- [ ] `render_saved_report()` 새 UX 적용
- [ ] `render_text()` 정보 순서 개선 (판정 우선)
- [ ] 중복 정보 제거

### cli.py
- [ ] action_menu 한국어 통일
- [ ] action_result 메시지 정리
- [ ] `_doctor()` 한국어 출력 정리

## 검증 단계

- [ ] 기존 테스트 통과 (`python -m pytest tests/ -v`)
- [ ] malicious demo 출력 확인
- [ ] benign demo 출력 확인
- [ ] safe/suspicious/malicious 출력 분리 확인
- [ ] narrow terminal (80칸) 대응 확인
- [ ] NO_COLOR 환경변수 대응 확인

## 문서화

- [ ] `docs/5/terminal_ux_result.md` 작성
