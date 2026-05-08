# Guardit 2차 구현 체크리스트

- [x] 현재 구조 분석
- [x] `/docs/2/PROJECT_PLAN.md` 작성
- [x] `/docs/2/IMPLEMENTATION_CHECKLIST.md` 작성
- [x] CLI 옵션 개선
- [x] `report` 명령어 추가
- [x] 위험 파일 필터링 리포트에 reason 포함
- [x] 자동 실행 파일 탐지 강화
- [x] tasks.json → script 실행 흐름 추적
- [x] package.json → script 실행 흐름 추적
- [x] shell script → 하위 script 실행 흐름 추적
- [x] source-to-sink 분석 보완
- [x] sandbox-like 로그 구조화
- [x] risk score 기준 단순화 및 threshold 옵션 반영
- [x] safe clone 기능 보완
- [x] benign 5개 이상 데이터셋 구축
- [x] suspicious 5개 이상 데이터셋 구축
- [x] malicious 5개 이상 데이터셋 구축
- [x] 정탐률/오탐률 측정
- [x] Precision/Recall 측정
- [x] confusion matrix 생성
- [x] evidence count 및 처리 시간 측정
- [x] `results/eval_result.json` 생성
- [x] `results/eval_report.md` 생성
- [x] 결과 리포트 출력 개선
- [x] `/docs/2/IMPLEMENTATION_REPORT.md` 작성
- [x] `/docs/2/EVALUATION_PLAN.md` 작성
- [x] `/docs/2/DEMO_SCENARIO.md` 작성
- [x] README 개선
- [x] 테스트 및 검증

## 완료 기준

체크 항목은 파일 존재만으로 완료하지 않는다. CLI에서 실제 실행 가능하고, 리포트 또는 평가 결과로 확인 가능한 경우 완료 처리한다.
