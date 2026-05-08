# Guardit 구현 체크리스트

- [x] 1. docs 문서 초안 생성
- [x] 2. 기본 프로젝트 구조 생성
- [x] 3. CLI 기본 명령 구현
- [x] 4. GitHub URL 파싱 및 repo metadata 수집
- [x] 5. 파일 tree 수집
- [x] 6. 위험 후보 파일 필터링
- [x] 7. 후보 파일 다운로드
- [x] 8. 정규식 기반 evidence 탐지
- [x] 9. 위험 점수 계산
- [x] 10. 리포트 출력 및 JSON 저장
- [x] 11. package.json / tasks.json 전용 룰 고도화
- [x] 12. JS AST 분석 추가
- [x] 13. Python/Shell 분석 추가
- [x] 14. 샌드박스 모듈 skeleton 구현
- [x] 15. LLM judge skeleton 및 fallback 구현
- [x] 16. 개인정보 마스킹 구현
- [x] 17. safe clone 구현
- [x] 18. demo_repos / 테스트 fixture 작성
- [x] 19. 평가 metrics 구현
- [x] 20. README 및 docs 업데이트

## 체크 기준

각 항목은 코드가 존재하는 것만으로 완료하지 않는다. CLI 흐름, evidence 생성, JSON 저장, 실패 fallback이 실제로 연결되어야 완료로 표시한다.
