# LLM Always-On 개선 계획서

## 현재 문제 요약

Guardit은 `guardit clone <repo>` 실행 시 clone 이전에 자동 실행 파일, 정적 evidence, sandbox 로그, 작성자 신뢰도, LLM 의도 분석을 종합해 개인정보 탈취 위험을 판단한다. 하지만 현재 Gemini API 호출이 503/429/timeout을 반환하거나 모델 응답 JSON 파싱에 실패하면 즉시 offline fallback으로 내려간다.

그 결과 최종 리포트에 `LLM 없이 룰 기반 근거만으로 판단했습니다.` 같은 문구가 출력되어, 프로젝트 핵심인 “LLM 기반 사전 보안 분석”의 제품 경험이 약해진다.

## 왜 LLM 없이 판단되는지 원인 분석

- `guardit/ai/llm_judge.py`의 Gemini API 호출부가 단일 요청만 수행한다.
- `urllib.error.HTTPError`가 발생하면 HTTP status가 503/429 같은 일시 장애여도 즉시 fallback을 반환한다.
- 모델 응답 텍스트가 markdown code fence, 설명 문장, trailing comma, 작은 따옴표 등을 포함하면 `_parse_jsonish()`가 실패할 수 있다.
- `LLMJudgement` 모델에 attempts/status/notes가 없어 reporter가 LLM 실패 경과를 구조적으로 표현하지 못한다.
- fallback reason이 “LLM 없이”로 고정되어 API 장애로 인해 fallback된 상황과 사용자가 LLM을 끈 상황을 구분하지 못한다.

## 개선 목표

- Gemini API를 기본 LLM provider로 유지하고, 일시 오류는 최대한 재시도한다.
- JSON 파싱 실패 시 원문을 저장하고 복구 파싱을 단계적으로 시도한다.
- LLM 응답 스키마를 검증하고 confidence/verdict/reason/evidence/leaked_data를 정규화한다.
- fallback은 최후 수단으로만 유지한다.
- LLM 실패 시에도 “재시도 후 안전 fallback”임을 리포트에 명확히 표시한다.
- `GUARDIT_LLM_REQUIRED=true`일 때는 LLM 최종 실패 시 최종 판정을 `UNKNOWN`으로 보류하되 CLI는 종료되지 않게 한다.

## 수정 대상 파일

- `guardit/ai/llm_judge.py`: Gemini 재시도, backoff, JSON repair, schema validation, raw response logging
- `guardit/config.py`: LLM retry/required/strict JSON 설정 추가
- `guardit/models.py`: `LLMJudgement` 상태/시도 횟수/note/leaked_data, `UNKNOWN` risk level 확장
- `guardit/scanner.py`: LLMJudge에 config 전달, required 실패 시 score level 보류
- `guardit/reporter.py`: 저장 리포트 출력에서 LLM 상태 표시
- `guardit/terminal_ui.py`: 터미널 패널에서 LLM status/attempts/fallback reason 표시
- `tests/test_llm_judge.py`: retry, repair parsing, normalization, fallback message 테스트

## 구현 전략

1. `LLMJudge`에 `max_retries`, `backoff_seconds`, `strict_json` 필드를 추가한다.
2. Gemini API 호출을 attempt loop로 감싸고 503/429/timeout/OSError 계열은 exponential backoff 후 재시도한다.
3. 모델 텍스트 파싱은 다음 순서로 수행한다.
   - 원본 그대로 `json.loads()`
   - code fence 제거 후 `json.loads()`
   - 첫 `{`부터 마지막 `}`까지 추출 후 `json.loads()`
   - trailing comma 제거, 단순 작은따옴표 JSON 보정 후 `json.loads()`
4. 파싱 실패 시 raw response를 `logs/llm_raw_response.txt`에 저장하고 response preview를 note/error에 남긴다.
5. verdict는 대문자로 정규화하고 unknown 값은 `SUSPICIOUS`로 보정한다.
6. confidence가 `0~100`이면 `0~1` 범위로 정규화한다.
7. reason이 list이면 bullet형 문자열로 합친다.
8. leaked_data는 optional list로 보존한다.

## 실패 시 fallback 정책

- provider가 `off`인 경우: 명시적으로 LLM 미사용 상태를 표시한다.
- API key 없음: LLM 호출 불가로 안전 fallback을 적용한다.
- 503/429/timeout/OSError: 최대 3회 재시도 후 실패 시 안전 fallback을 적용한다.
- JSON 파싱 실패: 복구 파싱을 시도하고, 실패 시 raw response 저장 후 안전 fallback을 적용한다.
- `GUARDIT_LLM_REQUIRED=true`: LLM 최종 실패 시 `UNKNOWN`으로 최종 판정을 보류한다.

## 예상 출력 변화

성공 시:

```text
LLM Analysis:
- status: used
- provider: gemini-api
- attempts: 2/3
- verdict: MALICIOUS
- confidence: 92%
```

실패 후 fallback 시:

```text
LLM Analysis:
- status: fallback
- provider: gemini-api
- attempts: 3/3
- fallback: rule-based safety decision
- reason: Gemini API 503 unavailable after retries
```

required 모드 실패 시:

```text
Final Risk: UNKNOWN
Clone Gate Decision: LLM 분석 실패로 최종 판정 보류
```
