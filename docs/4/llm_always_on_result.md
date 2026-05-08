# LLM Always-On 구현 결과

## 수정 파일

- `guardit/ai/llm_judge.py`
- `guardit/config.py`
- `guardit/models.py`
- `guardit/scanner.py`
- `guardit/cli.py`
- `guardit/reporter.py`
- `guardit/terminal_ui.py`
- `tests/test_llm_judge.py`
- `tests/test_guardit_core.py`

## 수정 이유

Guardit은 clone 이전 개인정보 탈취 위험을 AI 기반으로 판단하는 보안 게이트다. 기존 구현은 Gemini API가 503/429/timeout을 반환하거나 응답 JSON 파싱에 실패하면 즉시 rule-based fallback으로 내려가 “LLM 없이 판단”처럼 보였다. 이는 프로젝트의 핵심 메시지인 “LLM 기반 의도 분석”과 맞지 않았다.

이번 수정은 LLM을 기본 판단 보조 계층으로 최대한 사용하고, 정말 불가능한 경우에만 안전 fallback을 적용하도록 개선했다.

## LLM 재시도 정책

- Gemini API 기본 총 시도 횟수는 `3`회다.
- 503, 429, timeout, 네트워크 계열 일시 오류는 즉시 fallback하지 않고 재시도한다.
- 재시도 간격은 exponential backoff다.
  - 기본: `1초 -> 2초 -> 4초` 패턴
- 각 시도 실패 사유는 `LLMJudgement.notes`에 기록된다.
- 최종 리포트에는 `status`, `attempts`, `fallback/error`가 표시된다.

## JSON 복구 파싱 정책

Gemini 모델 응답은 다음 순서로 파싱한다.

1. 원본 응답 그대로 `json.loads()`
2. markdown code fence 제거 후 `json.loads()`
3. 첫 `{`부터 마지막 `}`까지 JSON object 추출 후 `json.loads()`
4. trailing comma 제거, 단순 작은따옴표 JSON 보정
5. Python literal 형태면 `ast.literal_eval()`로 복구
6. 그래도 실패하면 raw response를 `logs/llm_raw_response.txt`에 저장

## 스키마 검증 및 정규화

- `verdict`는 대문자로 정규화한다.
- 허용 verdict는 `SAFE`, `SUSPICIOUS`, `MALICIOUS`다.
- 알 수 없는 verdict는 `SUSPICIOUS`로 보정하고 note에 기록한다.
- confidence가 `0~100` 범위면 `0~1`로 정규화한다.
- reason이 list면 사람이 읽을 수 있는 문자열로 합친다.
- optional `evidence`, `leaked_data`를 보존한다.

## fallback 정책

fallback은 최후 수단으로 유지한다.

- provider가 `off`: 명시적 LLM 미사용으로 표시
- API key 없음: LLM 호출 불가로 안전 fallback
- 503/429/timeout/OSError: 3회 재시도 후 안전 fallback
- JSON 파싱 실패: 복구 파싱 후 실패 시 안전 fallback

fallback 문구는 다음처럼 변경했다.

```text
LLM 분석을 재시도했으나 API 오류 또는 응답 파싱 문제로 실패하여,
정적 분석 근거 기반의 안전 fallback을 적용했습니다.
```

## 새 환경변수

- `GUARDIT_LLM_REQUIRED=true`
  - LLM 최종 실패 시 최종 판정을 `UNKNOWN`으로 보류한다.
  - CLI는 죽지 않고 리포트와 조치 UI를 출력한다.
- `GUARDIT_LLM_MAX_RETRIES=3`
  - Gemini API 최대 시도 횟수
- `GUARDIT_LLM_BACKOFF_SECONDS=1`
  - exponential backoff 기본 지연 시간
- `GUARDIT_LLM_STRICT_JSON=false`
  - true면 repair parsing을 제한한다.

## 출력 변화

성공 시:

```text
AI Security Analysis
Provider          [ gemini-api ]
Status            [ used ]
Attempts          2/3
AI Verdict        [ MALICIOUS ]
Confidence        92%
```

실패 후 fallback 시:

```text
AI Security Analysis
Provider          [ gemini-api ]
Status            [ failed ]
Attempts          3/3
Fallback          rule-based safety decision
LLM note: Gemini API HTTP 503 ...
```

required 모드 실패 시:

```text
Final Risk        [ UNKNOWN ]
Clone Gate Decision
Hold: LLM 분석 실패로 최종 판정을 보류했습니다.
```

## 테스트 및 검증

실행 명령:

```powershell
python -m unittest tests.test_llm_judge
python -m unittest discover -s tests
```

검증 항목:

- Gemini 503 발생 시 3회 재시도
- markdown fenced JSON 응답 파싱
- JSON 앞뒤 설명 문장 포함 응답 파싱
- 작은따옴표/trailing comma 복구
- confidence `90`을 `0.9`로 정규화
- lowercase verdict를 uppercase로 정규화
- LLM 최종 실패 시 개선된 fallback 메시지 출력
- `GUARDIT_LLM_REQUIRED=true`에서 최종 판정 `UNKNOWN` 보류

## 실행 예시

```powershell
$env:GEMINI_API_KEY="..."
python -m guardit clone https://github.com/owner/repo --sandbox docker
```

LLM 필수 모드:

```powershell
$env:GUARDIT_LLM_REQUIRED="true"
python -m guardit scan demo_repos/malicious --sandbox static
```
