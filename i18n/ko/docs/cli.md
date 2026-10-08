<!-- source: a59bc5927d86 -->

# 명령줄

```text
spamscanner <command> [options]
```

| 명령                                         | 하는 일                                      |
| ------------------------------------------ | ----------------------------------------- |
| `scan [file\|-]`                           | 파일이나 표준 입력의 메시지를 검사합니다                    |
| `filter -f <sender> -- <recipients...>`    | Postfix 콘텐츠 필터: 표준 입력을 검사하고 헤더를 추가해 넘겨줍니다 |
| `milter`                                   | Postfix와 Sendmail용 milter, 포트 7831        |
| `http`                                     | HTTP API, 포트 7832                         |
| `server`                                   | 일반 TCP 서버, 포트 7830                        |
| `spamd`                                    | SpamAssassin 호환 spamd 서버, 포트 783          |
| `train`                                    | mbox 파일, Maildir, 폴더, 데이터 세트로 모델을 학습합니다   |
| `eval`                                     | 레이블이 붙은 메일로 모델 성능을 측정합니다                  |
| `learn spam\|ham [file\|-] --model <file>` | 모델에 메시지 하나를 학습시킵니다                        |
| `llm-test`                                 | 샘플 메시지 세 개로 언어 모델 설정을 확인합니다               |
| `models`                                   | 권장 공개 모델 목록을 표시합니다                        |
| `version`, `help`                          |                                           |


## scan

```sh
spamscanner scan message.eml
spamscanner scan - < message.eml
spamscanner scan message.eml --json
spamscanner scan message.eml --headers > tagged.eml
spamscanner scan message.eml --subject-tag "[SPAM]" > tagged.eml
```

| 옵션                         | 의미                                     |
| -------------------------- | -------------------------------------- |
| `--json`                   | 전체 결과를 JSON으로 출력합니다                    |
| `--headers`                | `X-Spam-*` 헤더를 추가한 메시지를 출력합니다          |
| `--subject-tag <tag>`      | 스팸의 제목 앞에도 태그를 붙입니다                    |
| `--verbose`                | 모든 테스트와 분류기의 가장 강한 단서를 표시합니다           |
| `--threshold <n>`          | 메일을 스팸으로 판정하는 점수(기본값 5)                |
| `--reject-threshold <n>`   | 메일을 거부하는 점수(기본값 15)                    |
| `--model <file>`           | 번들 모델 대신 사용할 모델 파일                     |
| `--no-classifier`          | 분류기를 사용하지 않습니다                         |
| `--config <file>`          | [라이브러리 옵션](api.md#options)을 담은 JSON 파일 |
| `--allow-language <codes>` | 허용할 언어. 예: `en,de,fr`                  |

종료 코드: 0은 ham, 1은 스팸, 2는 오류.

### SMTP 세션

| 옵션                  | 의미                          |
| ------------------- | --------------------------- |
| `--ip <address>`    | 메시지를 보낸 클라이언트의 IP 주소        |
| `--hostname <name>` | 클라이언트의 검증된 역방향 DNS 이름       |
| `--helo <name>`     | 클라이언트가 HELO 또는 EHLO에서 밝힌 이름 |
| `--from <address>`  | 엔벌로프 발신자(MAIL FROM)         |
| `--to <address>`    | 엔벌로프 수신자. 여러 명이면 반복합니다      |

### 검사

| 옵션                    | 의미                                          |
| --------------------- | ------------------------------------------- |
| `--auth`              | SPF, DKIM, DMARC, ARC를 검사합니다(`--ip` 필요)     |
| `--dnsbl <zone>`      | IP 차단 목록. 예: `zen.spamhaus.org`. 반복 가능      |
| `--uribl <zone>`      | 링크용 도메인 차단 목록. 예: `dbl.spamhaus.org`. 반복 가능 |
| `--dns-server <ip>`   | DNS 검사에 쓸 네임 서버. 반복 가능                      |
| `--no-cloudflare`     | 링크를 Cloudflare의 필터링 리졸버에 조회하지 않습니다          |
| `--clamav [socket]`   | 기본 소켓 또는 지정한 소켓의 clamd로 첨부 파일을 검사합니다        |
| `--allowlist <value>` | 이 IP 주소, 도메인 또는 주소를 항상 수락합니다. 반복 가능         |
| `--denylist <value>`  | 이 IP 주소, 도메인 또는 주소를 항상 거부합니다. 반복 가능         |

### 언어 모델

| 옵션                                                         | 의미                                                                  |
| ---------------------------------------------------------- | ------------------------------------------------------------------- |
| `--llm <provider>`                                         | `ollama`, `openai`, `anthropic`, `gemini` 등([목록](llm.md#providers)) |
| `--llm-model <name>`                                       | 모델. 예: `qwen3.5:4b` 또는 `claude-haiku-4-5`                           |
| `--llm-url <url>`                                          | 기본 URL. 예: `http://10.0.0.5:11434`                                  |
| `--llm-host`, `--llm-port`, `--llm-path`, `--llm-protocol` | 제공자 URL의 일부만 변경합니다                                                  |
| `--llm-api-key <key>`                                      | API 키. 아래 환경 변수도 참고하십시오                                             |
| `--llm-auth <type>`                                        | `bearer`, `x-api-key`, `api-key`, `basic`, `header` 또는 `none`       |
| `--llm-auth-header <name>`                                 | `--llm-auth header` 사용 시 키를 담을 헤더                                   |
| `--llm-username`, `--llm-password`                         | `--llm-auth basic`용                                                 |
| `--llm-header "Name: value"`                               | 추가 요청 헤더. 반복 가능                                                     |
| `--llm-mode <mode>`                                        | `auto`(애매한 메시지만, 기본값) 또는 `always`                                   |
| `--llm-timeout <ms>`                                       | 기본값 30000                                                           |
| `--llm-policy <text>`                                      | 모델에 줄 추가 규칙. 예: "당사는 청구서를 이메일로 보내지 않습니다"                            |
| `--llm-redact`, `--no-llm-redact`                          | 먼저 개인 데이터를 제거합니다. 원격 제공자에게는 기본으로 켜져 있습니다                            |


## filter

[Postfix 콘텐츠 필터](postfix.md#content-filter)입니다. 표준 입력에서 메시지를 읽고, `X-Spam-*` 헤더를 추가한 뒤, 같은 엔벌로프로 sendmail에 넘겨줍니다.

```sh
spamscanner filter -f "$sender" -- "$recipient"
```

| 옵션                    | 의미                           |
| --------------------- | ---------------------------- |
| `--sendmail <path>`   | 기본값 `/usr/sbin/sendmail`     |
| `--subject-tag <tag>` | 스팸의 제목 앞에 태그를 붙입니다           |
| `--reject`            | 거부 임계값에 이른 메일을 넘겨주지 않고 반송합니다 |
| `--discard`           | 거부 임계값에 이른 메일을 넘겨주지 않고 버립니다  |

종료 코드는 Postfix가 읽는 sendmail의 규칙을 따릅니다. 0은 전달(또는 폐기), 64는 수신자 미지정, 69는 스팸으로 거부(Postfix가 반송), 75는 모든 종류의 실패로, 이 경우 Postfix가 메시지를 보관하고 나중에 다시 시도합니다.


## milter, http, server, spamd

```sh
spamscanner milter --port 7831 --reject --subject-tag "[SPAM]"
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
spamscanner server --port 7830
spamscanner spamd --port 783
```

포트 783은 SpamAssassin 클라이언트가 기본으로 쓰는 포트입니다. 1024 미만 포트에는 root 권한이나 `CAP_NET_BIND_SERVICE` 기능이 필요합니다. `--port 7833`처럼 다른 포트를 사용하고 클라이언트에 알려 주십시오.

| 옵션                    | 의미                                                          |
| --------------------- | ----------------------------------------------------------- |
| `--port <n>`          | TCP 포트                                                      |
| `--host <ip>`         | 수신할 주소(기본값 127.0.0.1)                                       |
| `--socket <path>`     | 대신 Unix 소켓에서 수신합니다                                          |
| `--reject`            | milter: 거부 임계값에 이른 메일을 거부합니다                                |
| `--reject-code <n>`   | milter: 451(나중에 다시 시도, 기본값) 또는 550                          |
| `--quarantine`        | milter: 스팸을 메일 서버의 격리 영역에 보류합니다                             |
| `--name <hostname>`   | milter: Authentication-Results에 쓸 이 서버의 이름                  |
| `--token <secret>`    | HTTP: `Authorization: Bearer <secret>`을 요구합니다. `/learn`에 필요 |
| `--allow-tell`        | spamd: 학습용 TELL 요청(`spamc -L spam`)을 받습니다                   |
| `--out <file>`        | HTTP와 spamd: 학습한 내용을 이 모델 파일에 저장합니다                         |
| `--subject-tag <tag>` | milter와 spamd: 스팸의 제목 앞에 태그를 붙입니다                           |
| `--verbose`           | milter: 모든 검사를 기록합니다. TCP 서버: 텍스트 한 줄로 응답합니다                |

위의 검사 옵션은 서버에도 적용됩니다. [milter](postfix.md#milter), [HTTP API, TCP 서버, spamd](http-api.md).


## train, eval, learn

```sh
spamscanner train --spam ~/Mail/Junk --ham ~/Mail/Archive --out my-model.json
spamscanner eval --model my-model.json --spam test/spam.mbox --ham test/ham.mbox
spamscanner learn spam message.eml --model my-model.json
```

| 옵션                                              | 의미                                             |
| ----------------------------------------------- | ---------------------------------------------- |
| `--spam <path>`                                 | 스팸: mbox 파일, Maildir 또는 `.eml` 파일이 든 폴더. 반복 가능 |
| `--ham <path>`                                  | ham: 위와 같음. 반복 가능                              |
| `--dataset <file>`                              | 텍스트 열과 레이블 열이 있는 CSV 또는 JSON Lines 파일. 반복 가능   |
| `--text-column <name>`, `--label-column <name>` | 자동으로 감지되지 않을 때 지정할 열 이름                        |
| `--out <file>`                                  | 모델을 기록할 위치(기본값 `spamscanner-model.json`)       |
| `--merge`                                       | 빈 모델 대신 번들 모델(또는 `--model`)에서 시작합니다            |

`learn`은 모델 파일을 그 자리에서 갱신하며, 처음에는 번들 모델로 파일을 만듭니다. [학습](training.md)


## llm-test와 models

```sh
spamscanner models
spamscanner llm-test --llm ollama --llm-model qwen3.5:4b
```

`llm-test`는 평범한 메시지 하나와 영어·이탈리아어 사기 메시지 두 개를 모델에 보내 판정을 출력하고, 세 판정이 모두 맞을 때만 0으로 종료합니다.


## 설정 파일

`--config file.json`(또는 `SPAMSCANNER_CONFIG` 환경 변수)은 [라이브러리 옵션](api.md#options)을 불러옵니다. 명령줄 옵션이 파일보다 우선합니다.

```json
{
  "threshold": 6,
  "authentication": true,
  "dnsbl": {"ip": ["zen.spamhaus.org"], "domain": ["dbl.spamhaus.org"]},
  "dns": {"servers": ["127.0.0.1"]},
  "clamav": {"socket": "/var/run/clamav/clamd.ctl"},
  "llm": {"provider": "ollama", "model": "qwen3.5:4b"},
  "scores": {"deceptiveLink": 4, "FROM_NAME_BRAND": 3}
}
```


## 환경 변수

| 변수                                                                                                                                                                                                                                                   | 의미                     |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------- |
| `SPAMSCANNER_CONFIG`                                                                                                                                                                                                                                 | 설정 파일                  |
| `SPAMSCANNER_MODEL`                                                                                                                                                                                                                                  | 번들 모델 대신 사용할 모델 파일     |
| `SPAMSCANNER_TOKEN`                                                                                                                                                                                                                                  | HTTP API용 토큰           |
| `SPAMSCANNER_LLM_API_KEY`                                                                                                                                                                                                                            | 모든 언어 모델 제공자에 쓰는 API 키 |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY`, `XAI_API_KEY`, `TOGETHER_API_KEY`, `FIREWORKS_API_KEY`, `CEREBRAS_API_KEY`, `HF_TOKEN`, `AZURE_OPENAI_API_KEY` | 각 제공자의 자체 키            |
| `NODE_DEBUG=spamscanner*`                                                                                                                                                                                                                            | 디버그 로그                 |
