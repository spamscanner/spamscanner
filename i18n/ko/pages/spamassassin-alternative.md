<!-- source: 1562b843d858 -->

<!--
label: SpamAssassin 대안
title: spamd 프로토콜을 지원하는 SpamAssassin 대안
description: SpamAssassin의 spamd를 Spam Scanner로 교체합니다. spamc, Exim, Haraka는 그대로 동작하고 X-Spam 헤더 이름도 같으며 모든 언어를 지원합니다.
keywords: SpamAssassin 대안, SpamAssassin 대체, spamd 대체, spamc, Exim 스팸 필터, Haraka spamassassin, rspamd 대안, X-Spam-Status
-->

# spamd 프로토콜을 지원하는 SpamAssassin 대안

Spam Scanner는 SpamAssassin의 spamd 프로토콜에 응답하므로, SpamAssassin용으로 작성된 소프트웨어가 수정 없이 사용할 수 있습니다. spamc, Exim의 `spam` 조건, Haraka의 `spamassassin` 플러그인 등이 그렇습니다.


## 교체하기

```sh
sudo systemctl disable --now spamd       # or spamassassin
npm install --global spamscanner
spamscanner spamd --port 783 --auth
```

```sh
spamc -c < message.eml     # prints the score, exits 1 for spam
spamc -R < message.eml     # the report, one line per test
spamc < message.eml        # the message with X-Spam-* headers
```

`CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING`, 그리고 `--allow-tell`을 사용하면 학습용 `TELL`에도 응답합니다. 프로젝트의 엔드투엔드 테스트에서는 SpamAssassin의 spamc로 직접 테스트합니다.


## 그대로인 것

* 헤더: SpamAssassin 형식의 `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Level`, `X-Spam-Status`. 기존 Sieve, procmail, 메일 클라이언트 규칙이 그대로 동작합니다.
* 이름이 붙은 테스트와 점수로 이루어진, 임계값 5의 점수: `BAYES_99`, `RBL_ZEN`, `SPF_FAIL`, `DKIM_PASS` 등.
* 테스트별 점수는 테스트 이름으로 변경할 수 있습니다.


## 다른 점

* **언어.** 유니코드 규칙으로 단어를 분리하므로, 중국어, 일본어, 태국어를 하나의 긴 문자열이 아니라 단어로 읽으며, 보이지 않는 문자나 라틴 문자 단어 속 키릴 문자 같은 위장을 먼저 되돌립니다.
* **피싱.** 유사 도메인, 기만적인 링크, 표시 이름 속 브랜드 이름을 추가 규칙 없이 검사합니다.
* **첨부 파일**은 바이트로 식별합니다. `.pdf`로 이름을 바꾼 실행 파일도 여전히 실행 파일입니다.
* **언어 모델.** 애매한 메시지는 Ollama를 통한 로컬 모델이나 호스팅 모델로 보낼 수 있습니다.
* **Node.js.** `npm install` 한 번이나 독립 실행형 바이너리면 됩니다. 관리할 Perl 모듈이나 규칙 업데이트가 없습니다.

Spam Scanner는 SpamAssassin의 규칙 파일을 실행하지 않으며, Bayes 데이터베이스 형식도 독자적입니다. 같은 메일로 `spamscanner train`을 실행해 학습시키십시오.


## Exim

```text
spamd_address = 127.0.0.1 783

# in the DATA ACL
warn  spam       = nobody:true
      add_header = X-Spam-Score: $spam_score
defer spam       = nobody:true
      condition  = ${if >={$spam_score_int}{150}}
      message    = Message rejected as spam
```

[Exim, Haraka, Dovecot, procmail](../../docs/mail-servers.md)
