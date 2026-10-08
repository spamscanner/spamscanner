<!-- source: f33722183f00 -->

<!--
label: Postfix 스팸 필터
title: milter 또는 콘텐츠 필터로 동작하는 Postfix 스팸 필터
description: Spam Scanner의 milter나 콘텐츠 필터로 Postfix 서버의 스팸을 거릅니다. 설정, systemd 유닛, 4xx 또는 5xx 거부, Junk 폴더까지.
keywords: Postfix 스팸 필터, Postfix milter, smtpd_milters, Postfix 콘텐츠 필터, Postfix 스팸 차단, Postfix 스팸 거부, 메일 서버 스팸 필터
-->

# Postfix 스팸 필터

Spam Scanner로 5분 정도면 Postfix 서버에 필터를 적용할 수 있습니다. milter로 실행되므로, Postfix는 SMTP 세션 중에 각 메시지에 대해 Spam Scanner에 묻고, 수락하기 전에 스팸을 거부할 수 있습니다.


## 설치와 실행

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]"
```

`--auth`는 SPF, DKIM, DMARC, ARC를 검사하고, `--subject-tag`는 제목에 스팸 표시를 붙입니다. 모든 메시지에 `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Status`, `X-Spam-Action` 헤더가 추가되며, 발신자가 넣은 `X-Spam-*` 헤더는 먼저 제거합니다.


## Postfix 연결

```ini
# /etc/postfix/main.cf
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
milter_default_action = accept
```

```sh
sudo postfix reload
```

`milter_default_action = accept`는 milter가 중단되었을 때 메일을 필터링 없이 통과시킵니다. `tempfail`로 설정하면 대신 발신 서버에 다시 시도하도록 요청합니다.


## SMTP 세션 중 스팸 거부

```sh
spamscanner milter --port 7831 --auth --reject
```

거부 임계값(15점)에 이른 메시지는 `451 4.7.1 Message rejected as spam`으로 거부합니다. 451은 일시적 오류입니다. 발신 서버가 메시지를 보관하고 다시 시도하므로, 잘못된 판정의 대가는 메시지 손실이 아니라 지연입니다. 결과가 적절해 보이면 `--reject-code 550`으로 영구 거부로 바꿉니다.


## milter 없이

콘텐츠 필터는 Postfix가 메시지를 수락한 뒤에 실행됩니다. Postfix가 메시지를 `spamscanner filter`로 파이프하면, 필터가 헤더를 추가해 다시 넘겨줍니다. 세션 중에 거부되는 메일은 없으며, 실패하면 반송하지 않고 항상 전달을 연기합니다. [콘텐츠 필터 설정](../../docs/postfix.md#content-filter)


## 스팸을 Junk 폴더로

Dovecot에서는 Sieve 규칙으로 표시된 메일을 분류합니다.

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" { fileinto "Junk"; stop; }
```


## 실제 Postfix로 테스트

프로젝트의 엔드투엔드 테스트는 milter와 콘텐츠 필터를 붙인 Postfix를 실행합니다. ham은 헤더가 추가되고 위조된 `X-Spam-Flag`가 제거된 채 전달되고, 스팸은 표시되며, GTUBE는 SMTP 세션 중에 550으로 거부됩니다.

다음: systemd 유닛과 Sendmail의 `INPUT_MAIL_FILTER`를 포함한 [Postfix와 Sendmail 전체 가이드](../../docs/postfix.md).
