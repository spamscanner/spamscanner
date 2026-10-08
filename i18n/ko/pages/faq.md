<!-- source: 361732724f0e -->

<!--
label: FAQ
title: 자주 묻는 질문
description: Spam Scanner의 정확도, 지원 언어, 네트워크로 보내는 데이터, 언어 모델, SpamAssassin, Forward Email에 대한 답변입니다.
keywords: Spam Scanner FAQ, 스팸 필터 질문, 스팸 필터 정확도, 스팸 필터 개인정보 보호
-->

# 자주 묻는 질문


## Spam Scanner란 무엇입니까?

Node.js, 명령줄, 메일 서버를 위한 스팸 필터입니다. 원본 이메일 메시지를 읽고, 그 메시지가 스팸, 피싱, 사기인지 또는 악성코드를 담고 있는지를 점수와 판정에 쓰인 테스트 목록과 함께 판정합니다. 라이브러리, Postfix와 Sendmail용 milter, SpamAssassin 호환 spamd 서버, Postfix 콘텐츠 필터, HTTP API, TCP 서버로 실행할 수 있습니다.


## 무료입니까?

[라이선스](https://github.com/spamscanner/spamscanner/blob/master/LICENSE)인 Business Source License 1.1은 다른 사람에게 스팸 탐지를 서비스로 제공하는 경우를 제외한 모든 용도를 허용하며, Apache License 2.0으로 바뀌는 날짜를 명시하고 있습니다.


## 얼마나 정확합니까?

학습 데이터에서 따로 떼어 둔 영어 메시지에 대해, 번들 분류기는 단독으로 ham을 하나도 스팸으로 표시하지 않았고 스팸의 97%를 잡았습니다. 언어별 전체 수치는 [학습 가이드](../../docs/training.md#the-bundled-model)에 있습니다. 링크, 첨부 파일, 인증, 차단 목록, 언어 모델이 여기에 더해집니다. 진짜 시험은 직접 받는 메일입니다. `spamscanner eval`로 레이블이 붙은 어떤 메일로도 어떤 모델이든 측정할 수 있습니다.


## 어떤 언어를 지원합니까?

모든 언어를 지원합니다. 띄어쓰기가 없는 중국어, 일본어, 태국어를 포함해 유니코드 규칙으로 단어를 분리합니다. 번들 모델이 거의 보지 못한 언어의 메일은 스팸으로 표시하지 않고 unsure로 두며, 언어 모델이나 직접 수행한 학습이 판정합니다. [언어](../../docs/languages.md)


## 메일을 어딘가로 보냅니까?

아니요. 기본적으로 링크의 호스트 이름을 Cloudflare의 필터링 DNS 리졸버에서 조회할 뿐, 그 밖에는 아무것도 컴퓨터 밖으로 나가지 않습니다. 인증, 차단 목록, 언어 모델, 평판 서비스는 설정하기 전까지 꺼져 있으며, 호스팅 언어 모델로 메일을 보내기 전에 개인 데이터를 제거합니다. [보안과 개인정보](../../docs/security.md)


## 언어 모델이 꼭 필요합니까?

아니요. 언어 모델은 애매한 메시지에 대한 두 번째 의견입니다. 언어 모델이 없으면 그런 메시지는 점수만으로 판정합니다.


## 어떤 언어 모델을 써야 합니까?

CPU라면 Ollama로 `qwen3.5:4b`를, GPU가 있다면 `qwen3.5:9b`를 사용하십시오. 둘 다 Apache 라이선스이며 201개 언어를 읽습니다. Spam Scanner는 모델의 한 단계에서 각 판정의 확률을 읽습니다. 2코어 CPU에서 이 방식은 메시지당 약 11초가 걸렸고, 답을 작성하게 하면 31초가 걸렸으며, 정확도는 같았습니다. 호스팅 서비스로는 결정 모델인 Cloudflare Clef와 TypeSafe Jev가 1초 안에 답합니다. Anthropic, OpenAI, Google 등의 모델도 동작합니다. [측정 결과](../../docs/llm.md#measured)와 [권장 모델](../../docs/llm.md#recommended-open-models)


## SpamAssassin을 대체할 수 있습니까?

대부분의 환경에서는 그렇습니다. spamd 프로토콜을 지원하므로 spamc, Exim, Haraka가 수정 없이 동작하고, 같은 `X-Spam-*` 헤더를 기록합니다. SpamAssassin의 규칙 파일은 실행하지 않습니다. [SpamAssassin 대안](/spamassassin-alternative/)


## 정상 메일을 거부하지는 않습니까?

메일 거부는 기본으로 꺼져 있으며, milter는 표시만 합니다. `--reject`를 사용해도 15점 이상인 메시지만 일시적 451 오류로 거부하므로, 발신 서버가 다시 시도하고 잘못된 판정은 설정을 바꿔 바로잡을 수 있습니다. 콘텐츠 필터는 SMTP 세션 중에 거부하지 않습니다.


## 직접 받은 메일로 어떻게 학습시킵니까?

`spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out model.json`을 실행한 뒤 `--model model.json`을 사용합니다. mbox 파일, Maildir, `.eml` 파일이 든 폴더, CSV 또는 JSON Lines 데이터 세트를 모두 사용할 수 있습니다. [학습](../../docs/training.md)


## Node.js 없이도 동작합니까?

예. Linux, macOS, Windows용 독립 실행형 바이너리에 Node.js와 모델이 포함되어 있습니다. `curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash`.


## 누가 만듭니까?

[Forward Email](https://forwardemail.net)이 자사 메일 서버를 위해 만듭니다.
