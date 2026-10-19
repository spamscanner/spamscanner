<!-- source: 988243aec4f3 -->

<!--
label: 자체 호스팅 스팸 필터
title: 내 메일 서버를 위한 자체 호스팅 스팸 필터
description: 내 서버에서 돌아가는 스팸 필터. Spam Scanner는 메일을 서버에 두고, 모델을 패키지에 포함하며, 원격 측정 데이터를 보내지 않고, Postfix나 Exim에 연결됩니다.
keywords: 자체 호스팅 스팸 필터, 온프레미스 스팸 필터, 프라이빗 스팸 필터, 로컬 스팸 필터, 메일 서버 스팸 필터, 클라우드 없는 스팸 필터
-->

# 자체 호스팅 스팸 필터

Spam Scanner는 내 서버에서 실행되고 메일을 그곳에 둡니다. 분류기 모델은 패키지에 들어 있고, 원격 측정이나 업데이트 확인이 없으며, 기본적으로 내보내는 것은 각 링크의 호스트 이름에 대한 DNS 조회뿐입니다.


## 서버 밖으로 나가는 것

기본적으로 메시지에 있는 링크의 호스트 이름뿐입니다. Cloudflare의 필터링 리졸버(1.1.1.2와 1.1.1.3)에서 일반 DNS 조회로 확인하며, 메시지나 주소의 어떤 부분도 보내지 않습니다. `--no-cloudflare`로 이것도 끌 수 있습니다.

네트워크를 쓰는 다른 검사는 켜기 전까지 모두 꺼져 있습니다.

| 검사                    | 켜는 방법                | 보내는 것                           |
| --------------------- | -------------------- | ------------------------------- |
| SPF, DKIM, DMARC, ARC | `--auth`             | 발신자 레코드에 대한 DNS 조회              |
| DNS 차단 목록             | `--dnsbl`, `--uribl` | 클라이언트 IP 주소와 링크 도메인, DNS 조회 형태로 |
| ClamAV                | `--clamav`           | 첨부 파일, 내 clamd로                 |
| 언어 모델                 | `--llm`              | 메시지 요약, 지정한 서버로                 |

검사 내역은 기록하거나 저장하지 않습니다. [보안과 개인정보](../../docs/security.md)


## 서버에 설치하기

```sh
npm install --global spamscanner
```

또는 Node.js와 모델이 들어 있는 독립 실행 바이너리:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

설치 스크립트는 설치 전에 릴리스의 `SHA256SUMS` 파일로 바이너리를 확인하며, 각 바이너리에는 `gh attestation verify`로 확인할 수 있는 서명된 빌드 출처 증명이 있습니다. 바이너리는 Linux(x64와 arm64), macOS, Windows용이 있습니다. Linux 바이너리는 glibc가 필요하므로 Alpine에서는 npm으로 설치하세요. [시작하기](../../docs/getting-started.md)

업데이트 확인 기능은 없습니다. 업데이트하려면 설치 명령을 다시 실행하세요. 두 명령 모두 최신 릴리스를 설치합니다.


## 서비스로 실행하기

milter, HTTP, TCP, spamd 서버는 `--host`로 따로 지정하지 않으면 127.0.0.1에서 대기합니다. 권한이 없는 사용자로, 예를 들어 systemd 아래에서 실행하세요.

```ini
[Service]
ExecStart=/usr/local/bin/spamscanner milter --port 7831 --auth --subject-tag [SPAM]
User=spamscanner
Group=spamscanner
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
```

[전체 유닛과 설정 방법](../../docs/postfix.md#1-run-the-milter)은 Postfix 가이드에 있습니다. 어떤 서버도 TLS를 지원하지 않으므로, 다른 머신에서 접속하려면 사설 네트워크, SSH 터널, TLS를 쓰는 리버스 프록시를 사용하세요.


## 메일 서버 연결하기

| 메일 서버                 | 명령                                      | 포트   |
| --------------------- | --------------------------------------- | ---- |
| Postfix 또는 Sendmail   | `spamscanner milter`                    | 7831 |
| Postfix, 메일을 거부하지 않고  | `spamscanner filter`, 콘텐츠 필터            | 없음   |
| Exim, Haraka 또는 spamc | `spamscanner spamd`                     | 783  |
| HTTP를 쓰는 모든 것         | `spamscanner http`                      | 7832 |
| 간단한 TCP 클라이언트         | `spamscanner server`                    | 7830 |
| Node.js로 작성한 메일 서버    | `import SpamScanner from 'spamscanner'` | 없음   |

서버는 메시지에 `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Status` 헤더를 추가할 수 있고, 라이브러리는 점수와 작동한 모든 테스트를 반환합니다. 가이드: [Postfix 스팸 필터](/postfix-spam-filter/), [다른 메일 서버](../../docs/mail-servers.md), [HTTP API](../../docs/http-api.md).


## 언어 모델을 로컬에서 쓰기

언어 모델은 선택 사항이며 판단이 애매한 메시지만 읽습니다. 확실한 스팸과 확실한 ham은 전달되지 않습니다. Ollama를 쓰면 같은 서버에서 실행되므로 어떤 메시지도 서버 밖으로 나가지 않습니다.

```sh
ollama pull qwen3.5:4b
spamscanner milter --llm ollama --llm-model qwen3.5:4b
```

`qwen3.5:4b`는 CPU에서 실행됩니다. 호스팅 제공자를 쓰면 보내기 전에 메시지에서 개인정보를 제거합니다. [언어 모델](../../docs/llm.md)


## 내 메일로 학습시키기

기본 모델은 공개 데이터셋으로 학습했습니다. 내 서버가 받는 메일로 학습한 모델이 더 정확하며, 그 서버에 남습니다.

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out /var/lib/spamscanner/model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

모델 파일에는 해시된 특징 개수가 들어 있으며, 단어나 메시지 본문은 들어 있지 않습니다. [학습](../../docs/training.md)


## 요구 사항

Linux, macOS, Windows의 Node.js 18 이상. 독립 실행 바이너리를 쓰면 아무것도 필요 없습니다. ClamAV와 Ollama는 선택 사항이며 각자 별도 서비스로 실행됩니다.
