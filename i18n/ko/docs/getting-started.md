<!-- source: 8263c06f1dab -->

# 시작하기

Spam Scanner에는 Node.js 18 이상이 필요합니다. 독립 실행형 바이너리를 쓰면 아무것도 필요하지 않습니다.


## 설치

명령줄 도구로 설치:

```sh
npm install --global spamscanner
spamscanner version
```

Node.js 프로젝트의 라이브러리로 설치:

```sh
npm install spamscanner
```

Node.js와 모델이 내장된 Linux 또는 macOS용 독립 실행형 바이너리로 설치:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Linux(x64, arm64), macOS(Intel, Apple 실리콘), Windows용 바이너리는 모든 [릴리스](https://github.com/spamscanner/spamscanner/releases)에 첨부되어 있습니다.


## 메시지 검사

메시지를 파일로 저장한 뒤(대부분의 메일 프로그램에서 "다른 이름으로 저장" 또는 "원본 보기"라고 부릅니다) 검사합니다.

```sh
spamscanner scan message.eml
```

```text
SPAM  score 16.3 (spam at 5.0, reject at 15.0)  action: reject  language: en
     +6.3  BAYES_999                    Classifier spam probability 99.9%
     +5.0  PHISHING_LOOKALIKE_DOMAIN    "paypa1-secure.top" imitates paypal by swapping characters
     +3.0  DECEPTIVE_LINK               A link shows "https://www.paypal.com/signin" but goes to paypa1-secure.top
     +2.0  FROM_NAME_BRAND              Display name says "paypal" but the message is from paypa1-secure.top
```

종료 코드는 ham이면 0, 스팸이면 1, 오류면 2이므로 스크립트에서 바로 사용할 수 있습니다. `--json`은 전체 결과를 출력하고, `--headers`는 `X-Spam-*` 헤더를 추가한 메시지를 출력합니다.

메시지는 표준 입력으로도 받을 수 있습니다.

```sh
cat message.eml | spamscanner scan -
```


## Node.js에서 사용

```js
import SpamScanner from 'spamscanner';
import {readFile} from 'node:fs/promises';

const scanner = new SpamScanner();
const result = await scanner.scan(await readFile('message.eml'));

console.log(result.isSpam, result.score, result.action);
for (const test of result.tests) {
  console.log(test.name, test.score, test.description);
}
```

CommonJS도 동작합니다.

```js
const SpamScanner = require('spamscanner');
```

`scan()`은 원본 메시지를 Buffer, 문자열, Uint8Array 또는 읽기 가능한 스트림으로 받습니다. 문자열은 항상 메시지 텍스트로 취급합니다. 문자열이 경로처럼 보인다고 해서 Spam Scanner가 파일을 읽는 일은 없습니다. 파일에는 `scanner.scanFile(path)`를 사용합니다.


## SMTP 세션 정보 전달

클라이언트 IP 주소, 검증된 호스트 이름, HELO 이름, 엔벌로프를 전달하면 결과가 더 정확해집니다. 인증에는 IP 주소가 필요하고, 자기 도메인 사칭 규칙에는 수신자가 필요합니다.

```js
const result = await scanner.scan(raw, {
  session: {
    remoteAddress: '203.0.113.5',
    resolvedClientHostname: 'mail.example.com',
    helo: 'mail.example.com',
    envelope: {
      mailFrom: {address: 'alice@example.com'},
      rcptTo: [{address: 'bob@example.org'}],
    },
  },
});
```

명령줄에서는 다음과 같습니다.

```sh
spamscanner scan message.eml --ip 203.0.113.5 --helo mail.example.com \
  --from alice@example.com --to bob@example.org --auth
```


## 추가 검사 켜기

아래 검사는 모두 기본으로 꺼져 있습니다. 각각 별도 서비스나 운영자의 결정이 필요하기 때문입니다.

| 검사                    | 라이브러리 옵션                                         | 명령줄                         |
| --------------------- | ------------------------------------------------ | --------------------------- |
| SPF, DKIM, DMARC, ARC | `authentication: true`                           | `--auth`                    |
| IP 차단 목록              | `dnsbl: {ip: ['zen.spamhaus.org']}`              | `--dnsbl zen.spamhaus.org`  |
| 링크용 도메인 차단 목록         | `dnsbl: {domain: ['dbl.spamhaus.org']}`          | `--uribl dbl.spamhaus.org`  |
| ClamAV                | `clamav: true` 또는 `clamav: {socket}`             | `--clamav [socket]`         |
| 언어 모델                 | `llm: {provider: 'ollama', model: 'qwen3.5:4b'}` | `--llm ollama`              |
| 허용 목록과 거부 목록          | `allowlist: [...]`, `denylist: [...]`            | `--allowlist`, `--denylist` |

Cloudflare의 필터링 리졸버(악성코드용 1.1.1.2, 성인 콘텐츠용 1.1.1.3)에는 기본으로 링크 호스트를 조회합니다. `phishing: {cloudflare: false}` 또는 `--no-cloudflare`로 끌 수 있습니다. [컴퓨터 밖으로 나가는 데이터](security.md)

Spamhaus를 비롯한 일부 차단 목록은 8.8.8.8이나 1.1.1.1 같은 공개 리졸버를 거친 조회에 응답하지 않습니다. 로컬 캐싱 리졸버와 함께 사용하고, 조회량에 맞는 이용 약관을 확인하십시오.


## 다음 단계

* 메일 서버 앞에 배치합니다: [Postfix와 Sendmail](postfix.md), [기타 서버](mail-servers.md).
* 직접 받은 메일로 학습시킵니다: [학습](training.md).
* 애매한 메시지를 위해 언어 모델을 추가합니다: [언어 모델](llm.md).
