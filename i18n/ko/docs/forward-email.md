<!-- source: dc9016edd59e -->

# Forward Email

Spam Scanner는 오픈 소스 기반의 개인정보 보호 중심 이메일 서비스인 [Forward Email](https://forwardemail.net)이 자사 메일 서버에 쓰기 위해 개발했습니다. Forward Email은 메시지 내용을 기록하지 않으므로 외부 필터링 서비스는 쓸 수 없었습니다. 필터는 자체 서버에서 실행되어야 했고, 사람이 메일을 읽지 않고도 각 판정을 설명할 수 있어야 했습니다.

이 페이지에서는 Forward Email과 같은 메일 서버가 Spam Scanner를 사용하는 방식과, Spam Scanner 5 또는 6용으로 작성된 코드에서 무엇이 바뀌었는지 설명합니다.


## 수신 메일 서버에서

Forward Email은 [smtp-server](https://nodemailer.com/extras/smtp-server/)로 메일을 받습니다. smtp-server 기반 서버라면 어디에나 쓸 수 있는 패턴은 다음과 같습니다.

```js
const SpamScanner = require('spamscanner');

const scanner = new SpamScanner({
  clamav: true,                  // clamd on its default socket
  authentication: true,          // SPF, DKIM, DMARC, ARC
  dnsbl: {ip: ['zen.spamhaus.org'], domain: ['dbl.spamhaus.org']},
  dns: {servers: ['127.0.0.1']}, // a local caching resolver
});

async function onData(stream, session, callback) {
  const scan = await scanner.scan(stream, {
    session: {
      remoteAddress: session.remoteAddress,
      resolvedClientHostname: session.clientHostname,
      helo: session.hostNameAppearsAs,
      envelope: session.envelope,
    },
  });

  if (scan.results.viruses.length > 0) {
    return callback(Object.assign(new Error(`Message contains a virus: ${scan.results.viruses[0]}`), {responseCode: 554}));
  }

  if (scan.action === 'reject') {
    // A temporary error: the sender retries, and a wrong decision can be undone.
    return callback(Object.assign(new Error(`Message rejected as spam: ${scan.message}`), {responseCode: 421}));
  }

  // scan.isSpam: deliver to the Junk folder, or add scan's headers (spamHeaders) and forward.
  callback();
}
```

`scanner.scan()`은 SMTP 스트림을 직접 받습니다. 이미 [mailauth](https://github.com/postalsys/mailauth) 결과가 있다면 `authentication`은 생략하고 IP 주소만 전달하십시오.

421 또는 451로 응답하면 발신 서버는 메시지를 큐에 넣고 나중에 다시 시도합니다. 새 거부 규칙은 일시적 코드로 시작했다가 결과를 확인한 뒤 550으로 바꿀 수 있으며, 그동안 메일을 잃지 않습니다.


## 버전 5 또는 6에서 업그레이드

버전 7은 새로 작성한 버전입니다. 버전 5와 6 코드가 사용하는 생성자, `scan()`, 결과 필드는 여전히 동작합니다. 분류기, 모델, 선택적 TensorFlow 검사는 바뀌었습니다.

### 그대로인 것

* `new SpamScanner(options)`와 `await scanner.scan(source)`.
* `require('spamscanner')`는 클래스를 반환하며, `import SpamScanner from 'spamscanner'`도 동작합니다.
* `result.isSpam`, `result.message`, 그리고 `result.results.classification`, `.phishing`, `.executables`, `.arbitrary`, `.viruses`, `.macros`, `.idnHomographAttack`.
* `results.phishing`, `.executables`, `.arbitrary`, `.viruses`의 각 항목은 이전과 같은 종류의 메시지 문자열로 변환됩니다(`String(item)`, 템플릿 리터럴, `message.includes('adult-related content')`). 이제 각 항목은 `type`, `message`, 세부 정보를 가진 객체입니다.
* `getTokensAndMailFromSource()`, `getClassification()`, `getTokens()`.
* 다음 옵션은 새 이름으로 대응됩니다. `clamscan`은 `clamav`로, `enableMacroDetection: false`는 `macros: false`로, `enableArbitraryDetection: false`는 `arbitrary: false`로, `authOptions`와 함께 쓰던 `enableAuthentication`은 `authentication`과 `session`으로, `reputationOptions.apiUrl`과 함께 쓰던 `enableReputation`은 `reputation`으로, `strictIDNDetection`은 `phishing.homograph.strictMode`로 바뀌었고, `allowlist`와 `denylist`는 그대로입니다. `logger`와 `memoize`는 받기는 하지만 무시합니다.

### 바뀐 것

| 이전                                                     | 현재                                                                                                                                  |
| ------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------- |
| `scan('path/to/file.eml')`이 파일을 읽었습니다                  | 문자열은 메시지 텍스트입니다. `scanFile(path)`를 사용하거나 Buffer를 전달하십시오                                                                             |
| 단어 기반 나이브 베이즈 모델(`classifier.json`). 이제는 불러올 수 없습니다    | 새 분류기와 모델 형식. `spamscanner train`으로 다시 학습하십시오([학습](training.md))                                                                    |
| 유해성 검사와 NSFW 검사가 처음 사용할 때 네트워크에서 TensorFlow 모델을 불러왔습니다 | 모델은 직접 준비합니다. `toxicity: {model}`과 `nsfw: {model}`은 `classify()` 메서드가 있는 객체라면 무엇이든 받습니다. 예: `@tensorflow-models/toxicity`, `nsfwjs` |
| `results.arbitrary`에 일치한 모든 패턴이 나열되었습니다                | 단독으로 스팸을 표시할 만큼 강한 규칙만 나열합니다. 모든 규칙은 `result.tests`에 있습니다                                                                           |
| 예 또는 아니요로 답했습니다                                        | `result.score`, `result.action`(`accept`, `tag`, `reject`), 그리고 각각 점수와 이유가 붙은 `result.tests`                                        |
| 분류기나 단일 검사 하나가 `isSpam`을 결정했습니다                        | `isSpam`은 점수가 5 이상이라는 뜻입니다. 임계값과 점수는 변경할 수 있습니다                                                                                     |
| Forward Email 엔드포인트로 평판을 검사했습니다                        | 범용 평판 서비스를 사용하며, `reputation.apiUrl`을 설정하지 않으면 꺼져 있습니다                                                                              |

### 새로운 것

* 애매한 메시지를 위한 로컬 또는 호스팅 [언어 모델](llm.md).
* SPF, DKIM, DMARC, ARC. DNS 차단 목록. Cloudflare의 필터링 리졸버.
* 내용 기반 첨부 파일 검사: 위장한 실행 파일, 압축 파일, 매크로, 동적 PDF.
* [milter, HTTP API, TCP 서버, spamd 서버](mail-servers.md), 그리고 [명령줄](cli.md).
* 명령줄이나 API를 통한 학습, 평가, 신고 기반 학습.
