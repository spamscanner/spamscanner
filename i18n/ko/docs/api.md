<!-- source: 9134d1cd102c -->

# API 레퍼런스

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

스캐너는 하나만 만들어 재사용하십시오. 모델을 한 번만 불러오고, DNS 응답과 언어 모델 답변을 캐시합니다.

타입 선언이 포함되어 있습니다. `import`로 쓰려면 TypeScript 4.7 이상, `require`로 쓰려면 5.3 이상이 필요합니다.


## 옵션

모든 옵션은 생성자에 전달할 수 있습니다. 대부분은 메시지 하나에 대해 `scan()`에도 전달할 수 있으며, 이때 생성자의 옵션 위에 병합됩니다. `undefined`로 전달한 옵션은 기본값을 유지합니다. `classifier`, `classifierOptions`, `dns`, `phishing.homograph`, `strictIDNDetection`은 생성자만 읽습니다. `classifier`로 지정한 모델 파일이나 객체도 생성자에서 읽으므로, 모델이 없거나 손상되었으면 즉시 오류가 발생합니다.

| 옵션                      | 기본값                              | 의미                                                                                                                                         |
| ----------------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `threshold`             | `5`                              | 메시지를 스팸으로 판정하는 점수                                                                                                                          |
| `rejectThreshold`       | `15`                             | `action`이 `reject`가 되는 점수                                                                                                                  |
| `scores`                | `{}`                             | 테스트별 점수. 설정 키 또는 테스트 이름으로 지정합니다([테스트와 점수](scoring.md))                                                                                     |
| `classifier`            | 번들 모델                            | `Classifier`, 모델 객체, 모델 파일 경로 또는 `false`                                                                                                   |
| `classifierOptions`     | `{}`                             | 번들 모델의 옵션([Classifier](#classifier) 참고)                                                                                                    |
| `allowedLanguages`      | `[]`                             | ISO 639-1 코드(`no`는 `nb`로, `fil`은 `tl`로, 옛 코드 `iw`, `in`, `ji`는 `he`, `id`, `yi`로 읽습니다). 그 밖의 언어에는 `LANGUAGE_NOT_ALLOWED`가 붙습니다             |
| `phishing.cloudflare`   | `true`                           | 링크 호스트를 Cloudflare의 필터링 리졸버에 조회합니다                                                                                                         |
| `phishing.adult`        | `true`                           | 성인 사이트를 차단하는 가족용 리졸버에도 조회합니다                                                                                                               |
| `phishing.maxHosts`     | `25`                             | 메시지당 조회할 링크 호스트 수                                                                                                                          |
| `phishing.maxLength`    | `1000000`                        | 링크를 찾기 위해 읽는 본문 문자 수(HTML은 두 배). 더 긴 본문은 `results.linksTruncated`를 설정합니다; `Infinity`나 양수가 아닌 값은 기본값을 뜻합니다                                  |
| `phishing.homograph`    | `{}`                             | `brands`(내장 목록 대체), `extraBrands`, `allowlist`(표시하지 않을 도메인), `strictMode`                                                                  |
| `dnsbl`                 | `{ip: [], domain: []}`           | 클라이언트 IP와 링크 도메인용 DNS 차단 목록 영역                                                                                                             |
| `dns`                   | `{servers: null, timeout: 3000}` | DNS 검사에 쓸 네임 서버(기본값: 시스템 설정)                                                                                                               |
| `attachments`           | `true`                           | 첨부 파일을 검사합니다                                                                                                                               |
| `macros`                | `true`                           | 매크로, 동적 PDF, RTF 개체를 표시합니다                                                                                                                 |
| `arbitrary`             | `true`                           | [규칙](scoring.md#rules)을 실행합니다                                                                                                              |
| `authentication`        | `false`                          | `true` 또는 `{dnsServers, timeout, maxDnsQueries, mta, weights, trustedArcSealers}`: SPF, DKIM, DMARC, ARC ([점수](scoring.md#authentication)) |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout, concurrency, cacheTtl, cacheSize}`. 응답은 서비스와 헤더별로 보관하며, `cacheSize`는 스캐너 전체에 적용됩니다        |
| `allowlist`, `denylist` |                                  | IP 주소, 도메인 또는 주소. `reputation`의 축약형 → [허용 목록과 차단 목록](#allowlist-and-denylist)                                                              |
| `clamav`                | `false`                          | `true`(기본 소켓), `{socket}` 또는 `{host, port}`, 그리고 `timeout`: 메시지의 모든 첨부 파일에 허용하는 시간(밀리초, `60000`)                                           |
| `llm`                   | `null`                           | `mode`, `minScore`, `maxScore`를 포함한 [언어 모델 설정](llm.md#any-server-port-and-authentication)                                                  |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: `classify([text])`가 `@tensorflow-models/toxicity`처럼 응답하는 모델                                                    |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: `classify(imageBuffer)`가 `nsfwjs`처럼 응답하는 모델                                                                    |
| `maxLength`             | `100000`                         | 읽을 본문 텍스트의 글자 수                                                                                                                            |
| `timeout`               | `10000`                          | 각 네트워크 검사에 허용하는 시간(밀리초); 인증과 이미지 모델은 전체 합쳐 이 시간 안에 끝납니다(ClamAV에는 별도의 `clamav.timeout`이 있습니다)                                               |
| `session`               | `{}`                             | 기본 SMTP 세션 정보                                                                                                                              |

`scan()`은 `session`도 받습니다.

```js
await scanner.scan(raw, {
  session: {
    remoteAddress: '203.0.113.5',             // the client's IP address
    resolvedClientHostname: 'mx.example.com', // its verified reverse DNS name
    helo: 'mx.example.com',
    envelope: {
      mailFrom: {address: 'alice@example.com'},
      rcptTo: [{address: 'bob@example.org'}],
    },
  },
});
```

SPF, DKIM, DMARC, ARC를 이미 ([mailauth](https://github.com/postalsys/mailauth)로) 검사한 서버는 그 결과를 `authenticationResults`로 전달할 수 있으며, 이때 결과는 다시 검사하지 않고 점수에 반영됩니다.

```js
import {authenticate} from 'mailauth';

const auth = await authenticate(raw, {ip, helo, sender, mta});
await scanner.scan(raw, {authenticationResults: auth});
```

### 허용 목록과 차단 목록

차단 목록은 클라이언트의 IP 주소와 호스트 이름, From·봉투 발신자·Reply-To 주소와 그 도메인을, 그것이 무엇이든 대조합니다. 차단된 도메인 아래의 이름은 유효한 호스트 이름이 아니더라도(`a_b!.evil.example`, 또는 63자를 넘는 레이블이 있는 이름 등) 마지막 127개 레이블과 253자를 기준으로 그 도메인과 일치합니다. 허용 목록과 평판 서비스의 허용 목록 및 신뢰 출처는 발신자가 위조할 수 없는 것만 대조합니다. 클라이언트의 IP 주소와 확인된 호스트 이름(`remoteAddress`, `resolvedClientHostname`), 도메인에 대해 DMARC가 통과하거나 통과한 DKIM 서명이 정렬된(그리고 그 도메인이 유효한 호스트 이름인 경우. DMARC와 같은 완화 방식으로, From 도메인과 서명 도메인 또는 SPF 도메인의 등록 가능 도메인이 같은 경우이며, mailauth는 이를 DMARC 도메인으로 밝힙니다. `news.example.com`처럼 하위 도메인을 지정한 항목은 그 도메인, 그 아래 도메인 또는 그 상위 도메인이 메시지에 서명했거나 SPF를 통과했을 때만 해당하며, `evil.example.com` 같은 다른 하위 도메인이나 공개 접미사는 해당하지 않습니다. mailauth의 정렬 정보 없이 등록 가능 도메인에 대해 통과한 DMARC는 등록 가능 도메인을 지정한 항목에만 해당합니다. 엄격 정렬, 즉 도메인의 DMARC 레코드에 `adkim=s`나 `aspf=s`가 대소문자나 공백에 관계없이 있으면 From 도메인 자체의 서명이나 SPF 통과만 해당하며, 그런 것이 없으면 DMARC는 실패합니다) From 주소, 도메인에 대해 SPF가 통과한 봉투 발신자입니다. 본문의 앞부분만 서명한 DKIM 서명(본문 길이 `l=`이 본문보다 짧은 서명: 그 뒤에는 누구나 텍스트를 덧붙일 수 있습니다)은 아무것에도 해당하지 않으며, 그런 서명에 기댄 DMARC 통과도 마찬가지이고, DMARC가 실패하거나 From 필드가 너무 길어 전체를 읽을 수 없으면(`mail.from.truncated`) 어떤 서명도 해당하지 않습니다. `authenticationResults`로 전달한 결과는 통과한 도메인을 밝히고 있을 때만 반영되며, 호스트 이름이 아닌 도메인(URL 파서가 `bank.example`로 읽는 `bank.example/x.attacker.example` 등)은 어디에도 해당하지 않고, 그런 도메인에 기댄 DMARC 통과도 마찬가지입니다. 국제화 도메인은 `bücher.example`과 `xn--bcher-kva.example` 어느 형태로든 일치합니다. Reply-To는 절대 반영되지 않습니다. 도메인을 허용하려면 `authentication`을 켜거나 `authenticationResults`를 전달하세요.

각 항목은 IP 주소, 도메인, 이메일 주소 중 하나이며 정확히 일치해야 합니다. 도메인 항목은 그 하위 도메인과 그 도메인들의 주소도 포함하지만, 주소 범위(`192.0.2.0/24`), 와일드카드(`*.example.com`), 패턴(`@example.com`)은 없습니다. IPv6 주소는 어떤 형태로든 일치하며(`2001:0db8::0001`은 RFC 5952 형식인 `2001:db8::1`입니다), IPv6에 매핑된 IPv4 주소(`::ffff:192.0.2.1`)는 그 IPv4 주소와 일치하며, IPv6로 변환된 IPv4 주소나 NAT64 접두사 아래의 IPv4 주소는 항목과 클라이언트 주소 모두에서 그 IPv4 주소를 점 표기로 붙여 씁니다(`::ffff:0:192.0.2.1`, `64:ff9b::192.0.2.1`).


## 메서드

| 메서드                                  | 반환값                                                                    |
| ------------------------------------ | ---------------------------------------------------------------------- |
| `scan(source, options)`              | 결과. `source`는 Buffer, 문자열, Uint8Array 또는 읽기 가능한 스트림                    |
| `scanFile(path, options)`            | 메시지 파일의 결과                                                             |
| `learn(source, 'spam' \| 'ham')`     | 분류기에 메시지 하나를 학습시킵니다                                                    |
| `unlearn(source, 'spam' \| 'ham')`   | `learn`을 취소합니다                                                         |
| `saveModel(path, options)`           | 분류기를 파일로 기록합니다(`options`: `minCount`, `maxFeatures`, `metadata`)       |
| `getClassifier()`                    | 사용 중인 `Classifier` 또는 `null`                                           |
| `getClassification(features)`        | `getFeatures`에서 얻은 특징에 대한 분류기의 판정                                      |
| `getFeatures(mail)`                  | 메시지의 `{features, words, language, script, links, hosts, text, hidden}` |
| `getTokens(text, locale)`            | 텍스트의 단어                                                                |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                             |
| `parse(source)`                      | `{raw, mail, error}`. `mail`은 mailparser의 결과(아래 참조)                    |

`scan`, `parse`, `learn`, `unlearn`, `getTokensAndMailFromSource`는 모두 같은 방식으로 메시지를 읽습니다. MIME 파서의 한도(파트 1000개 초과, 한 파트의 헤더 1 MB 초과)를 넘는 메시지는 파서가 허용하는 만큼 읽습니다. 메시지, 그 파트, 첨부된 메시지의 주소 필드(From, To, Cc, Bcc, Sender, Reply-To, Delivered-To, Return-Path, Disposition-Notification-To, List-\*)는 각각 최대 16 KB, 쉼표와 세미콜론 2000개, 중첩 그룹 16개까지, 메시지마다 모두 합쳐 64 KB까지 읽으며, 항상 온전한 주소의 끝까지 읽으므로 필드에 없는 주소를 읽는 일은 없습니다. 잘린 필드에는 `truncated`가 표시되며(`mail.to.truncated`), From 필드가 잘리면 발신자의 인증에 따른 감점이 주어지지 않습니다. 첫 줄이 헤더 필드(`Name: value`, 또는 mbox 파일에서 각 메시지를 시작하는 `From` 줄)가 아닌 텍스트는 헤더 없는 메시지의 본문으로 읽으므로, `mail.text`가 그 텍스트가 됩니다. 그 밖의 오류는 예외로 던집니다. `parse`는 메시지가 넘은 파서의 한도를 `error`로 돌려주며, 이는 `scan`이 `parseError`로 돌려주는 것과 같고, 전부 읽은 메시지에서는 null입니다.

`getFeatures`에서 `text`는 메일 클라이언트가 보여 주는 텍스트로, 단어는 여기에서 읽습니다. `hidden`은 HTML이 숨기는 텍스트의 글자 수입니다. 여기서 mailparser는 HTML을 텍스트로 만들지 않습니다. `mail.text`에는 일반 텍스트 파트만 들어 있으며, HTML만으로 된 메시지에서는 비어 있습니다. HTML이 보여 주는 텍스트는 `getFeatures(mail).text`입니다.

`scanner.metrics`에는 `totalScans`, `averageTime`, `lastScanTime`이 들어 있습니다.


## 결과

```js
{
  isSpam: true,
  score: 16.25,
  threshold: 5,
  rejectThreshold: 15,
  action: 'reject',                       // 'accept', 'tag' or 'reject'
  message: 'Spam (BAYES_999, PHISHING_LOOKALIKE_DOMAIN, DECEPTIVE_LINK, FROM_NAME_BRAND)',
  tests: [
    {name: 'BAYES_999', score: 6.25, description: 'Classifier spam probability 99.9%'},
    {name: 'PHISHING_LOOKALIKE_DOMAIN', score: 5, description: '"paypa1-secure.top" imitates paypal by swapping characters'},
    // ...
  ],
  results: {
    classification: {probability, category, spam, ham, clues, coverage},
    parseError: null,    // the MIME parser's limit the message, or one attached to it, exceeds, or why an attached message could not be read (MIME_TOO_COMPLEX)
    phishing: [],        // lookalike domains, deceptive links, Cloudflare and URIBL findings
    uncheckedHosts: 0,   // link hosts beyond phishing.maxHosts, not looked up
    timedOutHosts: 0,    // link hosts looked up but not answered (in time, or at all)
    linksTruncated: false, // more text than phishing.maxLength, whose links were not read
    attachments: [],     // every attachment finding
    executables: [],     // the executable findings among them
    macros: [],          // macros, active PDFs, RTF objects
    viruses: [],         // ClamAV findings: {filename, virus: [names], message}
    virusScanErrors: [], // attachments ClamAV could not scan: {filename, error}
    virusScanSkipped: [], // attachments larger than clamd accepts, not scanned: {filename, reason}
    unopenedAttachments: [], // attached messages not opened, past the limits they are read within: {filename, reason}
    arbitrary: [],       // rules strong enough to mark spam alone
    obfuscation: {invisible, mixed, styled},
    authentication: null, // mailauth's results with a score, when checked
    reputation: null,
    dnsbl: [],           // {zone, value, answers} for each listing
    language: {language, script, notAllowed},
    llm: null,           // the language model's verdict, when asked
    toxicity: [],
    nsfw: [],
    idnHomographAttack: {detected, domains, riskScore},
  },
  links: ['http://paypa1-secure.top/login'], // the links checked, of the whole message up to phishing.maxLength
  language: 'en',
  tokens: ['dear', 'customer', /* ... */],
  mail: {/* the parsed message, from mailparser; mail.text: the plain text parts only */},
  version: VERSION,      // this package's version
  metrics: {totalTime: 42},
}
```

`phishing`, `attachments`, `executables`, `macros`, `viruses`, `arbitrary`의 검출 항목은 `type`과 `message`를 가진 객체입니다. `String(finding)`은 그 메시지입니다. 첨부된 메시지(`message/rfc822`, `message/global`, `.eml`, `.u8msg`)의 첨부 파일은 그 메시지 이름을 붙여 부릅니다: `fw.eml/invoice.exe`. ClamAV가 이런 첨부 파일에서 찾은 바이러스는 그 첨부 파일에 대해서만 보고하며, 그것을 담은 첨부된 메시지에 대해 다시 보고하지 않습니다. `virusScanErrors`는 ClamAV가 검사하지 못한 첨부 파일을 `{filename, error}` 형태로 나열합니다. 이런 메시지에는 바이러스가 있을 수 있으니 전달하지 말고 보류하세요. milter와 콘텐츠 필터는 `onError`(`--on-error`)가 `accept`가 아니면 이런 메시지를 일시적으로 거부하며, 모든 서버는 이런 메시지를 넘겨줄 때 `X-Spam-Virus-Scan: failed`를 붙입니다. `virusScanSkipped`는 clamd가 받아들이는 크기(clamd의 `StreamMaxLength`)보다 큰 첨부 파일을 `{filename, reason}` 형태로 나열합니다. clamd는 이런 파일을 몇 번을 시도해도 거부하므로, clamav-milter가 `MaxFileSize`를 넘는 파일을 건너뛰는 것과 마찬가지로 실패로 보지 않습니다. 압축 폭탄이 도달하는 clamd의 다른 한도(`MaxScanSize`, `MaxFiles`, `MaxRecursion`, `MaxScanTime`)는 실패입니다. 첨부된 메시지는 세 단계 깊이까지, 그 안의 첨부 파일 100개까지, 합계 25MB까지 엽니다. `unopenedAttachments`는 이 한도를 넘어 열지 않은 메시지를 `{filename, reason}` 형태로 나열하며, 그 첨부 파일은 검사하지 않았습니다. 전달된 메시지는 이렇게 중첩될 수 있으므로 점수에는 반영하지 않지만, 메시지를 전부 읽어야 하는 호출자는 예를 들어 그 안의 프로그램을 차단하기 위해 이런 항목이 하나라도 있는 메시지를 거부할 수 있습니다. 첨부된 메시지는 모두 합쳐 최대 100개까지 엽니다.

각 `dnsbl` 항목에는 목록의 `answers`(127.0.0.0/8 범위의 주소로, 그 의미는 각 목록이 문서로 밝힙니다)가 들어 있습니다. 목록이 거부하거나 답할 수 없는 조회에 주는 응답은 클라이언트 주소에 대해서든 링크 도메인(`phishing`의 `uribl` 검출 항목)에 대해서든 등재가 아닙니다. Spamhaus의 127.255.255.x(공개 리졸버를 거친 조회에 대한 127.255.255.254, 조회가 너무 많을 때의 127.255.255.255 등), Spamhaus DBL의 127.0.1.255, 모든 목록의 127.0.0.255, 그리고 SURBL과 URIBL이 차단한 리졸버에 답하는 127.0.0.1이 그렇습니다.


## 내보내기

```js
import SpamScanner, {
  Classifier, getFeatures, segmentWords, unwrapLink, detectLanguage,
  LLMClassifier, PROVIDERS, RECOMMENDED_MODELS, CLASSIFIER_MODELS, DECISION_MODELS,
  DEFAULT_SCORES, scoreResults, spamHeaders, rewriteMessage,
  loadModel, saveModel, defaultModelPath, loadDefaultModel,
  train, evaluate, readExamples,
  MilterServer, createHttpServer, createTcpServer, createSpamdServer,
  DEFAULTS, VERSION,
} from 'spamscanner';
import {SpamScanner} from 'spamscanner'; // the same class, as a named export
// unwrapLink(address): the URL a link goes to, through Safe Links and
// Proofpoint URL Defense, as the scanner reads it (null for no URL)

import ArfParser from 'spamscanner/arf';
```

### Classifier

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| 옵션                                     | 기본값            | 의미                                                                                          |
| -------------------------------------- | -------------- | ------------------------------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`  | Robinson의 s와 x. 드문 특징을 0.5 쪽으로 얼마나 강하게 끌어당길지 정합니다                                           |
| `minDistance`                          | `0.1`          | 0.5와의 거리가 이 값보다 가까운 특징은 무시합니다                                                               |
| `maxClues`                             | `150`          | 메시지당 결합할 가장 강한 특징의 수                                                                        |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | `unsure` 범위의 경계                                                                             |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | 한 언어에서 완전한 확신에 필요한 햄 메시지 수와 그 5분의 1만큼의 스팸 메시지 수. 전체 햄이나 스팸의 `languageShare`가 이보다 적으면 더 적습니다 |
| `languagePrior`                        | `true`         | 단어를 그 언어 자체의 개수를 기준으로 평가합니다                                                                 |

`merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size`, `entries()`도 사용할 수 있습니다. `Classifier.fromJSON`은 모델을 검사하고, 손상된 데이터에는 `Corrupt classifier model`로 시작하는 `TypeError`를 던집니다. JSON에는 `Infinity`가 없으므로, 버전 7.0.3이 `Infinity`로 저장한 옵션은 `null`로 다시 읽힙니다. 이 값은 `maxClues`, `minDistance`, `minLanguageExamples`에서는 `Infinity`로, `hamCutoff`에서는 `-Infinity`(햄으로 판정하지 않음)로, `spamCutoff`에서는 `Infinity`(스팸으로 판정하지 않음)로, 나머지 옵션에서는 기본값으로 읽습니다. `toJSON`은 0과 1을 벗어난 기준값을 -1 또는 2로 저장하며, 이는 똑같이 동작합니다. `loadModel`은 파일이 바뀌면 다시 읽고, `saveModel`은 새 임시 파일을 거쳐 쓰며, 이 파일은 모델을 대체하기 전에 디스크에 플러시되고 모델의 권한은 유지됩니다.

### 학습

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

`evaluate(classifier, examples)`는 `{label, features}` 항목 또는 `train`과 같은 입력을 읽는 `readExamples(sources)`의 결과를 받아, 개수, 정밀도, 재현율, F1, 정확도, 그리고 오탐률, 미탐률, unsure 비율을 반환합니다.

### 서버

```js
import SpamScanner, {MilterServer, createHttpServer, createSpamdServer} from 'spamscanner';

const scanner = new SpamScanner({authentication: true});
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]', onError: 'tempfail'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

milter의 `onError`는 검사에 실패하거나 ClamAV가 첨부 파일을 검사하지 못했을 때의 응답으로, `'tempfail'`(기본값) 또는 `'accept'`이며, 후자는 메시지에 `X-Spam-Virus-Scan: failed`를 붙이고 발신자가 추가한 `X-Spam-*` 헤더를 뺀 채 넘겨줍니다.

### ARF 보고서

`spamscanner/arf`는 메일박스 제공자가 스팸 신고를 전달할 때 쓰는 형식인 남용 피드백 보고서(RFC 5965)를 읽고 씁니다.

```js
import ArfParser from 'spamscanner/arf';

const report = await ArfParser.parse(rawReport);
console.log(report.feedbackType, report.sourceIp, report.originalHeaders?.subject);

const raw = ArfParser.create({
  feedbackType: 'abuse', userAgent: 'MyService/1.0',
  from: 'abuse@example.com', to: 'fbl@example.net',
  originalMessage, sourceIp: '192.0.2.1',
});
```

`parse()`는 Buffer, Uint8Array 또는 문자열을 받습니다. `ArfParser.tryParse()`는 보고서가 아닌 메시지에 대해 예외를 던지는 대신 `null`을 반환하며, `isArfMessage(mail)`은 파싱한 메시지를 검사합니다. 원본 메시지가 없는 보고서에서는 `originalHeaders`가 `null`입니다. `create()`는 문자열을 반환하지만, `originalMessage`가 `Buffer`이면 반환값도 같은 형식이므로 문자 집합과 상관없이 바이트가 그대로 유지됩니다.
