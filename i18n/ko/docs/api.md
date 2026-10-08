<!-- source: b3cc9f949acd -->

# API 레퍼런스

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

스캐너는 하나만 만들어 재사용하십시오. 모델을 한 번만 불러오고, DNS 응답과 언어 모델 답변을 캐시합니다.


## 옵션

모든 옵션은 생성자에 전달할 수 있습니다. 대부분은 메시지 하나에 대해 `scan()`에도 전달할 수 있으며, 이때 생성자의 옵션 위에 병합됩니다.

| 옵션                      | 기본값                              | 의미                                                                                        |
| ----------------------- | -------------------------------- | ----------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | 메시지를 스팸으로 판정하는 점수                                                                         |
| `rejectThreshold`       | `15`                             | `action`이 `reject`가 되는 점수                                                                 |
| `scores`                | `{}`                             | 테스트별 점수. 설정 키 또는 테스트 이름으로 지정합니다([테스트와 점수](scoring.md))                                    |
| `classifier`            | 번들 모델                            | `Classifier`, 모델 객체, 모델 파일 경로 또는 `false`                                                  |
| `classifierOptions`     | `{}`                             | 번들 모델의 옵션([Classifier](#classifier) 참고)                                                   |
| `allowedLanguages`      | `[]`                             | ISO 639-1 코드. 그 밖의 언어에는 `LANGUAGE_NOT_ALLOWED`가 붙습니다                                      |
| `phishing.cloudflare`   | `true`                           | 링크 호스트를 Cloudflare의 필터링 리졸버에 조회합니다                                                        |
| `phishing.adult`        | `true`                           | 성인 사이트를 차단하는 가족용 리졸버에도 조회합니다                                                              |
| `phishing.maxHosts`     | `25`                             | 메시지당 조회할 링크 호스트 수                                                                         |
| `phishing.homograph`    | `{}`                             | `brands`(내장 목록 대체), `extraBrands`, `allowlist`(표시하지 않을 도메인), `strictMode`                 |
| `dnsbl`                 | `{ip: [], domain: []}`           | 클라이언트 IP와 링크 도메인용 DNS 차단 목록 영역                                                            |
| `dns`                   | `{servers: null, timeout: 3000}` | DNS 검사에 쓸 네임 서버(기본값: 시스템 설정)                                                              |
| `attachments`           | `true`                           | 첨부 파일을 검사합니다                                                                              |
| `macros`                | `true`                           | 매크로, 동적 PDF, RTF 개체를 표시합니다                                                                |
| `arbitrary`             | `true`                           | [규칙](scoring.md#rules)을 실행합니다                                                             |
| `authentication`        | `false`                          | `true` 또는 `{dnsServers, timeout, mta, weights}`: SPF, DKIM, DMARC, ARC                    |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout}`                                         |
| `allowlist`, `denylist` |                                  | IP 주소, 도메인 또는 주소. `reputation`의 축약형                                                       |
| `clamav`                | `false`                          | `true`(기본 소켓), `{socket}` 또는 `{host, port}`                                               |
| `llm`                   | `null`                           | `mode`, `minScore`, `maxScore`를 포함한 [언어 모델 설정](llm.md#any-server-port-and-authentication) |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: `classify([text])`가 `@tensorflow-models/toxicity`처럼 응답하는 모델   |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: `classify(imageBuffer)`가 `nsfwjs`처럼 응답하는 모델                   |
| `maxLength`             | `100000`                         | 읽을 본문 텍스트의 글자 수                                                                           |
| `timeout`               | `10000`                          | 각 네트워크 검사에 허용하는 시간(밀리초)                                                                   |
| `session`               | `{}`                             | 기본 SMTP 세션 정보                                                                             |

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


## 메서드

| 메서드                                  | 반환값                                                              |
| ------------------------------------ | ---------------------------------------------------------------- |
| `scan(source, options)`              | 결과. `source`는 Buffer, 문자열, Uint8Array 또는 읽기 가능한 스트림              |
| `scanFile(path, options)`            | 메시지 파일의 결과                                                       |
| `learn(source, 'spam' \| 'ham')`     | 분류기에 메시지 하나를 학습시킵니다                                              |
| `unlearn(source, 'spam' \| 'ham')`   | `learn`을 취소합니다                                                   |
| `saveModel(path, options)`           | 분류기를 파일로 기록합니다(`options`: `minCount`, `maxFeatures`, `metadata`) |
| `getClassifier()`                    | 사용 중인 `Classifier` 또는 `null`                                     |
| `getClassification(features)`        | `getFeatures`에서 얻은 특징에 대한 분류기의 판정                                |
| `getFeatures(mail)`                  | 파싱한 메시지의 `{features, words, language, script, links}`            |
| `getTokens(text, locale)`            | 텍스트의 단어                                                          |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                       |
| `parse(source)`                      | `{raw, mail}`. `mail`은 mailparser의 결과                            |

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
    phishing: [],        // lookalike domains, deceptive links, Cloudflare and URIBL findings
    attachments: [],     // every attachment finding
    executables: [],     // the executable findings among them
    macros: [],          // macros, active PDFs, RTF objects
    viruses: [],         // ClamAV findings: {filename, virus: [names], message}
    arbitrary: [],       // rules strong enough to mark spam alone
    obfuscation: {invisible, mixed, styled},
    authentication: null, // mailauth's results with a score, when checked
    reputation: null,
    dnsbl: [],           // {zone, value} for each listing
    language: {language, script, notAllowed},
    llm: null,           // the language model's verdict, when asked
    toxicity: [],
    nsfw: [],
    idnHomographAttack: {detected, domains, riskScore},
  },
  links: ['http://paypa1-secure.top/login'],
  language: 'en',
  tokens: ['dear', 'customer', /* ... */],
  mail: {/* the parsed message, from mailparser */},
  version: '7.0.0',
  metrics: {totalTime: 42},
}
```

`phishing`, `attachments`, `executables`, `macros`, `viruses`, `arbitrary`의 검출 항목은 `type`과 `message`를 가진 객체입니다. `String(finding)`은 그 메시지입니다.


## 내보내기

```js
import SpamScanner, {
  Classifier, getFeatures, segmentWords, detectLanguage,
  LLMClassifier, PROVIDERS, RECOMMENDED_MODELS, CLASSIFIER_MODELS,
  DEFAULT_SCORES, scoreResults, spamHeaders, rewriteMessage,
  loadModel, saveModel, defaultModelPath, loadDefaultModel,
  train, evaluate, readExamples,
  MilterServer, createHttpServer, createTcpServer, createSpamdServer,
  DEFAULTS, VERSION,
} from 'spamscanner';

import ArfParser from 'spamscanner/arf';
```

### Classifier

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| 옵션                                     | 기본값            | 의미                                                |
| -------------------------------------- | -------------- | ------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`  | Robinson의 s와 x. 드문 특징을 0.5 쪽으로 얼마나 강하게 끌어당길지 정합니다 |
| `minDistance`                          | `0.1`          | 0.5와의 거리가 이 값보다 가까운 특징은 무시합니다                     |
| `maxClues`                             | `150`          | 메시지당 결합할 가장 강한 특징의 수                              |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | `unsure` 범위의 경계                                   |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | 한 언어에서 완전한 확신에 필요한 분류별 메시지 수                      |
| `languagePrior`                        | `true`         | 단어를 그 언어 자체의 개수를 기준으로 평가합니다                       |

`merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size`, `entries()`도 사용할 수 있습니다.

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
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

### ARF 보고서

`spamscanner/arf`는 메일박스 제공자가 스팸 신고를 전달할 때 쓰는 형식인 남용 피드백 보고서(RFC 5965)를 읽고 씁니다.

```js
import ArfParser from 'spamscanner/arf';

const report = await ArfParser.parse(rawReport);
console.log(report.feedbackType, report.sourceIp, report.originalHeaders.subject);

const raw = ArfParser.create({
  feedbackType: 'abuse', userAgent: 'MyService/1.0',
  from: 'abuse@example.com', to: 'fbl@example.net',
  originalMessage, sourceIp: '192.0.2.1',
});
```

`ArfParser.tryParse()`는 보고서가 아닌 메시지에 대해 예외를 던지는 대신 `null`을 반환하며, `isArfMessage(mail)`은 파싱한 메시지를 검사합니다.
