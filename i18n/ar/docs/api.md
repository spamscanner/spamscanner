<!-- source: b3cc9f949acd -->

# مرجع API

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

أنشئ ماسحًا واحدًا وأعد استخدامه: فهو يحمّل النموذج مرة واحدة ويخزّن إجابات DNS والنموذج اللغوي مؤقتًا.


## الخيارات

يمكن تمرير كل خيار إلى المُنشئ. ويمكن تمرير معظمها أيضًا إلى `scan()` لرسالة واحدة، فتُدمج فوق خيارات المُنشئ.

| الخيار                  | القيمة الافتراضية                | المعنى                                                                                                 |
| ----------------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `threshold`             | `5`                              | الدرجة التي تصبح عندها الرسالة مزعجة                                                                   |
| `rejectThreshold`       | `15`                             | الدرجة التي يصبح عندها `action` هو `reject`                                                            |
| `scores`                | `{}`                             | النقاط لكل اختبار: مفاتيح إعدادات أو أسماء اختبارات ([الاختبارات والدرجات](scoring.md))                |
| `classifier`            | النموذج المرفق                   | `Classifier`، أو كائن نموذج، أو مسار ملف نموذج، أو `false`                                             |
| `classifierOptions`     | `{}`                             | خيارات النموذج المرفق (انظر [المصنِّف](#classifier))                                                   |
| `allowedLanguages`      | `[]`                             | رموز ISO 639-1؛ اللغات الأخرى تحصل على `LANGUAGE_NOT_ALLOWED`                                          |
| `phishing.cloudflare`   | `true`                           | سؤال محلِّلات Cloudflare الترشيحية عن مضيفي الروابط                                                    |
| `phishing.adult`        | `true`                           | سؤال المحلِّل العائلي أيضًا، وهو يحظر مواقع البالغين                                                   |
| `phishing.maxHosts`     | `25`                             | عدد مضيفي الروابط الذين يُبحث عنهم في كل رسالة                                                         |
| `phishing.homograph`    | `{}`                             | `brands` (يستبدل القائمة المدمجة)، و`extraBrands`، و`allowlist` (نطاقات لا تُوسم أبدًا)، و`strictMode` |
| `dnsbl`                 | `{ip: [], domain: []}`           | مناطق قوائم حظر DNS لعنوان IP للعميل ولنطاقات الروابط                                                  |
| `dns`                   | `{servers: null, timeout: 3000}` | خوادم الأسماء لفحوص DNS (الافتراضي: خوادم النظام)                                                      |
| `attachments`           | `true`                           | فحص المرفقات                                                                                           |
| `macros`                | `true`                           | وسم وحدات الماكرو وملفات PDF النشطة وكائنات RTF                                                        |
| `arbitrary`             | `true`                           | تشغيل [القواعد](scoring.md#rules)                                                                      |
| `authentication`        | `false`                          | `true`، أو `{dnsServers, timeout, mta, weights}`: SPF وDKIM وDMARC وARC                                |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout}`                                                      |
| `allowlist`، `denylist` |                                  | عناوين IP أو نطاقات أو عناوين بريد؛ اختصار لـ `reputation`                                             |
| `clamav`                | `false`                          | `true` (المقبس الافتراضي)، أو `{socket}` أو `{host, port}`                                             |
| `llm`                   | `null`                           | [إعدادات النموذج اللغوي](llm.md#any-server-port-and-authentication)، مع `mode` و`minScore` و`maxScore` |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: نموذج تجيب `classify([text])` فيه مثل `@tensorflow-models/toxicity`        |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: نموذج تجيب `classify(imageBuffer)` فيه مثل `nsfwjs`                        |
| `maxLength`             | `100000`                         | عدد محارف نص المتن المقروءة                                                                            |
| `timeout`               | `10000`                          | المللي ثانية المسموح بها لكل فحص شبكي                                                                  |
| `session`               | `{}`                             | تفاصيل جلسة SMTP الافتراضية                                                                            |

تأخذ `scan()` أيضًا `session`:

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


## الدوال

| الدالة                               | تُرجع                                                                        |
| ------------------------------------ | ---------------------------------------------------------------------------- |
| `scan(source, options)`              | النتيجة. `source` هو Buffer أو سلسلة نصية أو Uint8Array أو تدفق قابل للقراءة |
| `scanFile(path, options)`            | النتيجة لملف رسالة                                                           |
| `learn(source, 'spam' \| 'ham')`     | تعلّم المصنِّف رسالة واحدة                                                   |
| `unlearn(source, 'spam' \| 'ham')`   | تتراجع عن `learn`                                                            |
| `saveModel(path, options)`           | تكتب المصنِّف إلى ملف (`options`: `minCount`، `maxFeatures`، `metadata`)     |
| `getClassifier()`                    | الـ `Classifier` المستخدم، أو `null`                                         |
| `getClassification(features)`        | حكم المصنِّف على السمات المأخوذة من `getFeatures`                            |
| `getFeatures(mail)`                  | `{features, words, language, script, links}` لرسالة محلَّلة                  |
| `getTokens(text, locale)`            | كلمات نص                                                                     |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                   |
| `parse(source)`                      | `{raw, mail}`، مع `mail` من mailparser                                       |

تحتوي `scanner.metrics` على `totalScans` و`averageTime` و`lastScanTime`.


## النتيجة

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

النتائج في `phishing` و`attachments` و`executables` و`macros` و`viruses` و`arbitrary` كائنات لها `type` و`message`. و`String(finding)` هو الرسالة.


## الصادرات

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

### المصنِّف

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| الخيار                                 | القيمة الافتراضية | المعنى                                                      |
| -------------------------------------- | ----------------- | ----------------------------------------------------------- |
| `strength`، `unknown`                  | `0.45`، `0.5`     | قيمتا s وx عند Robinson: مدى شدة سحب السمات النادرة نحو 0.5 |
| `minDistance`                          | `0.1`             | تُتجاهل السمات الأقرب إلى 0.5 من هذه القيمة                 |
| `maxClues`                             | `150`             | أقوى السمات التي تُجمع في كل رسالة                          |
| `hamCutoff`، `spamCutoff`              | `0.2`، `0.99`     | حدود نطاق `unsure`                                          |
| `minLanguageExamples`، `languageShare` | `1000`، `0.02`    | عدد رسائل كل فئة اللازم في لغة ما للوصول إلى الثقة الكاملة  |
| `languagePrior`                        | `true`            | وزن الكلمات مقابل أعداد لغتها نفسها                         |

تتوفر أيضًا `merge(other)` و`toJSON(options)` و`Classifier.fromJSON(json)` و`size` و`entries()`.

### التدريب

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

تأخذ `evaluate(classifier, examples)` عناصر `{label, features}`، أو `readExamples(sources)` التي تقرأ المصادر نفسها التي تقرؤها `train`، وتُرجع الأعداد، والدقة، والاستدعاء، وF1، والصحة، ومعدلات الإيجابيات الكاذبة والسلبيات الكاذبة وغير المؤكد.

### الخوادم

```js
import SpamScanner, {MilterServer, createHttpServer, createSpamdServer} from 'spamscanner';

const scanner = new SpamScanner({authentication: true});
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

### تقارير ARF

تقرأ `spamscanner/arf` تقارير الإبلاغ عن الإساءة (RFC 5965) وتكتبها، وهي الصيغة التي يستخدمها مزوّدو صناديق البريد للإبلاغ عن شكاوى البريد المزعج:

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

تُرجع `ArfParser.tryParse()` القيمة `null` بدل رمي استثناء للرسائل التي ليست تقارير، وتفحص `isArfMessage(mail)` رسالة محلَّلة.
