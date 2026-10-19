<!-- source: 581d018dd514 -->

# مرجع API

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

أنشئ ماسحًا واحدًا وأعد استخدامه: فهو يحمّل النموذج مرة واحدة ويخزّن إجابات DNS والنموذج اللغوي مؤقتًا.

تعريفات الأنواع مضمّنة. وهي تحتاج إلى TypeScript 4.7 أو أحدث مع `import`، و5.3 أو أحدث مع `require`.


## الخيارات

يمكن تمرير كل خيار إلى المُنشئ. ويمكن تمرير معظمها أيضًا إلى `scan()` لرسالة واحدة، فتُدمج فوق خيارات المُنشئ. الخيارات الممرَّرة بقيمة `undefined` تحتفظ بقيمها الافتراضية. لا يقرأ `classifier` و`classifierOptions` و`dns` و`phishing.homograph` و`strictIDNDetection` إلا المُنشئ؛ ويُقرأ ملف النموذج أو كائنه المعطى في `classifier` هناك، فيرمي النموذج المفقود أو التالف خطأً فورًا.

| الخيار                  | القيمة الافتراضية                | المعنى                                                                                                                                                                   |
| ----------------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `threshold`             | `5`                              | الدرجة التي تصبح عندها الرسالة مزعجة                                                                                                                                     |
| `rejectThreshold`       | `15`                             | الدرجة التي يصبح عندها `action` هو `reject`                                                                                                                              |
| `scores`                | `{}`                             | النقاط لكل اختبار: مفاتيح إعدادات أو أسماء اختبارات ([الاختبارات والدرجات](scoring.md))                                                                                  |
| `classifier`            | النموذج المرفق                   | `Classifier`، أو كائن نموذج، أو مسار ملف نموذج، أو `false`                                                                                                               |
| `classifierOptions`     | `{}`                             | خيارات النموذج المرفق (انظر [المصنِّف](#classifier))                                                                                                                     |
| `allowedLanguages`      | `[]`                             | رموز ISO 639-1 (يُقرأ `no` على أنه `nb`، و`fil` على أنه `tl`، والرموز القديمة `iw` و`in` و`ji` على أنها `he` و`id` و`yi`)؛ اللغات الأخرى تحصل على `LANGUAGE_NOT_ALLOWED` |
| `phishing.cloudflare`   | `true`                           | سؤال محلِّلات Cloudflare الترشيحية عن مضيفي الروابط                                                                                                                      |
| `phishing.adult`        | `true`                           | سؤال المحلِّل العائلي أيضًا، وهو يحظر مواقع البالغين                                                                                                                     |
| `phishing.maxHosts`     | `25`                             | عدد مضيفي الروابط الذين يُبحث عنهم في كل رسالة                                                                                                                           |
| `phishing.maxLength`    | `1000000`                        | عدد أحرف النص المقروءة بحثًا عن الروابط (وضعفها من HTML)؛ النص الأطول يضبط `results.linksTruncated`؛ القيمة `Infinity` أو أي شيء غير عدد موجب تعني القيمة الافتراضية     |
| `phishing.homograph`    | `{}`                             | `brands` (يستبدل القائمة المدمجة)، و`extraBrands`، و`allowlist` (نطاقات لا تُوسم أبدًا)، و`strictMode`                                                                   |
| `dnsbl`                 | `{ip: [], domain: []}`           | مناطق قوائم حظر DNS لعنوان IP للعميل ولنطاقات الروابط                                                                                                                    |
| `dns`                   | `{servers: null, timeout: 3000}` | خوادم الأسماء لفحوص DNS (الافتراضي: خوادم النظام)                                                                                                                        |
| `attachments`           | `true`                           | فحص المرفقات                                                                                                                                                             |
| `macros`                | `true`                           | وسم وحدات الماكرو وملفات PDF النشطة وكائنات RTF                                                                                                                          |
| `arbitrary`             | `true`                           | تشغيل [القواعد](scoring.md#rules)                                                                                                                                        |
| `authentication`        | `false`                          | `true`، أو `{dnsServers, timeout, maxDnsQueries, mta, weights, trustedArcSealers}`: SPF وDKIM وDMARC وARC ([التقييم](scoring.md#authentication))                         |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout, concurrency, cacheTtl, cacheSize}`؛ تُحفظ الإجابات لكل خدمة وترويسات، و`cacheSize` يخص الماسح كله                       |
| `allowlist`، `denylist` |                                  | عناوين IP أو نطاقات أو عناوين بريد؛ اختصار لـ `reputation` → [قائمة السماح وقائمة الحظر](#allowlist-and-denylist)                                                        |
| `clamav`                | `false`                          | `true` (المقبس الافتراضي)، أو `{socket}` أو `{host, port}`، مع `timeout`: المللي ثانية لكل مرفقات الرسالة (`60000`)                                                      |
| `llm`                   | `null`                           | [إعدادات النموذج اللغوي](llm.md#any-server-port-and-authentication)، مع `mode` و`minScore` و`maxScore`                                                                   |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: نموذج تجيب `classify([text])` فيه مثل `@tensorflow-models/toxicity`                                                                          |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: نموذج تجيب `classify(imageBuffer)` فيه مثل `nsfwjs`                                                                                          |
| `maxLength`             | `100000`                         | عدد محارف نص المتن المقروءة                                                                                                                                              |
| `timeout`               | `10000`                          | المللي ثانية المسموح بها لكل فحص شبكي؛ وتحصل المصادقة ونموذج الصور على هذه المدة إجمالًا (لـ ClamAV مهلته الخاصة `clamav.timeout`)                                       |
| `session`               | `{}`                             | تفاصيل جلسة SMTP الافتراضية                                                                                                                                              |

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

يمكن للخادم الذي فحص SPF وDKIM وDMARC وARC مسبقًا (باستخدام [mailauth](https://github.com/postalsys/mailauth)) أن يمرّر نتائجه في `authenticationResults`، فتُحتسب بدلًا من فحصها مرة أخرى:

```js
import {authenticate} from 'mailauth';

const auth = await authenticate(raw, {ip, helo, sender, mta});
await scanner.scan(raw, {authenticationResults: auth});
```

### قائمة السماح وقائمة الحظر

تطابق قائمة الحظر عنوان IP للعميل واسم مضيفه، وعناوين From والمرسل في المغلف وReply-To، ونطاقاتها، أيًّا كانت: فالاسم الواقع تحت نطاق محظور يطابقه حتى لو لم يكن اسم مضيف صالحًا (مثل `a_b!.evil.example`، أو اسم فيه مقطع يتجاوز 63 حرفًا)، وذلك بآخر 127 مقطعًا منه وآخر 253 حرفًا. أما قائمة السماح، وقائمة السماح ومصادر الثقة لدى خدمة السمعة، فلا تطابق إلا ما لا يستطيع المرسل تزويره: عنوان IP للعميل واسم مضيفه الموثّق (`remoteAddress` و`resolvedClientHostname`)، وعنوان From عندما ينجح DMARC لنطاقه أو يتوافق معه توقيع DKIM ناجح (وكان نطاقه اسم مضيف صالحًا؛ توافقًا مرنًا كما في DMARC: لنطاق From وللنطاق الموقِّع أو نطاق SPF النطاق القابل للتسجيل نفسه، وهو ما يسمّيه mailauth نطاق DMARC؛ والمُدخل الذي يسمّي نطاقًا فرعيًا، مثل `news.example.com`، لا يُحتسب إلا إذا كان ذلك النطاق أو نطاق تحته أو نطاق فوقه قد وقّع الرسالة أو نجح في SPF، لا نطاق فرعي آخر مثل `evil.example.com`، ولا لاحقة عامة؛ ونجاح DMARC للنطاق القابل للتسجيل دون تفاصيل التوافق من mailauth لا يُحتسب إلا لمُدخل يسمّي النطاق القابل للتسجيل؛ ومع التوافق الصارم، أي `adkim=s` أو `aspf=s` في سجل DMARC للنطاق بأي حالة أحرف أو تباعد، لا يُحتسب إلا توقيع نطاق From نفسه أو نجاحه في SPF، ويفشل DMARC من دون ذلك)، والمرسل في المغلف عندما ينجح SPF لنطاقه. توقيع DKIM لبداية النص فقط (طول للنص، `l=`، أقصر من النص: يستطيع أي أحد أن يضيف نصًا بعده) لا يُحتسب بشيء، ولا نجاح DMARC القائم على مثله، ولا يُحتسب أي توقيع عندما يفشل DMARC، ولا لحقل From أطول من أن يُقرأ كاملًا (`mail.from.truncated`). لا تُحتسب النتائج المُمرَّرة في `authenticationResults` إلا حين تسمّي النطاق الذي نجحت له، والنطاق الذي ليس اسم مضيف (مثل `bank.example/x.attacker.example`، الذي تقرؤه محلّلات عناوين URL على أنه `bank.example`) لا يُحتسب لأي نطاق، ولا نجاح DMARC القائم على مثله. تتطابق النطاقات الدولية بأيّ من صيغتيها: `bücher.example` أو `xn--bcher-kva.example`. لا يُحتسب Reply-To أبدًا. لإضافة نطاق إلى قائمة السماح، فعّل `authentication` أو مرّر `authenticationResults`.

كل مُدخل عنوان IP واحد أو نطاق واحد أو عنوان بريد إلكتروني واحد، ويُطابَق تمامًا: مُدخل النطاق يشمل أيضًا نطاقاته الفرعية والعناوين فيها، لكن لا توجد نطاقات عناوين (`192.0.2.0/24`) ولا أحرف بدل (`*.example.com`) ولا أنماط (`@example.com`). تتطابق عناوين IPv6 بأي صيغة (`2001:0db8::0001` هو `2001:db8::1`، وهي صيغة RFC 5952)، وعنوان IPv4 المُعيَّن داخل IPv6 (`::ffff:192.0.2.1`) يطابق عنوان IPv4، وعنوان IPv4 المُترجَم إلى IPv6 أو الواقع تحت بادئة NAT64 يُكتب معها بالصيغة النقطية (`::ffff:0:192.0.2.1` و`64:ff9b::192.0.2.1`)، في المُدخلات وعناوين العملاء على السواء.


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
| `getFeatures(mail)`                  | `{features, words, language, script, links, hosts, text, hidden}` لرسالة     |
| `getTokens(text, locale)`            | كلمات نص                                                                     |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                   |
| `parse(source)`                      | `{raw, mail}`، مع `mail` من mailparser (انظر أدناه)                          |

تقرأ `scan` و`parse` و`learn` و`unlearn` و`getTokensAndMailFromSource` جميعها الرسالة بالطريقة نفسها: الرسالة التي تتجاوز حدود محلّل MIME (أكثر من 1000 جزء، أو ترويسة جزء تتجاوز 1 MB) تُقرأ بالقدر الذي يسمح به المحلّل. وتُقرأ حقول العناوين (From وTo وCc وBcc وSender وReply-To وDelivered-To وReturn-Path وDisposition-Notification-To وList-\*)، في الرسالة وأجزائها والرسائل المرفقة، حتى 16 KB لكل منها، و2000 فاصلة وفاصلة منقوطة و16 مجموعة متداخلة، و64 KB إجمالًا لكل رسالة، وتُقرأ دائمًا حتى نهاية عنوان كامل، فلا يُقرأ عنوان لا يذكره الحقل؛ ويُعلَّم الحقل المقطوع بـ `truncated` (`mail.to.truncated`)، ولا يمنح حقل From المقطوع أي رصيد لمصادقة المرسل. والنص الذي ليس سطره الأول حقل ترويسة (`Name: value`، أو سطر `From` الذي تبدأ به كل رسالة في ملفات mbox) يُقرأ على أنه نص رسالة بلا ترويسة، فيكون `mail.text` هو ذلك النص. أما الأخطاء الأخرى فتُرمى.

في `getFeatures`، يكون `text` هو النص الذي يعرضه عميل البريد، ومنه تُقرأ الكلمات، و`hidden` عدد محارف النص التي يخفيها HTML. لا يستخرج mailparser هنا نصًا من HTML: يحمل `mail.text` أجزاء النص العادي فقط، ويكون فارغًا في رسالة من HTML وحده؛ أما النص الذي يعرضه HTML الخاص بها فهو `getFeatures(mail).text`.

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

النتائج في `phishing` و`attachments` و`executables` و`macros` و`viruses` و`arbitrary` كائنات لها `type` و`message`. و`String(finding)` هو الرسالة. تُسمّى مرفقات الرسالة المرفقة (`message/rfc822` و`.eml`) باسمها: `fw.eml/invoice.exe`. والفيروس الذي يجده ClamAV في مثل هذا المرفق يُبلَّغ عنه له وحده، لا مرة أخرى للرسالة المرفقة التي تحمله. يسرد `virusScanErrors` المرفقات التي لم يستطع ClamAV فحصها، بالشكل `{filename, error}`: قد تحمل هذه الرسالة فيروسًا، فاحتجزها بدل تسليمها. يؤجّلها الـ milter ومرشِّح المحتوى ما لم يكن `onError` (`--on-error`) هو `accept`، ويَسِم كل خادم مثل هذه الرسالة التي يمرّرها بـ `X-Spam-Virus-Scan: failed`. ويسرد `virusScanSkipped` المرفقات الأكبر مما يقبله clamd (حدّه `StreamMaxLength`)، بالشكل `{filename, reason}`: يرفضها clamd في كل محاولة، لذا فهي ليست حالات فشل، كما يتخطى clamav-milter ملفًا يتجاوز حدّه `MaxFileSize`. أما حدوده الأخرى (`MaxScanSize` و`MaxFiles` و`MaxRecursion` و`MaxScanTime`)، التي تبلغها قنبلة الأرشيف، فهي حالات فشل.

يحمل كل عنصر في `dnsbl` قيمة `answers` للقائمة (عناوين في 127.0.0.0/8، توثّق كل قائمة معناها). والإجابات التي تعطيها القوائم للاستعلامات التي ترفضها أو لا تستطيع الإجابة عنها ليست إدراجات، لا لعنوان العميل ولا لنطاقات الروابط (نتائج `uribl` في `phishing`): 127.255.255.x لدى Spamhaus (مثل 127.255.255.254 لاستعلام عبر محلّل عام، و127.255.255.255 لكثرة الاستعلامات)، و127.0.1.255 لدى Spamhaus DBL، و127.0.0.255 لدى أي قائمة، و127.0.0.1 لدى SURBL وURIBL، اللتين تجيبان بها المحلّلات التي تحظرانها.


## الصادرات

```js
import SpamScanner, {
  Classifier, getFeatures, segmentWords, detectLanguage,
  LLMClassifier, PROVIDERS, RECOMMENDED_MODELS, CLASSIFIER_MODELS, DECISION_MODELS,
  DEFAULT_SCORES, scoreResults, spamHeaders, rewriteMessage,
  loadModel, saveModel, defaultModelPath, loadDefaultModel,
  train, evaluate, readExamples,
  MilterServer, createHttpServer, createTcpServer, createSpamdServer,
  DEFAULTS, VERSION,
} from 'spamscanner';
import {SpamScanner} from 'spamscanner'; // the same class, as a named export

import ArfParser from 'spamscanner/arf';
```

### المصنِّف

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| الخيار                                 | القيمة الافتراضية | المعنى                                                                                                                                                |
| -------------------------------------- | ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `strength`، `unknown`                  | `0.45`، `0.5`     | قيمتا s وx عند Robinson: مدى شدة سحب السمات النادرة نحو 0.5                                                                                           |
| `minDistance`                          | `0.1`             | تُتجاهل السمات الأقرب إلى 0.5 من هذه القيمة                                                                                                           |
| `maxClues`                             | `150`             | أقوى السمات التي تُجمع في كل رسالة                                                                                                                    |
| `hamCutoff`، `spamCutoff`              | `0.2`، `0.99`     | حدود نطاق `unsure`                                                                                                                                    |
| `minLanguageExamples`، `languageShare` | `1000`، `0.02`    | عدد رسائل ham اللازم في لغة ما للوصول إلى الثقة الكاملة، وخُمس هذا العدد من رسائل spam؛ وأقل حين تكون حصة `languageShare` من كل رسائل ham أو spam أقل |
| `languagePrior`                        | `true`            | وزن الكلمات مقابل أعداد لغتها نفسها                                                                                                                   |

تتوفر أيضًا `merge(other)` و`toJSON(options)` و`Classifier.fromJSON(json)` و`size` و`entries()`. يتحقق `Classifier.fromJSON` من النموذج ويرمي `TypeError` يبدأ بـ `Corrupt classifier model` عند البيانات التالفة. لا يعرف JSON القيمة `Infinity`، لذا فالخيار الذي حفظه الإصدار 7.0.3 بالقيمة `Infinity` يُقرأ مجددًا على أنه `null`: فيُقرأ `Infinity` لـ `maxClues` و`minDistance` و`minLanguageExamples`، و`-Infinity` لـ `hamCutoff` (لا ham أبدًا) و`Infinity` لـ `spamCutoff` (لا spam أبدًا)، والقيمة الافتراضية لسائر الخيارات. ويحفظ `toJSON` العتبة التي تتجاوز 0 و1 على أنها -1 أو 2، وهو ما يعمل بالطريقة نفسها. يعيد `loadModel` قراءة الملف عند تغيّره، ويكتب `saveModel` عبر ملف مؤقت جديد، يُدفَع إلى القرص قبل أن يحل محل النموذج، الذي يحتفظ بأذوناته.

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
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]', onError: 'tempfail'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

`onError` في الـ milter هو رده حين يفشل الفحص أو لا يستطيع ClamAV فحص مرفق: `'tempfail'` (الافتراضي) أو `'accept'`، الذي يمرّر الرسالة موسومة بـ `X-Spam-Virus-Scan: failed`، دون ترويسات `X-Spam-*` التي أضافها المرسل.

### تقارير ARF

تقرأ `spamscanner/arf` تقارير الإبلاغ عن الإساءة (RFC 5965) وتكتبها، وهي الصيغة التي يستخدمها مزوّدو صناديق البريد للإبلاغ عن شكاوى البريد المزعج:

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

تقبل `parse()` كائن Buffer أو Uint8Array أو سلسلة نصية. تُرجع `ArfParser.tryParse()` القيمة `null` بدل رمي استثناء للرسائل التي ليست تقارير، وتفحص `isArfMessage(mail)` رسالة محلَّلة. تكون `originalHeaders` بالقيمة `null` للتقرير الذي لا يتضمن الرسالة الأصلية. وتُرجع `create()` سلسلة نصية، أو `Buffer` إذا كانت `originalMessage` من هذا النوع، فتبقى بايتاتها كما هي أيًّا كانت مجموعة محارفها.
