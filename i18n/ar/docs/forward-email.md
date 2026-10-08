<!-- source: dc9016edd59e -->

# Forward Email

بنت [Forward Email](https://forwardemail.net)، خدمة البريد الإلكتروني مفتوحة المصدر التي تركّز على الخصوصية، Spam Scanner لخوادم بريدها. لا تحتفظ Forward Email بأي سجلات لمحتوى الرسائل، فلم تكن أي خدمة ترشيح خارجية مناسبة: كان على المرشِّح أن يعمل على خوادمها، وأن يشرح كل قرار دون أن يقرأ أي شخص البريد.

تعرض هذه الصفحة كيف يستخدمه خادم بريد مثل خادم Forward Email، وما الذي تغيّر للشيفرة المكتوبة لـ Spam Scanner 5 أو 6.


## على خادم بريد وارد

تستقبل Forward Email البريد باستخدام [smtp-server](https://nodemailer.com/extras/smtp-server/). النمط، لأي خادم مبني عليه:

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

تقبل `scanner.scan()` تدفق SMTP مباشرة. إذا كانت نتائج [mailauth](https://github.com/postalsys/mailauth) متاحة لديك مسبقًا، فتخطَّ `authentication` ومرّر عنوان IP فقط.

الرد بـ 421 أو 451 يجعل الخادم المرسل يضع الرسالة في الطابور ويعيد المحاولة لاحقًا. يمكن أن تبدأ قواعد الرفض الجديدة برمز مؤقت ثم تنتقل إلى 550 بعد التحقق من نتائجها، دون فقدان أي بريد في الأثناء.


## الترقية من الإصدار 5 أو 6

الإصدار 7 إعادة كتابة كاملة. المُنشئ و`scan()` وحقول النتيجة التي تقرؤها شيفرة الإصدارين 5 و6 ما زالت تعمل؛ أما المصنِّف والنموذج وفحوص TensorFlow الاختيارية فقد تغيّرت.

### ما بقي كما هو

* `new SpamScanner(options)` و`await scanner.scan(source)`.
* تُرجع `require('spamscanner')` الصنف، و`import SpamScanner from 'spamscanner'` تعمل.
* `result.isSpam`، و`result.message`، و`result.results.classification` و`.phishing` و`.executables` و`.arbitrary` و`.viruses` و`.macros` و`.idnHomographAttack`.
* يتحوّل كل عنصر في `results.phishing` و`.executables` و`.arbitrary` و`.viruses` إلى النوع نفسه من سلاسل الرسائل كما في السابق (`String(item)`، والقوالب النصية، و`message.includes('adult-related content')`). وهي الآن كائنات لها `type` و`message` وتفاصيل.
* `getTokensAndMailFromSource()` و`getClassification()` و`getTokens()`.
* تُربط هذه الخيارات بأسمائها الجديدة: `clamscan` إلى `clamav`، و`enableMacroDetection: false` إلى `macros: false`، و`enableArbitraryDetection: false` إلى `arbitrary: false`، و`enableAuthentication` مع `authOptions` إلى `authentication` و`session`، و`enableReputation` مع `reputationOptions.apiUrl` إلى `reputation`، و`strictIDNDetection` إلى `phishing.homograph.strictMode`، و`allowlist` و`denylist`. يُقبل `logger` و`memoize` ويُتجاهلان.

### ما تغيّر

| سابقًا                                                                          | الآن                                                                                                                             |
| ------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| كانت `scan('path/to/file.eml')` تقرأ الملف                                      | السلسلة النصية نص رسالة. استخدم `scanFile(path)` أو مرّر Buffer                                                                  |
| نموذج Bayes بسيط للكلمات (`classifier.json`)، لا يمكن تحميله الآن               | مصنِّف جديد وصيغة نموذج جديدة؛ أعد التدريب باستخدام `spamscanner train` ([التدريب](training.md))                                 |
| كانت فحوص المحتوى المسيء وNSFW تحمّل نماذج TensorFlow من الشبكة عند أول استخدام | أحضر نموذجك: يأخذ `toxicity: {model}` و`nsfw: {model}` أي كائن له دالة `classify()`، مثل `@tensorflow-models/toxicity` و`nsfwjs` |
| كانت `results.arbitrary` تسرد كل نمط تطابق                                      | تسرد القواعد القوية بما يكفي لوسم البريد بأنه مزعج وحدها؛ كل القواعد موجودة في `result.tests`                                    |
| إجابة بنعم أو لا                                                                | `result.score` و`result.action` (`accept` أو `tag` أو `reject`) و`result.tests`، ولكل منها نقاط وسبب                             |
| كان `isSpam` يُحدَّد بالمصنِّف أو بأي فحص منفرد                                 | `isSpam` درجة 5 أو أكثر؛ ويمكن تغيير العتبات والنقاط                                                                             |
| فحوص السمعة مقابل نقطة نهاية لدى Forward Email                                  | خدمة سمعة عامة، معطّلة ما لم يُضبط `reputation.apiUrl`                                                                           |

### الجديد

* [نماذج لغوية](llm.md) للحالات المتقاربة، محلية أو مستضافة.
* SPF وDKIM وDMARC وARC؛ وقوائم حظر DNS؛ ومحلِّلات Cloudflare الترشيحية.
* فحوص المرفقات بحسب المحتوى: الملفات التنفيذية المتنكّرة، والأرشيفات، ووحدات الماكرو، وملفات PDF النشطة.
* [milter وHTTP API وخادم TCP وخادم spamd](mail-servers.md)، و[سطر أوامر](cli.md).
* التدريب، والتقييم، والتعلّم من التقارير، من سطر الأوامر أو من API.
