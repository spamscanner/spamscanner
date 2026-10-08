<!-- source: b3cc9f949acd -->

# API başvurusu

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Bir tarayıcı oluşturun ve onu yeniden kullanın: model bir kez yüklenir, DNS ve dil modeli yanıtları önbelleğe alınır.


## Seçenekler

Her seçenek oluşturucuya verilebilir. Çoğu, tek bir ileti için `scan()` yöntemine de verilebilir; bu durumda oluşturucudakilerin üzerine birleştirilir.

| Seçenek                 | Varsayılan                       | Anlamı                                                                                                               |
| ----------------------- | -------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Bir iletinin spam sayıldığı puan                                                                                     |
| `rejectThreshold`       | `15`                             | `action` değerinin `reject` olduğu puan                                                                              |
| `scores`                | `{}`                             | Test başına puanlar: ayar anahtarları veya test adları ([testler ve puanlar](scoring.md))                            |
| `classifier`            | paketle gelen model              | Bir `Classifier`, bir model nesnesi, bir model dosyası yolu veya `false`                                             |
| `classifierOptions`     | `{}`                             | Paketle gelen modelin seçenekleri (bkz. [Sınıflandırıcı](#classifier))                                               |
| `allowedLanguages`      | `[]`                             | ISO 639-1 kodları; diğer diller `LANGUAGE_NOT_ALLOWED` alır                                                          |
| `phishing.cloudflare`   | `true`                           | Bağlantı ana makinelerini Cloudflare'in filtreleme yapan çözümleyicilerine sor                                       |
| `phishing.adult`        | `true`                           | Yetişkin içerikli siteleri engelleyen aile çözümleyicisine de sor                                                    |
| `phishing.maxHosts`     | `25`                             | İleti başına sorgulanan bağlantı ana makinesi sayısı                                                                 |
| `phishing.homograph`    | `{}`                             | `brands` (yerleşik listenin yerine geçer), `extraBrands`, `allowlist` (hiç işaretlenmeyen alan adları), `strictMode` |
| `dnsbl`                 | `{ip: [], domain: []}`           | İstemci IP'si ve bağlantı alan adları için DNS engelleme listesi bölgeleri                                           |
| `dns`                   | `{servers: null, timeout: 3000}` | DNS denetimleri için ad sunucuları (varsayılan: sistemin sunucuları)                                                 |
| `attachments`           | `true`                           | Ekleri incele                                                                                                        |
| `macros`                | `true`                           | Makroları, etkin içerikli PDF'leri ve RTF nesnelerini işaretle                                                       |
| `arbitrary`             | `true`                           | [Kuralları](scoring.md#rules) çalıştır                                                                               |
| `authentication`        | `false`                          | `true` veya `{dnsServers, timeout, mta, weights}`: SPF, DKIM, DMARC, ARC                                             |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout}`                                                                    |
| `allowlist`, `denylist` |                                  | IP adresleri, alan adları veya adresler; `reputation` için kısayol                                                   |
| `clamav`                | `false`                          | `true` (varsayılan soket), `{socket}` veya `{host, port}`                                                            |
| `llm`                   | `null`                           | `mode`, `minScore`, `maxScore` ile birlikte [dil modeli ayarları](llm.md#any-server-port-and-authentication)         |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: `classify([text])` yöntemi `@tensorflow-models/toxicity` gibi yanıt veren bir model      |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: `classify(imageBuffer)` yöntemi `nsfwjs` gibi yanıt veren bir model                      |
| `maxLength`             | `100000`                         | Okunan gövde metni karakter sayısı                                                                                   |
| `timeout`               | `10000`                          | Her ağ denetimi için izin verilen milisaniye                                                                         |
| `session`               | `{}`                             | Varsayılan SMTP oturumu ayrıntıları                                                                                  |

`scan()` ayrıca `session` alır:

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


## Yöntemler

| Yöntem                               | Döndürdüğü                                                                            |
| ------------------------------------ | ------------------------------------------------------------------------------------- |
| `scan(source, options)`              | Sonuç. `source` bir Buffer, dize, Uint8Array veya okunabilir akıştır                  |
| `scanFile(path, options)`            | Bir ileti dosyası için sonuç                                                          |
| `learn(source, 'spam' \| 'ham')`     | Sınıflandırıcıya bir ileti öğretir                                                    |
| `unlearn(source, 'spam' \| 'ham')`   | `learn` işlemini geri alır                                                            |
| `saveModel(path, options)`           | Sınıflandırıcıyı bir dosyaya yazar (`options`: `minCount`, `maxFeatures`, `metadata`) |
| `getClassifier()`                    | Kullanımdaki `Classifier` veya `null`                                                 |
| `getClassification(features)`        | `getFeatures` ile elde edilen özellikler için sınıflandırıcının kararı                |
| `getFeatures(mail)`                  | Ayrıştırılmış bir ileti için `{features, words, language, script, links}`             |
| `getTokens(text, locale)`            | Bir metnin sözcükleri                                                                 |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                            |
| `parse(source)`                      | mailparser'dan gelen `mail` ile birlikte `{raw, mail}`                                |

`scanner.metrics`, `totalScans`, `averageTime` ve `lastScanTime` değerlerini tutar.


## Sonuç

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

`phishing`, `attachments`, `executables`, `macros`, `viruses` ve `arbitrary` içindeki bulgular bir `type` ve bir `message` içeren nesnelerdir. `String(finding)` iletiyi verir.


## Dışa aktarılanlar

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

### Sınıflandırıcı

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| Seçenek                                | Varsayılan     | Anlamı                                                                                |
| -------------------------------------- | -------------- | ------------------------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`  | Robinson'ın s ve x değerleri: nadir özelliklerin 0,5'e doğru ne kadar güçlü çekildiği |
| `minDistance`                          | `0.1`          | 0,5'e bundan daha yakın özellikler yok sayılır                                        |
| `maxClues`                             | `150`          | İleti başına birleştirilen en güçlü özellikler                                        |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | `unsure` aralığının sınırları                                                         |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Tam güven için bir dilde her sınıftan gereken ileti sayısı                            |
| `languagePrior`                        | `true`         | Sözcükleri kendi dillerinin sayılarına göre tart                                      |

`merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` ve `entries()` da kullanılabilir.

### Eğitim

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

`evaluate(classifier, examples)`, `{label, features}` öğelerini ya da `train` ile aynı kaynakları okuyan `readExamples(sources)` çıktısını alır; sayıları, kesinliği, duyarlılığı, F1'i, doğruluğu ve yanlış pozitif, yanlış negatif ve "emin değil" oranlarını döndürür.

### Sunucular

```js
import SpamScanner, {MilterServer, createHttpServer, createSpamdServer} from 'spamscanner';

const scanner = new SpamScanner({authentication: true});
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

### ARF raporları

`spamscanner/arf`, posta kutusu sağlayıcılarının spam şikâyetlerini bildirmek için kullandığı biçim olan kötüye kullanım geri bildirim raporlarını (RFC 5965) okur ve yazar:

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

`ArfParser.tryParse()`, rapor olmayan iletiler için hata fırlatmak yerine `null` döndürür; `isArfMessage(mail)` ise ayrıştırılmış bir iletiyi denetler.
