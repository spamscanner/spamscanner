<!-- source: 581d018dd514 -->

# API başvurusu

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Bir tarayıcı oluşturun ve onu yeniden kullanın: model bir kez yüklenir, DNS ve dil modeli yanıtları önbelleğe alınır.

Tür bildirimleri pakete dahildir. `import` ile TypeScript 4.7 veya üstü, `require` ile 5.3 veya üstü gerekir.


## Seçenekler

Her seçenek oluşturucuya verilebilir. Çoğu, tek bir ileti için `scan()` yöntemine de verilebilir; bu durumda oluşturucudakilerin üzerine birleştirilir. `undefined` olarak verilen seçenekler varsayılan değerlerini korur. `classifier`, `classifierOptions`, `dns`, `phishing.homograph` ve `strictIDNDetection` yalnızca oluşturucu tarafından okunur; `classifier` olarak verilen model dosyası veya nesnesi orada yüklenir, bu yüzden eksik ya da bozuk bir model hemen hata verir.

| Seçenek                 | Varsayılan                       | Anlamı                                                                                                                                                                                                       |
| ----------------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `threshold`             | `5`                              | Bir iletinin spam sayıldığı puan                                                                                                                                                                             |
| `rejectThreshold`       | `15`                             | `action` değerinin `reject` olduğu puan                                                                                                                                                                      |
| `scores`                | `{}`                             | Test başına puanlar: ayar anahtarları veya test adları ([testler ve puanlar](scoring.md))                                                                                                                    |
| `classifier`            | paketle gelen model              | Bir `Classifier`, bir model nesnesi, bir model dosyası yolu veya `false`                                                                                                                                     |
| `classifierOptions`     | `{}`                             | Paketle gelen modelin seçenekleri (bkz. [Sınıflandırıcı](#classifier))                                                                                                                                       |
| `allowedLanguages`      | `[]`                             | ISO 639-1 kodları (`no`, `nb` olarak; `fil`, `tl` olarak; eski `iw`, `in`, `ji` ise `he`, `id`, `yi` olarak okunur); diğer diller `LANGUAGE_NOT_ALLOWED` alır                                                |
| `phishing.cloudflare`   | `true`                           | Bağlantı ana makinelerini Cloudflare'in filtreleme yapan çözümleyicilerine sor                                                                                                                               |
| `phishing.adult`        | `true`                           | Yetişkin içerikli siteleri engelleyen aile çözümleyicisine de sor                                                                                                                                            |
| `phishing.maxHosts`     | `25`                             | İleti başına sorgulanan bağlantı ana makinesi sayısı                                                                                                                                                         |
| `phishing.maxLength`    | `1000000`                        | Bağlantılar için okunan metin karakterleri (HTML'de iki katı); daha uzun metin `results.linksTruncated` değerini ayarlar; `Infinity` ya da pozitif sayı olmayan herhangi bir değer varsayılan anlamına gelir |
| `phishing.homograph`    | `{}`                             | `brands` (yerleşik listenin yerine geçer), `extraBrands`, `allowlist` (hiç işaretlenmeyen alan adları), `strictMode`                                                                                         |
| `dnsbl`                 | `{ip: [], domain: []}`           | İstemci IP'si ve bağlantı alan adları için DNS engelleme listesi bölgeleri                                                                                                                                   |
| `dns`                   | `{servers: null, timeout: 3000}` | DNS denetimleri için ad sunucuları (varsayılan: sistemin sunucuları)                                                                                                                                         |
| `attachments`           | `true`                           | Ekleri incele                                                                                                                                                                                                |
| `macros`                | `true`                           | Makroları, etkin içerikli PDF'leri ve RTF nesnelerini işaretle                                                                                                                                               |
| `arbitrary`             | `true`                           | [Kuralları](scoring.md#rules) çalıştır                                                                                                                                                                       |
| `authentication`        | `false`                          | `true` veya `{dnsServers, timeout, maxDnsQueries, mta, weights, trustedArcSealers}`: SPF, DKIM, DMARC, ARC ([puanlama](scoring.md#authentication))                                                           |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout, concurrency, cacheTtl, cacheSize}`; yanıtlar hizmete ve başlıklara göre ayrı tutulur ve `cacheSize` tüm tarayıcı için geçerlidir                            |
| `allowlist`, `denylist` |                                  | IP adresleri, alan adları veya adresler; `reputation` için kısayol → [İzin listesi ve engelleme listesi](#allowlist-and-denylist)                                                                            |
| `clamav`                | `false`                          | `true` (varsayılan soket), `{socket}` veya `{host, port}`, `timeout` ile birlikte: bir iletinin tüm ekleri için toplam milisaniye (`60000`)                                                                  |
| `llm`                   | `null`                           | `mode`, `minScore`, `maxScore` ile birlikte [dil modeli ayarları](llm.md#any-server-port-and-authentication)                                                                                                 |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: `classify([text])` yöntemi `@tensorflow-models/toxicity` gibi yanıt veren bir model                                                                                              |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: `classify(imageBuffer)` yöntemi `nsfwjs` gibi yanıt veren bir model                                                                                                              |
| `maxLength`             | `100000`                         | Okunan gövde metni karakter sayısı                                                                                                                                                                           |
| `timeout`               | `10000`                          | Her ağ denetimi için izin verilen milisaniye; kimlik doğrulama ve görüntü modeli toplamda bu kadar süre alır (ClamAV'ın kendi `clamav.timeout` seçeneği vardır)                                              |
| `session`               | `{}`                             | Varsayılan SMTP oturumu ayrıntıları                                                                                                                                                                          |

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

SPF, DKIM, DMARC ve ARC denetimlerini ([mailauth](https://github.com/postalsys/mailauth) ile) zaten yapmış bir sunucu, sonuçlarını `authenticationResults` olarak iletebilir; bu sonuçlar yeniden denetlenmek yerine puanlanır:

```js
import {authenticate} from 'mailauth';

const auth = await authenticate(raw, {ip, helo, sender, mta});
await scanner.scan(raw, {authenticationResults: auth});
```

### İzin listesi ve engelleme listesi

Engelleme listesi, istemcinin IP adresini ve ana makine adını, From, zarf göndericisi ve Reply-To adreslerini ve bunların alan adlarını, ne olurlarsa olsunlar, karşılaştırır: engelleme listesindeki bir alan adının altındaki bir ad, geçerli bir ana makine adı olmasa bile (`a_b!.evil.example` gibi ya da 63 karakterden uzun bir etiketi olan bir ad) son 127 etiketi ve 253 karakteriyle o alan adıyla eşleşir. İzin listesi, ayrıca bir itibar hizmetinin izin listesi ve güvenilir kaynakları, yalnızca göndericinin sahteleyemeyeceği şeyleri karşılaştırır: istemcinin IP adresi ve doğrulanmış ana makine adı (`remoteAddress`, `resolvedClientHostname`), alan adı için DMARC geçtiğinde ya da geçerli bir DKIM imzası onunla hizalı olduğunda (ve geçerli bir ana makine adı olduğunda; DMARC'taki gibi gevşek biçimde: From alan adının ve imzalayan ya da SPF alan adının kayıt edilebilir alan adı aynıdır, mailauth bunu DMARC alan adı olarak adlandırır; `news.example.com` gibi bir alt alan adını belirten bir girdi yalnızca o alan adı, onun altındaki bir alan adı ya da onun bir üst alan adı iletiyi imzaladığında veya SPF'den geçtiğinde sayılır, `evil.example.com` gibi başka bir alt alan adı ya da bir genel sonek için sayılmaz; kayıt edilebilir alan adı için mailauth'un hizalama ayrıntıları olmadan gelen bir DMARC geçişi yalnızca kayıt edilebilir alan adını belirten bir girdi için sayılır; katı hizalamada, yani alan adının DMARC kaydında `adkim=s` veya `aspf=s` varsa, büyük/küçük harf ya da boşluk ne olursa olsun, yalnızca From alan adının kendisinin imzası ya da SPF geçişi sayılır ve böyle biri olmadan DMARC başarısız olur) From adresi ve alan adı için SPF geçtiğinde zarf göndericisi. İleti gövdesinin yalnızca başını imzalayan bir DKIM imzası (gövdeden kısa bir gövde uzunluğu, `l=`: ardına herkes metin ekleyebilir) hiçbir şey için sayılmaz, buna dayanan bir DMARC geçişi de sayılmaz ve DMARC başarısız olduğunda ya da bütünüyle okunamayacak kadar uzun bir From alanı için (`mail.from.truncated`) hiçbir imza sayılmaz. `authenticationResults` içinde verilen sonuçlar yalnızca geçtikleri alan adını belirttiklerinde sayılır; ana makine adı olmayan bir alan adı (URL ayrıştırıcıların `bank.example` olarak okuduğu `bank.example/x.attacker.example` gibi) hiçbir şey için sayılmaz, böyle bir alan adına dayanan bir DMARC geçişi de sayılmaz. Uluslararası alan adları iki biçimde de eşleşir: `bücher.example` veya `xn--bcher-kva.example`. Reply-To hiçbir zaman sayılmaz. Bir alan adına izin vermek için `authentication` seçeneğini açın veya `authenticationResults` verin.

Her girdi tek bir IP adresi, alan adı veya e-posta adresidir ve birebir eşleştirilir: bir alan adı girdisi alt alan adlarını ve bunlardaki adresleri de kapsar, ancak adres aralıkları (`192.0.2.0/24`), joker karakterler (`*.example.com`) veya kalıplar (`@example.com`) yoktur. IPv6 adresleri her biçimde eşleşir (`2001:0db8::0001`, RFC 5952 biçimi olan `2001:db8::1` ile aynıdır), IPv6 içine eşlenmiş bir IPv4 adresi (`::ffff:192.0.2.1`) o IPv4 adresiyle eşleşir ve IPv6'ya çevrilmiş ya da NAT64 önekinin altındaki bir IPv4 adresi, hem girdilerde hem istemci adreslerinde, bu önekle birlikte noktalı biçimde yazılır (`::ffff:0:192.0.2.1`, `64:ff9b::192.0.2.1`).


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
| `getFeatures(mail)`                  | Bir ileti için `{features, words, language, script, links, hosts, text, hidden}`      |
| `getTokens(text, locale)`            | Bir metnin sözcükleri                                                                 |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                            |
| `parse(source)`                      | mailparser'dan gelen `mail` ile birlikte `{raw, mail}` (aşağıya bakın)                |

`scan`, `parse`, `learn`, `unlearn` ve `getTokensAndMailFromSource` bir iletiyi hep aynı biçimde okur: MIME ayrıştırıcının sınırlarını (1000'den fazla parça, 1 MB'ı aşan bir parça başlığı) aşan bir ileti, ayrıştırıcının izin verdiği kadar okunur. İletinin, parçalarının ve ekli iletilerin adres alanları (From, To, Cc, Bcc, Sender, Reply-To, Delivered-To, Return-Path, Disposition-Notification-To ve List-\*), her biri en fazla 16 KB, 2000 virgül ve noktalı virgül ve 16 iç içe grup, her ileti için toplamda en fazla 64 KB olmak üzere ve her zaman tam bir adresin sonuna kadar okunur; böylece alanın vermediği hiçbir adres okunmaz. Kesilen bir alan `truncated` olarak işaretlenir (`mail.to.truncated`) ve kesilen bir From alanı, göndericinin kimlik doğrulaması için hiçbir indirim sağlamaz. İlk satırı bir başlık alanı olmayan metin (`Name: value` ya da mbox dosyalarında her iletiyi başlatan `From` satırı), başlığı olmayan bir iletinin gövdesi olarak okunur, yani `mail.text` o metindir. Diğer hatalar fırlatılır.

`getFeatures` içinde `text`, bir e-posta istemcisinin gösterdiği ve sözcüklerin okunduğu metindir; `hidden` ise HTML'nin gizlediği metnin kaç karakter olduğudur. mailparser burada HTML'den metin üretmez: `mail.text` yalnızca düz metin parçalarını içerir ve yalnızca HTML'den oluşan bir iletide boştur; HTML'nin gösterdiği metin `getFeatures(mail).text` içindedir.

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

`phishing`, `attachments`, `executables`, `macros`, `viruses` ve `arbitrary` içindeki bulgular bir `type` ve bir `message` içeren nesnelerdir. `String(finding)` iletiyi verir. Ekli bir iletinin (`message/rfc822`, `.eml`) ekleri onun adını alır: `fw.eml/invoice.exe`. ClamAV'ın böyle bir ekte bulduğu bir virüs yalnızca o ek için bildirilir, onu taşıyan ekli ileti için yeniden bildirilmez. `virusScanErrors`, ClamAV'ın tarayamadığı ekleri `{filename, error}` biçiminde listeler: böyle bir ileti virüs içerebilir, bu yüzden teslim etmek yerine bekletin. Milter ve içerik filtresi, `onError` (`--on-error`) `accept` olmadıkça böyle bir iletiyi erteler ve her sunucu, aktardığı böyle bir iletiyi `X-Spam-Virus-Scan: failed` ile işaretler. `virusScanSkipped`, clamd'nin kabul ettiğinden (`StreamMaxLength` değerinden) büyük ekleri `{filename, reason}` biçiminde listeler: clamd bunları her denemede reddeder, bu yüzden, clamav-milter'ın `MaxFileSize` değerini aşan bir dosyayı atlaması gibi, hata sayılmazlar. clamd'nin bir arşiv bombasının ulaştığı diğer sınırları (`MaxScanSize`, `MaxFiles`, `MaxRecursion`, `MaxScanTime`) ise hata sayılır.

Her `dnsbl` öğesi listenin `answers` değerini taşır (anlamını her listenin belgelediği, 127.0.0.0/8 içindeki adresler). Listelerin reddettikleri ya da yanıtlayamadıkları sorgulara verdikleri yanıtlar, ister istemcinin adresi ister bağlantı alan adları için olsun (`phishing` içindeki `uribl` bulguları), listeleme değildir: Spamhaus'ta 127.255.255.x (örneğin herkese açık bir çözümleyici üzerinden gelen sorgu için 127.255.255.254 ve çok fazla sorgu için 127.255.255.255), Spamhaus DBL'de 127.0.1.255, herhangi bir listede 127.0.0.255 ve engelledikleri çözümleyicilere bu yanıtı veren SURBL ile URIBL'de 127.0.0.1.


## Dışa aktarılanlar

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

### Sınıflandırıcı

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| Seçenek                                | Varsayılan     | Anlamı                                                                                                                                                |
| -------------------------------------- | -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`  | Robinson'ın s ve x değerleri: nadir özelliklerin 0,5'e doğru ne kadar güçlü çekildiği                                                                 |
| `minDistance`                          | `0.1`          | 0,5'e bundan daha yakın özellikler yok sayılır                                                                                                        |
| `maxClues`                             | `150`          | İleti başına birleştirilen en güçlü özellikler                                                                                                        |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | `unsure` aralığının sınırları                                                                                                                         |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Tam güven için bir dilde gereken ham ileti sayısı ve bunun beşte biri kadar spam ileti; tüm ham ya da spam içindeki `languageShare` daha azsa daha az |
| `languagePrior`                        | `true`         | Sözcükleri kendi dillerinin sayılarına göre tart                                                                                                      |

`merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` ve `entries()` da kullanılabilir. `Classifier.fromJSON` modeli denetler ve bozuk verilerde `Corrupt classifier model` ile başlayan bir `TypeError` fırlatır. JSON'da `Infinity` yoktur, bu yüzden 7.0.3 sürümünün `Infinity` olarak kaydettiği bir seçenek geri `null` olarak okunur: bu değer `maxClues`, `minDistance` ve `minLanguageExamples` için `Infinity`, `hamCutoff` için `-Infinity` (hiçbir zaman ham değil) ve `spamCutoff` için `Infinity` (hiçbir zaman spam değil), diğerleri için ise varsayılan değer olarak okunur. `toJSON`, 0 ile 1 dışındaki bir eşiği -1 veya 2 olarak kaydeder; bu da aynı şekilde çalışır. `loadModel` bir dosya değiştiğinde onu yeniden okur, `saveModel` ise yeni bir geçici dosya üzerinden yazar; bu dosya modelin yerini almadan önce diske aktarılır ve model izinlerini korur.

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
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]', onError: 'tempfail'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

Milter'ın `onError` seçeneği, bir tarama başarısız olduğunda ya da ClamAV bir eki tarayamadığında vereceği yanıttır: `'tempfail'` (varsayılan) veya `'accept'`; ikincisi iletiyi `X-Spam-Virus-Scan: failed` ile işaretleyerek, göndericinin eklediği `X-Spam-*` başlıkları olmadan aktarır.

### ARF raporları

`spamscanner/arf`, posta kutusu sağlayıcılarının spam şikâyetlerini bildirmek için kullandığı biçim olan kötüye kullanım geri bildirim raporlarını (RFC 5965) okur ve yazar:

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

`parse()` bir Buffer, Uint8Array veya dize alır. `ArfParser.tryParse()`, rapor olmayan iletiler için hata fırlatmak yerine `null` döndürür; `isArfMessage(mail)` ise ayrıştırılmış bir iletiyi denetler. Özgün iletiyi içermeyen bir raporda `originalHeaders` `null` olur. `create()` bir dize döndürür; `originalMessage` bir `Buffer` ise dönüş değeri de aynı türde olur, böylece baytları karakter kümesi ne olursa olsun korunur.
