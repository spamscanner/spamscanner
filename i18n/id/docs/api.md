<!-- source: b3cc9f949acd -->

# Referensi API

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Buat satu scanner dan gunakan kembali: scanner memuat model sekali dan menyimpan cache jawaban DNS dan model bahasa.


## Opsi

Setiap opsi dapat diberikan ke konstruktor. Sebagian besar juga dapat diberikan ke `scan()` untuk satu pesan, dan akan digabungkan di atas opsi konstruktor.

| Opsi                    | Bawaan                           | Arti                                                                                                             |
| ----------------------- | -------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Skor saat sebuah pesan dianggap spam                                                                             |
| `rejectThreshold`       | `15`                             | Skor saat `action` bernilai `reject`                                                                             |
| `scores`                | `{}`                             | Poin per tes: kunci pengaturan atau nama tes ([tes dan skor](scoring.md))                                        |
| `classifier`            | model bawaan                     | Sebuah `Classifier`, objek model, path file model, atau `false`                                                  |
| `classifierOptions`     | `{}`                             | Opsi untuk model bawaan (lihat [Classifier](#classifier))                                                        |
| `allowedLanguages`      | `[]`                             | Kode ISO 639-1; bahasa lain mendapat `LANGUAGE_NOT_ALLOWED`                                                      |
| `phishing.cloudflare`   | `true`                           | Tanyakan host tautan ke resolver penyaring Cloudflare                                                            |
| `phishing.adult`        | `true`                           | Tanyakan juga ke resolver keluarga, yang memblokir situs dewasa                                                  |
| `phishing.maxHosts`     | `25`                             | Jumlah host tautan yang dicari per pesan                                                                         |
| `phishing.homograph`    | `{}`                             | `brands` (mengganti daftar bawaan), `extraBrands`, `allowlist` (domain yang tidak pernah ditandai), `strictMode` |
| `dnsbl`                 | `{ip: [], domain: []}`           | Zona daftar blokir DNS untuk IP klien dan untuk domain tautan                                                    |
| `dns`                   | `{servers: null, timeout: 3000}` | Name server untuk pemeriksaan DNS (bawaan: milik sistem)                                                         |
| `attachments`           | `true`                           | Periksa lampiran                                                                                                 |
| `macros`                | `true`                           | Tandai makro, PDF aktif, dan objek RTF                                                                           |
| `arbitrary`             | `true`                           | Jalankan [aturan](scoring.md#rules)                                                                              |
| `authentication`        | `false`                          | `true`, atau `{dnsServers, timeout, mta, weights}`: SPF, DKIM, DMARC, ARC                                        |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout}`                                                                |
| `allowlist`, `denylist` |                                  | Alamat IP, domain, atau alamat email; singkatan untuk `reputation`                                               |
| `clamav`                | `false`                          | `true` (soket bawaan), `{socket}`, atau `{host, port}`                                                           |
| `llm`                   | `null`                           | [Pengaturan model bahasa](llm.md#any-server-port-and-authentication), dengan `mode`, `minScore`, `maxScore`      |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: model yang `classify([text])`-nya menjawab seperti `@tensorflow-models/toxicity`     |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: model yang `classify(imageBuffer)`-nya menjawab seperti `nsfwjs`                     |
| `maxLength`             | `100000`                         | Jumlah karakter teks isi pesan yang dibaca                                                                       |
| `timeout`               | `10000`                          | Milidetik yang diizinkan untuk setiap pemeriksaan jaringan                                                       |
| `session`               | `{}`                             | Detail sesi SMTP bawaan                                                                                          |

`scan()` juga menerima `session`:

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


## Metode

| Metode                               | Mengembalikan                                                                      |
| ------------------------------------ | ---------------------------------------------------------------------------------- |
| `scan(source, options)`              | Hasilnya. `source` berupa Buffer, string, Uint8Array, atau readable stream         |
| `scanFile(path, options)`            | Hasil untuk sebuah file pesan                                                      |
| `learn(source, 'spam' \| 'ham')`     | Mengajari pengklasifikasi satu pesan                                               |
| `unlearn(source, 'spam' \| 'ham')`   | Membatalkan `learn`                                                                |
| `saveModel(path, options)`           | Menulis pengklasifikasi ke file (`options`: `minCount`, `maxFeatures`, `metadata`) |
| `getClassifier()`                    | `Classifier` yang sedang dipakai, atau `null`                                      |
| `getClassification(features)`        | Vonis pengklasifikasi untuk fitur dari `getFeatures`                               |
| `getFeatures(mail)`                  | `{features, words, language, script, links}` untuk pesan yang sudah diurai         |
| `getTokens(text, locale)`            | Kata-kata dari sebuah teks                                                         |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                         |
| `parse(source)`                      | `{raw, mail}`, dengan `mail` dari mailparser                                       |

`scanner.metrics` berisi `totalScans`, `averageTime`, dan `lastScanTime`.


## Hasil

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

Temuan di `phishing`, `attachments`, `executables`, `macros`, `viruses`, dan `arbitrary` berupa objek dengan `type` dan `message`. `String(finding)` adalah pesannya.


## Ekspor

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

| Opsi                                   | Bawaan         | Arti                                                                                    |
| -------------------------------------- | -------------- | --------------------------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`  | s dan x dari Robinson: seberapa kuat fitur yang jarang ditarik ke arah 0,5              |
| `minDistance`                          | `0.1`          | Fitur yang lebih dekat ke 0,5 daripada nilai ini diabaikan                              |
| `maxClues`                             | `150`          | Jumlah fitur terkuat yang digabungkan per pesan                                         |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | Batas rentang `unsure`                                                                  |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Jumlah pesan dari setiap kelas yang diperlukan dalam suatu bahasa untuk keyakinan penuh |
| `languagePrior`                        | `true`         | Timbang kata terhadap jumlah dalam bahasanya sendiri                                    |

`merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size`, dan `entries()` juga tersedia.

### Pelatihan

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

`evaluate(classifier, examples)` menerima item `{label, features}`, atau `readExamples(sources)`, yang membaca sumber yang sama dengan `train`, dan mengembalikan jumlah, presisi, recall, F1, akurasi, serta tingkat positif palsu, negatif palsu, dan ragu.

### Server

```js
import SpamScanner, {MilterServer, createHttpServer, createSpamdServer} from 'spamscanner';

const scanner = new SpamScanner({authentication: true});
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

### Laporan ARF

`spamscanner/arf` membaca dan menulis laporan umpan balik penyalahgunaan (RFC 5965), format yang dipakai penyedia kotak surat untuk melaporkan keluhan spam:

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

`ArfParser.tryParse()` mengembalikan `null` alih-alih melempar galat untuk pesan yang bukan laporan, dan `isArfMessage(mail)` memeriksa pesan yang sudah diurai.
