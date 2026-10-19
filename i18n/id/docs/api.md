<!-- source: b19ea85ceb6d -->

# Referensi API

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Buat satu scanner dan gunakan kembali: scanner memuat model sekali dan menyimpan cache jawaban DNS dan model bahasa.

Deklarasi tipe sudah disertakan. Deklarasi ini membutuhkan TypeScript 4.7 atau lebih baru dengan `import`, dan 5.3 atau lebih baru dengan `require`.


## Opsi

Setiap opsi dapat diberikan ke konstruktor. Sebagian besar juga dapat diberikan ke `scan()` untuk satu pesan, dan akan digabungkan di atas opsi konstruktor. Opsi yang diberikan sebagai `undefined` tetap memakai nilai bawaannya. `classifier`, `classifierOptions`, `dns`, `phishing.homograph` dan `strictIDNDetection` hanya dibaca oleh konstruktor; berkas atau objek model yang diberikan sebagai `classifier` dibaca di sana, sehingga model yang hilang atau rusak langsung memunculkan galat.

| Opsi                    | Bawaan                           | Arti                                                                                                                                                                                                          |
| ----------------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Skor saat sebuah pesan dianggap spam                                                                                                                                                                          |
| `rejectThreshold`       | `15`                             | Skor saat `action` bernilai `reject`                                                                                                                                                                          |
| `scores`                | `{}`                             | Poin per tes: kunci pengaturan atau nama tes ([tes dan skor](scoring.md))                                                                                                                                     |
| `classifier`            | model bawaan                     | Sebuah `Classifier`, objek model, path file model, atau `false`                                                                                                                                               |
| `classifierOptions`     | `{}`                             | Opsi untuk model bawaan (lihat [Classifier](#classifier))                                                                                                                                                     |
| `allowedLanguages`      | `[]`                             | Kode ISO 639-1 (`no` dibaca sebagai `nb`, `fil` sebagai `tl`, dan kode lama `iw`, `in`, `ji` sebagai `he`, `id`, `yi`); bahasa lain mendapat `LANGUAGE_NOT_ALLOWED`                                           |
| `phishing.cloudflare`   | `true`                           | Tanyakan host tautan ke resolver penyaring Cloudflare                                                                                                                                                         |
| `phishing.adult`        | `true`                           | Tanyakan juga ke resolver keluarga, yang memblokir situs dewasa                                                                                                                                               |
| `phishing.maxHosts`     | `25`                             | Jumlah host tautan yang dicari per pesan                                                                                                                                                                      |
| `phishing.maxLength`    | `1000000`                        | Karakter teks yang dibaca untuk mencari tautan (dua kali lipat untuk HTML); teks yang lebih panjang mengatur `results.linksTruncated`; `Infinity`, atau apa pun selain bilangan positif, berarti nilai bawaan |
| `phishing.homograph`    | `{}`                             | `brands` (mengganti daftar bawaan), `extraBrands`, `allowlist` (domain yang tidak pernah ditandai), `strictMode`                                                                                              |
| `dnsbl`                 | `{ip: [], domain: []}`           | Zona daftar blokir DNS untuk IP klien dan untuk domain tautan                                                                                                                                                 |
| `dns`                   | `{servers: null, timeout: 3000}` | Name server untuk pemeriksaan DNS (bawaan: milik sistem)                                                                                                                                                      |
| `attachments`           | `true`                           | Periksa lampiran                                                                                                                                                                                              |
| `macros`                | `true`                           | Tandai makro, PDF aktif, dan objek RTF                                                                                                                                                                        |
| `arbitrary`             | `true`                           | Jalankan [aturan](scoring.md#rules)                                                                                                                                                                           |
| `authentication`        | `false`                          | `true`, atau `{dnsServers, timeout, mta, weights, trustedArcSealers}`: SPF, DKIM, DMARC, ARC ([penilaian](scoring.md#authentication))                                                                         |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout, concurrency, cacheTtl, cacheSize}`; jawaban disimpan per layanan dan header, dan `cacheSize` berlaku untuk seluruh pemindai                                  |
| `allowlist`, `denylist` |                                  | Alamat IP, domain, atau alamat email; singkatan untuk `reputation` → [Daftar izin dan daftar tolak](#allowlist-and-denylist)                                                                                  |
| `clamav`                | `false`                          | `true` (soket bawaan), `{socket}`, atau `{host, port}`, dengan `timeout`: milidetik untuk semua lampiran sebuah pesan (`60000`)                                                                               |
| `llm`                   | `null`                           | [Pengaturan model bahasa](llm.md#any-server-port-and-authentication), dengan `mode`, `minScore`, `maxScore`                                                                                                   |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: model yang `classify([text])`-nya menjawab seperti `@tensorflow-models/toxicity`                                                                                                  |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: model yang `classify(imageBuffer)`-nya menjawab seperti `nsfwjs`                                                                                                                  |
| `maxLength`             | `100000`                         | Jumlah karakter teks isi pesan yang dibaca                                                                                                                                                                    |
| `timeout`               | `10000`                          | Milidetik yang diizinkan untuk setiap pemeriksaan jaringan; autentikasi dan model gambar mendapat waktu sebanyak ini secara keseluruhan (ClamAV punya `clamav.timeout` sendiri)                               |
| `session`               | `{}`                             | Detail sesi SMTP bawaan                                                                                                                                                                                       |

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

Server yang sudah memeriksa SPF, DKIM, DMARC, dan ARC (dengan [mailauth](https://github.com/postalsys/mailauth)) dapat meneruskan hasilnya sebagai `authenticationResults`, dan hasil itu diberi skor alih-alih diperiksa ulang:

```js
import {authenticate} from 'mailauth';

const auth = await authenticate(raw, {ip, helo, sender, mta});
await scanner.scan(raw, {authenticationResults: auth});
```

### Daftar izin dan daftar tolak

Daftar tolak mencocokkan alamat IP dan nama host klien, alamat From, pengirim amplop, dan Reply-To, serta domainnya, apa pun bentuknya: nama di bawah domain dalam daftar tolak cocok dengannya meskipun bukan nama host yang valid (seperti `a_b!.evil.example`, atau nama dengan label lebih dari 63 karakter), berdasarkan 127 label dan 253 karakter terakhirnya. Daftar izin, juga daftar izin dan sumber tepercaya dari layanan reputasi, hanya mencocokkan hal yang tidak dapat dipalsukan pengirim: alamat IP dan nama host terverifikasi klien (`remoteAddress`, `resolvedClientHostname`), alamat From ketika DMARC lolos untuk domainnya atau tanda tangan DKIM yang lolos selaras dengannya (dan merupakan nama host yang valid; secara longgar, seperti di DMARC: domain From dan domain penanda tangan atau domain SPF memiliki domain terdaftar yang sama, yang disebut mailauth sebagai domain DMARC; entri yang menyebut subdomain, seperti `news.example.com`, hanya dihitung jika domain itu, domain di bawahnya, atau domain di atasnya menandatangani pesan atau lolos SPF, bukan subdomain lain seperti `evil.example.com`, dan bukan sufiks publik; kelulusan DMARC untuk domain terdaftar tanpa detail keselarasan dari mailauth hanya dihitung untuk entri yang menyebut domain terdaftar itu; dengan keselarasan ketat, `adkim=s` atau `aspf=s` dalam catatan DMARC domain itu dengan huruf besar-kecil atau spasi apa pun, hanya tanda tangan atau kelulusan SPF dari domain From itu sendiri yang dihitung, dan DMARC gagal tanpanya), dan pengirim amplop ketika SPF lolos untuk domainnya. Tanda tangan DKIM yang hanya mencakup awal isi pesan (panjang isi, `l=`, lebih pendek daripada isi: siapa pun dapat menambahkan teks setelahnya) tidak dihitung sama sekali, begitu pula kelulusan DMARC yang bergantung padanya, dan tidak ada tanda tangan yang dihitung ketika DMARC gagal. Hasil yang diberikan dalam `authenticationResults` hanya dihitung jika menyebutkan domain tempat hasil itu lolos, dan domain yang bukan nama host (seperti `bank.example/x.attacker.example`, yang dibaca parser URL sebagai `bank.example`) tidak dihitung untuk domain mana pun, begitu pula kelulusan DMARC yang bergantung pada domain seperti itu. Domain internasional cocok dalam kedua bentuknya: `bücher.example` atau `xn--bcher-kva.example`. Reply-To tidak pernah dihitung. Untuk mengizinkan sebuah domain, aktifkan `authentication` atau berikan `authenticationResults`.

Setiap entri adalah satu alamat IP, domain, atau alamat email, yang dicocokkan secara persis: entri domain juga mencakup subdomainnya dan alamat di subdomain itu, tetapi tidak ada rentang alamat (`192.0.2.0/24`), wildcard (`*.example.com`), atau pola (`@example.com`). Alamat IPv6 cocok dalam bentuk apa pun (`2001:0db8::0001` sama dengan `2001:db8::1`, bentuk dari RFC 5952), alamat IPv4 yang dipetakan ke IPv6 (`::ffff:192.0.2.1`) cocok dengan alamat IPv4 itu, dan alamat IPv4 yang diterjemahkan ke IPv6 atau berada di bawah prefiks NAT64 ditulis dengan alamat IPv4 itu dalam bentuk bertitik (`::ffff:0:192.0.2.1`, `64:ff9b::192.0.2.1`), baik dalam entri maupun dalam alamat klien.


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
| `getFeatures(mail)`                  | `{features, words, language, script, links, hosts, text, hidden}` dari pesan       |
| `getTokens(text, locale)`            | Kata-kata dari sebuah teks                                                         |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                         |
| `parse(source)`                      | `{raw, mail}`, dengan `mail` dari mailparser (lihat di bawah)                      |

`scan`, `parse`, `learn`, `unlearn`, dan `getTokensAndMailFromSource` semuanya membaca pesan dengan cara yang sama: pesan yang melampaui batas parser MIME (lebih dari 1000 bagian, header bagian lebih dari 1 MB) dibaca sejauh yang diizinkan parser. Teks yang baris pertamanya bukan bidang header (`Name: value`, atau baris `From` yang mengawali setiap pesan dalam file mbox) dibaca sebagai isi pesan tanpa header, sehingga `mail.text` adalah teks itu. Kesalahan lain dilempar.

Pada `getFeatures`, `text` adalah teks yang ditampilkan klien email, tempat kata-kata dibaca, dan `hidden` adalah jumlah karakter teks yang disembunyikan HTML. Di sini mailparser tidak membuat teks dari HTML: `mail.text` hanya berisi bagian teks biasa, dan kosong untuk pesan yang hanya berisi HTML; teks yang ditampilkan HTML-nya adalah `getFeatures(mail).text`.

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

Temuan di `phishing`, `attachments`, `executables`, `macros`, `viruses`, dan `arbitrary` berupa objek dengan `type` dan `message`. `String(finding)` adalah pesannya. Lampiran dari pesan yang dilampirkan (`message/rfc822`, `.eml`) diberi nama menurut pesan itu: `fw.eml/invoice.exe`. Virus yang ditemukan ClamAV dalam lampiran seperti itu dilaporkan hanya untuk lampiran itu, tidak lagi untuk pesan terlampir yang membawanya. `virusScanErrors` mencantumkan lampiran yang tidak dapat dipindai ClamAV, sebagai `{filename, error}`: pesan seperti itu mungkin berisi virus, jadi tahan pesan itu alih-alih mengirimkannya. Milter dan content filter menundanya kecuali `onError` (`--on-error`) bernilai `accept`, dan setiap server menandai pesan seperti itu yang diteruskannya dengan `X-Spam-Virus-Scan: failed`. `virusScanSkipped` mencantumkan lampiran yang lebih besar daripada yang diterima clamd (`StreamMaxLength`-nya), sebagai `{filename, reason}`: clamd menolaknya pada setiap percobaan, jadi, sebagaimana clamav-milter melewati berkas yang melebihi `MaxFileSize`-nya, lampiran itu bukan kegagalan. Batas lainnya (`MaxScanSize`, `MaxFiles`, `MaxRecursion`, `MaxScanTime`), yang dicapai oleh bom arsip, adalah kegagalan.

Setiap item `dnsbl` membawa `answers` dari daftar itu (alamat dalam 127.0.0.0/8, yang maknanya didokumentasikan oleh setiap daftar). Jawaban yang diberikan daftar untuk kueri yang mereka tolak atau tidak dapat dijawab bukanlah listing, baik untuk alamat klien maupun untuk domain tautan (temuan `uribl` di `phishing`): 127.255.255.x di Spamhaus (seperti 127.255.255.254 untuk kueri melalui resolver publik, dan 127.255.255.255 untuk terlalu banyak kueri), 127.0.1.255 di Spamhaus DBL, 127.0.0.255 di daftar mana pun, dan 127.0.0.1 di SURBL dan URIBL, yang memberikannya kepada resolver yang mereka blokir.


## Ekspor

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

### Classifier

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| Opsi                                   | Bawaan         | Arti                                                                                                                                                                                            |
| -------------------------------------- | -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`  | s dan x dari Robinson: seberapa kuat fitur yang jarang ditarik ke arah 0,5                                                                                                                      |
| `minDistance`                          | `0.1`          | Fitur yang lebih dekat ke 0,5 daripada nilai ini diabaikan                                                                                                                                      |
| `maxClues`                             | `150`          | Jumlah fitur terkuat yang digabungkan per pesan                                                                                                                                                 |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | Batas rentang `unsure`                                                                                                                                                                          |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Jumlah pesan ham yang diperlukan dalam suatu bahasa untuk keyakinan penuh, dan seperlima jumlah itu untuk pesan spam; lebih sedikit bila `languageShare` dari seluruh ham atau spam lebih kecil |
| `languagePrior`                        | `true`         | Timbang kata terhadap jumlah dalam bahasanya sendiri                                                                                                                                            |

`merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size`, dan `entries()` juga tersedia. `Classifier.fromJSON` memeriksa model dan memunculkan `TypeError` yang diawali `Corrupt classifier model` untuk data yang rusak. JSON tidak memiliki `Infinity`, jadi opsi yang disimpan sebagai `Infinity` oleh versi 7.0.3 terbaca kembali sebagai `null`: opsi itu dibaca sebagai `Infinity` untuk `maxClues`, `minDistance`, dan `minLanguageExamples`, sebagai `-Infinity` untuk `hamCutoff` (tidak pernah ham) dan `Infinity` untuk `spamCutoff` (tidak pernah spam), dan sebagai nilai bawaan untuk yang lainnya. `toJSON` menyimpan ambang di luar 0 dan 1 sebagai -1 atau 2, yang hasilnya sama. `loadModel` membaca ulang berkas saat berkas berubah, dan `saveModel` menulis melalui berkas sementara.

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
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]', onError: 'tempfail'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

`onError` pada milter adalah jawabannya ketika pemindaian gagal atau ClamAV tidak dapat memindai sebuah lampiran: `'tempfail'` (bawaan) atau `'accept'`, yang meneruskan pesan dengan tanda `X-Spam-Virus-Scan: failed`, tanpa header `X-Spam-*` yang ditambahkan pengirim.

### Laporan ARF

`spamscanner/arf` membaca dan menulis laporan umpan balik penyalahgunaan (RFC 5965), format yang dipakai penyedia kotak surat untuk melaporkan keluhan spam:

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

`ArfParser.tryParse()` mengembalikan `null` alih-alih melempar galat untuk pesan yang bukan laporan, dan `isArfMessage(mail)` memeriksa pesan yang sudah diurai. `originalHeaders` bernilai `null` untuk laporan tanpa pesan asli. `create()` mengembalikan string, atau `Buffer` jika `originalMessage` juga demikian, sehingga byte-nya tetap terjaga apa pun set karakternya.
