<!-- source: b19ea85ceb6d -->

# API-Referenz

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Erstellen Sie einen Scanner und verwenden Sie ihn wieder: Er lädt das Modell einmal und speichert Antworten von DNS und Sprachmodell zwischen.

Typdeklarationen sind enthalten. Sie benötigen TypeScript 4.7 oder neuer mit `import` und 5.3 oder neuer mit `require`.


## Optionen

Jede Option kann an den Konstruktor übergeben werden. Die meisten lassen sich auch für eine einzelne Nachricht an `scan()` übergeben und überschreiben dann die des Konstruktors. Optionen, die als `undefined` übergeben werden, behalten ihren Standardwert. `classifier`, `classifierOptions`, `dns`, `phishing.homograph` und `strictIDNDetection` liest nur der Konstruktor; eine als `classifier` angegebene Modelldatei oder ein Modellobjekt wird dort gelesen, sodass ein fehlendes oder beschädigtes Modell sofort einen Fehler wirft.

| Option                  | Standard                         | Bedeutung                                                                                                                                                                                     |
| ----------------------- | -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Score, ab dem eine Nachricht Spam ist                                                                                                                                                         |
| `rejectThreshold`       | `15`                             | Score, ab dem `action` den Wert `reject` hat                                                                                                                                                  |
| `scores`                | `{}`                             | Punkte pro Test: Einstellungsschlüssel oder Testnamen ([Tests und Scores](scoring.md))                                                                                                        |
| `classifier`            | mitgeliefertes Modell            | Ein `Classifier`, ein Modellobjekt, ein Pfad zu einer Modelldatei oder `false`                                                                                                                |
| `classifierOptions`     | `{}`                             | Optionen für das mitgelieferte Modell (siehe [Classifier](#classifier))                                                                                                                       |
| `allowedLanguages`      | `[]`                             | ISO-639-1-Codes (`no` wird als `nb` gelesen, `fil` als `tl` und die alten `iw`, `in`, `ji` als `he`, `id`, `yi`); andere Sprachen erhalten `LANGUAGE_NOT_ALLOWED`                             |
| `phishing.cloudflare`   | `true`                           | Die filternden Resolver von Cloudflare zu Link-Hosts befragen                                                                                                                                 |
| `phishing.adult`        | `true`                           | Zusätzlich den Familien-Resolver befragen, der Seiten für Erwachsene blockiert                                                                                                                |
| `phishing.maxHosts`     | `25`                             | Pro Nachricht abgefragte Link-Hosts                                                                                                                                                           |
| `phishing.maxLength`    | `1000000`                        | Für Links gelesene Zeichen des Textes (bei HTML doppelt so viele); längerer Text setzt `results.linksTruncated`; `Infinity` oder alles außer einer positiven Zahl bedeutet den Standardwert   |
| `phishing.homograph`    | `{}`                             | `brands` (ersetzt die eingebaute Liste), `extraBrands`, `allowlist` (nie markierte Domains), `strictMode`                                                                                     |
| `dnsbl`                 | `{ip: [], domain: []}`           | Zonen von DNS-Blocklisten für die Client-IP und für Link-Domains                                                                                                                              |
| `dns`                   | `{servers: null, timeout: 3000}` | Nameserver für DNS-Prüfungen (Standard: die des Systems)                                                                                                                                      |
| `attachments`           | `true`                           | Anhänge untersuchen                                                                                                                                                                           |
| `macros`                | `true`                           | Makros, aktive PDFs und RTF-Objekte markieren                                                                                                                                                 |
| `arbitrary`             | `true`                           | Die [Regeln](scoring.md#rules) ausführen                                                                                                                                                      |
| `authentication`        | `false`                          | `true` oder `{dnsServers, timeout, mta, weights, trustedArcSealers}`: SPF, DKIM, DMARC, ARC ([Bewertung](scoring.md#authentication))                                                          |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout, concurrency, cacheTtl, cacheSize}`; Antworten werden pro Dienst und Headern zwischengespeichert, und `cacheSize` gilt für den ganzen Scanner |
| `allowlist`, `denylist` |                                  | IP-Adressen, Domains oder Adressen; Kurzform für `reputation` → [Positivliste und Sperrliste](#allowlist-and-denylist)                                                                        |
| `clamav`                | `false`                          | `true` (Standard-Socket), `{socket}` oder `{host, port}`, mit `timeout`: Millisekunden für alle Anhänge einer Nachricht (`60000`)                                                             |
| `llm`                   | `null`                           | [Einstellungen für das Sprachmodell](llm.md#any-server-port-and-authentication), mit `mode`, `minScore`, `maxScore`                                                                           |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: ein Modell, dessen `classify([text])` wie `@tensorflow-models/toxicity` antwortet                                                                                 |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: ein Modell, dessen `classify(imageBuffer)` wie `nsfwjs` antwortet                                                                                                 |
| `maxLength`             | `100000`                         | Gelesene Zeichen des Nachrichtentexts                                                                                                                                                         |
| `timeout`               | `10000`                          | Erlaubte Millisekunden pro Netzwerkprüfung; die Authentifizierung und das Bildmodell haben insgesamt so lange Zeit (ClamAV hat sein eigenes `clamav.timeout`)                                 |
| `session`               | `{}`                             | Standardangaben zur SMTP-Sitzung                                                                                                                                                              |

`scan()` nimmt außerdem `session` entgegen:

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

Ein Server, der SPF, DKIM, DMARC und ARC bereits geprüft hat (mit [mailauth](https://github.com/postalsys/mailauth)), kann seine Ergebnisse als `authenticationResults` übergeben, und sie werden bewertet statt erneut geprüft:

```js
import {authenticate} from 'mailauth';

const auth = await authenticate(raw, {ip, helo, sender, mta});
await scanner.scan(raw, {authenticationResults: auth});
```

### Positivliste und Sperrliste

Die Sperrliste vergleicht die IP-Adresse und den Hostnamen des Clients, die Adressen in From, im Umschlagabsender und in Reply-To sowie deren Domains, wie auch immer sie lauten: Ein Name unter einer gesperrten Domain stimmt mit ihr überein, auch wenn er kein gültiger Hostname ist (etwa `a_b!.evil.example` oder einer mit einem Label von mehr als 63 Zeichen), anhand seiner letzten 127 Labels und 253 Zeichen. Die Positivliste sowie die Positivliste und die vertrauenswürdigen Quellen eines Reputationsdienstes vergleichen nur, was ein Absender nicht fälschen kann: die IP-Adresse und den geprüften Hostnamen des Clients (`remoteAddress`, `resolvedClientHostname`), eine From-Adresse, wenn DMARC für ihre Domain besteht oder eine gültige DKIM-Signatur auf sie ausgerichtet ist (und ihre Domain ein gültiger Hostname ist; locker, wie bei DMARC: Die From-Domain und die signierende oder SPF-Domain haben dieselbe registrierbare Domain, die mailauth als DMARC-Domain nennt; ein Eintrag, der eine Subdomain nennt, etwa `news.example.com`, zählt nur, wenn diese Domain, eine darunter oder eine darüber die Nachricht signiert oder SPF bestanden hat, nicht eine andere Subdomain wie `evil.example.com` und auch kein öffentliches Suffix; ein DMARC-Pass für die registrierbare Domain ohne die Ausrichtungsangaben von mailauth zählt nur für einen Eintrag, der die registrierbare Domain nennt; bei strikter Ausrichtung, `adkim=s` oder `aspf=s` im DMARC-Eintrag der Domain in beliebiger Groß- und Kleinschreibung und mit beliebigen Leerzeichen, zählt nur eine Signatur oder ein SPF-Pass der From-Domain selbst, und ohne eine solche schlägt DMARC fehl), und den Umschlagabsender, wenn SPF für seine Domain besteht. Eine DKIM-Signatur nur des Anfangs des Bodys (eine Body-Länge, `l=`, kürzer als der Body: Jeder kann danach Text anfügen) zählt nichts, ebenso wenig ein DMARC-Pass, der auf einer solchen beruht, und keine Signatur zählt, wenn DMARC fehlschlägt. In `authenticationResults` übergebene Ergebnisse zählen nur, wenn sie die Domain nennen, für die sie bestanden wurden, und eine Domain, die kein Hostname ist (etwa `bank.example/x.attacker.example`, das URL-Parser als `bank.example` lesen), zählt für keine, ebenso wenig ein DMARC-Pass, der auf einer solchen beruht. Internationale Domains stimmen in beiden Formen überein: `bücher.example` oder `xn--bcher-kva.example`. Reply-To zählt nie. Um eine Domain freizugeben, schalten Sie `authentication` ein oder übergeben `authenticationResults`.

Jeder Eintrag ist eine IP-Adresse, eine Domain oder eine E-Mail-Adresse und wird exakt verglichen: Ein Domain-Eintrag deckt auch ihre Subdomains und die Adressen darauf ab, aber es gibt keine Adressbereiche (`192.0.2.0/24`), Platzhalter (`*.example.com`) oder Muster (`@example.com`). IPv6-Adressen stimmen in jeder Form überein (`2001:0db8::0001` ist `2001:db8::1`, die Form nach RFC 5952), eine in IPv6 abgebildete IPv4-Adresse (`::ffff:192.0.2.1`) stimmt mit der IPv4-Adresse überein, und eine in IPv6 übersetzte oder unter dem NAT64-Präfix stehende IPv4-Adresse wird mit diesem in Punktschreibweise geschrieben (`::ffff:0:192.0.2.1`, `64:ff9b::192.0.2.1`), in Einträgen ebenso wie in Client-Adressen.


## Methoden

| Methode                              | Rückgabe                                                                                    |
| ------------------------------------ | ------------------------------------------------------------------------------------------- |
| `scan(source, options)`              | Das Ergebnis. `source` ist ein Buffer, String, Uint8Array oder lesbarer Stream              |
| `scanFile(path, options)`            | Das Ergebnis für eine Nachrichtendatei                                                      |
| `learn(source, 'spam' \| 'ham')`     | Bringt dem Klassifikator eine Nachricht bei                                                 |
| `unlearn(source, 'spam' \| 'ham')`   | Macht `learn` rückgängig                                                                    |
| `saveModel(path, options)`           | Schreibt den Klassifikator in eine Datei (`options`: `minCount`, `maxFeatures`, `metadata`) |
| `getClassifier()`                    | Der verwendete `Classifier` oder `null`                                                     |
| `getClassification(features)`        | Das Urteil des Klassifikators für Merkmale aus `getFeatures`                                |
| `getFeatures(mail)`                  | `{features, words, language, script, links, hosts, text, hidden}` einer Nachricht           |
| `getTokens(text, locale)`            | Die Wörter eines Texts                                                                      |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                                  |
| `parse(source)`                      | `{raw, mail}`, mit `mail` aus mailparser (siehe unten)                                      |

`scan`, `parse`, `learn`, `unlearn` und `getTokensAndMailFromSource` lesen eine Nachricht alle auf dieselbe Weise: Eine Nachricht jenseits der Grenzen des MIME-Parsers (mehr als 1000 Teile, der Header eines Teils über 1 MB) wird gelesen, soweit der Parser es zulässt. Text, dessen erste Zeile kein Header-Feld ist (`Name: value` oder die `From`-Zeile, mit der in mbox-Dateien jede Nachricht beginnt), wird als Body einer Nachricht ohne Header gelesen, sodass `mail.text` dieser Text ist. Andere Fehler werden geworfen.

In `getFeatures` ist `text` der Text, den ein Mailprogramm anzeigt und aus dem die Wörter gelesen werden, und `hidden` die Anzahl der Textzeichen, die das HTML versteckt. mailparser macht hier aus HTML keinen Text: `mail.text` enthält nur die Klartextteile und ist bei einer Nachricht nur aus HTML leer; der Text, den ihr HTML anzeigt, ist `getFeatures(mail).text`.

`scanner.metrics` enthält `totalScans`, `averageTime` und `lastScanTime`.


## Das Ergebnis

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

Befunde in `phishing`, `attachments`, `executables`, `macros`, `viruses` und `arbitrary` sind Objekte mit einem `type` und einer `message`. `String(finding)` ergibt die Meldung. Anhänge einer angehängten Nachricht (`message/rfc822`, `.eml`) werden nach ihr benannt: `fw.eml/invoice.exe`. Einen Virus, den ClamAV in einem solchen Anhang findet, meldet es nur für diesen, nicht noch einmal für die angehängte Nachricht, die ihn enthält. `virusScanErrors` listet die Anhänge, die ClamAV nicht prüfen konnte, als `{filename, error}`: Eine solche Nachricht kann einen Virus enthalten, halten Sie sie daher zurück, statt sie zuzustellen. Der Milter und der Content-Filter stellen sie zurück, sofern `onError` (`--on-error`) nicht `accept` ist, und jeder Server kennzeichnet eine solche Nachricht, die er weitergibt, mit `X-Spam-Virus-Scan: failed`. `virusScanSkipped` listet die Anhänge, die größer sind, als clamd annimmt (sein `StreamMaxLength`), als `{filename, reason}`: clamd lehnt sie bei jedem Versuch ab, daher sind sie keine Fehler, so wie clamav-milter eine Datei über seinem `MaxFileSize` überspringt. Seine anderen Grenzen (`MaxScanSize`, `MaxFiles`, `MaxRecursion`, `MaxScanTime`), die eine Archivbombe erreicht, sind Fehler.

Jedes `dnsbl`-Element enthält die `answers` der Liste (Adressen in 127.0.0.0/8, deren Bedeutung jede Liste dokumentiert). Die Antworten, die Listen auf Anfragen geben, die sie ablehnen oder nicht beantworten können, sind keine Listungen, weder für die Adresse des Clients noch für Link-Domains (`uribl`-Befunde in `phishing`): 127.255.255.x bei Spamhaus (etwa 127.255.255.254 für eine Anfrage über einen öffentlichen Resolver und 127.255.255.255 für zu viele Anfragen), 127.0.1.255 bei der Spamhaus DBL, 127.0.0.255 bei jeder Liste und 127.0.0.1 bei SURBL und URIBL, die dies Resolvern antworten, die sie sperren.


## Exporte

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

| Option                                 | Standard       | Bedeutung                                                                                                                                                                            |
| -------------------------------------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `strength`, `unknown`                  | `0.45`, `0.5`  | Robinsons s und x: wie stark seltene Merkmale in Richtung 0,5 gezogen werden                                                                                                         |
| `minDistance`                          | `0.1`          | Merkmale, die näher als dieser Wert an 0,5 liegen, werden ignoriert                                                                                                                  |
| `maxClues`                             | `150`          | Pro Nachricht kombinierte stärkste Merkmale                                                                                                                                          |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | Grenzen des Bereichs `unsure`                                                                                                                                                        |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Ham-Nachrichten, die eine Sprache für volle Konfidenz braucht, und ein Fünftel so viele Spam-Nachrichten; weniger, wenn `languageShare` aller Ham- oder Spam-Nachrichten weniger ist |
| `languagePrior`                        | `true`         | Wörter an den Zählungen ihrer eigenen Sprache gewichten                                                                                                                              |

Außerdem stehen `merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` und `entries()` zur Verfügung. `Classifier.fromJSON` prüft das Modell und wirft bei beschädigten Daten einen `TypeError`, der mit `Corrupt classifier model` beginnt. JSON kennt kein `Infinity`, daher wird eine Option, die Version 7.0.3 als `Infinity` gespeichert hat, als `null` zurückgelesen: Sie wird als `Infinity` gelesen für `maxClues`, `minDistance` und `minLanguageExamples`, als `-Infinity` für `hamCutoff` (nie Ham) und als `Infinity` für `spamCutoff` (nie Spam) und für die übrigen als Standardwert. `toJSON` speichert einen Grenzwert jenseits von 0 und 1 als -1 oder 2, was genauso wirkt. `loadModel` liest eine Datei erneut, wenn sie sich ändert, und `saveModel` schreibt über eine temporäre Datei.

### Training

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

`evaluate(classifier, examples)` nimmt `{label, features}`-Einträge entgegen oder `readExamples(sources)`, das dieselben Quellen liest wie `train`, und gibt Zählungen, Präzision, Trefferquote, F1, Genauigkeit sowie die Raten für Fehlalarme, übersehenen Spam und unsichere Fälle zurück.

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

`onError` ist die Antwort des Milters, wenn ein Scan fehlschlägt oder ClamAV einen Anhang nicht prüfen konnte: `'tempfail'` (Standard) oder `'accept'`, das die Nachricht mit `X-Spam-Virus-Scan: failed` gekennzeichnet weitergibt, ohne die `X-Spam-*`-Header, die der Absender hinzugefügt hat.

### ARF-Berichte

`spamscanner/arf` liest und schreibt Abuse-Feedback-Berichte (RFC 5965), das Format, mit dem Postfachanbieter Spam-Beschwerden melden:

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

`ArfParser.tryParse()` gibt bei Nachrichten, die keine Berichte sind, `null` zurück, statt einen Fehler zu werfen, und `isArfMessage(mail)` prüft eine geparste Nachricht. `originalHeaders` ist `null` bei einem Bericht ohne die Originalnachricht. `create()` gibt einen String zurück, oder einen `Buffer`, wenn `originalMessage` einer ist, damit deren Bytes unabhängig vom Zeichensatz erhalten bleiben.
