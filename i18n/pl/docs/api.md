<!-- source: 581d018dd514 -->

# Dokumentacja API

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Utwórz jeden skaner i używaj go wielokrotnie: wczytuje model raz i zapamiętuje odpowiedzi DNS oraz modelu językowego.

Deklaracje typów są dołączone. Wymagają TypeScript 4.7 lub nowszego z `import` oraz 5.3 lub nowszego z `require`.


## Opcje

Każdą opcję można przekazać do konstruktora. Większość można też przekazać do `scan()` dla jednej wiadomości; nakładają się wtedy na opcje konstruktora. Opcje przekazane jako `undefined` zachowują wartości domyślne. `classifier`, `classifierOptions`, `dns`, `phishing.homograph` i `strictIDNDetection` odczytuje tylko konstruktor; plik lub obiekt modelu podany jako `classifier` jest wczytywany właśnie tam, więc brakujący lub uszkodzony model od razu zgłasza błąd.

| Opcja                   | Domyślnie                        | Znaczenie                                                                                                                                                                                         |
| ----------------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Wynik, od którego wiadomość jest spamem                                                                                                                                                           |
| `rejectThreshold`       | `15`                             | Wynik, od którego `action` ma wartość `reject`                                                                                                                                                    |
| `scores`                | `{}`                             | Punkty za test: klucze ustawień lub nazwy testów ([testy i punkty](scoring.md))                                                                                                                   |
| `classifier`            | dołączony model                  | `Classifier`, obiekt modelu, ścieżka do pliku modelu lub `false`                                                                                                                                  |
| `classifierOptions`     | `{}`                             | Opcje dołączonego modelu (zobacz [Classifier](#classifier))                                                                                                                                       |
| `allowedLanguages`      | `[]`                             | Kody ISO 639-1 (`no` jest czytane jako `nb`, `fil` jako `tl`, a dawne `iw`, `in`, `ji` jako `he`, `id`, `yi`); inne języki dostają `LANGUAGE_NOT_ALLOWED`                                         |
| `phishing.cloudflare`   | `true`                           | Pytaj filtrujące resolvery Cloudflare o hosty z linków                                                                                                                                            |
| `phishing.adult`        | `true`                           | Pytaj też resolver rodzinny, który blokuje witryny dla dorosłych                                                                                                                                  |
| `phishing.maxHosts`     | `25`                             | Liczba hostów z linków sprawdzanych na wiadomość                                                                                                                                                  |
| `phishing.maxLength`    | `1000000`                        | Znaki tekstu czytane w poszukiwaniu linków (dwa razy więcej w HTML); dłuższy tekst ustawia `results.linksTruncated`; `Infinity` lub cokolwiek innego niż liczba dodatnia oznacza wartość domyślną |
| `phishing.homograph`    | `{}`                             | `brands` (zastępuje wbudowaną listę), `extraBrands`, `allowlist` (domeny nigdy nieoznaczane), `strictMode`                                                                                        |
| `dnsbl`                 | `{ip: [], domain: []}`           | Strefy czarnych list DNS dla IP klienta i domen z linków                                                                                                                                          |
| `dns`                   | `{servers: null, timeout: 3000}` | Serwery nazw dla kontroli DNS (domyślnie systemowe)                                                                                                                                               |
| `attachments`           | `true`                           | Sprawdzaj załączniki                                                                                                                                                                              |
| `macros`                | `true`                           | Oznaczaj makra, aktywne pliki PDF i obiekty RTF                                                                                                                                                   |
| `arbitrary`             | `true`                           | Uruchamiaj [reguły](scoring.md#rules)                                                                                                                                                             |
| `authentication`        | `false`                          | `true` lub `{dnsServers, timeout, maxDnsQueries, mta, weights, trustedArcSealers}`: SPF, DKIM, DMARC, ARC ([punktacja](scoring.md#authentication))                                                |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout, concurrency, cacheTtl, cacheSize}`; odpowiedzi są przechowywane osobno dla każdej usługi i nagłówków, a `cacheSize` dotyczy całego skanera       |
| `allowlist`, `denylist` |                                  | Adresy IP, domeny lub adresy e-mail; skrót dla `reputation` → [Lista dozwolonych i lista blokowanych](#allowlist-and-denylist)                                                                    |
| `clamav`                | `false`                          | `true` (domyślne gniazdo), `{socket}` lub `{host, port}`, z `timeout`: milisekundy na wszystkie załączniki wiadomości łącznie (`60000`)                                                           |
| `llm`                   | `null`                           | [Ustawienia modelu językowego](llm.md#any-server-port-and-authentication), z `mode`, `minScore`, `maxScore`                                                                                       |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: model, którego `classify([text])` odpowiada jak `@tensorflow-models/toxicity`                                                                                         |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: model, którego `classify(imageBuffer)` odpowiada jak `nsfwjs`                                                                                                         |
| `maxLength`             | `100000`                         | Liczba czytanych znaków treści                                                                                                                                                                    |
| `timeout`               | `10000`                          | Milisekundy dozwolone na każdą kontrolę sieciową; uwierzytelnianie i model obrazów mają łącznie tyle czasu (ClamAV ma własny `clamav.timeout`)                                                    |
| `session`               | `{}`                             | Domyślne dane sesji SMTP                                                                                                                                                                          |

`scan()` przyjmuje też `session`:

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

Serwer, który już sprawdził SPF, DKIM, DMARC i ARC (za pomocą [mailauth](https://github.com/postalsys/mailauth)), może przekazać wyniki jako `authenticationResults`, a wtedy są one oceniane zamiast ponownie sprawdzane:

```js
import {authenticate} from 'mailauth';

const auth = await authenticate(raw, {ip, helo, sender, mta});
await scanner.scan(raw, {authenticationResults: auth});
```

### Lista dozwolonych i lista blokowanych

Lista blokowanych porównuje adres IP i nazwę hosta klienta, adresy From, nadawcy koperty i Reply-To oraz ich domeny, jakiekolwiek by były: nazwa pod domeną z listy blokowanych pasuje do niej, nawet jeśli nie jest poprawną nazwą hosta (taka jak `a_b!.evil.example` albo nazwa z etykietą dłuższą niż 63 znaki), według swoich ostatnich 127 etykiet i 253 znaków. Lista dozwolonych, a także lista dozwolonych i zaufane źródła usługi reputacji, porównują tylko to, czego nadawca nie może sfałszować: adres IP i zweryfikowaną nazwę hosta klienta (`remoteAddress`, `resolvedClientHostname`), adres From, gdy DMARC przechodzi dla jego domeny lub poprawny podpis DKIM jest z nim wyrównany (i jest to poprawna nazwa hosta; w trybie relaxed, jak w DMARC: domena From i domena podpisująca lub domena SPF mają tę samą domenę rejestrowalną, którą mailauth podaje jako domenę DMARC; wpis wskazujący subdomenę, taką jak `news.example.com`, liczy się tylko wtedy, gdy ta domena, domena pod nią lub domena nadrzędna podpisała wiadomość lub przeszła SPF, a nie inna subdomena, taka jak `evil.example.com`, ani sufiks publiczny; przejście DMARC dla domeny rejestrowalnej bez szczegółów wyrównania od mailauth liczy się tylko dla wpisu wskazującego domenę rejestrowalną; przy ścisłym wyrównaniu, `adkim=s` lub `aspf=s` w rekordzie DMARC domeny, bez względu na wielkość liter i odstępy, liczy się tylko podpis lub przejście SPF samej domeny From, a bez niego DMARC nie przechodzi), oraz nadawcę koperty, gdy SPF przechodzi dla jego domeny. Podpis DKIM obejmujący tylko początek treści (długość treści, `l=`, krótsza niż treść: każdy może dopisać za nią tekst) nie liczy się dla niczego, podobnie jak oparte na nim przejście DMARC, a gdy DMARC nie przechodzi albo pole From jest zbyt długie, by przeczytać je w całości (`mail.from.truncated`), nie liczy się żaden podpis. Wyniki przekazane w `authenticationResults` liczą się tylko wtedy, gdy podają domenę, dla której przeszły, a domena, która nie jest nazwą hosta (taka jak `bank.example/x.attacker.example`, którą parsery URL odczytują jako `bank.example`), nie liczy się dla żadnej, podobnie jak oparte na niej przejście DMARC. Domeny międzynarodowe pasują w obu postaciach: `bücher.example` lub `xn--bcher-kva.example`. Reply-To nigdy się nie liczy. Aby dopuścić domenę, włącz `authentication` lub przekaż `authenticationResults`.

Każdy wpis to jeden adres IP, domena lub adres e-mail, porównywany dokładnie: wpis domeny obejmuje też jej subdomeny i adresy w nich, ale nie ma zakresów adresów (`192.0.2.0/24`), symboli wieloznacznych (`*.example.com`) ani wzorców (`@example.com`). Adresy IPv6 pasują w dowolnej postaci (`2001:0db8::0001` to `2001:db8::1`, postać z RFC 5952), adres IPv4 zmapowany na IPv6 (`::ffff:192.0.2.1`) pasuje do adresu IPv4, a adres IPv4 przetłumaczony na IPv6 lub pod prefiksem NAT64 jest zapisywany z tym adresem IPv4 w notacji kropkowej (`::ffff:0:192.0.2.1`, `64:ff9b::192.0.2.1`), zarówno we wpisach, jak i w adresach klientów.


## Metody

| Metoda                               | Zwraca                                                                            |
| ------------------------------------ | --------------------------------------------------------------------------------- |
| `scan(source, options)`              | Wynik. `source` to Buffer, string, Uint8Array lub strumień do odczytu             |
| `scanFile(path, options)`            | Wynik dla pliku z wiadomością                                                     |
| `learn(source, 'spam' \| 'ham')`     | Uczy klasyfikator jednej wiadomości                                               |
| `unlearn(source, 'spam' \| 'ham')`   | Cofa `learn`                                                                      |
| `saveModel(path, options)`           | Zapisuje klasyfikator do pliku (`options`: `minCount`, `maxFeatures`, `metadata`) |
| `getClassifier()`                    | Używany `Classifier` lub `null`                                                   |
| `getClassification(features)`        | Werdykt klasyfikatora dla cech z `getFeatures`                                    |
| `getFeatures(mail)`                  | `{features, words, language, script, links, hosts, text, hidden}` wiadomości      |
| `getTokens(text, locale)`            | Słowa tekstu                                                                      |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                        |
| `parse(source)`                      | `{raw, mail}`, gdzie `mail` pochodzi z mailparser (zob. niżej)                    |

`scan`, `parse`, `learn`, `unlearn` i `getTokensAndMailFromSource` czytają wiadomość w ten sam sposób: wiadomość przekraczająca limity parsera MIME (ponad 1000 części, nagłówek części ponad 1 MB) jest czytana na tyle, na ile pozwala parser. Pola adresowe (From, To, Cc, Bcc, Sender, Reply-To, Delivered-To, Return-Path, Disposition-Notification-To i List-\*) wiadomości, jej części i załączonych wiadomości są czytane do 16 KB każde, 2000 przecinków i średników oraz 16 zagnieżdżonych grup, i łącznie do 64 KB dla każdej wiadomości, zawsze do końca całego adresu, więc nie jest czytany żaden adres, którego pole nie podaje; obcięte pole jest oznaczane jako `truncated` (`mail.to.truncated`), a obcięte pole From nie daje żadnego kredytu za uwierzytelnienie nadawcy. Tekst, którego pierwszy wiersz nie jest polem nagłówka (`Name: value` albo wiersz `From`, od którego zaczyna się każda wiadomość w plikach mbox), jest czytany jako treść wiadomości bez nagłówka, więc `mail.text` to ten tekst. Inne błędy są zgłaszane jako wyjątki.

W `getFeatures` `text` to tekst, który pokazuje program pocztowy i z którego odczytywane są słowa, a `hidden` to liczba znaków tekstu ukrytych przez HTML. mailparser nie tworzy tu tekstu z HTML: `mail.text` zawiera tylko części ze zwykłym tekstem i jest pusty dla wiadomości składającej się wyłącznie z HTML; tekst, który pokazuje jej HTML, to `getFeatures(mail).text`.

`scanner.metrics` zawiera `totalScans`, `averageTime` i `lastScanTime`.


## Wynik

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

Ustalenia w `phishing`, `attachments`, `executables`, `macros`, `viruses` i `arbitrary` to obiekty z polami `type` i `message`. `String(finding)` zwraca komunikat. Załączniki załączonej wiadomości (`message/rfc822`, `.eml`) otrzymują jej nazwę: `fw.eml/invoice.exe`. Wirus, którego ClamAV znajdzie w takim załączniku, jest zgłaszany tylko dla niego, a nie ponownie dla załączonej wiadomości, która go zawiera. `virusScanErrors` wymienia załączniki, których ClamAV nie zdołał przeskanować, jako `{filename, error}`: taka wiadomość może zawierać wirusa, więc lepiej ją wstrzymać, niż dostarczyć. Milter i filtr treści odraczają taką wiadomość, chyba że `onError` (`--on-error`) ma wartość `accept`, a każdy serwer oznacza taką wiadomość, którą przekazuje dalej, nagłówkiem `X-Spam-Virus-Scan: failed`. `virusScanSkipped` wymienia załączniki większe, niż clamd przyjmuje (jego `StreamMaxLength`), jako `{filename, reason}`: clamd odrzuca je przy każdej próbie, więc, tak jak clamav-milter pomija plik ponad swój `MaxFileSize`, nie są one błędami. Jego pozostałe limity (`MaxScanSize`, `MaxFiles`, `MaxRecursion`, `MaxScanTime`), które osiąga bomba archiwalna, są błędami.

Każdy element `dnsbl` zawiera `answers` listy (adresy w 127.0.0.0/8, których znaczenie dokumentuje każda lista). Odpowiedzi, które listy dają na zapytania, których odmawiają lub na które nie mogą odpowiedzieć, nie są wpisami, ani dla adresu klienta, ani dla domen linków (ustalenia `uribl` w `phishing`): 127.255.255.x w Spamhaus (na przykład 127.255.255.254 dla zapytania przez publiczny resolver i 127.255.255.255 przy zbyt wielu zapytaniach), 127.0.1.255 w Spamhaus DBL, 127.0.0.255 w dowolnej liście oraz 127.0.0.1 w SURBL i URIBL, które dają tę odpowiedź blokowanym przez siebie resolverom.


## Eksporty

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

| Opcja                                  | Domyślnie      | Znaczenie                                                                                                                                                                           |
| -------------------------------------- | -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`  | Parametry s i x Robinsona: jak mocno rzadkie cechy są przyciągane do 0,5                                                                                                            |
| `minDistance`                          | `0.1`          | Cechy bliższe 0,5 niż ta wartość są pomijane                                                                                                                                        |
| `maxClues`                             | `150`          | Liczba najsilniejszych cech łączonych na wiadomość                                                                                                                                  |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | Granice przedziału `unsure`                                                                                                                                                         |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Liczba wiadomości ham w danym języku potrzebna do pełnej pewności oraz pięć razy mniej wiadomości spam; mniej, gdy `languageShare` wszystkich wiadomości ham lub spam jest mniejszy |
| `languagePrior`                        | `true`         | Porównuj słowa z licznikami ich własnego języka                                                                                                                                     |

Dostępne są też `merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` i `entries()`. `Classifier.fromJSON` sprawdza model i przy uszkodzonych danych zgłasza `TypeError` zaczynający się od `Corrupt classifier model`. JSON nie ma `Infinity`, więc opcja zapisana jako `Infinity` przez wersję 7.0.3 jest odczytywana jako `null`: jest ona traktowana jako `Infinity` dla `maxClues`, `minDistance` i `minLanguageExamples`, jako `-Infinity` dla `hamCutoff` (nigdy ham) i `Infinity` dla `spamCutoff` (nigdy spam), a dla pozostałych jako wartość domyślna. `toJSON` zapisuje próg spoza zakresu od 0 do 1 jako -1 lub 2, co działa tak samo. `loadModel` wczytuje plik ponownie, gdy się zmieni, a `saveModel` zapisuje przez nowy plik tymczasowy, zrzucany na dysk, zanim zastąpi model, który zachowuje swoje uprawnienia.

### Trenowanie

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

`evaluate(classifier, examples)` przyjmuje elementy `{label, features}` lub `readExamples(sources)`, które czyta te same źródła co `train`, i zwraca liczniki, precyzję, czułość, F1, dokładność oraz odsetki fałszywie pozytywnych, fałszywie negatywnych i niepewnych wyników.

### Serwery

```js
import SpamScanner, {MilterServer, createHttpServer, createSpamdServer} from 'spamscanner';

const scanner = new SpamScanner({authentication: true});
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]', onError: 'tempfail'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

`onError` miltera to jego odpowiedź, gdy skanowanie się nie powiedzie lub ClamAV nie zdołał przeskanować załącznika: `'tempfail'` (domyślnie) lub `'accept'`, które przekazuje wiadomość dalej oznaczoną `X-Spam-Virus-Scan: failed`, bez nagłówków `X-Spam-*` dodanych przez nadawcę.

### Raporty ARF

`spamscanner/arf` czyta i zapisuje raporty o nadużyciach (RFC 5965), czyli format, w którym dostawcy skrzynek pocztowych zgłaszają skargi na spam:

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

`parse()` przyjmuje Buffer, Uint8Array albo ciąg znaków. `ArfParser.tryParse()` zwraca `null` zamiast rzucać wyjątek dla wiadomości, które nie są raportami, a `isArfMessage(mail)` sprawdza sparsowaną wiadomość. `originalHeaders` ma wartość `null` dla raportu bez oryginalnej wiadomości. `create()` zwraca ciąg znaków albo `Buffer`, gdy `originalMessage` też nim jest, dzięki czemu jej bajty zostają zachowane bez względu na zestaw znaków.
