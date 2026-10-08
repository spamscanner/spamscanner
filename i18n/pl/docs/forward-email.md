<!-- source: dc9016edd59e -->

# Forward Email

Spam Scanner zbudował [Forward Email](https://forwardemail.net), otwartoźródłowa usługa poczty e-mail nastawiona na prywatność, na potrzeby własnych serwerów pocztowych. Forward Email nie przechowuje logów z treścią wiadomości, więc żadna zewnętrzna usługa filtrująca nie wchodziła w grę: filtr musiał działać na jego własnych serwerach i wyjaśniać każdą decyzję bez czytania poczty przez człowieka.

Ta strona pokazuje, jak korzysta z niego serwer pocztowy taki jak serwery Forward Email, i co się zmieniło dla kodu napisanego pod Spam Scanner 5 lub 6.


## Na serwerze poczty przychodzącej

Forward Email odbiera pocztę za pomocą [smtp-server](https://nodemailer.com/extras/smtp-server/). Wzorzec dla każdego serwera zbudowanego na tej bibliotece:

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

`scanner.scan()` przyjmuje bezpośrednio strumień SMTP. Jeśli wyniki z [mailauth](https://github.com/postalsys/mailauth) są już dostępne, pomiń `authentication` i przekaż tylko adres IP.

Odpowiedź 421 lub 451 sprawia, że serwer wysyłający umieszcza wiadomość w kolejce i ponawia próbę później. Nowe reguły odrzucania mogą zaczynać od kodu tymczasowego i przejść na 550, gdy ich wyniki zostaną sprawdzone, bez utraty poczty w międzyczasie.


## Aktualizacja z wersji 5 lub 6

Wersja 7 została napisana od nowa. Konstruktor, `scan()` i pola wyniku, które czyta kod z wersji 5 i 6, nadal działają; zmieniły się klasyfikator, model i opcjonalne kontrole TensorFlow.

### Bez zmian

* `new SpamScanner(options)` i `await scanner.scan(source)`.
* `require('spamscanner')` zwraca klasę, a `import SpamScanner from 'spamscanner'` działa.
* `result.isSpam`, `result.message` oraz `result.results.classification`, `.phishing`, `.executables`, `.arbitrary`, `.viruses`, `.macros` i `.idnHomographAttack`.
* Każdy element w `results.phishing`, `.executables`, `.arbitrary` i `.viruses` daje się zamienić na taki sam komunikat tekstowy jak wcześniej (`String(item)`, literały szablonowe, `message.includes('adult-related content')`). Teraz są to obiekty z `type`, `message` i szczegółami.
* `getTokensAndMailFromSource()`, `getClassification()` i `getTokens()`.
* Te opcje odpowiadają nowym nazwom: `clamscan` to `clamav`, `enableMacroDetection: false` to `macros: false`, `enableArbitraryDetection: false` to `arbitrary: false`, `enableAuthentication` z `authOptions` to `authentication` i `session`, `enableReputation` z `reputationOptions.apiUrl` to `reputation`, `strictIDNDetection` to `phishing.homograph.strictMode`, a także `allowlist` i `denylist`. `logger` i `memoize` są akceptowane i ignorowane.

### Zmiany

| Wcześniej                                                                              | Teraz                                                                                                                                                      |
| -------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan('path/to/file.eml')` czytało plik                                                | Ciąg znaków to tekst wiadomości. Użyj `scanFile(path)` lub przekaż Buffer                                                                                  |
| Naiwny model Bayesa dla słów (`classifier.json`), którego nie da się teraz wczytać     | Nowy klasyfikator i format modelu; wytrenuj ponownie przez `spamscanner train` ([trenowanie](training.md))                                                 |
| Kontrole toksyczności i NSFW przy pierwszym użyciu pobierały modele TensorFlow z sieci | Własny model: `toxicity: {model}` i `nsfw: {model}` przyjmują dowolny obiekt z metodą `classify()`, na przykład z `@tensorflow-models/toxicity` i `nsfwjs` |
| `results.arbitrary` wymieniało każdy dopasowany wzorzec                                | Wymienia reguły na tyle silne, by same oznaczyć spam; wszystkie reguły są w `result.tests`                                                                 |
| Odpowiedź tak albo nie                                                                 | `result.score`, `result.action` (`accept`, `tag` lub `reject`) i `result.tests`, każdy z punktami i powodem                                                |
| O `isSpam` decydował klasyfikator lub dowolna pojedyncza kontrola                      | `isSpam` oznacza wynik 5 lub więcej; progi i punkty można zmienić                                                                                          |
| Kontrole reputacji w punkcie końcowym Forward Email                                    | Ogólna usługa reputacji, wyłączona, dopóki nie ustawisz `reputation.apiUrl`                                                                                |

### Nowości

* [Modele językowe](llm.md) do trudnych przypadków, lokalne lub hostowane.
* SPF, DKIM, DMARC i ARC; czarne listy DNS; filtrujące resolvery Cloudflare.
* Kontrole załączników według zawartości: zamaskowane pliki wykonywalne, archiwa, makra, aktywne pliki PDF.
* [Milter, HTTP API, serwer TCP i serwer spamd](mail-servers.md) oraz [wiersz poleceń](cli.md).
* Trenowanie, ewaluacja i nauka ze zgłoszeń, z wiersza poleceń lub przez API.
