<!-- source: dc9016edd59e -->

# Forward Email

Spam Scanner vytvořil [Forward Email](https://forwardemail.net), e-mailová služba s otevřeným zdrojovým kódem zaměřená na soukromí, pro vlastní poštovní servery. Forward Email neuchovává žádné záznamy o obsahu zpráv, takže žádná externí filtrovací služba nepřicházela v úvahu: filtr musel běžet na jeho vlastních serverech a vysvětlit každé rozhodnutí, aniž by poštu četl člověk.

Tato stránka ukazuje, jak ho používá poštovní server, jako je ten od Forward Email, a co se změnilo pro kód napsaný pro Spam Scanner 5 nebo 6.


## Na serveru příchozí pošty

Forward Email přijímá poštu pomocí [smtp-server](https://nodemailer.com/extras/smtp-server/). Vzor pro jakýkoli server postavený na něm:

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

`scanner.scan()` přijímá stream SMTP přímo. Pokud už máte k dispozici výsledky z [mailauth](https://github.com/postalsys/mailauth), vynechte `authentication` a předejte jen IP adresu.

Odpověď 421 nebo 451 způsobí, že odesílající server zprávu zařadí do fronty a zkusí to později znovu. Nová pravidla pro odmítání tak mohou začít s dočasným kódem a přejít na 550, až budou jejich výsledky ověřené, aniž by se mezitím ztratila pošta.


## Přechod z verze 5 nebo 6

Verze 7 je přepsaná od základu. Konstruktor, `scan()` a pole výsledku, která čte kód pro verze 5 a 6, stále fungují; změnil se klasifikátor, model a volitelné kontroly s TensorFlow.

### Beze změny

* `new SpamScanner(options)` a `await scanner.scan(source)`.
* `require('spamscanner')` vrací třídu a `import SpamScanner from 'spamscanner'` funguje.
* `result.isSpam`, `result.message` a `result.results.classification`, `.phishing`, `.executables`, `.arbitrary`, `.viruses`, `.macros` a `.idnHomographAttack`.
* Každá položka v `results.phishing`, `.executables`, `.arbitrary` a `.viruses` se převede na stejný druh textu zprávy jako dřív (`String(item)`, šablonové literály, `message.includes('adult-related content')`). Nyní jsou to objekty s `type`, `message` a podrobnostmi.
* `getTokensAndMailFromSource()`, `getClassification()` a `getTokens()`.
* Tyto volby se převádějí na nové názvy: `clamscan` na `clamav`, `enableMacroDetection: false` na `macros: false`, `enableArbitraryDetection: false` na `arbitrary: false`, `enableAuthentication` s `authOptions` na `authentication` a `session`, `enableReputation` s `reputationOptions.apiUrl` na `reputation`, `strictIDNDetection` na `phishing.homograph.strictMode`, a `allowlist` a `denylist`. `logger` a `memoize` se přijímají a ignorují.

### Změněno

| Dříve                                                                          | Nyní                                                                                                                                                                 |
| ------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan('path/to/file.eml')` přečetl soubor                                      | Řetězec je text zprávy. Použijte `scanFile(path)` nebo předejte Buffer                                                                                               |
| Naivní Bayesův model slov (`classifier.json`), který už nelze načíst           | Nový klasifikátor a formát modelu; přetrénujte pomocí `spamscanner train` ([trénování](training.md))                                                                 |
| Kontroly toxicity a NSFW načítaly při prvním použití modely TensorFlow ze sítě | Použijte vlastní model: `toxicity: {model}` a `nsfw: {model}` přijímají jakýkoli objekt s metodou `classify()`, například z `@tensorflow-models/toxicity` a `nsfwjs` |
| `results.arbitrary` uváděl každý vzor, který odpovídal                         | Uvádí pravidla dost silná na to, aby samy označila spam; všechna pravidla jsou v `result.tests`                                                                      |
| Odpověď ano, nebo ne                                                           | `result.score`, `result.action` (`accept`, `tag` nebo `reject`) a `result.tests`, každý s body a důvodem                                                             |
| `isSpam` rozhodoval klasifikátor nebo kterákoli jednotlivá kontrola            | `isSpam` znamená skóre 5 nebo více; prahy i body lze změnit                                                                                                          |
| Kontroly reputace proti koncovému bodu Forward Email                           | Obecná služba reputace, vypnutá, dokud není nastaveno `reputation.apiUrl`                                                                                            |

### Nové

* [Jazykové modely](llm.md) pro hraniční případy, lokální nebo hostované.
* SPF, DKIM, DMARC a ARC; DNS blocklisty; filtrovací resolvery Cloudflare.
* Kontroly příloh podle obsahu: maskované spustitelné soubory, archivy, makra, aktivní PDF.
* [Milter, HTTP API, TCP server a server spamd](mail-servers.md) a [příkazová řádka](cli.md).
* Trénování, vyhodnocování a učení z hlášení, z příkazové řádky nebo přes API.
