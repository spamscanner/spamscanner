<!-- source: 8263c06f1dab -->

# Aan de slag

Spam Scanner heeft Node.js 18 of nieuwer nodig, of helemaal niets met de standalone binary.


## Installeren

Als opdrachtregeltool:

```sh
npm install --global spamscanner
spamscanner version
```

Als bibliotheek in een Node.js-project:

```sh
npm install spamscanner
```

Als standalone binary voor Linux of macOS, met Node.js en het model ingebouwd:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Binaries voor Linux (x64 en arm64), macOS (Intel en Apple silicon) en Windows zijn bij elke [release](https://github.com/spamscanner/spamscanner/releases) gevoegd.


## Een bericht scannen

Sla een bericht op als bestand (de meeste mailprogramma's noemen dit „Opslaan als” of „Origineel weergeven”) en scan het:

```sh
spamscanner scan message.eml
```

```text
SPAM  score 16.3 (spam at 5.0, reject at 15.0)  action: reject  language: en
     +6.3  BAYES_999                    Classifier spam probability 99.9%
     +5.0  PHISHING_LOOKALIKE_DOMAIN    "paypa1-secure.top" imitates paypal by swapping characters
     +3.0  DECEPTIVE_LINK               A link shows "https://www.paypal.com/signin" but goes to paypa1-secure.top
     +2.0  FROM_NAME_BRAND              Display name says "paypal" but the message is from paypa1-secure.top
```

De exitcode is 0 voor ham, 1 voor spam en 2 voor een fout, zodat scripts hem direct kunnen gebruiken. `--json` toont het volledige resultaat en `--headers` toont het bericht met toegevoegde `X-Spam-*`-headers.

Berichten kunnen ook via standaardinvoer binnenkomen:

```sh
cat message.eml | spamscanner scan -
```


## Gebruik vanuit Node.js

```js
import SpamScanner from 'spamscanner';
import {readFile} from 'node:fs/promises';

const scanner = new SpamScanner();
const result = await scanner.scan(await readFile('message.eml'));

console.log(result.isSpam, result.score, result.action);
for (const test of result.tests) {
  console.log(test.name, test.score, test.description);
}
```

CommonJS werkt ook:

```js
const SpamScanner = require('spamscanner');
```

`scan()` neemt het ruwe bericht aan als Buffer, string, Uint8Array of readable stream. Een string is altijd berichttekst: Spam Scanner leest nooit een bestand omdat een string op een pad lijkt. Gebruik `scanner.scanFile(path)` voor bestanden.


## Geef informatie over de SMTP-sessie mee

Het IP-adres van de client, de geverifieerde hostnaam, de HELO-naam en de envelope maken het resultaat nauwkeuriger: authenticatie heeft het IP-adres nodig en de self-spoofingregel heeft de ontvangers nodig.

```js
const result = await scanner.scan(raw, {
  session: {
    remoteAddress: '203.0.113.5',
    resolvedClientHostname: 'mail.example.com',
    helo: 'mail.example.com',
    envelope: {
      mailFrom: {address: 'alice@example.com'},
      rcptTo: [{address: 'bob@example.org'}],
    },
  },
});
```

Hetzelfde vanaf de opdrachtregel:

```sh
spamscanner scan message.eml --ip 203.0.113.5 --helo mail.example.com \
  --from alice@example.com --to bob@example.org --auth
```


## Meer controles aanzetten

Geen van deze staat standaard aan, omdat elk een dienst of een beslissing vereist:

| Controle                   | Bibliotheekoptie                                 | Opdrachtregel               |
| -------------------------- | ------------------------------------------------ | --------------------------- |
| SPF, DKIM, DMARC, ARC      | `authentication: true`                           | `--auth`                    |
| IP-blocklist               | `dnsbl: {ip: ['zen.spamhaus.org']}`              | `--dnsbl zen.spamhaus.org`  |
| Domeinblocklist voor links | `dnsbl: {domain: ['dbl.spamhaus.org']}`          | `--uribl dbl.spamhaus.org`  |
| ClamAV                     | `clamav: true` of `clamav: {socket}`             | `--clamav [socket]`         |
| Een taalmodel              | `llm: {provider: 'ollama', model: 'qwen3.5:4b'}` | `--llm ollama`              |
| Allow- en denylists        | `allowlist: [...]`, `denylist: [...]`            | `--allowlist`, `--denylist` |

De filterende resolvers van Cloudflare (1.1.1.2 voor malware, 1.1.1.3 voor content voor volwassenen) worden standaard naar linkhosts gevraagd. Zet dat uit met `phishing: {cloudflare: false}` of `--no-cloudflare`. [Wat de machine verlaat](security.md)

Spamhaus en sommige andere blocklists beantwoorden geen queries die via publieke resolvers zoals 8.8.8.8 of 1.1.1.1 worden verstuurd. Gebruik ze met een lokale caching resolver en controleer hun gebruiksvoorwaarden voor je volume.


## Volgende stappen

* Zet het voor een mailserver: [Postfix en Sendmail](postfix.md), [andere servers](mail-servers.md).
* Leer het je eigen mail: [training](training.md).
* Voeg een taalmodel toe voor twijfelgevallen: [taalmodellen](llm.md).
