<!-- source: 8263c06f1dab -->

# Kom i gang

Spam Scanner krever Node.js 18 eller nyere, eller ingenting i det hele tatt med den frittstående binærfilen.


## Installer

Som kommandolinjeverktøy:

```sh
npm install --global spamscanner
spamscanner version
```

Som bibliotek i et Node.js-prosjekt:

```sh
npm install spamscanner
```

Som frittstående binærfil for Linux eller macOS, med Node.js og modellen innebygd:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Binærfiler for Linux (x64 og arm64), macOS (Intel og Apple silicon) og Windows er lagt ved hver [utgivelse](https://github.com/spamscanner/spamscanner/releases).


## Skann en melding

Lagre en melding som en fil (de fleste e-postprogrammer kaller dette «Lagre som» eller «Vis original») og skann den:

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

Avslutningskoden er 0 for ham, 1 for spam og 2 for en feil, så skript kan bruke den direkte. `--json` skriver ut hele resultatet, og `--headers` skriver ut meldingen med `X-Spam-*`-hoder lagt til.

Meldinger kan også komme fra standard inndata:

```sh
cat message.eml | spamscanner scan -
```


## Bruk det fra Node.js

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

CommonJS fungerer også:

```js
const SpamScanner = require('spamscanner');
```

`scan()` tar imot den rå meldingen som en Buffer, en streng, en Uint8Array eller en lesbar strøm. En streng er alltid meldingstekst: Spam Scanner leser aldri en fil fordi en streng ser ut som en sti. Bruk `scanner.scanFile(path)` for filer.


## Fortell det om SMTP-økten

Klientens IP-adresse, det verifiserte vertsnavnet, HELO-navnet og konvolutten gjør resultatet mer nøyaktig: autentisering trenger IP-adressen, og regelen mot forfalskning av eget domene trenger mottakerne.

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

Det samme fra kommandolinjen:

```sh
spamscanner scan message.eml --ip 203.0.113.5 --helo mail.example.com \
  --from alice@example.com --to bob@example.org --auth
```


## Slå på flere sjekker

Ingen av disse er på som standard, fordi hver av dem krever en tjeneste eller en beslutning:

| Sjekk                             | Bibliotekalternativ                              | Kommandolinje               |
| --------------------------------- | ------------------------------------------------ | --------------------------- |
| SPF, DKIM, DMARC, ARC             | `authentication: true`                           | `--auth`                    |
| IP-blokkeringsliste               | `dnsbl: {ip: ['zen.spamhaus.org']}`              | `--dnsbl zen.spamhaus.org`  |
| Domeneblokkeringsliste for lenker | `dnsbl: {domain: ['dbl.spamhaus.org']}`          | `--uribl dbl.spamhaus.org`  |
| ClamAV                            | `clamav: true` eller `clamav: {socket}`          | `--clamav [socket]`         |
| En språkmodell                    | `llm: {provider: 'ollama', model: 'qwen3.5:4b'}` | `--llm ollama`              |
| Tillatelses- og blokkeringslister | `allowlist: [...]`, `denylist: [...]`            | `--allowlist`, `--denylist` |

Cloudflares filtrerende resolvere (1.1.1.2 for skadevare, 1.1.1.3 for voksent innhold) blir som standard spurt om vertene i lenker. Slå det av med `phishing: {cloudflare: false}` eller `--no-cloudflare`. [Hva som forlater maskinen](security.md)

Spamhaus og enkelte andre blokkeringslister svarer ikke på forespørsler sendt via offentlige resolvere som 8.8.8.8 eller 1.1.1.1. Bruk dem med en lokal mellomlagrende resolver, og sjekk bruksvilkårene deres for ditt volum.


## Neste steg

* Sett det foran en e-postserver: [Postfix og Sendmail](postfix.md), [andre servere](mail-servers.md).
* Lær det opp på din egen e-post: [trening](training.md).
* Legg til en språkmodell for vanskelige tilfeller: [språkmodeller](llm.md).
