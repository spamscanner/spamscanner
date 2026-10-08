<!-- source: 8263c06f1dab -->

# Kom i gang

Spam Scanner kræver Node.js 18 eller nyere eller slet ingenting med den selvstændige binærfil.


## Installér

Som kommandolinjeværktøj:

```sh
npm install --global spamscanner
spamscanner version
```

Som bibliotek i et Node.js-projekt:

```sh
npm install spamscanner
```

Som selvstændig binærfil til Linux eller macOS med Node.js og modellen indbygget:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Binærfiler til Linux (x64 og arm64), macOS (Intel og Apple silicon) og Windows er vedhæftet hver [udgivelse](https://github.com/spamscanner/spamscanner/releases).


## Scan en besked

Gem en besked som en fil (de fleste mailprogrammer kalder det »Gem som« eller »Vis original«), og scan den:

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

Afslutningskoden er 0 for ham, 1 for spam og 2 for en fejl, så scripts kan bruge den direkte. `--json` udskriver hele resultatet, og `--headers` udskriver beskeden med `X-Spam-*`-headere tilføjet.

Beskeder kan også komme fra standardinput:

```sh
cat message.eml | spamscanner scan -
```


## Brug det fra Node.js

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

CommonJS virker også:

```js
const SpamScanner = require('spamscanner');
```

`scan()` tager den rå besked som en Buffer, en streng, et Uint8Array eller en læsbar stream. En streng er altid beskedtekst: Spam Scanner læser aldrig en fil, fordi en streng ligner en sti. Brug `scanner.scanFile(path)` til filer.


## Fortæl det om SMTP-sessionen

Klientens IP-adresse, dens verificerede værtsnavn, HELO-navnet og konvolutten gør resultatet mere præcist: godkendelse kræver IP-adressen, og reglen om selvforfalskning kræver modtagerne.

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


## Slå flere tjek til

Ingen af disse er slået til som standard, fordi hver af dem kræver en tjeneste eller en beslutning:

| Tjek                             | Biblioteksindstilling                            | Kommandolinje               |
| -------------------------------- | ------------------------------------------------ | --------------------------- |
| SPF, DKIM, DMARC, ARC            | `authentication: true`                           | `--auth`                    |
| IP-blokeringsliste               | `dnsbl: {ip: ['zen.spamhaus.org']}`              | `--dnsbl zen.spamhaus.org`  |
| Domæneblokeringsliste for links  | `dnsbl: {domain: ['dbl.spamhaus.org']}`          | `--uribl dbl.spamhaus.org`  |
| ClamAV                           | `clamav: true` eller `clamav: {socket}`          | `--clamav [socket]`         |
| En sprogmodel                    | `llm: {provider: 'ollama', model: 'qwen3.5:4b'}` | `--llm ollama`              |
| Tilladelses- og blokeringslister | `allowlist: [...]`, `denylist: [...]`            | `--allowlist`, `--denylist` |

Cloudflares filtrerende resolvere (1.1.1.2 for malware, 1.1.1.3 for voksenindhold) spørges som standard om værter i links. Slå det fra med `phishing: {cloudflare: false}` eller `--no-cloudflare`. [Hvad der forlader maskinen](security.md)

Spamhaus og nogle andre blokeringslister svarer ikke på forespørgsler, der sendes via offentlige resolvere som 8.8.8.8 eller 1.1.1.1. Brug dem med en lokal cachende resolver, og tjek deres brugsvilkår for din mængde post.


## Næste skridt

* Sæt det foran en mailserver: [Postfix og Sendmail](postfix.md), [andre servere](mail-servers.md).
* Lær det op på din egen post: [træning](training.md).
* Tilføj en sprogmodel til tvivlstilfælde: [sprogmodeller](llm.md).
