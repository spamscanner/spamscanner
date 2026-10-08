<!-- source: 8263c06f1dab -->

# Kom igång

Spam Scanner kräver Node.js 18 eller senare, eller ingenting alls med den fristående binärfilen.


## Installera

Som kommandoradsverktyg:

```sh
npm install --global spamscanner
spamscanner version
```

Som bibliotek i ett Node.js-projekt:

```sh
npm install spamscanner
```

Som fristående binärfil för Linux eller macOS, med Node.js och modellen inbyggda:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Binärfiler för Linux (x64 och arm64), macOS (Intel och Apple silicon) och Windows bifogas varje [version](https://github.com/spamscanner/spamscanner/releases).


## Skanna ett meddelande

Spara ett meddelande som en fil (de flesta e-postprogram kallar detta ”Spara som” eller ”Visa original”) och skanna det:

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

Slutkoden är 0 för ham (önskad e-post), 1 för spam och 2 vid fel, så skript kan använda den direkt. `--json` skriver ut hela resultatet och `--headers` skriver ut meddelandet med `X-Spam-*`-huvuden tillagda.

Meddelanden kan också komma från standard in:

```sh
cat message.eml | spamscanner scan -
```


## Använd det från Node.js

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

CommonJS fungerar också:

```js
const SpamScanner = require('spamscanner');
```

`scan()` tar emot det råa meddelandet som en Buffer, en sträng, en Uint8Array eller en läsbar ström. En sträng är alltid meddelandetext: Spam Scanner läser aldrig en fil för att en sträng ser ut som en sökväg. Använd `scanner.scanFile(path)` för filer.


## Berätta om SMTP-sessionen

Klientens IP-adress, dess verifierade värdnamn, HELO-namnet och kuvertet gör resultatet mer träffsäkert: autentiseringen behöver IP-adressen och regeln för självförfalskning behöver mottagarna.

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

Samma sak från kommandoraden:

```sh
spamscanner scan message.eml --ip 203.0.113.5 --helo mail.example.com \
  --from alice@example.com --to bob@example.org --auth
```


## Slå på fler kontroller

Ingen av dessa är påslagen som standard, eftersom var och en kräver en tjänst eller ett beslut:

| Kontroll                   | Bibliotekets alternativ                          | Kommandorad                 |
| -------------------------- | ------------------------------------------------ | --------------------------- |
| SPF, DKIM, DMARC, ARC      | `authentication: true`                           | `--auth`                    |
| IP-blocklista              | `dnsbl: {ip: ['zen.spamhaus.org']}`              | `--dnsbl zen.spamhaus.org`  |
| Domänblocklista för länkar | `dnsbl: {domain: ['dbl.spamhaus.org']}`          | `--uribl dbl.spamhaus.org`  |
| ClamAV                     | `clamav: true` eller `clamav: {socket}`          | `--clamav [socket]`         |
| En språkmodell             | `llm: {provider: 'ollama', model: 'qwen3.5:4b'}` | `--llm ollama`              |
| Tillåt- och blocklistor    | `allowlist: [...]`, `denylist: [...]`            | `--allowlist`, `--denylist` |

Cloudflares filtrerande resolvrar (1.1.1.2 för skadlig kod, 1.1.1.3 för vuxeninnehåll) tillfrågas om länkarnas värdar som standard. Stäng av det med `phishing: {cloudflare: false}` eller `--no-cloudflare`. [Vad som lämnar datorn](security.md)

Spamhaus och vissa andra blocklistor svarar inte på frågor som skickas via publika resolvrar som 8.8.8.8 eller 1.1.1.1. Använd dem med en lokal cachande resolver, och kontrollera deras användarvillkor för din volym.


## Nästa steg

* Placera det framför en e-postserver: [Postfix och Sendmail](postfix.md), [andra servrar](mail-servers.md).
* Lär det din egen e-post: [träning](training.md).
* Lägg till en språkmodell för gränsfall: [språkmodeller](llm.md).
