<!-- source: 8263c06f1dab -->

# Első lépések

A Spam Scannerhez Node.js 18 vagy újabb szükséges, az önálló bináris fájlhoz pedig semmi.


## Telepítés

Parancssori eszközként:

```sh
npm install --global spamscanner
spamscanner version
```

Könyvtárként egy Node.js-projektben:

```sh
npm install spamscanner
```

Önálló bináris fájlként Linuxra vagy macOS-re, beépített Node.js-szel és modellel:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

A Linuxra (x64 és arm64), macOS-re (Intel és Apple silicon) és Windowsra készült bináris fájlok minden [kiadáshoz](https://github.com/spamscanner/spamscanner/releases) csatolva vannak.


## Levél vizsgálata

Mentsen el egy levelet fájlként (a legtöbb levelezőprogramban ez a „Mentés másként” vagy az „Eredeti megjelenítése” menüpont), és vizsgálja meg:

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

A kilépési kód ham (kért levél) esetén 0, spam esetén 1, hiba esetén 2, így a szkriptek közvetlenül használhatják. A `--json` a teljes eredményt írja ki, a `--headers` pedig a levelet a hozzáadott `X-Spam-*` fejlécekkel.

A levelek a szabványos bemenetről is érkezhetnek:

```sh
cat message.eml | spamscanner scan -
```


## Használat Node.js-ből

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

CommonJS-szel is működik:

```js
const SpamScanner = require('spamscanner');
```

A `scan()` a nyers levelet Bufferként, karakterláncként, Uint8Array-ként vagy olvasható streamként fogadja. A karakterlánc mindig a levél szövege: a Spam Scanner soha nem olvas be fájlt csak azért, mert egy karakterlánc elérési útnak tűnik. Fájlokhoz a `scanner.scanFile(path)` használható.


## Az SMTP-munkamenet adatainak átadása

A kliens IP-címe, ellenőrzött gépneve, a HELO név és a boríték pontosabbá teszi az eredményt: a hitelesítéshez szükség van az IP-címre, az önhamisítási szabályhoz pedig a címzettekre.

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

Ugyanez a parancssorból:

```sh
spamscanner scan message.eml --ip 203.0.113.5 --helo mail.example.com \
  --from alice@example.com --to bob@example.org --auth
```


## További ellenőrzések bekapcsolása

Ezek közül egyik sincs alapértelmezetten bekapcsolva, mert mindegyikhez szolgáltatás vagy döntés kell:

| Ellenőrzés                          | Könyvtári beállítás                              | Parancssor                  |
| ----------------------------------- | ------------------------------------------------ | --------------------------- |
| SPF, DKIM, DMARC, ARC               | `authentication: true`                           | `--auth`                    |
| IP-tiltólista                       | `dnsbl: {ip: ['zen.spamhaus.org']}`              | `--dnsbl zen.spamhaus.org`  |
| Domain-tiltólista a hivatkozásokhoz | `dnsbl: {domain: ['dbl.spamhaus.org']}`          | `--uribl dbl.spamhaus.org`  |
| ClamAV                              | `clamav: true` vagy `clamav: {socket}`           | `--clamav [socket]`         |
| Nyelvi modell                       | `llm: {provider: 'ollama', model: 'qwen3.5:4b'}` | `--llm ollama`              |
| Engedélyező és tiltó listák         | `allowlist: [...]`, `denylist: [...]`            | `--allowlist`, `--denylist` |

A Cloudflare szűrő DNS-feloldóit (1.1.1.2 a kártevőkhöz, 1.1.1.3 a felnőtt tartalomhoz) alapértelmezetten megkérdezi a hivatkozások gépneveiről. Ez a `phishing: {cloudflare: false}` vagy a `--no-cloudflare` beállítással kapcsolható ki. [Mi hagyja el a gépet](security.md)

A Spamhaus és néhány más tiltólista nem válaszol a nyilvános DNS-feloldókon, például a 8.8.8.8-on vagy az 1.1.1.1-en keresztül küldött lekérdezésekre. Ezeket helyi, gyorsítótárazó DNS-feloldóval érdemes használni, és a forgalomnak megfelelően ellenőrizni kell a felhasználási feltételeiket.


## Következő lépések

* Levelezőszerver elé helyezés: [Postfix és Sendmail](postfix.md), [más szerverek](mail-servers.md).
* Tanítás a saját leveleken: [tanítás](training.md).
* Nyelvi modell hozzáadása a kétes esetekhez: [nyelvi modellek](llm.md).
