<!-- source: 8263c06f1dab -->

# Začínáme

Spam Scanner potřebuje Node.js 18 nebo novější, se samostatnou binárkou nepotřebuje vůbec nic.


## Instalace

Jako nástroj pro příkazovou řádku:

```sh
npm install --global spamscanner
spamscanner version
```

Jako knihovna v projektu Node.js:

```sh
npm install spamscanner
```

Jako samostatná binárka pro Linux nebo macOS s vestavěným Node.js a modelem:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Binárky pro Linux (x64 a arm64), macOS (Intel a Apple silicon) a Windows jsou přiložené ke každému [vydání](https://github.com/spamscanner/spamscanner/releases).


## Kontrola zprávy

Uložte zprávu do souboru (většina poštovních programů tomu říká „Uložit jako“ nebo „Zobrazit originál“) a zkontrolujte ji:

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

Návratový kód je 0 pro ham, 1 pro spam a 2 pro chybu, takže ho skripty mohou použít přímo. `--json` vypíše celý výsledek a `--headers` vypíše zprávu s přidanými hlavičkami `X-Spam-*`.

Zprávy mohou přicházet i ze standardního vstupu:

```sh
cat message.eml | spamscanner scan -
```


## Použití z Node.js

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

Funguje i CommonJS:

```js
const SpamScanner = require('spamscanner');
```

`scan()` přijímá surovou zprávu jako Buffer, řetězec, Uint8Array nebo čitelný stream. Řetězec je vždy text zprávy: Spam Scanner nikdy nečte soubor jen proto, že řetězec vypadá jako cesta. Pro soubory použijte `scanner.scanFile(path)`.


## Informace o relaci SMTP

IP adresa klienta, jeho ověřený název hostitele, jméno z HELO a obálka zpřesňují výsledek: ověření potřebuje IP adresu a pravidlo proti podvrhování vlastní domény potřebuje příjemce.

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

Totéž z příkazové řádky:

```sh
spamscanner scan message.eml --ip 203.0.113.5 --helo mail.example.com \
  --from alice@example.com --to bob@example.org --auth
```


## Zapnutí dalších kontrol

Žádná z nich není ve výchozím stavu zapnutá, protože každá potřebuje službu nebo rozhodnutí:

| Kontrola                        | Volba knihovny                                   | Příkazová řádka             |
| ------------------------------- | ------------------------------------------------ | --------------------------- |
| SPF, DKIM, DMARC, ARC           | `authentication: true`                           | `--auth`                    |
| Blocklist IP adres              | `dnsbl: {ip: ['zen.spamhaus.org']}`              | `--dnsbl zen.spamhaus.org`  |
| Blocklist domén v odkazech      | `dnsbl: {domain: ['dbl.spamhaus.org']}`          | `--uribl dbl.spamhaus.org`  |
| ClamAV                          | `clamav: true` nebo `clamav: {socket}`           | `--clamav [socket]`         |
| Jazykový model                  | `llm: {provider: 'ollama', model: 'qwen3.5:4b'}` | `--llm ollama`              |
| Seznamy povolených a zakázaných | `allowlist: [...]`, `denylist: [...]`            | `--allowlist`, `--denylist` |

Filtrovacích resolverů Cloudflare (1.1.1.2 pro malware, 1.1.1.3 pro obsah pro dospělé) se Spam Scanner ve výchozím stavu ptá na hostitele z odkazů. Vypnete to pomocí `phishing: {cloudflare: false}` nebo `--no-cloudflare`. [Co opouští počítač](security.md)

Spamhaus a některé další blocklisty neodpovídají na dotazy poslané přes veřejné resolvery jako 8.8.8.8 nebo 1.1.1.1. Používejte je s lokálním cachovacím resolverem a ověřte si jejich podmínky použití pro váš objem pošty.


## Další kroky

* Postavte ho před poštovní server: [Postfix a Sendmail](postfix.md), [další servery](mail-servers.md).
* Naučte ho vaši vlastní poštu: [trénování](training.md).
* Přidejte jazykový model pro hraniční případy: [jazykové modely](llm.md).
