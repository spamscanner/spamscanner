<!-- source: 8263c06f1dab -->

# Pierwsze kroki

Spam Scanner wymaga Node.js 18 lub nowszego albo niczego, jeśli używasz samodzielnego pliku binarnego.


## Instalacja

Jako narzędzie wiersza poleceń:

```sh
npm install --global spamscanner
spamscanner version
```

Jako biblioteka w projekcie Node.js:

```sh
npm install spamscanner
```

Jako samodzielny plik binarny dla Linux lub macOS, z wbudowanym Node.js i modelem:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Pliki binarne dla Linux (x64 i arm64), macOS (Intel i Apple silicon) oraz Windows są dołączone do każdego [wydania](https://github.com/spamscanner/spamscanner/releases).


## Skanowanie wiadomości

Zapisz wiadomość jako plik (większość programów pocztowych nazywa to „Zapisz jako” lub „Pokaż oryginał”) i przeskanuj ją:

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

Kod wyjścia to 0 dla hamu, 1 dla spamu i 2 dla błędu, więc skrypty mogą go używać bezpośrednio. `--json` wypisuje pełny wynik, a `--headers` wypisuje wiadomość z dodanymi nagłówkami `X-Spam-*`.

Wiadomości mogą też pochodzić ze standardowego wejścia:

```sh
cat message.eml | spamscanner scan -
```


## Użycie z Node.js

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

CommonJS też działa:

```js
const SpamScanner = require('spamscanner');
```

`scan()` przyjmuje surową wiadomość jako Buffer, string, Uint8Array lub strumień do odczytu. Ciąg znaków to zawsze tekst wiadomości: Spam Scanner nigdy nie czyta pliku tylko dlatego, że ciąg wygląda jak ścieżka. Dla plików użyj `scanner.scanFile(path)`.


## Przekazanie danych sesji SMTP

Adres IP klienta, jego zweryfikowana nazwa hosta, nazwa z HELO i koperta zwiększają dokładność wyniku: uwierzytelnianie wymaga adresu IP, a reguła podszywania się pod własną domenę wymaga odbiorców.

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

To samo z wiersza poleceń:

```sh
spamscanner scan message.eml --ip 203.0.113.5 --helo mail.example.com \
  --from alice@example.com --to bob@example.org --auth
```


## Włączanie kolejnych kontroli

Żadna z nich nie jest domyślnie włączona, bo każda wymaga usługi lub decyzji:

| Kontrola                          | Opcja biblioteki                                 | Wiersz poleceń              |
| --------------------------------- | ------------------------------------------------ | --------------------------- |
| SPF, DKIM, DMARC, ARC             | `authentication: true`                           | `--auth`                    |
| Czarna lista IP                   | `dnsbl: {ip: ['zen.spamhaus.org']}`              | `--dnsbl zen.spamhaus.org`  |
| Czarna lista domen dla linków     | `dnsbl: {domain: ['dbl.spamhaus.org']}`          | `--uribl dbl.spamhaus.org`  |
| ClamAV                            | `clamav: true` lub `clamav: {socket}`            | `--clamav [socket]`         |
| Model językowy                    | `llm: {provider: 'ollama', model: 'qwen3.5:4b'}` | `--llm ollama`              |
| Listy dozwolonych i zablokowanych | `allowlist: [...]`, `denylist: [...]`            | `--allowlist`, `--denylist` |

Filtrujące resolvery Cloudflare (1.1.1.2 dla złośliwego oprogramowania, 1.1.1.3 dla treści dla dorosłych) są domyślnie pytane o hosty z linków. Wyłącz to przez `phishing: {cloudflare: false}` lub `--no-cloudflare`. [Co opuszcza komputer](security.md)

Spamhaus i niektóre inne czarne listy nie odpowiadają na zapytania wysyłane przez publiczne resolvery, takie jak 8.8.8.8 lub 1.1.1.1. Używaj ich z lokalnym resolverem buforującym i sprawdź ich warunki użytkowania dla swojego wolumenu.


## Dalsze kroki

* Postaw go przed serwerem pocztowym: [Postfix i Sendmail](postfix.md), [inne serwery](mail-servers.md).
* Naucz go swojej własnej poczty: [trenowanie](training.md).
* Dodaj model językowy do trudnych przypadków: [modele językowe](llm.md).
