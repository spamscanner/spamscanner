<!-- source: 8263c06f1dab -->

# Primi passi

Spam Scanner richiede Node.js 18 o successivo, oppure niente del tutto con il binario autonomo.


## Installazione

Come strumento da riga di comando:

```sh
npm install --global spamscanner
spamscanner version
```

Come libreria in un progetto Node.js:

```sh
npm install spamscanner
```

Come binario autonomo per Linux o macOS, con Node.js e il modello inclusi:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

I binari per Linux (x64 e arm64), macOS (Intel e Apple silicon) e Windows sono allegati a ogni [release](https://github.com/spamscanner/spamscanner/releases).


## Analizzare un messaggio

Salva un messaggio come file (la maggior parte dei programmi di posta chiama questa funzione "Salva come" o "Mostra originale") e analizzalo:

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

Il codice di uscita è 0 per l'ham, 1 per lo spam e 2 per un errore, quindi gli script possono usarlo direttamente. `--json` stampa il risultato completo e `--headers` stampa il messaggio con le intestazioni `X-Spam-*` aggiunte.

I messaggi possono arrivare anche dallo standard input:

```sh
cat message.eml | spamscanner scan -
```


## Usarlo da Node.js

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

Funziona anche CommonJS:

```js
const SpamScanner = require('spamscanner');
```

`scan()` accetta il messaggio grezzo come Buffer, stringa, Uint8Array o stream leggibile. Una stringa è sempre il testo del messaggio: Spam Scanner non legge mai un file solo perché una stringa somiglia a un percorso. Per i file usa `scanner.scanFile(path)`.


## Fornire i dati della sessione SMTP

L'indirizzo IP del client, il suo hostname verificato, il nome HELO e l'envelope rendono il risultato più accurato: l'autenticazione richiede l'indirizzo IP e la regola sull'auto-spoofing richiede i destinatari.

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

Lo stesso dalla riga di comando:

```sh
spamscanner scan message.eml --ip 203.0.113.5 --helo mail.example.com \
  --from alice@example.com --to bob@example.org --auth
```


## Attivare altri controlli

Nessuno di questi è attivo per impostazione predefinita, perché ciascuno richiede un servizio o una decisione:

| Controllo                      | Opzione della libreria                           | Riga di comando             |
| ------------------------------ | ------------------------------------------------ | --------------------------- |
| SPF, DKIM, DMARC, ARC          | `authentication: true`                           | `--auth`                    |
| Blocklist di IP                | `dnsbl: {ip: ['zen.spamhaus.org']}`              | `--dnsbl zen.spamhaus.org`  |
| Blocklist di domini per i link | `dnsbl: {domain: ['dbl.spamhaus.org']}`          | `--uribl dbl.spamhaus.org`  |
| ClamAV                         | `clamav: true` o `clamav: {socket}`              | `--clamav [socket]`         |
| Un modello linguistico         | `llm: {provider: 'ollama', model: 'qwen3.5:4b'}` | `--llm ollama`              |
| Liste di consenso e di blocco  | `allowlist: [...]`, `denylist: [...]`            | `--allowlist`, `--denylist` |

I resolver con filtraggio di Cloudflare (1.1.1.2 per il malware, 1.1.1.3 per i contenuti per adulti) vengono interrogati sugli host dei link per impostazione predefinita. Per disattivarli usa `phishing: {cloudflare: false}` o `--no-cloudflare`. [Cosa lascia la macchina](security.md)

Spamhaus e alcune altre blocklist non rispondono alle query inviate tramite resolver pubblici come 8.8.8.8 o 1.1.1.1. Usale con un resolver locale con cache, e verifica i loro termini d'uso per il tuo volume.


## Prossimi passi

* Mettilo davanti a un server di posta: [Postfix e Sendmail](postfix.md), [altri server](mail-servers.md).
* Insegnagli la tua posta: [addestramento](training.md).
* Aggiungi un modello linguistico per i casi dubbi: [modelli linguistici](llm.md).
