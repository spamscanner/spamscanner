<!-- source: 8263c06f1dab -->

# Erste Schritte

Spam Scanner benötigt Node.js 18 oder neuer, mit der eigenständigen Binärdatei gar nichts.


## Installieren

Als Kommandozeilenwerkzeug:

```sh
npm install --global spamscanner
spamscanner version
```

Als Bibliothek in einem Node.js-Projekt:

```sh
npm install spamscanner
```

Als eigenständige Binärdatei für Linux oder macOS, mit eingebautem Node.js und Modell:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Binärdateien für Linux (x64 und arm64), macOS (Intel und Apple Silicon) und Windows hängen an jedem [Release](https://github.com/spamscanner/spamscanner/releases).


## Eine Nachricht prüfen

Speichern Sie eine Nachricht als Datei (die meisten E-Mail-Programme nennen das „Speichern unter“ oder „Original anzeigen“) und prüfen Sie sie:

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

Der Exit-Code ist 0 für Ham, 1 für Spam und 2 für einen Fehler, sodass Skripte ihn direkt verwenden können. `--json` gibt das vollständige Ergebnis aus, `--headers` gibt die Nachricht mit hinzugefügten `X-Spam-*`-Headern aus.

Nachrichten können auch von der Standardeingabe kommen:

```sh
cat message.eml | spamscanner scan -
```


## Aus Node.js verwenden

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

CommonJS funktioniert ebenfalls:

```js
const SpamScanner = require('spamscanner');
```

`scan()` nimmt die rohe Nachricht als Buffer, String, Uint8Array oder lesbaren Stream entgegen. Ein String ist immer Nachrichtentext: Spam Scanner liest nie eine Datei, nur weil ein String wie ein Pfad aussieht. Für Dateien gibt es `scanner.scanFile(path)`.


## Angaben zur SMTP-Sitzung übergeben

Die IP-Adresse des Clients, sein verifizierter Hostname, der HELO-Name und der Umschlag machen das Ergebnis genauer: Die Authentifizierung braucht die IP-Adresse, die Regel gegen Selbst-Spoofing braucht die Empfänger.

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

Dasselbe auf der Kommandozeile:

```sh
spamscanner scan message.eml --ip 203.0.113.5 --helo mail.example.com \
  --from alice@example.com --to bob@example.org --auth
```


## Weitere Prüfungen einschalten

Keine davon ist standardmäßig aktiv, denn jede braucht einen Dienst oder eine Entscheidung:

| Prüfung                     | Bibliotheksoption                                | Kommandozeile               |
| --------------------------- | ------------------------------------------------ | --------------------------- |
| SPF, DKIM, DMARC, ARC       | `authentication: true`                           | `--auth`                    |
| IP-Blockliste               | `dnsbl: {ip: ['zen.spamhaus.org']}`              | `--dnsbl zen.spamhaus.org`  |
| Domain-Blockliste für Links | `dnsbl: {domain: ['dbl.spamhaus.org']}`          | `--uribl dbl.spamhaus.org`  |
| ClamAV                      | `clamav: true` oder `clamav: {socket}`           | `--clamav [socket]`         |
| Ein Sprachmodell            | `llm: {provider: 'ollama', model: 'qwen3.5:4b'}` | `--llm ollama`              |
| Erlaubt- und Sperrlisten    | `allowlist: [...]`, `denylist: [...]`            | `--allowlist`, `--denylist` |

Die filternden Resolver von Cloudflare (1.1.1.2 für Malware, 1.1.1.3 für Inhalte für Erwachsene) werden standardmäßig zu Link-Hosts befragt. Abschalten lässt sich das mit `phishing: {cloudflare: false}` oder `--no-cloudflare`. [Was den Rechner verlässt](security.md)

Spamhaus und einige andere Blocklisten beantworten keine Anfragen, die über öffentliche Resolver wie 8.8.8.8 oder 1.1.1.1 gestellt werden. Verwenden Sie sie mit einem lokalen, cachenden Resolver und prüfen Sie ihre Nutzungsbedingungen für Ihr Anfragevolumen.


## Nächste Schritte

* Vor einen Mailserver schalten: [Postfix und Sendmail](postfix.md), [andere Server](mail-servers.md).
* Mit den eigenen E-Mails anlernen: [Training](training.md).
* Ein Sprachmodell für knappe Fälle hinzufügen: [Sprachmodelle](llm.md).
