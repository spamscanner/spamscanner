<!-- source: 988243aec4f3 -->

<!--
label: Selbst gehosteter Spamfilter
title: Selbst gehosteter Spamfilter für Ihren eigenen Mailserver
description: Ein Spamfilter auf Ihrem eigenen Server. Spam Scanner behält die E-Mails auf dem Rechner, liefert sein Modell im Paket mit, sendet keine Telemetrie und passt zu Postfix oder Exim.
keywords: selbst gehosteter Spamfilter, On-Premises-Spamfilter, privater Spamfilter, lokaler Spamfilter, Spamfilter für Mailserver, Spamfilter ohne Cloud
-->

# Selbst gehosteter Spamfilter

Spam Scanner läuft auf Ihrem eigenen Server und behält die E-Mails dort. Das Modell des Klassifikators ist im Paket enthalten, es gibt keine Telemetrie und keine Update-Prüfung, und standardmäßig sendet er nur eine DNS-Abfrage für den Hostnamen jedes Links.


## Was den Server verlässt

Standardmäßig nur die Hostnamen der Links in einer Nachricht. Sie werden als gewöhnliche DNS-Abfragen bei den Filter-Resolvern von Cloudflare (1.1.1.2 und 1.1.1.3) nachgeschlagen, und kein Teil der Nachricht oder ihrer Adressen wird gesendet. `--no-cloudflare` schaltet auch das ab.

Jede andere Prüfung, die das Netz nutzt, ist aus, bis Sie sie einschalten:

| Prüfung               | Einschalten mit      | Was sie sendet                                                        |
| --------------------- | -------------------- | --------------------------------------------------------------------- |
| SPF, DKIM, DMARC, ARC | `--auth`             | DNS-Abfragen nach den Einträgen des Absenders                         |
| DNS-Blocklisten       | `--dnsbl`, `--uribl` | Die IP-Adresse des Clients und Link-Domains, als DNS-Abfragen         |
| ClamAV                | `--clamav`           | Anhänge, an Ihr eigenes clamd                                         |
| Ein Sprachmodell      | `--llm`              | Eine Zusammenfassung der Nachricht, an den von Ihnen genannten Server |

Scans werden weder protokolliert noch gespeichert. [Sicherheit und Datenschutz](../../docs/security.md)


## Auf einem Server installieren

```sh
npm install --global spamscanner
```

Oder die eigenständige Binärdatei, mit Node.js und dem Modell eingebaut:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Das Installationsskript prüft die Binärdatei vor der Installation anhand der Datei `SHA256SUMS` des Releases, und jede Binärdatei hat eine signierte Build-Provenienz-Attestierung, die `gh attestation verify` prüft. Binärdateien gibt es für Linux (x64 und arm64), macOS und Windows. Die Linux-Binärdateien benötigen glibc, installieren Sie auf Alpine daher mit npm. [Erste Schritte](../../docs/getting-started.md)

Es gibt keine Update-Prüfung. Zum Aktualisieren führen Sie den Installationsbefehl erneut aus: Beide Befehle installieren das neueste Release.


## Als Dienst betreiben

Die Milter-, HTTP-, TCP- und spamd-Server lauschen auf 127.0.0.1, sofern `--host` nichts anderes angibt. Betreiben Sie sie als Benutzer ohne Privilegien, zum Beispiel unter systemd:

```ini
[Service]
ExecStart=/usr/local/bin/spamscanner milter --port 7831 --auth --subject-tag [SPAM]
User=spamscanner
Group=spamscanner
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
```

Die [vollständige Unit und ihre Einrichtung](../../docs/postfix.md#1-run-the-milter) stehen in der Postfix-Anleitung. Keiner der Server spricht TLS. Um einen von einem anderen Rechner aus zu erreichen, nutzen Sie ein privates Netz, einen SSH-Tunnel oder einen Reverse Proxy mit TLS.


## Ihren Mailserver anbinden

| Mailserver                              | Befehl                                   | Port   |
| --------------------------------------- | ---------------------------------------- | ------ |
| Postfix oder Sendmail                   | `spamscanner milter`                     | 7831   |
| Postfix, ohne je E-Mails abzuweisen     | `spamscanner filter`, ein Content-Filter | keiner |
| Exim, Haraka oder spamc                 | `spamscanner spamd`                      | 783    |
| Alles, was HTTP spricht                 | `spamscanner http`                       | 7832   |
| Ein einfacher TCP-Client                | `spamscanner server`                     | 7830   |
| Ein in Node.js geschriebener Mailserver | `import SpamScanner from 'spamscanner'`  | keiner |

Die Server können der Nachricht die Header `X-Spam-Flag`, `X-Spam-Score` und `X-Spam-Status` hinzufügen, und die Bibliothek liefert den Score und jeden ausgelösten Test. Anleitungen: [Spamfilter für Postfix](/postfix-spam-filter/), [andere Mailserver](../../docs/mail-servers.md) und [die HTTP-API](../../docs/http-api.md).


## Sprachmodelle lokal halten

Ein Sprachmodell ist optional und liest nur knappe Fälle: Eindeutiger Spam und eindeutiger Ham erreichen es nie. Mit Ollama läuft es auf demselben Server, sodass keine Nachricht ihn verlässt:

```sh
ollama pull qwen3.5:4b
spamscanner milter --llm ollama --llm-model qwen3.5:4b
```

`qwen3.5:4b` läuft auf einer CPU. Nutzen Sie stattdessen einen gehosteten Anbieter, werden personenbezogene Daten vor dem Senden aus der Nachricht entfernt. [Sprachmodelle](../../docs/llm.md)


## Mit Ihren eigenen E-Mails trainieren

Das mitgelieferte Modell ist mit öffentlichen Datensätzen trainiert. Ein Modell, das mit den E-Mails trainiert ist, die Ihr Server empfängt, ist besser, und es bleibt auf diesem Server:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out /var/lib/spamscanner/model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

Eine Modelldatei enthält gehashte Merkmalszählungen, keine Wörter und keinen Nachrichtentext. [Training](../../docs/training.md)


## Voraussetzungen

Node.js 18 oder neuer unter Linux, macOS oder Windows, oder mit einer eigenständigen Binärdatei gar nichts. ClamAV und Ollama sind optional und laufen als eigene Dienste.
