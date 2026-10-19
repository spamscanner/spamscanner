<!-- source: 1d7373f991c2 -->

# Sicherheit und Datenschutz

Spam Scanner liest E-Mails, die privat sind, von Absendern, die feindselig sein können. Diese Seite listet auf, was er irgendwohin sendet und wie er mit dem umgeht, was er liest.


## Was den Rechner verlässt

Standardmäßig eine Sache: Die **Hostnamen von Links** in einer Nachricht werden bei den filternden Resolvern von Cloudflare abgefragt, 1.1.1.2 und 1.0.0.2 (Malware und Phishing) sowie 1.1.1.3 und 1.0.0.3 (zusätzlich Inhalte für Erwachsene). Das sind gewöhnliche DNS-Anfragen nach Namen wie `example.com`; kein Teil der Nachricht oder ihrer Adressen wird gesendet. Abschalten lassen sie sich mit `phishing: {cloudflare: false}` oder `--no-cloudflare`, nur die Prüfung auf Inhalte für Erwachsene mit `phishing: {adult: false}`.

Alles andere ist ausgeschaltet, bis es konfiguriert wird:

| Prüfung             | Sendet                                                                                                                           | An                                                                            |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| `authentication`    | DNS-Anfragen nach den SPF-, DKIM-, DMARC- und ARC-Einträgen des Absenders                                                        | Ihren Resolver oder `dnsServers`                                              |
| `dnsbl`             | Die umgekehrte IP-Adresse des Clients und Link-Domains, als DNS-Anfragen                                                         | Die Nameserver der Blocklisten, über Ihren Resolver oder `dns.servers`        |
| `llm`               | Eine Zusammenfassung der Nachricht, bei entfernten Anbietern ohne personenbezogene Daten                                         | Den von Ihnen angegebenen Sprachmodell-Server ([Datenschutz](llm.md#privacy)) |
| `reputation.apiUrl` | IP-Adresse und geprüfter Hostname des Clients sowie die Adressen in From, im Umschlagabsender und in Reply-To samt ihren Domains | Den von Ihnen angegebenen Dienst                                              |
| `clamav`            | Anhänge                                                                                                                          | Ihr clamd, über dessen Socket                                                 |

Es gibt keine Telemetrie, keine Update-Prüfung und keine Downloads zur Laufzeit. Das Modell ist im Paket enthalten.


## Was gespeichert wird

Nichts, sofern nicht verlangt. Scans werden weder protokolliert noch gespeichert. `learn()` ändert den Klassifikator im Speicher; auf die Festplatte geschrieben wird er nur von `saveModel()`, `spamscanner learn` oder der Option `--out` der Server. Eine Modelldatei enthält gehashte Merkmalszählungen, keine Wörter und keinen Nachrichtentext.

Antworten des Sprachmodells werden im Speicher zwischengespeichert, mit einem Hash des Gesendeten als Schlüssel, sodass wiederholte Kopien derselben Nachricht nur einmal angefragt werden. DNS-Antworten werden zehn Minuten lang im Speicher zwischengespeichert und die Antworten eines Reputationsdienstes fünf Minuten (`reputation.cacheTtl`; eine fehlgeschlagene Anfrage eine Minute).


## Feindselige Eingaben

* Anhänge werden an ihren Bytes erkannt, nie ausgeführt oder von einem anderen Programm geöffnet. ZIP-Archive werden aus ihrem zentralen Verzeichnis gelesen, mit Obergrenzen für die Zahl der Einträge (2000) und für die Bytes ihrer Namen (1 MiB; ein Name über 1 KiB behält seine ersten und letzten 512 Bytes, und Befunde zeigen höchstens 100 Zeichen davon), wobei jeder Eintrag einmal gelesen wird, wie viele Verzeichniseinträge auch auf ihn verweisen; nichts wird dekomprimiert, daher werden Programme in verschachtelten oder komprimierten Archiven nicht gesehen. Angehängte Nachrichten (`message/rfc822` oder Anhänge, deren Dateiname auf `.eml` endet) werden bis zu drei Ebenen tief geöffnet, für höchstens 100 ihrer Anhänge und insgesamt 25 MB angehängter Nachrichten; die eigenen Anhänge der Nachricht werden immer alle untersucht. Eine Nachricht jenseits der Grenzen des MIME-Parsers (mehr als 1000 Teile oder der Header eines Teils über 1 MB) wird gelesen, soweit der Parser es zulässt (ihre ersten Teile, mit einem übergroßen Header gekürzt, damit ihr Absender weiter zählt), und erhält `MIME_TOO_COMPLEX`, das keine Gutschrift ausgleicht; ClamAV liest sie vollständig. Eine angehängte Nachricht, an der der Parser scheitert, erhält es ebenfalls und lässt die Prüfung nie fehlschlagen. Adressfelder werden bis zu je 16 KB (2000 Adressen, 16 verschachtelte Gruppen) und insgesamt 64 KB je Nachricht gelesen, gekürzt nur am Ende einer ganzen Adresse, da der Adressparser Zeit braucht, die mit dem Quadrat der Zahl der Adressen wächst; mailauth liest From und Return-Path ebenso begrenzt (die anderen Felder so, wie sie sind, damit eine Signatur über sie gültig bleibt), und ein Header, dessen Lesen mehr als lineare Zeit bräuchte (Tausende gefalteter Zeilen oder Signaturen, die Tausende Felder nennen), wird gekürzt. Ein gekürztes From-Feld lässt DMARC fehlschlagen und gibt nichts frei. HTML wird von Spam Scanners eigenem Parser gelesen, in linearer Zeit, wie tief es auch verschachtelt ist.
* Der Nachrichtentext wird bis `maxLength` (100.000 Zeichen) gelesen, und die Server nehmen Nachrichten bis 25 MB an. Links werden bis `phishing.maxLength` (1.000.000 Zeichen) gelesen.
* Jede Netzwerkprüfung hat ein Zeitlimit (`timeout`, standardmäßig 10 Sekunden). Eine Prüfung, die fehlschlägt oder das Zeitlimit überschreitet, wird übersprungen, und der Scan endet ohne sie. Authentifizierung und das Bildmodell (die ersten 10 Bilder) enden jeweils insgesamt innerhalb dieser Zeit: Die Authentifizierung sendet danach keine DNS-Anfrage mehr und nicht mehr als 300 für eine Nachricht (Raum für SPF an den Grenzen von RFC 7208, mit DKIM, ARC, DMARC und BIMI) und prüft nur die ersten 8 DKIM-Signaturen einer Nachricht (mailauth selbst liest höchstens 50 ARC-Sätze). Der `Authentication-Results`-Header, den der Milter hinzufügt, enthält höchstens 8 KiB an Ergebnissen. ClamAV (vier Anhänge gleichzeitig) hat ein eigenes Limit für alle Anhänge einer Nachricht (`clamav.timeout`, 60 Sekunden), und Anhänge, die es nicht prüfen konnte, stehen in `results.virusScanErrors`. Das Sprachmodell hat sein eigenes Zeitlimit (`llm.timeout`).
* Die Positivliste vertraut nur dem, was ein Absender nicht fälschen kann: der Adresse und dem geprüften Hostnamen des Clients sowie Absenderdomains, die die Authentifizierung bestätigt. [Positiv- und Sperrliste](api.md#allowlist-and-denylist)
* Bereits in einer Nachricht vorhandene `X-Spam-*`-Header werden vom Milter, vom Content-Filter und von `--headers` entfernt, sodass Absender ihre eigenen E-Mails nicht als sauber markieren können.
* Den Spam-Urteils-Headern von Microsoft wird nur vertraut, wenn die Nachricht direkt von Microsofts Servern kam, und Received-Header werden nie verwendet, um zu entscheiden, woher eine Nachricht kam.
* Text, der sich an KI-Filter richtet, wird als Spam gewertet, und dem Sprachmodell wird mitgeteilt, dass die Nachricht Daten sind, keine Anweisungen. [Prompt Injection](llm.md#prompt-injection)


## Server

Milter-, HTTP-, TCP- und spamd-Server lauschen auf 127.0.0.1, sofern `--host` nichts anderes angibt. Die HTTP-API vergleicht ihr Token in konstanter Zeit und lehnt `/learn` ohne Token ab. Keiner von ihnen spricht TLS: Um sie über ein Netzwerk zu erreichen, verwenden Sie ein privates Netz, einen SSH-Tunnel oder einen Reverse Proxy mit TLS.

Führen Sie sie als unprivilegierten Benutzer aus. Die [systemd-Unit in der Anleitung zu Postfix](postfix.md#1-run-the-milter) fügt die übliche Härtung hinzu.


## Eine Sicherheitslücke melden

Melden Sie Sicherheitsprobleme vertraulich über die [Meldefunktion für Sicherheitslücken auf GitHub](https://github.com/spamscanner/spamscanner/security/advisories/new), nicht in öffentlichen Issues.
