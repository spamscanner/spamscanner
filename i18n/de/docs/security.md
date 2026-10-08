<!-- source: 60f00f92b5aa -->

# Sicherheit und Datenschutz

Spam Scanner liest E-Mails, die privat sind, von Absendern, die feindselig sein können. Diese Seite listet auf, was er irgendwohin sendet und wie er mit dem umgeht, was er liest.


## Was den Rechner verlässt

Standardmäßig eine Sache: Die **Hostnamen von Links** in einer Nachricht werden bei den filternden Resolvern von Cloudflare abgefragt, 1.1.1.2 und 1.0.0.2 (Malware und Phishing) sowie 1.1.1.3 und 1.0.0.3 (zusätzlich Inhalte für Erwachsene). Das sind gewöhnliche DNS-Anfragen nach Namen wie `example.com`; kein Teil der Nachricht oder ihrer Adressen wird gesendet. Abschalten lassen sie sich mit `phishing: {cloudflare: false}` oder `--no-cloudflare`, nur die Prüfung auf Inhalte für Erwachsene mit `phishing: {adult: false}`.

Alles andere ist ausgeschaltet, bis es konfiguriert wird:

| Prüfung             | Sendet                                                                                   | An                                                                            |
| ------------------- | ---------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| `authentication`    | DNS-Anfragen nach den SPF-, DKIM-, DMARC- und ARC-Einträgen des Absenders                | Ihren Resolver oder `dnsServers`                                              |
| `dnsbl`             | Die umgekehrte IP-Adresse des Clients und Link-Domains, als DNS-Anfragen                 | Die Nameserver der Blocklisten, über Ihren Resolver oder `dns.servers`        |
| `llm`               | Eine Zusammenfassung der Nachricht, bei entfernten Anbietern ohne personenbezogene Daten | Den von Ihnen angegebenen Sprachmodell-Server ([Datenschutz](llm.md#privacy)) |
| `reputation.apiUrl` | IP-Adresse, Domain und Adresse des Absenders                                             | Den von Ihnen angegebenen Dienst                                              |
| `clamav`            | Anhänge                                                                                  | Ihr clamd, über dessen Socket                                                 |

Es gibt keine Telemetrie, keine Update-Prüfung und keine Downloads zur Laufzeit. Das Modell ist im Paket enthalten.


## Was gespeichert wird

Nichts, sofern nicht verlangt. Scans werden weder protokolliert noch gespeichert. `learn()` ändert den Klassifikator im Speicher; auf die Festplatte geschrieben wird er nur von `saveModel()`, `spamscanner learn` oder der Option `--out` der Server. Eine Modelldatei enthält gehashte Merkmalszählungen, keine Wörter und keinen Nachrichtentext.

Antworten des Sprachmodells werden im Speicher zwischengespeichert, mit einem Hash des Gesendeten als Schlüssel, sodass wiederholte Kopien derselben Nachricht nur einmal angefragt werden. DNS-Antworten werden zehn Minuten lang im Speicher zwischengespeichert.


## Feindselige Eingaben

* Anhänge werden an ihren Bytes erkannt, nie ausgeführt oder von einem anderen Programm geöffnet. ZIP-Archive werden aus ihrem zentralen Verzeichnis gelesen, mit einer Obergrenze für die Zahl der Einträge; verschachtelte Archive werden nicht entpackt.
* Der Nachrichtentext wird bis `maxLength` (100.000 Zeichen) gelesen, und die Server nehmen Nachrichten bis 25 MB an.
* Jede Netzwerkprüfung hat ein Zeitlimit (`timeout`, standardmäßig 10 Sekunden). Eine Prüfung, die fehlschlägt oder das Zeitlimit überschreitet, wird übersprungen, und der Scan endet ohne sie.
* Bereits in einer Nachricht vorhandene `X-Spam-*`-Header werden vom Milter, vom Content-Filter und von `--headers` entfernt, sodass Absender ihre eigenen E-Mails nicht als sauber markieren können.
* Den Spam-Urteils-Headern von Microsoft wird nur vertraut, wenn die Nachricht direkt von Microsofts Servern kam, und Received-Header werden nie verwendet, um zu entscheiden, woher eine Nachricht kam.
* Text, der sich an KI-Filter richtet, wird als Spam gewertet, und dem Sprachmodell wird mitgeteilt, dass die Nachricht Daten sind, keine Anweisungen. [Prompt Injection](llm.md#prompt-injection)


## Server

Milter-, HTTP-, TCP- und spamd-Server lauschen auf 127.0.0.1, sofern `--host` nichts anderes angibt. Die HTTP-API vergleicht ihr Token in konstanter Zeit und lehnt `/learn` ohne Token ab. Keiner von ihnen spricht TLS: Um sie über ein Netzwerk zu erreichen, verwenden Sie ein privates Netz, einen SSH-Tunnel oder einen Reverse Proxy mit TLS.

Führen Sie sie als unprivilegierten Benutzer aus. Die [systemd-Unit in der Anleitung zu Postfix](postfix.md#1-run-the-milter) fügt die übliche Härtung hinzu.


## Eine Sicherheitslücke melden

Melden Sie Sicherheitsprobleme vertraulich über die [Meldefunktion für Sicherheitslücken auf GitHub](https://github.com/spamscanner/spamscanner/security/advisories/new), nicht in öffentlichen Issues.
