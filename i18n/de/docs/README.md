<!-- source: c56969e779c4 -->

# Dokumentation zu Spam Scanner

Spam Scanner ist ein Spamfilter für Node.js und die Kommandozeile, dessen Quellcode auf GitHub liegt. Er liest eine rohe E-Mail-Nachricht und entscheidet, ob sie Spam, Phishing oder Betrug ist oder Malware enthält, in jeder Sprache. Er läuft als Bibliothek, als Kommandozeilenwerkzeug, als Milter für Postfix oder Sendmail, als Content-Filter für Postfix, als SpamAssassin-kompatibler spamd-Server, als HTTP-API oder als TCP-Server.

Entwickelt wird er von [Forward Email](https://forwardemail.net) für die eigenen Mailserver.


## Wie eine Nachricht bewertet wird

Jede Prüfung fügt Punkte hinzu oder zieht sie ab. Die Summe entscheidet über das Ergebnis:

| Score      | Aktion   | Was ein Mailserver tut                |
| ---------- | -------- | ------------------------------------- |
| Unter 5    | `accept` | Stellt die Nachricht zu               |
| 5 bis 14,9 | `tag`    | Stellt sie als Spam markiert zu       |
| Ab 15      | `reject` | Weist sie während der SMTP-Sitzung ab |

Beide Schwellenwerte lassen sich ändern. Jedes Ergebnis listet die ausgelösten Tests mit ihren Punkten und einer Begründung auf, sodass sich jede Entscheidung erklären lässt.

Die Prüfungen:

* **Ein trainierter Klassifikator** liest die Wörter der Nachricht in jeder Schrift, die Form ihrer Links, ihren Absender und ihre Anhänge. Er wird mit öffentlichen Datensätzen trainiert ausgeliefert und lernt aus Ihren eigenen E-Mails. [Wie der Klassifikator funktioniert](how-it-works.md#the-classifier)
* **Phishing-Prüfungen** erkennen Doppelgänger-Domains (`paypa1.com`, `pаypal.com` mit kyrillischem а), Links, deren Text eine Adresse zeigt und deren Ziel eine andere ist, sowie Anzeigenamen, die eine Marke vorgeben. [Phishing](how-it-works.md#phishing)
* **Anhangsprüfungen** finden ausführbare Dateien, als Dokumente umbenannte ausführbare Dateien, doppelte Endungen, Tricks mit Rechts-nach-links-Dateinamen, ausführbare Dateien in ZIP-Archiven, Office-Makros und aktive PDF-Inhalte. ClamAV kann Anhänge auf Viren prüfen. [Anhänge](how-it-works.md#attachments)
* **Authentifizierung**: SPF, DKIM, DMARC und ARC, wenn die IP-Adresse des Clients bekannt ist. [Authentifizierung](how-it-works.md#authentication)
* **DNS-Blocklisten** für die IP-Adresse des Clients und die Domains in Links sowie die filternden Resolver von Cloudflare für bekannte Malware- und Erwachsenenseiten. [Blocklisten](how-it-works.md#blocklists)
* **Regeln** für Muster, die kein Klassifikator lernen muss: die GTUBE-Testzeichenkette, Betreffzeilen von Sextortion-Mails, Rechnungsbetrug über PayPal, Selbst-Spoofing und für KI-Filter versteckte Anweisungen. [Regeln](scoring.md#rules)
* **Ein Sprachmodell**, optional, liefert bei knappen Fällen eine zweite Meinung: ein lokales Modell über Ollama oder einen beliebigen OpenAI-kompatiblen Server, oder Claude, ChatGPT, Gemini und andere. [Sprachmodelle](llm.md)


## Wo Sie anfangen

* [Erste Schritte](getting-started.md): installieren und eine erste Nachricht prüfen.
* [Kommandozeile](cli.md): alle Befehle und Optionen.
* [Postfix und Sendmail](postfix.md): einen Mailserver mit dem Milter oder einem Content-Filter filtern.
* [Andere Mailserver](mail-servers.md): Exim, Haraka, Dovecot, procmail und alles, was eine HTTP-API aufrufen kann.
* [Training](training.md): den eigenen E-Mail-Bestand anlernen und das Ergebnis messen.
* [Sprachmodelle](llm.md): Anbieter, empfohlene offene Modelle, Datenschutz und Prompt Injection.
* [Sprachen](languages.md): wie Chinesisch, Arabisch, Thai und jede andere Schrift gelesen werden.
* [Forward Email](forward-email.md): wie Forward Email ihn nutzt und wie man von Version 5 oder 6 aktualisiert.
* [API-Referenz](api.md) und [Tests und Scores](scoring.md).
* [Sicherheit und Datenschutz](security.md): was den Rechner verlässt und wie sich das verhindern lässt.
