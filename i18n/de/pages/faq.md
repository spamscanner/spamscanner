<!-- source: c93fa1a3f9c7 -->

<!--
label: FAQ
title: Häufig gestellte Fragen
description: Antworten zu Spam Scanner: wie genau er ist, welche Sprachen er unterstützt, was er übers Netz sendet, Sprachmodelle, SpamAssassin und Forward Email.
keywords: Spam Scanner FAQ, Fragen zum Spamfilter, Spamfilter Genauigkeit, Spamfilter Datenschutz
-->

# Häufig gestellte Fragen


## Was ist Spam Scanner?

Ein Spamfilter für Node.js, die Kommandozeile und Mailserver. Er liest eine rohe E-Mail-Nachricht und entscheidet, ob sie Spam, Phishing oder Betrug ist oder Malware enthält, mit einem Score und der Liste der Tests, die entschieden haben. Er läuft als Bibliothek, als Milter für Postfix und Sendmail, als SpamAssassin-kompatibler spamd-Server, als Content-Filter für Postfix, als HTTP-API oder als TCP-Server.


## Ist er kostenlos?

Seine [Lizenz](https://github.com/spamscanner/spamscanner/blob/master/LICENSE), die Business Source License 1.1, erlaubt jede Nutzung außer dem Angebot von Spamerkennung als Dienst für andere und nennt das Datum, an dem sie zur Apache License 2.0 wird.


## Wie genau ist er?

Auf zurückgehaltenen englischen Nachrichten aus seinen Trainingsdaten hat der mitgelieferte Klassifikator allein keinen Ham als Spam markiert und 97 % des Spams erkannt; die vollständigen Zahlen pro Sprache stehen in der [Anleitung zum Training](../../docs/training.md#the-bundled-model). Links, Anhänge, Authentifizierung, Blocklisten und ein Sprachmodell kommen hinzu. Der eigentliche Test sind Ihre eigenen E-Mails: `spamscanner eval` misst jedes Modell an beliebigen gelabelten E-Mails.


## Welche Sprachen unterstützt er?

Alle. Er segmentiert Wörter nach den Unicode-Regeln, auch Chinesisch, Japanisch und Thai, die ohne Leerzeichen auskommen. Hat das mitgelieferte Modell in einer Sprache wenige E-Mails gesehen, bleibt es unsicher, statt zu markieren, und ein Sprachmodell oder Ihr eigenes Training entscheidet. [Sprachen](../../docs/languages.md)


## Sendet er meine E-Mails irgendwohin?

Nein. Standardmäßig fragt er die Hostnamen von Links bei den filternden DNS-Resolvern von Cloudflare ab, sonst verlässt nichts den Rechner. Authentifizierung, Blocklisten, Sprachmodelle und Reputationsdienste sind ausgeschaltet, bis sie konfiguriert werden, und personenbezogene Daten werden entfernt, bevor E-Mails an ein gehostetes Sprachmodell gehen. [Sicherheit und Datenschutz](../../docs/security.md)


## Brauche ich ein Sprachmodell?

Nein. Es ist eine zweite Meinung für knappe Fälle. Ohne Sprachmodell entscheidet bei diesen Nachrichten allein der Score.


## Welches Sprachmodell sollte ich verwenden?

`qwen3.5:4b` über Ollama auf einer CPU oder `qwen3.5:9b` mit einer GPU. Beide stehen unter der Apache-Lizenz und lesen 201 Sprachen. Gehostete Modelle von Anthropic, OpenAI, Google und anderen funktionieren ebenfalls. [Empfohlene Modelle](../../docs/llm.md#recommended-open-models)


## Kann er SpamAssassin ersetzen?

In den meisten Setups ja: Er spricht das Protokoll von spamd, sodass spamc, Exim und Haraka unverändert funktionieren, und er schreibt dieselben `X-Spam-*`-Header. Die Regeldateien von SpamAssassin führt er nicht aus. [Alternative zu SpamAssassin](/spamassassin-alternative/)


## Weist er legitime E-Mails ab?

Das Abweisen von E-Mails ist standardmäßig ausgeschaltet: Der Milter markiert nur. Mit `--reject` werden nur Nachrichten mit 15 oder mehr Punkten abgewiesen, mit einem temporären Fehler 451, sodass Absender es erneut versuchen und sich ein Fehler durch Ändern einer Einstellung beheben lässt. Der Content-Filter weist während der SMTP-Sitzung nie etwas ab.


## Wie trainiere ich ihn mit meinen E-Mails?

`spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out model.json`, danach `--model model.json`. mbox-Dateien, Maildirs, Ordner mit `.eml`-Dateien und Datensätze im CSV- oder JSON-Lines-Format funktionieren alle. [Training](../../docs/training.md)


## Funktioniert er ohne Node.js?

Ja: Eigenständige Binärdateien für Linux, macOS und Windows enthalten Node.js und das Modell. `curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash`.


## Wer entwickelt ihn?

[Forward Email](https://forwardemail.net), für die eigenen Mailserver.
