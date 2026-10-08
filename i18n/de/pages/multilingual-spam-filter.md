<!-- source: 0ad167ddd34e -->

<!--
label: Mehrsprachiger Spamfilter
title: Mehrsprachiger Spamfilter für Chinesisch, Arabisch und Russisch
description: Wie Spam Scanner Spam in jeder Sprache filtert: Unicode-Wortsegmentierung, aufgelöste Tarnungen und keine Fehlalarme bei Sprachen, die das Modell kaum kennt.
keywords: mehrsprachiger Spamfilter, Spamfilter Chinesisch, Spamfilter Arabisch, Spamfilter Russisch, Spamfilter Japanisch, Unicode Spamerkennung, Homoglyphen Spam
-->

# Mehrsprachiger Spamfilter

Viele Spamfilter wurden für Englisch gebaut. Spam in anderen Sprachen schlüpft an ihnen vorbei, und gewöhnliche Post in anderen Sprachen wird wegen ihrer Schrift markiert. Spam Scanner ist darauf ausgelegt, beides zu vermeiden.


## Die Wörter lesen

Wörter werden mit `Intl.Segmenter` gefunden, also nach den Unicode-Regeln für Wortgrenzen mit Wörterbüchern für Chinesisch, Japanisch, Thai, Laotisch, Khmer und Birmanisch. Ein chinesischer Satz wird zu Wörtern wie 恭喜, 获得 und 大奖, nicht zu einer langen Zeichenkette, die sich nie wiederholt.

Tarnungen werden vor dem Zählen aufgelöst: unsichtbare Zeichen in Wörtern, kyrillische oder griechische Buchstaben in lateinischen Wörtern (`pаypal`), Ziffern statt Buchstaben (`v1agra`) und mathematische oder umrahmte Buchstaben (𝐅𝐑𝐄𝐄). Jede Tarnung ist zusätzlich ein eigener Hinweis.


## Nicht markieren, was er nicht kennt

Öffentliche Spam-Datensätze enthalten weit mehr fremdsprachigen Spam als fremdsprachigen Ham, daher lernt ein naiver Klassifikator, dass arabischer oder koreanischer Text an sich Spam ist. Spam Scanner verwendet die Sprache nie als Hinweis, gewichtet jedes Wort anhand der Spam- und Ham-Zählungen seiner eigenen Sprache und bleibt umso eher „unsicher“, je weniger Ham er in einer Sprache gesehen hat.

In einem Test mit SMS-Nachrichten in 21 Sprachen, die das mitgelieferte Modell nie gesehen hatte, senkte das die Fehlalarme auf Chinesisch, Arabisch, Koreanisch, Japanisch, Hindi, Bengalisch, Urdu, Türkisch, Ukrainisch und Schwedisch auf null.


## Spam in jeder Sprache erkennen

* **Prüfungen, die keine Wörter lesen:** Doppelgänger-Domains, irreführende Links, ausführbare Dateien, Makros, SPF, DKIM, DMARC und Blocklisten.
* **Ein Sprachmodell** für unsichere Nachrichten. Offene Modelle wie Qwen 3.5 und Gemma 4 lesen 140 bis 200 Sprachen; die End-to-End-Tests prüfen Spam und Ham auf Chinesisch, Arabisch, Koreanisch, Hindi und Thai mit einem echten Modell.
* **Ihre eigenen E-Mails.** Einige hundert Nachrichten jeder Art in einer Sprache geben einem Modell, das mit Ihren E-Mails trainiert ist, dort volle Konfidenz.

```sh
spamscanner scan message.eml --llm ollama --llm-model qwen3.5:4b
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out my-model.json
```

Um nur bestimmte Sprachen anzunehmen, addiert `--allow-language en,de` Punkte für E-Mails, die sicher als eine andere Sprache erkannt werden.

[Sprachen im Detail](../../docs/languages.md)
