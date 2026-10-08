<!-- source: 9537a0e62eb0 -->

# Sprachen

Spam kommt in jeder Sprache, gewöhnliche Post ebenso. Spam Scanner liest beides und ist vorsichtig bei Sprachen, über die er wenig weiß: Ein Spamfilter, der jede arabische oder chinesische Nachricht markiert, ist schlechter als gar keiner.


## Jede Schrift lesen

* **Wörter.** Text wird mit `Intl.Segmenter` getrennt. Er folgt den Unicode-Regeln für Wortgrenzen und verwendet Wörterbücher für Chinesisch, Japanisch, Thai, Laotisch, Khmer und Birmanisch, Schriften, die ohne Leerzeichen geschrieben werden. Lange Texte werden zuerst in Stücke geteilt, weil der Segmenter in Node.js 18 bei sehr langen Strings langsam wird.
* **Normalisierung.** Unicode NFKC macht aus Vollbreitenbuchstaben und den meisten Zierbuchstaben (𝐅𝐑𝐄𝐄, Ⓕⓡⓔⓔ) einfache Buchstaben. Kleingeschrieben wird nach Unicode-Regeln.
* **Tarnungen.** Unsichtbare Zeichen in Wörtern (`free` mit einem Leerzeichen ohne Breite zwischen zwei Buchstaben, weiche Trennstriche) werden entfernt und gezählt. Wörter, die Alphabete mischen, etwa `pаypal` mit einem kyrillischen а, werden auf ein Alphabet zurückgeführt und gezählt. Als Buchstaben verwendete Ziffern (`v1agra`) werden umgewandelt. Jede Tarnung ist ein eigenes Merkmal, und drei oder mehr unsichtbare Zeichen oder zwei oder mehr gemischte Wörter addieren zusätzlich Punkte.


## Die Sprache erkennen

Die Sprache jeder Nachricht wird an ihrer Schrift erkannt und, bei Schriften, die viele Sprachen teilen, an ihren Buchstaben:

* Hangul ist Koreanisch; Hiragana und Katakana bedeuten Japanisch; Thai, Griechisch, Hebräisch, Armenisch, Georgisch, Bengalisch, Tamil und andere Schriften, die nur eine Sprache verwendet, benennen diese direkt.
* Kyrillische Buchstaben, die es nur in einer Sprache gibt, entscheiden zwischen Ukrainisch (і, ї, є, ґ), Belarussisch (ў), Serbisch (ђ, ћ, џ), Mazedonisch (ѓ, ќ, ѕ) und Russisch (ы, э, ё).
* Text in Schriften, die mehrere Sprachen teilen (Lateinisch, Kyrillisch, Arabisch, Devanagari und andere), geht, wenn er für ein Urteil lang genug ist, an [franc](https://github.com/wooorm/franc), beschränkt auf in E-Mails verbreitete Sprachen, damit kurze Nachrichten nicht mit seltenen Sprachen gekennzeichnet werden.

Die Sprache steht in `result.language`, und `allowedLanguages: ['en', 'de']` (`--allow-language en,de`) addiert 3 Punkte für E-Mails, die sicher als eine andere Sprache erkannt werden.


## Sprachen, über die das Modell wenig weiß

Ein Klassifikator lernt aus Beispielen. Öffentliche Spam-Datensätze enthalten weit mehr fremdsprachigen Spam als fremdsprachigen Ham, daher lernt ein naiver Klassifikator, dass chinesischer oder arabischer Text an sich Spam bedeutet. Spam Scanner gleicht das auf drei Arten aus:

1. **Die Sprache ist nie ein Indiz.** Erkannte Sprache und Schrift werden nicht als Hinweise verwendet.
2. **Wörter werden innerhalb ihrer Sprache gewichtet.** Die Spam-Wahrscheinlichkeit eines Worts wird anhand der Zahl der Spam- und Ham-Nachrichten berechnet, die der Klassifikator in der Sprache der Nachricht gesehen hat, nicht in allen Sprachen. Ein portugiesisches Alltagswort bleibt in einem Modell, das vor allem portugiesischen Spam gesehen hat, neutral.
3. **Konfidenz folgt der Abdeckung.** Das Ergebnis wird umso stärker in Richtung „unsicher“ gezogen, je weniger Nachrichten jeder Art der Klassifikator in dieser Sprache gesehen hat: Volle Konfidenz erfordert 1.000 von jeder Art (oder bei kleinen persönlichen Modellen 2 % der kleineren Klasse). Eine Sprache ohne Ham in den Trainingsdaten erhält immer „unsicher“.

Das mitgelieferte Modell hat die [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset) nie gesehen, SMS-Nachrichten, die maschinell in 21 Sprachen übersetzt wurden. Vor diesen Regeln markierte es 5,7 % dieses Hams als Spam, darunter 55 % des portugiesischen und 41 % des französischen. Mit ihnen sind es 0,18 %: keine auf Chinesisch, Arabisch, Koreanisch, Japanisch, Hindi, Portugiesisch, Französisch oder in 20 weiteren Sprachen, und 0,27 % auf Englisch.


## Spam in diesen Sprachen erkennen

„Unsicher“ ist sicher, erkennt aber keinen Spam. Drei Dinge tun es:

* **Die anderen Prüfungen** hängen nicht von der Sprache ab: Doppelgänger-Domains, irreführende Links, ausführbare Dateien, Makros, Authentifizierung, Blocklisten, die Regeln.
* **Ein Sprachmodell.** Moderne offene Modelle lesen 100 bis 200 Sprachen, und Spam Scanner fragt eines, sobald der Klassifikator unsicher ist. Die End-to-End-Tests prüfen, dass `qwen3.5:4b` Spam auf Chinesisch, Arabisch, Koreanisch, Hindi und Thai erkennt und Ham durchlässt. [Sprachmodelle](llm.md)
* **Training mit den eigenen E-Mails.** In einem Modell, das mit den eigenen E-Mails trainiert ist, geben einige hundert Nachrichten jeder Art in einer Sprache dem Klassifikator dort volle Konfidenz. [Training](training.md) und [ein optionaler Datensatz](training.md#more-languages), der 21 Sprachen hinzufügt.
