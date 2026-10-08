<!-- source: 6f6b765c5fc1 -->

# Tests und Scores

Eine Nachricht ist ab 5 Punkten Spam und wird ab 15 abgewiesen. Jeder der folgenden Tests fügt Punkte hinzu oder zieht sie ab; das Ergebnis listet die ausgelösten auf.

Die Schwellenwerte ändern Sie mit `threshold` und `rejectThreshold`. Punkte ändern Sie mit `scores`, entweder über den Einstellungsschlüssel (`scores: {deceptiveLink: 4}`) oder über den Testnamen, der die Punkte dieses Tests festlegt (`scores: {FROM_NAME_BRAND: 4}`).


## Klassifikator

| Test                       | Punkte         | Bedeutung                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| -------------------------- | -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BAYES_00` bis `BAYES_999` | −2,5 bis +6,25 | Die Spam-Wahrscheinlichkeit des Klassifikators auf einer Log-Odds-Skala: 2,4 Punkte bei 90 %, 5 bei 99 % und 6,25 bei 99,9 %, sodass der Klassifikator allein nur dann Spam markiert, wenn er sich zu mindestens 99 % sicher ist. Der Name gibt den Bereich an: `BAYES_999` ist 99,9 % oder mehr, `BAYES_99` 99 % bis 99,9 %, `BAYES_50` 40 % bis 60 %. Die Einstellungsschlüssel `bayesHam` und `bayesSpam` legen die beiden Enden fest. |


## Phishing und Links

| Test                        | Punkte | Einstellungsschlüssel | Bedeutung                                                                           |
| --------------------------- | -----: | --------------------- | ----------------------------------------------------------------------------------- |
| `PHISHING_LOOKALIKE_DOMAIN` |      5 | `homograph`           | Die Domain eines Links ahmt mit ähnlichen oder vertauschten Zeichen eine Marke nach |
| `MIXED_SCRIPT_DOMAIN`       |      3 | `mixedScriptDomain`   | Ein Domain-Label mischt Alphabete                                                   |
| `BRAND_IN_DOMAIN`           |    1,5 | `brandInDomain`       | Ein Markenname in der Domain eines anderen                                          |
| `TYPO_DOMAIN`               |      1 | `typoDomain`          | Einen Buchstaben von der Domain einer Marke entfernt                                |
| `DECEPTIVE_LINK`            |      3 | `deceptiveLink`       | Ein Link zeigt eine Adresse und führt zu einer anderen                              |
| `MALICIOUS_DOMAIN`          |      6 | `maliciousDomain`     | Der Malware-Resolver von Cloudflare blockiert eine verlinkte Domain                 |
| `ADULT_DOMAIN`              |      2 | `adultDomain`         | Der Familien-Resolver von Cloudflare blockiert eine verlinkte Domain                |
| `URIBL_<LIST>`              |      5 | `uriblListed`         | Eine verlinkte Domain steht auf einer Domain-Blockliste, zum Beispiel `URIBL_DBL`   |


## Anhänge

| Test                    |   Punkte | Einstellungsschlüssel                    | Bedeutung                                                          |
| ----------------------- | -------: | ---------------------------------------- | ------------------------------------------------------------------ |
| `EXECUTABLE_ATTACHMENT` |       10 | `executable`                             | Ein Programm oder Skript                                           |
| `DISGUISED_EXECUTABLE`  |       12 | `disguisedExecutable`                    | Ein Programm, das wie ein Dokument oder Bild benannt ist           |
| `DOUBLE_EXTENSION`      |        6 | `doubleExtension`                        | Ein Name wie `invoice.pdf.exe`                                     |
| `RTL_OVERRIDE_FILENAME` |        6 | `rtlOverride`                            | Ein Rechts-nach-links-Steuerzeichen verbirgt die echte Endung      |
| `EXECUTABLE_IN_ARCHIVE` |        8 | `executableInArchive`                    | Ein Programm in einer ZIP-Datei                                    |
| `ENCRYPTED_ARCHIVE`     |        2 | `encryptedArchive`                       | Ein Archiv, das Scanner nicht öffnen können                        |
| `MACRO_ATTACHMENT`      |        4 | `macro`                                  | Eine Office-Datei mit Makros                                       |
| `PDF_ACTIVE_CONTENT`    |        3 | `pdfActive`                              | Ein PDF mit JavaScript, Launch-Aktionen oder eingebetteten Dateien |
| `RTF_EMBEDDED_OBJECT`   |        4 | `rtfObject`                              | Eine RTF-Datei mit eingebetteten Objekten                          |
| `HTML_ATTACHMENT`       | 1 oder 3 | `htmlAttachment`, `activeHtmlAttachment` | Eine HTML-Datei; 3, wenn sie Skripte oder Formulare enthält        |
| `VIRUS`                 |      100 | `virus`                                  | ClamAV hat einen Virus gefunden                                    |


## Regeln

| Test                      | Punkte | Bedeutung                                                                                                        |
| ------------------------- | -----: | ---------------------------------------------------------------------------------------------------------------- |
| `GTUBE`                   |   1000 | Die GTUBE-Testzeichenkette                                                                                       |
| `SEXTORTION_SUBJECT`      |      6 | Ein Betreff, wie ihn Sextortion-Betrug und Betrug mit Kontoübernahmen verwenden                                  |
| `PAYPAL_INVOICE`          |      6 | Eine PayPal-Rechnung oder Zahlungsaufforderung, ein für Betrug missbrauchter Kanal                               |
| `MICROSOFT_SPAM_VERDICT`  |      5 | Microsoft hat die Nachricht vor dem Weiterleiten als Spam markiert (nur von Microsofts Servern vertrauenswürdig) |
| `MICROSOFT_HIGH_SCL`      |      3 | Microsoft hat ihr einen hohen Spam Confidence Level gegeben (ebenso)                                             |
| `PROMPT_INJECTION`        |      3 | Text, der sich an einen KI-Filter richtet                                                                        |
| `SELF_SPOOF`              |      3 | Gibt vor, von der eigenen Domain des Empfängers zu stammen, und authentifiziert sich nicht                       |
| `FROM_NAME_OTHER_ADDRESS` |    2,5 | Der Anzeigename enthält eine andere E-Mail-Adresse                                                               |
| `FROM_NAME_BRAND`         |      2 | Der Anzeigename gibt eine Marke vor, zu der die Adresse nicht gehört                                             |
| `DATE_IN_FUTURE`          |      1 | Mehr als einen Tag in die Zukunft datiert                                                                        |
| `MISSING_DATE`            |    0,5 | Kein Date-Header                                                                                                 |
| `MISSING_MESSAGE_ID`      |    0,5 | Kein Message-ID-Header                                                                                           |

Regeln, die mindestens den Spam-Schwellenwert erreichen, erscheinen wie in früheren Versionen auch in `results.arbitrary`.


## Verschleierung und Sprache

| Test                   | Punkte | Einstellungsschlüssel | Bedeutung                                                                   |
| ---------------------- | -----: | --------------------- | --------------------------------------------------------------------------- |
| `INVISIBLE_CHARACTERS` |      2 | `invisibleCharacters` | Drei oder mehr unsichtbare Zeichen im Text                                  |
| `MIXED_SCRIPT_WORDS`   |    2,5 | `mixedScriptWords`    | Zwei oder mehr Wörter mischen Buchstaben aus verschiedenen Alphabeten       |
| `STYLED_LETTERS`       |    1,5 | `styledLetters`       | Mathematische oder umrahmte Buchstaben, die sich als normaler Text ausgeben |
| `LANGUAGE_NOT_ALLOWED` |      3 | `languageNotAllowed`  | Nicht in `allowedLanguages`                                                 |


## Authentifizierung

Benötigt die IP-Adresse des Clients und `authentication: true`.

| Test           | Punkte | Einstellungsschlüssel (in `authentication.weights`) |
| -------------- | -----: | --------------------------------------------------- |
| `SPF_PASS`     |   −0,5 | `spfPass`                                           |
| `SPF_FAIL`     |      2 | `spfFail`                                           |
| `SPF_SOFTFAIL` |      1 | `spfSoftfail`                                       |
| `DKIM_PASS`    |   −0,5 | `dkimPass`                                          |
| `DKIM_FAIL`    |      1 | `dkimFail`                                          |
| `DMARC_PASS`   |   −1,5 | `dmarcPass`                                         |
| `DMARC_FAIL`   |    3,5 | `dmarcFail`                                         |
| `ARC_PASS`     |   −0,5 | `arcPass`                                           |
| `ARC_FAIL`     |      1 | `arcFail`                                           |


## Reputation und Blocklisten

| Test           | Punkte | Einstellungsschlüssel | Bedeutung                                                                     |
| -------------- | -----: | --------------------- | ----------------------------------------------------------------------------- |
| `DENYLISTED`   |    100 | `denylisted`          | IP-Adresse, Domain oder Adresse des Absenders steht auf der Sperrliste        |
| `ALLOWLISTED`  |    −20 | `allowlisted`         | Sie steht auf der Erlaubtliste                                                |
| `TRUTH_SOURCE` |     −5 | `truthSource`         | Ein Reputationsdienst stuft den Absender als vertrauenswürdig ein             |
| `RBL_<LIST>`   |      4 | `rblListed`           | Die IP-Adresse des Clients steht auf einer Blockliste, zum Beispiel `RBL_ZEN` |


## Sprachmodell und optionale Modelle

| Test                                                  | Punkte    | Einstellungsschlüssel | Bedeutung                                                             |
| ----------------------------------------------------- | --------- | --------------------- | --------------------------------------------------------------------- |
| `LLM_SPAM`, `LLM_PHISHING`, `LLM_SCAM`, `LLM_MALWARE` | bis zu +6 | `llmSpam`             | Das Urteil des Modells, multipliziert mit seiner Konfidenz            |
| `LLM_HAM`                                             | bis zu −3 | `llmHam`              | Ebenso                                                                |
| `TOXIC_CONTENT`                                       | 3         | `toxicity`            | Ein von Ihnen bereitgestelltes Toxizitätsmodell hat den Text markiert |
| `NSFW_IMAGE`                                          | 3         | `nsfw`                | Ein von Ihnen bereitgestelltes Bildmodell hat ein Bild markiert       |
