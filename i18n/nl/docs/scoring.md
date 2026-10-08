<!-- source: 6f6b765c5fc1 -->

# Tests en scores

Een bericht is spam bij 5 punten en wordt geweigerd bij 15. Elke test hieronder voegt punten toe of trekt ze af; het resultaat noemt de tests die afgingen.

Pas de drempels aan met `threshold` en `rejectThreshold`. Pas punten aan met `scores`, via de instellingssleutel (`scores: {deceptiveLink: 4}`) of via de testnaam, die de punten van die test vastzet (`scores: {FROM_NAME_BRAND: 4}`).


## Classifier

| Test                       | Punten         | Betekenis                                                                                                                                                                                                                                                                                                                                                                         |
| -------------------------- | -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BAYES_00` tot `BAYES_999` | -2,5 tot +6,25 | De spamkans van de classifier, op een log-oddsschaal: 2,4 punten bij 90%, 5 bij 99% en 6,25 bij 99,9%, zodat de classifier op zichzelf alleen spam markeert als hij minstens 99% zeker is. De naam geeft de band aan: `BAYES_999` is 99,9% of meer, `BAYES_99` 99% tot 99,9%, `BAYES_50` 40% tot 60%. De instellingssleutels `bayesHam` en `bayesSpam` bepalen de twee uitersten. |


## Phishing en links

| Test                        | Punten | Instellingssleutel  | Betekenis                                                                       |
| --------------------------- | -----: | ------------------- | ------------------------------------------------------------------------------- |
| `PHISHING_LOOKALIKE_DOMAIN` |      5 | `homograph`         | Het domein van een link bootst een merk na met lookalike- of verwisselde tekens |
| `MIXED_SCRIPT_DOMAIN`       |      3 | `mixedScriptDomain` | Een domeinlabel mengt alfabetten                                                |
| `BRAND_IN_DOMAIN`           |    1,5 | `brandInDomain`     | Een merknaam in het domein van iemand anders                                    |
| `TYPO_DOMAIN`               |      1 | `typoDomain`        | Eén letter verschil met het domein van een merk                                 |
| `DECEPTIVE_LINK`            |      3 | `deceptiveLink`     | Een link toont het ene adres en gaat naar een ander                             |
| `MALICIOUS_DOMAIN`          |      6 | `maliciousDomain`   | De malware-resolver van Cloudflare blokkeert een gelinkt domein                 |
| `ADULT_DOMAIN`              |      2 | `adultDomain`       | De gezinsresolver van Cloudflare blokkeert een gelinkt domein                   |
| `URIBL_<LIST>`              |      5 | `uriblListed`       | Een gelinkt domein staat op een domeinblocklist, bijvoorbeeld `URIBL_DBL`       |


## Bijlagen

| Test                    | Punten | Instellingssleutel                       | Betekenis                                                   |
| ----------------------- | -----: | ---------------------------------------- | ----------------------------------------------------------- |
| `EXECUTABLE_ATTACHMENT` |     10 | `executable`                             | Een programma of script                                     |
| `DISGUISED_EXECUTABLE`  |     12 | `disguisedExecutable`                    | Een programma met de naam van een document of afbeelding    |
| `DOUBLE_EXTENSION`      |      6 | `doubleExtension`                        | Een naam zoals `invoice.pdf.exe`                            |
| `RTL_OVERRIDE_FILENAME` |      6 | `rtlOverride`                            | Een right-to-left-override verbergt de echte extensie       |
| `EXECUTABLE_IN_ARCHIVE` |      8 | `executableInArchive`                    | Een programma in een ZIP-bestand                            |
| `ENCRYPTED_ARCHIVE`     |      2 | `encryptedArchive`                       | Een archief dat scanners niet kunnen openen                 |
| `MACRO_ATTACHMENT`      |      4 | `macro`                                  | Een Office-bestand met macro's                              |
| `PDF_ACTIVE_CONTENT`    |      3 | `pdfActive`                              | Een pdf met JavaScript, startacties of ingesloten bestanden |
| `RTF_EMBEDDED_OBJECT`   |      4 | `rtfObject`                              | Een RTF-bestand met ingesloten objecten                     |
| `HTML_ATTACHMENT`       | 1 of 3 | `htmlAttachment`, `activeHtmlAttachment` | Een HTML-bestand; 3 als het scripts of formulieren bevat    |
| `VIRUS`                 |    100 | `virus`                                  | ClamAV heeft een virus gevonden                             |


## Regels

| Test                      | Punten | Betekenis                                                                                                             |
| ------------------------- | -----: | --------------------------------------------------------------------------------------------------------------------- |
| `GTUBE`                   |   1000 | De GTUBE-teststring                                                                                                   |
| `SEXTORTION_SUBJECT`      |      6 | Een onderwerpregel die bij sextortion en accountovername-oplichting wordt gebruikt                                    |
| `PAYPAL_INVOICE`          |      6 | Een PayPal-factuur of betaalverzoek, een kanaal dat voor oplichting wordt misbruikt                                   |
| `MICROSOFT_SPAM_VERDICT`  |      5 | Microsoft markeerde het bericht als spam voordat het werd doorgegeven (alleen vertrouwd van de servers van Microsoft) |
| `MICROSOFT_HIGH_SCL`      |      3 | Microsoft gaf het een hoog spam confidence level (idem)                                                               |
| `PROMPT_INJECTION`        |      3 | Tekst gericht aan een AI-filter                                                                                       |
| `SELF_SPOOF`              |      3 | Zegt van het eigen domein van de ontvanger te komen en authenticeert niet                                             |
| `FROM_NAME_OTHER_ADDRESS` |    2,5 | De weergavenaam bevat een ander e-mailadres                                                                           |
| `FROM_NAME_BRAND`         |      2 | De weergavenaam beroept zich op een merk waar het adres niet bij hoort                                                |
| `DATE_IN_FUTURE`          |      1 | Meer dan een dag vooruit gedateerd                                                                                    |
| `MISSING_DATE`            |    0,5 | Geen Date-header                                                                                                      |
| `MISSING_MESSAGE_ID`      |    0,5 | Geen Message-ID-header                                                                                                |

Regels die minstens de spamdrempel waard zijn, staan ook in `results.arbitrary`, zoals in eerdere versies.


## Verhulling en taal

| Test                   | Punten | Instellingssleutel    | Betekenis                                                           |
| ---------------------- | -----: | --------------------- | ------------------------------------------------------------------- |
| `INVISIBLE_CHARACTERS` |      2 | `invisibleCharacters` | Drie of meer onzichtbare tekens in de tekst                         |
| `MIXED_SCRIPT_WORDS`   |    2,5 | `mixedScriptWords`    | Twee of meer woorden mengen letters uit verschillende alfabetten    |
| `STYLED_LETTERS`       |    1,5 | `styledLetters`       | Wiskundige of omcirkelde letters die zich als gewone tekst voordoen |
| `LANGUAGE_NOT_ALLOWED` |      3 | `languageNotAllowed`  | Niet in `allowedLanguages`                                          |


## Authenticatie

Vereist het IP-adres van de client en `authentication: true`.

| Test           | Punten | Instellingssleutel (in `authentication.weights`) |
| -------------- | -----: | ------------------------------------------------ |
| `SPF_PASS`     |   -0,5 | `spfPass`                                        |
| `SPF_FAIL`     |      2 | `spfFail`                                        |
| `SPF_SOFTFAIL` |      1 | `spfSoftfail`                                    |
| `DKIM_PASS`    |   -0,5 | `dkimPass`                                       |
| `DKIM_FAIL`    |      1 | `dkimFail`                                       |
| `DMARC_PASS`   |   -1,5 | `dmarcPass`                                      |
| `DMARC_FAIL`   |    3,5 | `dmarcFail`                                      |
| `ARC_PASS`     |   -0,5 | `arcPass`                                        |
| `ARC_FAIL`     |      1 | `arcFail`                                        |


## Reputatie en blocklists

| Test           | Punten | Instellingssleutel | Betekenis                                                                  |
| -------------- | -----: | ------------------ | -------------------------------------------------------------------------- |
| `DENYLISTED`   |    100 | `denylisted`       | Het IP-adres, het domein of het adres van de afzender staat op de denylist |
| `ALLOWLISTED`  |    -20 | `allowlisted`      | Het staat op de allowlist                                                  |
| `TRUTH_SOURCE` |     -5 | `truthSource`      | Een reputatiedienst markeert de afzender als vertrouwd                     |
| `RBL_<LIST>`   |      4 | `rblListed`        | Het IP-adres van de client staat op een blocklist, bijvoorbeeld `RBL_ZEN`  |


## Taalmodel en optionele modellen

| Test                                                  | Punten | Instellingssleutel | Betekenis                                                   |
| ----------------------------------------------------- | ------ | ------------------ | ----------------------------------------------------------- |
| `LLM_SPAM`, `LLM_PHISHING`, `LLM_SCAM`, `LLM_MALWARE` | tot +6 | `llmSpam`          | Het oordeel van het model, maal zijn zekerheid              |
| `LLM_HAM`                                             | tot -3 | `llmHam`           | Idem                                                        |
| `TOXIC_CONTENT`                                       | 3      | `toxicity`         | Een toxiciteitsmodel dat je zelf levert, markeerde de tekst |
| `NSFW_IMAGE`                                          | 3      | `nsfw`             | Een beeldmodel dat je zelf levert, markeerde een afbeelding |
