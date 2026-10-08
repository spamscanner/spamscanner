<!-- source: 6f6b765c5fc1 -->

# Tester og poeng

En melding er spam ved 5 poeng og avvises ved 15. Hver test nedenfor legger til eller trekker fra poeng; resultatet lister opp de som slo ut.

Endre tersklene med `threshold` og `rejectThreshold`. Endre poeng med `scores`, enten med innstillingsnøkkel (`scores: {deceptiveLink: 4}`) eller med testnavn, som låser poengene for den testen (`scores: {FROM_NAME_BRAND: 4}`).


## Klassifiserer

| Test                       | Poeng          | Betydning                                                                                                                                                                                                                                                                                                                                                                     |
| -------------------------- | -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BAYES_00` til `BAYES_999` | −2,5 til +6,25 | Klassifisererens spamsannsynlighet på en log-odds-skala: 2,4 poeng ved 90 %, 5 ved 99 % og 6,25 ved 99,9 %, så klassifisereren merker spam alene bare når den er minst 99 % sikker. Navnet angir intervallet: `BAYES_999` er 99,9 % eller mer, `BAYES_99` 99 % til 99,9 %, `BAYES_50` 40 % til 60 %. Innstillingsnøklene `bayesHam` og `bayesSpam` setter de to endepunktene. |


## Phishing og lenker

| Test                        | Poeng | Innstillingsnøkkel  | Betydning                                                                         |
| --------------------------- | ----: | ------------------- | --------------------------------------------------------------------------------- |
| `PHISHING_LOOKALIKE_DOMAIN` |     5 | `homograph`         | Domenet i en lenke etterligner et merkenavn med forvekslbare eller ombyttede tegn |
| `MIXED_SCRIPT_DOMAIN`       |     3 | `mixedScriptDomain` | En domeneetikett blander alfabeter                                                |
| `BRAND_IN_DOMAIN`           |   1,5 | `brandInDomain`     | Et merkenavn inne i noen andres domene                                            |
| `TYPO_DOMAIN`               |     1 | `typoDomain`        | Én bokstav unna domenet til et merkenavn                                          |
| `DECEPTIVE_LINK`            |     3 | `deceptiveLink`     | En lenke viser én adresse og går til en annen                                     |
| `MALICIOUS_DOMAIN`          |     6 | `maliciousDomain`   | Cloudflares resolver mot skadevare blokkerer et lenket domene                     |
| `ADULT_DOMAIN`              |     2 | `adultDomain`       | Cloudflares familieresolver blokkerer et lenket domene                            |
| `URIBL_<LIST>`              |     5 | `uriblListed`       | Et lenket domene står på en domeneblokkeringsliste, for eksempel `URIBL_DBL`      |


## Vedlegg

| Test                    |     Poeng | Innstillingsnøkkel                       | Betydning                                                               |
| ----------------------- | --------: | ---------------------------------------- | ----------------------------------------------------------------------- |
| `EXECUTABLE_ATTACHMENT` |        10 | `executable`                             | Et program eller skript                                                 |
| `DISGUISED_EXECUTABLE`  |        12 | `disguisedExecutable`                    | Et program med navn som et dokument eller bilde                         |
| `DOUBLE_EXTENSION`      |         6 | `doubleExtension`                        | Et navn som `invoice.pdf.exe`                                           |
| `RTL_OVERRIDE_FILENAME` |         6 | `rtlOverride`                            | Et høyre-til-venstre-overstyringstegn skjuler den virkelige filendelsen |
| `EXECUTABLE_IN_ARCHIVE` |         8 | `executableInArchive`                    | Et program i en ZIP-fil                                                 |
| `ENCRYPTED_ARCHIVE`     |         2 | `encryptedArchive`                       | Et arkiv som skannere ikke kan åpne                                     |
| `MACRO_ATTACHMENT`      |         4 | `macro`                                  | En Office-fil med makroer                                               |
| `PDF_ACTIVE_CONTENT`    |         3 | `pdfActive`                              | En PDF med JavaScript, starthandlinger eller innebygde filer            |
| `RTF_EMBEDDED_OBJECT`   |         4 | `rtfObject`                              | En RTF-fil med innebygde objekter                                       |
| `HTML_ATTACHMENT`       | 1 eller 3 | `htmlAttachment`, `activeHtmlAttachment` | En HTML-fil; 3 når den har skript eller skjemaer                        |
| `VIRUS`                 |       100 | `virus`                                  | ClamAV fant et virus                                                    |


## Regler

| Test                      | Poeng | Betydning                                                                                           |
| ------------------------- | ----: | --------------------------------------------------------------------------------------------------- |
| `GTUBE`                   |  1000 | GTUBE-teststrengen                                                                                  |
| `SEXTORTION_SUBJECT`      |     6 | En emnelinje brukt i sextortion-svindel og svindel med kontokapring                                 |
| `PAYPAL_INVOICE`          |     6 | En PayPal-faktura eller pengeforespørsel, en kanal som misbrukes til svindel                        |
| `MICROSOFT_SPAM_VERDICT`  |     5 | Microsoft merket meldingen som spam før den ble videresendt (stoles bare på fra Microsofts servere) |
| `MICROSOFT_HIGH_SCL`      |     3 | Microsoft ga den et høyt spam confidence level (på samme måte)                                      |
| `PROMPT_INJECTION`        |     3 | Tekst rettet mot et KI-filter                                                                       |
| `SELF_SPOOF`              |     3 | Utgir seg for å komme fra mottakerens eget domene og autentiserer seg ikke                          |
| `FROM_NAME_OTHER_ADDRESS` |   2,5 | Visningsnavnet inneholder en annen e-postadresse                                                    |
| `FROM_NAME_BRAND`         |     2 | Visningsnavnet utgir seg for å være et merkenavn som adressen ikke tilhører                         |
| `DATE_IN_FUTURE`          |     1 | Datert mer enn ett døgn frem i tid                                                                  |
| `MISSING_DATE`            |   0,5 | Mangler Date-hode                                                                                   |
| `MISSING_MESSAGE_ID`      |   0,5 | Mangler Message-ID-hode                                                                             |

Regler som gir minst spamterskelen, vises også i `results.arbitrary`, som i tidligere versjoner.


## Tilsløring og språk

| Test                   | Poeng | Innstillingsnøkkel    | Betydning                                                                    |
| ---------------------- | ----: | --------------------- | ---------------------------------------------------------------------------- |
| `INVISIBLE_CHARACTERS` |     2 | `invisibleCharacters` | Tre eller flere usynlige tegn i teksten                                      |
| `MIXED_SCRIPT_WORDS`   |   2,5 | `mixedScriptWords`    | To eller flere ord blander bokstaver fra ulike alfabeter                     |
| `STYLED_LETTERS`       |   1,5 | `styledLetters`       | Matematiske eller innrammede bokstaver som utgir seg for å være vanlig tekst |
| `LANGUAGE_NOT_ALLOWED` |     3 | `languageNotAllowed`  | Ikke i `allowedLanguages`                                                    |


## Autentisering

Krever klientens IP-adresse og `authentication: true`.

| Test           | Poeng | Innstillingsnøkkel (i `authentication.weights`) |
| -------------- | ----: | ----------------------------------------------- |
| `SPF_PASS`     |  −0,5 | `spfPass`                                       |
| `SPF_FAIL`     |     2 | `spfFail`                                       |
| `SPF_SOFTFAIL` |     1 | `spfSoftfail`                                   |
| `DKIM_PASS`    |  −0,5 | `dkimPass`                                      |
| `DKIM_FAIL`    |     1 | `dkimFail`                                      |
| `DMARC_PASS`   |  −1,5 | `dmarcPass`                                     |
| `DMARC_FAIL`   |   3,5 | `dmarcFail`                                     |
| `ARC_PASS`     |  −0,5 | `arcPass`                                       |
| `ARC_FAIL`     |     1 | `arcFail`                                       |


## Omdømme og blokkeringslister

| Test           | Poeng | Innstillingsnøkkel | Betydning                                                                |
| -------------- | ----: | ------------------ | ------------------------------------------------------------------------ |
| `DENYLISTED`   |   100 | `denylisted`       | Avsenderens IP-adresse, domene eller adresse står på blokkeringslisten   |
| `ALLOWLISTED`  |   −20 | `allowlisted`      | Den står på tillatelseslisten                                            |
| `TRUTH_SOURCE` |    −5 | `truthSource`      | En omdømmetjeneste merker avsenderen som pålitelig                       |
| `RBL_<LIST>`   |     4 | `rblListed`        | Klientens IP-adresse står på en blokkeringsliste, for eksempel `RBL_ZEN` |


## Språkmodell og valgfrie modeller

| Test                                                  | Poeng      | Innstillingsnøkkel | Betydning                                         |
| ----------------------------------------------------- | ---------- | ------------------ | ------------------------------------------------- |
| `LLM_SPAM`, `LLM_PHISHING`, `LLM_SCAM`, `LLM_MALWARE` | opptil +6  | `llmSpam`          | Modellens vurdering, multiplisert med sikkerheten |
| `LLM_HAM`                                             | ned til −3 | `llmHam`           | På samme måte                                     |
| `TOXIC_CONTENT`                                       | 3          | `toxicity`         | En toksisitetsmodell du leverer, flagget teksten  |
| `NSFW_IMAGE`                                          | 3          | `nsfw`             | En bildemodell du leverer, flagget et bilde       |
