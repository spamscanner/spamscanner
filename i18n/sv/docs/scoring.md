<!-- source: 6f6b765c5fc1 -->

# Tester och poäng

Ett meddelande är spam vid 5 poäng och avvisas vid 15. Varje test nedan lägger till eller drar av poäng; resultatet listar de som slog till.

Ändra gränsvärdena med `threshold` och `rejectThreshold`. Ändra poäng med `scores`, antingen med inställningsnyckel (`scores: {deceptiveLink: 4}`) eller med testnamn, vilket låser testets poäng (`scores: {FROM_NAME_BRAND: 4}`).


## Klassificerare

| Test                        | Poäng           | Betydelse                                                                                                                                                                                                                                                                                                                                                                                 |
| --------------------------- | --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BAYES_00` till `BAYES_999` | −2,5 till +6,25 | Klassificerarens spamsannolikhet på en log-odds-skala: 2,4 poäng vid 90 %, 5 vid 99 % och 6,25 vid 99,9 %, så klassificeraren markerar spam på egen hand bara när den är minst 99 % säker. Namnet anger intervallet: `BAYES_999` är 99,9 % eller mer, `BAYES_99` 99 % till 99,9 %, `BAYES_50` 40 % till 60 %. Inställningsnycklarna `bayesHam` och `bayesSpam` anger de två ändpunkterna. |


## Nätfiske och länkar

| Test                        | Poäng | Inställningsnyckel  | Betydelse                                                                      |
| --------------------------- | ----: | ------------------- | ------------------------------------------------------------------------------ |
| `PHISHING_LOOKALIKE_DOMAIN` |     5 | `homograph`         | En länks domän imiterar ett varumärke med förväxlingsbara eller utbytta tecken |
| `MIXED_SCRIPT_DOMAIN`       |     3 | `mixedScriptDomain` | En domänetikett blandar alfabet                                                |
| `BRAND_IN_DOMAIN`           |   1,5 | `brandInDomain`     | Ett varumärke i någon annans domän                                             |
| `TYPO_DOMAIN`               |     1 | `typoDomain`        | En bokstav ifrån ett varumärkes domän                                          |
| `DECEPTIVE_LINK`            |     3 | `deceptiveLink`     | En länk visar en adress och leder till en annan                                |
| `MALICIOUS_DOMAIN`          |     6 | `maliciousDomain`   | Cloudflares resolver mot skadlig kod blockerar en länkad domän                 |
| `ADULT_DOMAIN`              |     2 | `adultDomain`       | Cloudflares familjeresolver blockerar en länkad domän                          |
| `URIBL_<LIST>`              |     5 | `uriblListed`       | En länkad domän finns på en domänblocklista, till exempel `URIBL_DBL`          |


## Bilagor

| Test                    |     Poäng | Inställningsnyckel                       | Betydelse                                                           |
| ----------------------- | --------: | ---------------------------------------- | ------------------------------------------------------------------- |
| `EXECUTABLE_ATTACHMENT` |        10 | `executable`                             | Ett program eller skript                                            |
| `DISGUISED_EXECUTABLE`  |        12 | `disguisedExecutable`                    | Ett program med namn som ett dokument eller en bild                 |
| `DOUBLE_EXTENSION`      |         6 | `doubleExtension`                        | Ett namn som `invoice.pdf.exe`                                      |
| `RTL_OVERRIDE_FILENAME` |         6 | `rtlOverride`                            | En höger-till-vänster-åsidosättning döljer den verkliga filändelsen |
| `EXECUTABLE_IN_ARCHIVE` |         8 | `executableInArchive`                    | Ett program i en ZIP-fil                                            |
| `ENCRYPTED_ARCHIVE`     |         2 | `encryptedArchive`                       | Ett arkiv som skannrar inte kan öppna                               |
| `MACRO_ATTACHMENT`      |         4 | `macro`                                  | En Office-fil med makron                                            |
| `PDF_ACTIVE_CONTENT`    |         3 | `pdfActive`                              | En PDF med JavaScript, startåtgärder eller inbäddade filer          |
| `RTF_EMBEDDED_OBJECT`   |         4 | `rtfObject`                              | En RTF-fil med inbäddade objekt                                     |
| `HTML_ATTACHMENT`       | 1 eller 3 | `htmlAttachment`, `activeHtmlAttachment` | En HTML-fil; 3 när den har skript eller formulär                    |
| `VIRUS`                 |       100 | `virus`                                  | ClamAV hittade ett virus                                            |


## Regler

| Test                      | Poäng | Betydelse                                                                                                    |
| ------------------------- | ----: | ------------------------------------------------------------------------------------------------------------ |
| `GTUBE`                   |  1000 | Teststrängen GTUBE                                                                                           |
| `SEXTORTION_SUBJECT`      |     6 | En ämnesrad som används i bedrägerier med sextortion och kontokapning                                        |
| `PAYPAL_INVOICE`          |     6 | En PayPal-faktura eller betalningsbegäran, en kanal som missbrukas för bedrägerier                           |
| `MICROSOFT_SPAM_VERDICT`  |     5 | Microsoft markerade meddelandet som spam innan det vidarebefordrades (litas bara på från Microsofts servrar) |
| `MICROSOFT_HIGH_SCL`      |     3 | Microsoft gav det en hög spamkonfidensnivå (likaså)                                                          |
| `PROMPT_INJECTION`        |     3 | Text riktad till ett AI-filter                                                                               |
| `SELF_SPOOF`              |     3 | Påstår sig komma från mottagarens egen domän och autentiserar sig inte                                       |
| `FROM_NAME_OTHER_ADDRESS` |   2,5 | Visningsnamnet innehåller en annan e-postadress                                                              |
| `FROM_NAME_BRAND`         |     2 | Visningsnamnet anger ett varumärke som adressen inte tillhör                                                 |
| `DATE_IN_FUTURE`          |     1 | Daterat mer än ett dygn framåt                                                                               |
| `MISSING_DATE`            |   0,5 | Inget Date-huvud                                                                                             |
| `MISSING_MESSAGE_ID`      |   0,5 | Inget Message-ID-huvud                                                                                       |

Regler som är värda minst spamgränsen visas också i `results.arbitrary`, som i tidigare versioner.


## Förvrängning och språk

| Test                   | Poäng | Inställningsnyckel    | Betydelse                                                                    |
| ---------------------- | ----: | --------------------- | ---------------------------------------------------------------------------- |
| `INVISIBLE_CHARACTERS` |     2 | `invisibleCharacters` | Tre eller fler osynliga tecken i texten                                      |
| `MIXED_SCRIPT_WORDS`   |   2,5 | `mixedScriptWords`    | Två eller fler ord blandar bokstäver från olika alfabet                      |
| `STYLED_LETTERS`       |   1,5 | `styledLetters`       | Matematiska eller inringade bokstäver som utger sig för att vara vanlig text |
| `LANGUAGE_NOT_ALLOWED` |     3 | `languageNotAllowed`  | Inte i `allowedLanguages`                                                    |


## Autentisering

Kräver klientens IP-adress och `authentication: true`.

| Test           | Poäng | Inställningsnyckel (i `authentication.weights`) |
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


## Rykte och blocklistor

| Test           | Poäng | Inställningsnyckel | Betydelse                                                          |
| -------------- | ----: | ------------------ | ------------------------------------------------------------------ |
| `DENYLISTED`   |   100 | `denylisted`       | Avsändarens IP-adress, domän eller adress finns på blocklistan     |
| `ALLOWLISTED`  |   −20 | `allowlisted`      | Den finns på tillåtlistan                                          |
| `TRUTH_SOURCE` |    −5 | `truthSource`      | En ryktestjänst markerar avsändaren som betrodd                    |
| `RBL_<LIST>`   |     4 | `rblListed`        | Klientens IP-adress finns på en blocklista, till exempel `RBL_ZEN` |


## Språkmodell och valfria modeller

| Test                                                  | Poäng       | Inställningsnyckel | Betydelse                                                  |
| ----------------------------------------------------- | ----------- | ------------------ | ---------------------------------------------------------- |
| `LLM_SPAM`, `LLM_PHISHING`, `LLM_SCAM`, `LLM_MALWARE` | upp till +6 | `llmSpam`          | Modellens utslag gånger dess konfidens                     |
| `LLM_HAM`                                             | ned till −3 | `llmHam`           | Likaså                                                     |
| `TOXIC_CONTENT`                                       | 3           | `toxicity`         | En toxicitetsmodell som du tillhandahåller flaggade texten |
| `NSFW_IMAGE`                                          | 3           | `nsfw`             | En bildmodell som du tillhandahåller flaggade en bild      |
