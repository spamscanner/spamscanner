<!-- source: 6f6b765c5fc1 -->

# Test og scorer

En besked er spam ved 5 point og afvises ved 15. Hver test nedenfor lægger point til eller trækker point fra; resultatet viser dem, der slog til.

Ændr grænserne med `threshold` og `rejectThreshold`. Ændr point med `scores`, enten med en indstillingsnøgle (`scores: {deceptiveLink: 4}`) eller med et testnavn, som fastlåser den tests point (`scores: {FROM_NAME_BRAND: 4}`).


## Klassifikator

| Test                       | Point          | Betydning                                                                                                                                                                                                                                                                                                                                                                     |
| -------------------------- | -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BAYES_00` til `BAYES_999` | -2,5 til +6,25 | Klassifikatorens spamsandsynlighed på en log-odds-skala: 2,4 point ved 90 %, 5 ved 99 % og 6,25 ved 99,9 %, så klassifikatoren alene kun markerer spam, når den er mindst 99 % sikker. Navnet angiver intervallet: `BAYES_999` er 99,9 % eller mere, `BAYES_99` 99 % til 99,9 %, `BAYES_50` 40 % til 60 %. Indstillingsnøglerne `bayesHam` og `bayesSpam` sætter de to ender. |


## Phishing og links

| Test                        | Point | Indstillingsnøgle   | Betydning                                                                       |
| --------------------------- | ----: | ------------------- | ------------------------------------------------------------------------------- |
| `PHISHING_LOOKALIKE_DOMAIN` |     5 | `homograph`         | Et links domæne efterligner et varemærke med forvekslelige eller ombyttede tegn |
| `MIXED_SCRIPT_DOMAIN`       |     3 | `mixedScriptDomain` | En domæneetiket blander alfabeter                                               |
| `BRAND_IN_DOMAIN`           |   1,5 | `brandInDomain`     | Et varemærke inde i en andens domæne                                            |
| `TYPO_DOMAIN`               |     1 | `typoDomain`        | Ét bogstav fra et varemærkes domæne                                             |
| `DECEPTIVE_LINK`            |     3 | `deceptiveLink`     | Et link viser én adresse og går til en anden                                    |
| `MALICIOUS_DOMAIN`          |     6 | `maliciousDomain`   | Cloudflares malware-resolver blokerer et linket domæne                          |
| `ADULT_DOMAIN`              |     2 | `adultDomain`       | Cloudflares familieresolver blokerer et linket domæne                           |
| `URIBL_<LIST>`              |     5 | `uriblListed`       | Et linket domæne står på en domæneblokeringsliste, for eksempel `URIBL_DBL`     |


## Vedhæftede filer

| Test                    |     Point | Indstillingsnøgle                        | Betydning                                                     |
| ----------------------- | --------: | ---------------------------------------- | ------------------------------------------------------------- |
| `EXECUTABLE_ATTACHMENT` |        10 | `executable`                             | Et program eller script                                       |
| `DISGUISED_EXECUTABLE`  |        12 | `disguisedExecutable`                    | Et program navngivet som et dokument eller billede            |
| `DOUBLE_EXTENSION`      |         6 | `doubleExtension`                        | Et navn som `invoice.pdf.exe`                                 |
| `RTL_OVERRIDE_FILENAME` |         6 | `rtlOverride`                            | Et højre-mod-venstre-tegn skjuler den rigtige filendelse      |
| `EXECUTABLE_IN_ARCHIVE` |         8 | `executableInArchive`                    | Et program i en ZIP-fil                                       |
| `ENCRYPTED_ARCHIVE`     |         2 | `encryptedArchive`                       | Et arkiv, som scannere ikke kan åbne                          |
| `MACRO_ATTACHMENT`      |         4 | `macro`                                  | En Office-fil med makroer                                     |
| `PDF_ACTIVE_CONTENT`    |         3 | `pdfActive`                              | En PDF med JavaScript, starthandlinger eller indlejrede filer |
| `RTF_EMBEDDED_OBJECT`   |         4 | `rtfObject`                              | En RTF-fil med indlejrede objekter                            |
| `HTML_ATTACHMENT`       | 1 eller 3 | `htmlAttachment`, `activeHtmlAttachment` | En HTML-fil; 3, når den har scripts eller formularer          |
| `VIRUS`                 |       100 | `virus`                                  | ClamAV fandt en virus                                         |


## Regler

| Test                      | Point | Betydning                                                                                              |
| ------------------------- | ----: | ------------------------------------------------------------------------------------------------------ |
| `GTUBE`                   |  1000 | GTUBE-teststrengen                                                                                     |
| `SEXTORTION_SUBJECT`      |     6 | En emnelinje, der bruges i sextortion-svindel og svindel med kontoovertagelse                          |
| `PAYPAL_INVOICE`          |     6 | En PayPal-faktura eller pengeanmodning, en kanal, der misbruges til svindel                            |
| `MICROSOFT_SPAM_VERDICT`  |     5 | Microsoft markerede beskeden som spam, før den blev videresendt (stoles kun på fra Microsofts servere) |
| `MICROSOFT_HIGH_SCL`      |     3 | Microsoft gav den et højt spam confidence level (ligeledes)                                            |
| `PROMPT_INJECTION`        |     3 | Tekst rettet mod et AI-filter                                                                          |
| `SELF_SPOOF`              |     3 | Påstår at komme fra modtagerens eget domæne og er ikke godkendt                                        |
| `FROM_NAME_OTHER_ADDRESS` |   2,5 | Visningsnavnet indeholder en anden e-mailadresse                                                       |
| `FROM_NAME_BRAND`         |     2 | Visningsnavnet påstår at være et varemærke, som adressen ikke hører til                                |
| `DATE_IN_FUTURE`          |     1 | Dateret mere end en dag frem                                                                           |
| `MISSING_DATE`            |   0,5 | Ingen Date-header                                                                                      |
| `MISSING_MESSAGE_ID`      |   0,5 | Ingen Message-ID-header                                                                                |

Regler, der er mindst spamgrænsen værd, vises også i `results.arbitrary` som i tidligere versioner.


## Tilsløring og sprog

| Test                   | Point | Indstillingsnøgle     | Betydning                                                            |
| ---------------------- | ----: | --------------------- | -------------------------------------------------------------------- |
| `INVISIBLE_CHARACTERS` |     2 | `invisibleCharacters` | Tre eller flere usynlige tegn i teksten                              |
| `MIXED_SCRIPT_WORDS`   |   2,5 | `mixedScriptWords`    | To eller flere ord blander bogstaver fra forskellige alfabeter       |
| `STYLED_LETTERS`       |   1,5 | `styledLetters`       | Matematiske eller indrammede bogstaver forklædt som almindelig tekst |
| `LANGUAGE_NOT_ALLOWED` |     3 | `languageNotAllowed`  | Ikke i `allowedLanguages`                                            |


## Godkendelse

Kræver klientens IP-adresse og `authentication: true`.

| Test           | Point | Indstillingsnøgle (i `authentication.weights`) |
| -------------- | ----: | ---------------------------------------------- |
| `SPF_PASS`     |  -0,5 | `spfPass`                                      |
| `SPF_FAIL`     |     2 | `spfFail`                                      |
| `SPF_SOFTFAIL` |     1 | `spfSoftfail`                                  |
| `DKIM_PASS`    |  -0,5 | `dkimPass`                                     |
| `DKIM_FAIL`    |     1 | `dkimFail`                                     |
| `DMARC_PASS`   |  -1,5 | `dmarcPass`                                    |
| `DMARC_FAIL`   |   3,5 | `dmarcFail`                                    |
| `ARC_PASS`     |  -0,5 | `arcPass`                                      |
| `ARC_FAIL`     |     1 | `arcFail`                                      |


## Omdømme og blokeringslister

| Test           | Point | Indstillingsnøgle | Betydning                                                               |
| -------------- | ----: | ----------------- | ----------------------------------------------------------------------- |
| `DENYLISTED`   |   100 | `denylisted`      | Afsenderens IP-adresse, domæne eller adresse står på blokeringslisten   |
| `ALLOWLISTED`  |   -20 | `allowlisted`     | Den står på tilladelseslisten                                           |
| `TRUTH_SOURCE` |    -5 | `truthSource`     | En omdømmetjeneste markerer afsenderen som betroet                      |
| `RBL_<LIST>`   |     4 | `rblListed`       | Klientens IP-adresse står på en blokeringsliste, for eksempel `RBL_ZEN` |


## Sprogmodel og valgfrie modeller

| Test                                                  | Point      | Indstillingsnøgle | Betydning                                               |
| ----------------------------------------------------- | ---------- | ----------------- | ------------------------------------------------------- |
| `LLM_SPAM`, `LLM_PHISHING`, `LLM_SCAM`, `LLM_MALWARE` | op til +6  | `llmSpam`         | Modellens dom ganget med dens sikkerhed                 |
| `LLM_HAM`                                             | ned til -3 | `llmHam`          | Ligeledes                                               |
| `TOXIC_CONTENT`                                       | 3          | `toxicity`        | En toksicitetsmodel, du selv leverer, markerede teksten |
| `NSFW_IMAGE`                                          | 3          | `nsfw`            | En billedmodel, du selv leverer, markerede et billede   |
