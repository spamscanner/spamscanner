<!-- source: 6f6b765c5fc1 -->

# Testy a skóre

Zpráva je spam od 5 bodů a odmítne se od 15. Každý níže uvedený test body přidává nebo ubírá; výsledek uvádí ty, které se spustily.

Prahy změníte pomocí `threshold` a `rejectThreshold`. Body změníte pomocí `scores`, buď klíčem nastavení (`scores: {deceptiveLink: 4}`), nebo názvem testu, což pevně nastaví body daného testu (`scores: {FROM_NAME_BRAND: 4}`).


## Klasifikátor

| Test                      | Body          | Význam                                                                                                                                                                                                                                                                                                                                                                           |
| ------------------------- | ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BAYES_00` až `BAYES_999` | −2,5 až +6,25 | Pravděpodobnost spamu podle klasifikátoru na logaritmické stupnici šancí: 2,4 bodu při 90 %, 5 při 99 % a 6,25 při 99,9 %, takže klasifikátor sám označí spam jen tehdy, když si je jistý alespoň na 99 %. Název udává pásmo: `BAYES_999` je 99,9 % nebo více, `BAYES_99` 99 % až 99,9 %, `BAYES_50` 40 % až 60 %. Klíče nastavení `bayesHam` a `bayesSpam` nastavují oba konce. |


## Phishing a odkazy

| Test                        | Body | Klíč nastavení      | Význam                                                                      |
| --------------------------- | ---: | ------------------- | --------------------------------------------------------------------------- |
| `PHISHING_LOOKALIKE_DOMAIN` |    5 | `homograph`         | Doména odkazu napodobuje značku podobně vypadajícími nebo prohozenými znaky |
| `MIXED_SCRIPT_DOMAIN`       |    3 | `mixedScriptDomain` | Návěští domény míchá abecedy                                                |
| `BRAND_IN_DOMAIN`           |  1,5 | `brandInDomain`     | Název značky uvnitř cizí domény                                             |
| `TYPO_DOMAIN`               |    1 | `typoDomain`        | Od domény značky se liší jedním písmenem                                    |
| `DECEPTIVE_LINK`            |    3 | `deceptiveLink`     | Odkaz ukazuje jednu adresu a vede na jinou                                  |
| `MALICIOUS_DOMAIN`          |    6 | `maliciousDomain`   | Resolver Cloudflare proti malwaru blokuje odkazovanou doménu                |
| `ADULT_DOMAIN`              |    2 | `adultDomain`       | Rodinný resolver Cloudflare blokuje odkazovanou doménu                      |
| `URIBL_<LIST>`              |    5 | `uriblListed`       | Odkazovaná doména je na blocklistu domén, například `URIBL_DBL`             |


## Přílohy

| Test                    |     Body | Klíč nastavení                           | Význam                                                         |
| ----------------------- | -------: | ---------------------------------------- | -------------------------------------------------------------- |
| `EXECUTABLE_ATTACHMENT` |       10 | `executable`                             | Program nebo skript                                            |
| `DISGUISED_EXECUTABLE`  |       12 | `disguisedExecutable`                    | Program pojmenovaný jako dokument nebo obrázek                 |
| `DOUBLE_EXTENSION`      |        6 | `doubleExtension`                        | Název jako `invoice.pdf.exe`                                   |
| `RTL_OVERRIDE_FILENAME` |        6 | `rtlOverride`                            | Znak pro přepnutí směru zprava doleva skrývá skutečnou příponu |
| `EXECUTABLE_IN_ARCHIVE` |        8 | `executableInArchive`                    | Program uvnitř souboru ZIP                                     |
| `ENCRYPTED_ARCHIVE`     |        2 | `encryptedArchive`                       | Archiv, který skenery nedokážou otevřít                        |
| `MACRO_ATTACHMENT`      |        4 | `macro`                                  | Soubor Office s makry                                          |
| `PDF_ACTIVE_CONTENT`    |        3 | `pdfActive`                              | PDF s JavaScriptem, akcemi spuštění nebo vloženými soubory     |
| `RTF_EMBEDDED_OBJECT`   |        4 | `rtfObject`                              | Soubor RTF s vloženými objekty                                 |
| `HTML_ATTACHMENT`       | 1 nebo 3 | `htmlAttachment`, `activeHtmlAttachment` | Soubor HTML; 3, pokud obsahuje skripty nebo formuláře          |
| `VIRUS`                 |      100 | `virus`                                  | ClamAV našel virus                                             |


## Pravidla

| Test                      | Body | Význam                                                                                   |
| ------------------------- | ---: | ---------------------------------------------------------------------------------------- |
| `GTUBE`                   | 1000 | Testovací řetězec GTUBE                                                                  |
| `SEXTORTION_SUBJECT`      |    6 | Předmět používaný při podvodech typu sextortion a převzetí účtu                          |
| `PAYPAL_INVOICE`          |    6 | Faktura nebo žádost o peníze přes PayPal, kanál zneužívaný k podvodům                    |
| `MICROSOFT_SPAM_VERDICT`  |    5 | Microsoft zprávu před předáním označil jako spam (důvěryhodné jen ze serverů Microsoftu) |
| `MICROSOFT_HIGH_SCL`      |    3 | Microsoft jí přidělil vysokou úroveň spolehlivosti spamu (rovněž)                        |
| `PROMPT_INJECTION`        |    3 | Text určený filtru s AI                                                                  |
| `SELF_SPOOF`              |    3 | Tvrdí, že je z vlastní domény příjemce, a neprojde ověřením                              |
| `FROM_NAME_OTHER_ADDRESS` |  2,5 | Zobrazované jméno obsahuje jinou e-mailovou adresu                                       |
| `FROM_NAME_BRAND`         |    2 | Zobrazované jméno se hlásí ke značce, ke které adresa nepatří                            |
| `DATE_IN_FUTURE`          |    1 | Datum je více než den dopředu                                                            |
| `MISSING_DATE`            |  0,5 | Chybí hlavička Date                                                                      |
| `MISSING_MESSAGE_ID`      |  0,5 | Chybí hlavička Message-ID                                                                |

Pravidla s hodnotou alespoň na úrovni prahu spamu se jako v dřívějších verzích objevují také v `results.arbitrary`.


## Maskování a jazyk

| Test                   | Body | Klíč nastavení        | Význam                                                         |
| ---------------------- | ---: | --------------------- | -------------------------------------------------------------- |
| `INVISIBLE_CHARACTERS` |    2 | `invisibleCharacters` | Tři nebo více neviditelných znaků uvnitř textu                 |
| `MIXED_SCRIPT_WORDS`   |  2,5 | `mixedScriptWords`    | Dvě nebo více slov míchají písmena z různých abeced            |
| `STYLED_LETTERS`       |  1,5 | `styledLetters`       | Matematická nebo zakroužkovaná písmena vydávaná za prostý text |
| `LANGUAGE_NOT_ALLOWED` |    3 | `languageNotAllowed`  | Není v `allowedLanguages`                                      |


## Ověření

Vyžaduje IP adresu klienta a `authentication: true`.

| Test           | Body | Klíč nastavení (v `authentication.weights`) |
| -------------- | ---: | ------------------------------------------- |
| `SPF_PASS`     | −0,5 | `spfPass`                                   |
| `SPF_FAIL`     |    2 | `spfFail`                                   |
| `SPF_SOFTFAIL` |    1 | `spfSoftfail`                               |
| `DKIM_PASS`    | −0,5 | `dkimPass`                                  |
| `DKIM_FAIL`    |    1 | `dkimFail`                                  |
| `DMARC_PASS`   | −1,5 | `dmarcPass`                                 |
| `DMARC_FAIL`   |  3,5 | `dmarcFail`                                 |
| `ARC_PASS`     | −0,5 | `arcPass`                                   |
| `ARC_FAIL`     |    1 | `arcFail`                                   |


## Reputace a blocklisty

| Test           | Body | Klíč nastavení | Význam                                                             |
| -------------- | ---: | -------------- | ------------------------------------------------------------------ |
| `DENYLISTED`   |  100 | `denylisted`   | IP adresa, doména nebo adresa odesílatele je na seznamu zakázaných |
| `ALLOWLISTED`  |  −20 | `allowlisted`  | Je na seznamu povolených                                           |
| `TRUTH_SOURCE` |   −5 | `truthSource`  | Služba reputace označuje odesílatele jako důvěryhodného            |
| `RBL_<LIST>`   |    4 | `rblListed`    | IP adresa klienta je na blocklistu, například `RBL_ZEN`            |


## Jazykový model a volitelné modely

| Test                                                  | Body  | Klíč nastavení | Význam                                        |
| ----------------------------------------------------- | ----- | -------------- | --------------------------------------------- |
| `LLM_SPAM`, `LLM_PHISHING`, `LLM_SCAM`, `LLM_MALWARE` | až +6 | `llmSpam`      | Verdikt modelu vynásobený jeho jistotou       |
| `LLM_HAM`                                             | až −3 | `llmHam`       | Obdobně                                       |
| `TOXIC_CONTENT`                                       | 3     | `toxicity`     | Model toxicity, který dodáte, označil text    |
| `NSFW_IMAGE`                                          | 3     | `nsfw`         | Obrazový model, který dodáte, označil obrázek |
