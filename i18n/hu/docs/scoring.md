<!-- source: 6f6b765c5fc1 -->

# Tesztek és pontszámok

Egy levél 5 ponttól spam, 15 ponttól pedig elutasításra kerül. Az alábbi tesztek mindegyike pontot ad hozzá vagy von le; az eredmény felsorolja a teljesülteket.

A küszöbök a `threshold` és a `rejectThreshold` beállítással módosíthatók. A pontok a `scores` beállítással módosíthatók, vagy a beállításkulccsal (`scores: {deceptiveLink: 4}`), vagy a teszt nevével, amely rögzíti az adott teszt pontjait (`scores: {FROM_NAME_BRAND: 4}`).


## Osztályozó

| Teszt                  | Pont              | Jelentés                                                                                                                                                                                                                                                                                                                                                                          |
| ---------------------- | ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BAYES_00`–`BAYES_999` | -2,5-től +6,25-ig | Az osztályozó spamvalószínűsége log-esély skálán: 90%-nál 2,4 pont, 99%-nál 5, 99,9%-nál 6,25, így az osztályozó önmagában csak akkor jelöl spamet, ha legalább 99%-ban biztos. A név a sávot adja meg: a `BAYES_999` 99,9% vagy több, a `BAYES_99` 99% és 99,9% között, a `BAYES_50` 40% és 60% között. A `bayesHam` és a `bayesSpam` beállításkulcs a két végpontot állítja be. |


## Adathalászat és hivatkozások

| Teszt                       | Pont | Beállításkulcs      | Jelentés                                                                         |
| --------------------------- | ---: | ------------------- | -------------------------------------------------------------------------------- |
| `PHISHING_LOOKALIKE_DOMAIN` |    5 | `homograph`         | Egy hivatkozás domainje hasonmás vagy felcserélt karakterekkel utánoz egy márkát |
| `MIXED_SCRIPT_DOMAIN`       |    3 | `mixedScriptDomain` | Egy domaincímke ábécéket kever                                                   |
| `BRAND_IN_DOMAIN`           |  1,5 | `brandInDomain`     | Márkanév valaki más domainjében                                                  |
| `TYPO_DOMAIN`               |    1 | `typoDomain`        | Egy betűben tér el egy márka domainjétől                                         |
| `DECEPTIVE_LINK`            |    3 | `deceptiveLink`     | A hivatkozás egy címet mutat, és egy másikra visz                                |
| `MALICIOUS_DOMAIN`          |    6 | `maliciousDomain`   | A Cloudflare kártevőszűrő DNS-feloldója blokkol egy hivatkozott domaint          |
| `ADULT_DOMAIN`              |    2 | `adultDomain`       | A Cloudflare családi DNS-feloldója blokkol egy hivatkozott domaint               |
| `URIBL_<LIST>`              |    5 | `uriblListed`       | Egy hivatkozott domain szerepel egy domain-tiltólistán, például `URIBL_DBL`      |


## Mellékletek

| Teszt                   |     Pont | Beállításkulcs                           | Jelentés                                                                   |
| ----------------------- | -------: | ---------------------------------------- | -------------------------------------------------------------------------- |
| `EXECUTABLE_ATTACHMENT` |       10 | `executable`                             | Program vagy szkript                                                       |
| `DISGUISED_EXECUTABLE`  |       12 | `disguisedExecutable`                    | Dokumentumnak vagy képnek elnevezett program                               |
| `DOUBLE_EXTENSION`      |        6 | `doubleExtension`                        | Olyan név, mint az `invoice.pdf.exe`                                       |
| `RTL_OVERRIDE_FILENAME` |        6 | `rtlOverride`                            | Egy jobbról balra író felülíró karakter elrejti a valódi kiterjesztést     |
| `EXECUTABLE_IN_ARCHIVE` |        8 | `executableInArchive`                    | Program egy ZIP-fájlban                                                    |
| `ENCRYPTED_ARCHIVE`     |        2 | `encryptedArchive`                       | A vírusirtók által meg nem nyitható archívum                               |
| `MACRO_ATTACHMENT`      |        4 | `macro`                                  | Makrókat tartalmazó Office-fájl                                            |
| `PDF_ACTIVE_CONTENT`    |        3 | `pdfActive`                              | JavaScriptet, indítási műveleteket vagy beágyazott fájlokat tartalmazó PDF |
| `RTF_EMBEDDED_OBJECT`   |        4 | `rtfObject`                              | Beágyazott objektumokat tartalmazó RTF-fájl                                |
| `HTML_ATTACHMENT`       | 1 vagy 3 | `htmlAttachment`, `activeHtmlAttachment` | HTML-fájl; 3, ha szkripteket vagy űrlapokat tartalmaz                      |
| `VIRUS`                 |      100 | `virus`                                  | A ClamAV vírust talált                                                     |


## Szabályok

| Teszt                     | Pont | Jelentés                                                                                                  |
| ------------------------- | ---: | --------------------------------------------------------------------------------------------------------- |
| `GTUBE`                   | 1000 | A GTUBE tesztkarakterlánc                                                                                 |
| `SEXTORTION_SUBJECT`      |    6 | Szextorziós és fiókeltérítési csalásokban használt tárgysor                                               |
| `PAYPAL_INVOICE`          |    6 | PayPal-számla vagy pénzkérés, csalásokra visszaélésszerűen használt csatorna                              |
| `MICROSOFT_SPAM_VERDICT`  |    5 | A Microsoft továbbítás előtt spamnek jelölte a levelet (csak a Microsoft szervereiről érkezve megbízható) |
| `MICROSOFT_HIGH_SCL`      |    3 | A Microsoft magas spammagabiztossági szintet adott neki (ugyanígy)                                        |
| `PROMPT_INJECTION`        |    3 | MI-szűrőnek címzett szöveg                                                                                |
| `SELF_SPOOF`              |    3 | A címzett saját domainjéről érkezőnek mondja magát, és nem hitelesít                                      |
| `FROM_NAME_OTHER_ADDRESS` |  2,5 | A megjelenített név egy másik e-mail-címet tartalmaz                                                      |
| `FROM_NAME_BRAND`         |    2 | A megjelenített név olyan márkára hivatkozik, amelyhez a cím nem tartozik                                 |
| `DATE_IN_FUTURE`          |    1 | Több mint egy nappal előre keltezett                                                                      |
| `MISSING_DATE`            |  0,5 | Nincs Date fejléc                                                                                         |
| `MISSING_MESSAGE_ID`      |  0,5 | Nincs Message-ID fejléc                                                                                   |

A legalább a spamküszöbnek megfelelő pontot érő szabályok a korábbi verziókhoz hasonlóan a `results.arbitrary` mezőben is megjelennek.


## Elrejtés és nyelv

| Teszt                  | Pont | Beállításkulcs        | Jelentés                                                        |
| ---------------------- | ---: | --------------------- | --------------------------------------------------------------- |
| `INVISIBLE_CHARACTERS` |    2 | `invisibleCharacters` | Három vagy több láthatatlan karakter a szövegben                |
| `MIXED_SCRIPT_WORDS`   |  2,5 | `mixedScriptWords`    | Két vagy több szó különböző ábécék betűit keveri                |
| `STYLED_LETTERS`       |  1,5 | `styledLetters`       | Egyszerű szövegnek álcázott matematikai vagy bekarikázott betűk |
| `LANGUAGE_NOT_ALLOWED` |    3 | `languageNotAllowed`  | Nem szerepel az `allowedLanguages` listában                     |


## Hitelesítés

A kliens IP-címe és `authentication: true` szükséges hozzá.

| Teszt          | Pont | Beállításkulcs (az `authentication.weights` alatt) |
| -------------- | ---: | -------------------------------------------------- |
| `SPF_PASS`     | -0,5 | `spfPass`                                          |
| `SPF_FAIL`     |    2 | `spfFail`                                          |
| `SPF_SOFTFAIL` |    1 | `spfSoftfail`                                      |
| `DKIM_PASS`    | -0,5 | `dkimPass`                                         |
| `DKIM_FAIL`    |    1 | `dkimFail`                                         |
| `DMARC_PASS`   | -1,5 | `dmarcPass`                                        |
| `DMARC_FAIL`   |  3,5 | `dmarcFail`                                        |
| `ARC_PASS`     | -0,5 | `arcPass`                                          |
| `ARC_FAIL`     |    1 | `arcFail`                                          |


## Hírnév és tiltólisták

| Teszt          | Pont | Beállításkulcs | Jelentés                                                     |
| -------------- | ---: | -------------- | ------------------------------------------------------------ |
| `DENYLISTED`   |  100 | `denylisted`   | A feladó IP-címe, domainje vagy címe szerepel a tiltólistán  |
| `ALLOWLISTED`  |  -20 | `allowlisted`  | Szerepel az engedélyezőlistán                                |
| `TRUTH_SOURCE` |   -5 | `truthSource`  | Egy hírnévszolgáltatás megbízhatónak jelöli a feladót        |
| `RBL_<LIST>`   |    4 | `rblListed`    | A kliens IP-címe szerepel egy tiltólistán, például `RBL_ZEN` |


## Nyelvi modell és opcionális modellek

| Teszt                                                 | Pont          | Beállításkulcs | Jelentés                                          |
| ----------------------------------------------------- | ------------- | -------------- | ------------------------------------------------- |
| `LLM_SPAM`, `LLM_PHISHING`, `LLM_SCAM`, `LLM_MALWARE` | legfeljebb +6 | `llmSpam`      | A modell ítélete, megszorozva a magabiztosságával |
| `LLM_HAM`                                             | legfeljebb -3 | `llmHam`       | Ugyanígy                                          |
| `TOXIC_CONTENT`                                       | 3             | `toxicity`     | Egy saját toxicitásmodell megjelölte a szöveget   |
| `NSFW_IMAGE`                                          | 3             | `nsfw`         | Egy saját képmodell megjelölt egy képet           |
