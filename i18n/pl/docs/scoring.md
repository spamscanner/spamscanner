<!-- source: 6f6b765c5fc1 -->

# Testy i punkty

Wiadomość jest spamem od 5 punktów i jest odrzucana od 15. Każdy z poniższych testów dodaje lub odejmuje punkty; wynik wymienia te, które zadziałały.

Progi zmienisz przez `threshold` i `rejectThreshold`. Punkty zmienisz przez `scores`, albo kluczem ustawienia (`scores: {deceptiveLink: 4}`), albo nazwą testu, co ustala punkty tego testu na stałe (`scores: {FROM_NAME_BRAND: 4}`).


## Klasyfikator

| Test                      | Punkty           | Znaczenie                                                                                                                                                                                                                                                                                                                                                                                        |
| ------------------------- | ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `BAYES_00` do `BAYES_999` | od -2,5 do +6,25 | Prawdopodobieństwo spamu według klasyfikatora, w skali logarytmu szans: 2,4 punktu przy 90%, 5 przy 99% i 6,25 przy 99,9%, więc sam klasyfikator oznacza spam tylko wtedy, gdy jest pewny co najmniej w 99%. Nazwa wskazuje przedział: `BAYES_999` to 99,9% lub więcej, `BAYES_99` od 99% do 99,9%, `BAYES_50` od 40% do 60%. Klucze ustawień `bayesHam` i `bayesSpam` ustalają oba końce skali. |


## Phishing i linki

| Test                        | Punkty | Klucz ustawienia    | Znaczenie                                                                      |
| --------------------------- | -----: | ------------------- | ------------------------------------------------------------------------------ |
| `PHISHING_LOOKALIKE_DOMAIN` |      5 | `homograph`         | Domena linku udaje markę za pomocą podobnych lub zamienionych znaków           |
| `MIXED_SCRIPT_DOMAIN`       |      3 | `mixedScriptDomain` | Etykieta domeny miesza alfabety                                                |
| `BRAND_IN_DOMAIN`           |    1,5 | `brandInDomain`     | Nazwa marki wewnątrz cudzej domeny                                             |
| `TYPO_DOMAIN`               |      1 | `typoDomain`        | Jedna litera różnicy od domeny marki                                           |
| `DECEPTIVE_LINK`            |      3 | `deceptiveLink`     | Link pokazuje jeden adres, a prowadzi pod inny                                 |
| `MALICIOUS_DOMAIN`          |      6 | `maliciousDomain`   | Resolver Cloudflare blokujący złośliwe oprogramowanie blokuje linkowaną domenę |
| `ADULT_DOMAIN`              |      2 | `adultDomain`       | Rodzinny resolver Cloudflare blokuje linkowaną domenę                          |
| `URIBL_<LIST>`              |      5 | `uriblListed`       | Linkowana domena jest na czarnej liście domen, na przykład `URIBL_DBL`         |


## Załączniki

| Test                    |  Punkty | Klucz ustawienia                         | Znaczenie                                                                  |
| ----------------------- | ------: | ---------------------------------------- | -------------------------------------------------------------------------- |
| `EXECUTABLE_ATTACHMENT` |      10 | `executable`                             | Program lub skrypt                                                         |
| `DISGUISED_EXECUTABLE`  |      12 | `disguisedExecutable`                    | Program nazwany jak dokument lub obraz                                     |
| `DOUBLE_EXTENSION`      |       6 | `doubleExtension`                        | Nazwa taka jak `invoice.pdf.exe`                                           |
| `RTL_OVERRIDE_FILENAME` |       6 | `rtlOverride`                            | Znak wymuszający kierunek od prawej do lewej ukrywa prawdziwe rozszerzenie |
| `EXECUTABLE_IN_ARCHIVE` |       8 | `executableInArchive`                    | Program w pliku ZIP                                                        |
| `ENCRYPTED_ARCHIVE`     |       2 | `encryptedArchive`                       | Archiwum, którego skanery nie mogą otworzyć                                |
| `MACRO_ATTACHMENT`      |       4 | `macro`                                  | Plik Office z makrami                                                      |
| `PDF_ACTIVE_CONTENT`    |       3 | `pdfActive`                              | Plik PDF z JavaScript, akcjami uruchamiania lub osadzonymi plikami         |
| `RTF_EMBEDDED_OBJECT`   |       4 | `rtfObject`                              | Plik RTF z osadzonymi obiektami                                            |
| `HTML_ATTACHMENT`       | 1 lub 3 | `htmlAttachment`, `activeHtmlAttachment` | Plik HTML; 3, gdy zawiera skrypty lub formularze                           |
| `VIRUS`                 |     100 | `virus`                                  | ClamAV znalazł wirusa                                                      |


## Reguły

| Test                      | Punkty | Znaczenie                                                                                          |
| ------------------------- | -----: | -------------------------------------------------------------------------------------------------- |
| `GTUBE`                   |   1000 | Ciąg testowy GTUBE                                                                                 |
| `SEXTORTION_SUBJECT`      |      6 | Temat używany w oszustwach typu sextortion i przejmowania kont                                     |
| `PAYPAL_INVOICE`          |      6 | Faktura lub prośba o pieniądze w PayPal, kanał nadużywany do oszustw                               |
| `MICROSOFT_SPAM_VERDICT`  |      5 | Microsoft oznaczył wiadomość jako spam przed jej przekazaniem (zaufane tylko z serwerów Microsoft) |
| `MICROSOFT_HIGH_SCL`      |      3 | Microsoft nadał jej wysoki poziom pewności spamu (tak samo)                                        |
| `PROMPT_INJECTION`        |      3 | Tekst skierowany do filtra AI                                                                      |
| `SELF_SPOOF`              |      3 | Podaje się za wiadomość z własnej domeny odbiorcy i nie przechodzi uwierzytelnienia                |
| `FROM_NAME_OTHER_ADDRESS` |    2,5 | Nazwa wyświetlana zawiera inny adres e-mail                                                        |
| `FROM_NAME_BRAND`         |      2 | Nazwa wyświetlana podaje się za markę, do której adres nie należy                                  |
| `DATE_IN_FUTURE`          |      1 | Data o ponad dzień w przyszłości                                                                   |
| `MISSING_DATE`            |    0,5 | Brak nagłówka Date                                                                                 |
| `MISSING_MESSAGE_ID`      |    0,5 | Brak nagłówka Message-ID                                                                           |

Reguły warte co najmniej tyle co próg spamu pojawiają się też w `results.arbitrary`, jak we wcześniejszych wersjach.


## Zaciemnianie i język

| Test                   | Punkty | Klucz ustawienia      | Znaczenie                                              |
| ---------------------- | -----: | --------------------- | ------------------------------------------------------ |
| `INVISIBLE_CHARACTERS` |      2 | `invisibleCharacters` | Trzy lub więcej niewidocznych znaków w tekście         |
| `MIXED_SCRIPT_WORDS`   |    2,5 | `mixedScriptWords`    | Dwa lub więcej słów miesza litery z różnych alfabetów  |
| `STYLED_LETTERS`       |    1,5 | `styledLetters`       | Litery matematyczne lub w ramkach udające zwykły tekst |
| `LANGUAGE_NOT_ALLOWED` |      3 | `languageNotAllowed`  | Język spoza `allowedLanguages`                         |


## Uwierzytelnianie

Wymaga adresu IP klienta i `authentication: true`.

| Test           | Punkty | Klucz ustawienia (w `authentication.weights`) |
| -------------- | -----: | --------------------------------------------- |
| `SPF_PASS`     |   -0,5 | `spfPass`                                     |
| `SPF_FAIL`     |      2 | `spfFail`                                     |
| `SPF_SOFTFAIL` |      1 | `spfSoftfail`                                 |
| `DKIM_PASS`    |   -0,5 | `dkimPass`                                    |
| `DKIM_FAIL`    |      1 | `dkimFail`                                    |
| `DMARC_PASS`   |   -1,5 | `dmarcPass`                                   |
| `DMARC_FAIL`   |    3,5 | `dmarcFail`                                   |
| `ARC_PASS`     |   -0,5 | `arcPass`                                     |
| `ARC_FAIL`     |      1 | `arcFail`                                     |


## Reputacja i czarne listy

| Test           | Punkty | Klucz ustawienia | Znaczenie                                                              |
| -------------- | -----: | ---------------- | ---------------------------------------------------------------------- |
| `DENYLISTED`   |    100 | `denylisted`     | Adres IP, domena lub adres e-mail nadawcy jest na liście zablokowanych |
| `ALLOWLISTED`  |    -20 | `allowlisted`    | Jest na liście dozwolonych                                             |
| `TRUTH_SOURCE` |     -5 | `truthSource`    | Usługa reputacji oznacza nadawcę jako zaufanego                        |
| `RBL_<LIST>`   |      4 | `rblListed`      | Adres IP klienta jest na czarnej liście, na przykład `RBL_ZEN`         |


## Model językowy i modele opcjonalne

| Test                                                  | Punkty | Klucz ustawienia | Znaczenie                                                  |
| ----------------------------------------------------- | ------ | ---------------- | ---------------------------------------------------------- |
| `LLM_SPAM`, `LLM_PHISHING`, `LLM_SCAM`, `LLM_MALWARE` | do +6  | `llmSpam`        | Werdykt modelu pomnożony przez jego pewność                |
| `LLM_HAM`                                             | do -3  | `llmHam`         | Tak samo                                                   |
| `TOXIC_CONTENT`                                       | 3      | `toxicity`       | Dostarczony przez ciebie model toksyczności oznaczył tekst |
| `NSFW_IMAGE`                                          | 3      | `nsfw`           | Dostarczony przez ciebie model obrazów oznaczył obraz      |
