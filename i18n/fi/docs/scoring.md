<!-- source: 6f6b765c5fc1 -->

# Testit ja pisteet

Viesti on roskapostia 5 pisteestä alkaen ja hylätään 15 pisteestä alkaen. Jokainen alla oleva testi lisää tai vähentää pisteitä; tulos luettelee lauenneet testit.

Muuta rajoja valinnoilla `threshold` ja `rejectThreshold`. Muuta pisteitä valinnalla `scores`, joko asetusavaimen mukaan (`scores: {deceptiveLink: 4}`) tai testin nimen mukaan, mikä kiinnittää kyseisen testin pisteet (`scores: {FROM_NAME_BRAND: 4}`).


## Luokitin

| Testi                  | Pisteet    | Merkitys                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ---------------------- | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BAYES_00`–`BAYES_999` | −2,5…+6,25 | Luokittimen roskapostitodennäköisyys logaritmisella vedonlyöntisuhdeasteikolla: 2,4 pistettä kohdassa 90 %, 5 kohdassa 99 % ja 6,25 kohdassa 99,9 %, joten luokitin merkitsee roskapostin yksinään vain, kun se on vähintään 99-prosenttisen varma. Nimi kertoo vyöhykkeen: `BAYES_999` on 99,9 % tai enemmän, `BAYES_99` 99–99,9 %, `BAYES_50` 40–60 %. Asetusavaimet `bayesHam` ja `bayesSpam` asettavat kaksi ääripäätä. |


## Tietojenkalastelu ja linkit

| Testi                       | Pisteet | Asetusavain         | Merkitys                                                                                |
| --------------------------- | ------: | ------------------- | --------------------------------------------------------------------------------------- |
| `PHISHING_LOOKALIKE_DOMAIN` |       5 | `homograph`         | Linkin verkkotunnus jäljittelee tuotemerkkiä samannäköisillä tai vaihdetuilla merkeillä |
| `MIXED_SCRIPT_DOMAIN`       |       3 | `mixedScriptDomain` | Verkkotunnuksen nimiosa sekoittaa aakkostoja                                            |
| `BRAND_IN_DOMAIN`           |     1,5 | `brandInDomain`     | Tuotemerkin nimi jonkun toisen verkkotunnuksessa                                        |
| `TYPO_DOMAIN`               |       1 | `typoDomain`        | Yhden kirjaimen päässä tuotemerkin verkkotunnuksesta                                    |
| `DECEPTIVE_LINK`            |       3 | `deceptiveLink`     | Linkki näyttää yhden osoitteen ja vie toiseen                                           |
| `MALICIOUS_DOMAIN`          |       6 | `maliciousDomain`   | Cloudflaren haittaohjelmia estävä DNS-palvelu estää linkitetyn verkkotunnuksen          |
| `ADULT_DOMAIN`              |       2 | `adultDomain`       | Cloudflaren perhepalvelu estää linkitetyn verkkotunnuksen                               |
| `URIBL_<LIST>`              |       5 | `uriblListed`       | Linkitetty verkkotunnus on verkkotunnusten estolistalla, esimerkiksi `URIBL_DBL`        |


## Liitteet

| Testi                   | Pisteet | Asetusavain                              | Merkitys                                                                   |
| ----------------------- | ------: | ---------------------------------------- | -------------------------------------------------------------------------- |
| `EXECUTABLE_ATTACHMENT` |      10 | `executable`                             | Ohjelma tai skripti                                                        |
| `DISGUISED_EXECUTABLE`  |      12 | `disguisedExecutable`                    | Ohjelma, joka on nimetty kuin asiakirja tai kuva                           |
| `DOUBLE_EXTENSION`      |       6 | `doubleExtension`                        | Nimi kuten `invoice.pdf.exe`                                               |
| `RTL_OVERRIDE_FILENAME` |       6 | `rtlOverride`                            | Oikealta vasemmalle -ohitusmerkki piilottaa todellisen päätteen            |
| `EXECUTABLE_IN_ARCHIVE` |       8 | `executableInArchive`                    | Ohjelma ZIP-tiedoston sisällä                                              |
| `ENCRYPTED_ARCHIVE`     |       2 | `encryptedArchive`                       | Arkisto, jota tarkistimet eivät voi avata                                  |
| `MACRO_ATTACHMENT`      |       4 | `macro`                                  | Office-tiedosto, jossa on makroja                                          |
| `PDF_ACTIVE_CONTENT`    |       3 | `pdfActive`                              | PDF, jossa on JavaScriptiä, käynnistystoimintoja tai upotettuja tiedostoja |
| `RTF_EMBEDDED_OBJECT`   |       4 | `rtfObject`                              | RTF-tiedosto, jossa on upotettuja objekteja                                |
| `HTML_ATTACHMENT`       | 1 tai 3 | `htmlAttachment`, `activeHtmlAttachment` | HTML-tiedosto; 3, kun siinä on skriptejä tai lomakkeita                    |
| `VIRUS`                 |     100 | `virus`                                  | ClamAV löysi viruksen                                                      |


## Säännöt

| Testi                     | Pisteet | Merkitys                                                                                                  |
| ------------------------- | ------: | --------------------------------------------------------------------------------------------------------- |
| `GTUBE`                   |    1000 | GTUBE-testimerkkijono                                                                                     |
| `SEXTORTION_SUBJECT`      |       6 | Aiherivi, jota käytetään seksuaalisen kiristyksen ja tilin kaappaamisen huijauksissa                      |
| `PAYPAL_INVOICE`          |       6 | PayPal-lasku tai -maksupyyntö, kanava, jota käytetään väärin huijauksiin                                  |
| `MICROSOFT_SPAM_VERDICT`  |       5 | Microsoft merkitsi viestin roskapostiksi ennen sen välittämistä (luotetaan vain Microsoftin palvelimilta) |
| `MICROSOFT_HIGH_SCL`      |       3 | Microsoft antoi sille korkean roskapostin luottamustason (samoin)                                         |
| `PROMPT_INJECTION`        |       3 | Tekoälysuodattimelle osoitettua tekstiä                                                                   |
| `SELF_SPOOF`              |       3 | Väittää tulevansa vastaanottajan omasta verkkotunnuksesta eikä läpäise todennusta                         |
| `FROM_NAME_OTHER_ADDRESS` |     2,5 | Näyttönimi sisältää eri sähköpostiosoitteen                                                               |
| `FROM_NAME_BRAND`         |       2 | Näyttönimi väittää edustavansa tuotemerkkiä, johon osoite ei kuulu                                        |
| `DATE_IN_FUTURE`          |       1 | Päivätty yli vuorokauden päähän tulevaisuuteen                                                            |
| `MISSING_DATE`            |     0,5 | Ei Date-otsaketta                                                                                         |
| `MISSING_MESSAGE_ID`      |     0,5 | Ei Message-ID-otsaketta                                                                                   |

Säännöt, joiden arvo on vähintään roskapostiraja, näkyvät myös kohteessa `results.arbitrary`, kuten aiemmissa versioissa.


## Hämäys ja kieli

| Testi                  | Pisteet | Asetusavain           | Merkitys                                                           |
| ---------------------- | ------: | --------------------- | ------------------------------------------------------------------ |
| `INVISIBLE_CHARACTERS` |       2 | `invisibleCharacters` | Kolme tai useampi näkymätöntä merkkiä tekstin sisällä              |
| `MIXED_SCRIPT_WORDS`   |     2,5 | `mixedScriptWords`    | Kaksi tai useampi sanaa sekoittaa eri aakkostojen kirjaimia        |
| `STYLED_LETTERS`       |     1,5 | `styledLetters`       | Matemaattiset tai kehystetyt kirjaimet tavallisen tekstin asemesta |
| `LANGUAGE_NOT_ALLOWED` |       3 | `languageNotAllowed`  | Ei valinnassa `allowedLanguages`                                   |


## Todennus

Vaatii asiakkaan IP-osoitteen ja valinnan `authentication: true`.

| Testi          | Pisteet | Asetusavain (kohteessa `authentication.weights`) |
| -------------- | ------: | ------------------------------------------------ |
| `SPF_PASS`     |    −0,5 | `spfPass`                                        |
| `SPF_FAIL`     |       2 | `spfFail`                                        |
| `SPF_SOFTFAIL` |       1 | `spfSoftfail`                                    |
| `DKIM_PASS`    |    −0,5 | `dkimPass`                                       |
| `DKIM_FAIL`    |       1 | `dkimFail`                                       |
| `DMARC_PASS`   |    −1,5 | `dmarcPass`                                      |
| `DMARC_FAIL`   |     3,5 | `dmarcFail`                                      |
| `ARC_PASS`     |    −0,5 | `arcPass`                                        |
| `ARC_FAIL`     |       1 | `arcFail`                                        |


## Maine ja estolistat

| Testi          | Pisteet | Asetusavain   | Merkitys                                                      |
| -------------- | ------: | ------------- | ------------------------------------------------------------- |
| `DENYLISTED`   |     100 | `denylisted`  | Lähettäjän IP-osoite, verkkotunnus tai osoite on estolistalla |
| `ALLOWLISTED`  |     −20 | `allowlisted` | Se on sallittujen listalla                                    |
| `TRUTH_SOURCE` |      −5 | `truthSource` | Mainepalvelu merkitsee lähettäjän luotetuksi                  |
| `RBL_<LIST>`   |       4 | `rblListed`   | Asiakkaan IP-osoite on estolistalla, esimerkiksi `RBL_ZEN`    |


## Kielimalli ja valinnaiset mallit

| Testi                                                 | Pisteet     | Asetusavain | Merkitys                                     |
| ----------------------------------------------------- | ----------- | ----------- | -------------------------------------------- |
| `LLM_SPAM`, `LLM_PHISHING`, `LLM_SCAM`, `LLM_MALWARE` | enintään +6 | `llmSpam`   | Mallin tuomio kerrottuna sen varmuudella     |
| `LLM_HAM`                                             | enintään −3 | `llmHam`    | Samoin                                       |
| `TOXIC_CONTENT`                                       | 3           | `toxicity`  | Toimittamasi toksisuusmalli merkitsi tekstin |
| `NSFW_IMAGE`                                          | 3           | `nsfw`      | Toimittamasi kuvamalli merkitsi kuvan        |
