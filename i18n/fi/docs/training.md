<!-- source: 6f344039ec5d -->

# Koulutus

Mukana tuleva malli toimii heti. Omalla postillasi koulutettu malli toimii paremmin, koska se oppii, miltä sinun hamisi näyttää: uutiskirjeesi, kollegojesi kirjoitustyyli, kielet, joilla saat postia.


## Mallin kouluttaminen

Osoita `train` roskaposti- ja ham-kansioihin:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

Lähteet voivat olla:

* **mbox**-tiedostoja, myös gzip-pakattuja (`.mbox.gz`; muut `.gz`-tiedostot ohitetaan),
* **Maildir** (sen `cur`- ja `new`-kansiot luetaan, `tmp` ohitetaan),
* `.eml`-tiedostojen **kansio**, luettuna rekursiivisesti,
* **aineisto**: CSV- tai JSON Lines -tiedosto, jossa on tekstisarake ja luokkasarake (`--dataset`). Sarakkeet tai JSON-kentät, joiden nimi on `text`, `message`, `body`, `email text`, `email`, `content`, `sms` tai `v2`, sekä `label`, `category`, `is_spam`, `spam`, `email type`, `class`, `type`, `label_text`, `v1` tai `labels`, kirjainkoosta riippumatta, löydetään automaattisesti (JSON Linesissa `label_text` ennen `label`-kenttää); muussa tapauksessa käytä valitsimia `--text-column` ja `--label-column`. JSON-rivi, joka ei ole olio, ohitetaan. Luokat kuten `spam`, `1`, `phishing` ja `ham`, `0`, `not_spam`, `legitimate` ymmärretään.

Päällekkäiset viestit lasketaan kerran. Viesti, joka on sekä roskaposti- että ham-lähteissä, säilytetään roskapostina, koska roskapostilähteet luetaan ensin. Jos haluat rakentaa mukana tulevan mallin päälle tyhjästä aloittamisen sijaan, lisää `--merge`.

Mallin käyttäminen:

```sh
spamscanner scan message.eml --model my-model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

```js
const scanner = new SpamScanner({classifier: '/var/lib/spamscanner/model.json'});
```

Kuinka paljon postia riittää: muutama sata kumpaakin lajia antaa käyttökelpoisen mallin, muutama tuhat hyvän. Pidä nämä kaksi suunnilleen tasapainossa ja pidä hamissa posti, jota et halua suodattaa (salasanan palautukset, omien toimittajiesi laskut).


## Mittaaminen

Jätä osa postista koulutuksen ulkopuolelle ja mittaa sillä:

```sh
spamscanner eval --model my-model.json --spam held-out/spam --ham held-out/ham
```

Mukana tuleva malli 21 kielen tekstiviesteillä, joita se ei koskaan nähnyt, useimmat kielillä, joita se tuskin tuntee:

```text
Messages: 13028 spam, 92406 ham
Precision: 87.34%   Recall: 10.01%   F1: 17.96%
False positives: 189 (0.20% of ham)   False negatives: 372
Unsure: 87222 (82.73%)
```

Tarkkuus (precision) kertoo, kuinka suuri osa siitä, mitä malli kutsuu roskapostiksi, on roskapostia; saanti (recall), kuinka suuren osan roskapostista se tunnistaa. Epävarmat viestit lasketaan tässä ohi menneeksi roskapostiksi, vaikka tarkistuksessa muut tarkistukset ja kielimalli voivat silti tunnistaa ne. Tärkein seurattava luku on väärät positiiviset: roskapostiksi merkitty ham. Yllä olevassa ajossa malli on useimmista näistä viesteistä epävarma eikä väärässä, mikä on tarkoitettu toiminta kielille, joilla sillä on vähän postia.

`--json` antaa samat luvut skripteille.


## Oppiminen raporteista

Kun käyttäjät siirtävät postia Junk-kansioon tai sieltä pois, opeta mallille viesti kerrallaan:

```sh
spamscanner learn spam message.eml --model /var/lib/spamscanner/model.json
spamscanner learn ham message.eml --model /var/lib/spamscanner/model.json
```

Ensimmäinen `learn` luo tiedoston mukana tulevasta mallista. HTTP:n kautta [HTTP API:n](http-api.md) `POST /learn/spam` ja `/learn/ham` tekevät saman, ja `spamc -L spam` toimii [spamd-palvelinta](mail-servers.md#a-drop-in-for-spamassassins-spamd) vastaan valitsimella `--allow-tell`. [Dovecotin IMAPSieve](mail-servers.md#dovecot-junk-folder-and-learning) voi kutsua kumpaa tahansa, kun viesti siirretään.

Node.js:stä:

```js
await scanner.learn(raw, 'spam');
await scanner.unlearn(raw, 'spam'); // undo, before learning it as ham
scanner.saveModel('/var/lib/spamscanner/model.json');
```

Väärin luokitelluksi ilmoitettu viesti pitää poistaa opitusta väärästä luokasta ennen kuin se opitaan oikeaan, jos se on opittu aiemmin.


## Mukana tuleva malli

`model/classifier.json` koostetaan komennolla `npm run model:train` näistä Hugging Facen julkisista aineistoista, jotka ovat kaikki avoimien lisenssien alaisia:

| Aineisto                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Lisenssi                   | Sisältö                                                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------- | ------------------------------------------------------------------------------------ |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Apache-2.0                 | Viestejä ja sähköposteja 43 kielellä                                                 |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Julkinen tutkimuskorpus    | Enron-Spam-korpus                                                                    |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | CC0-1.0                    | Venäjänkielisiä Telegram-viestejä                                                    |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish)                                                                                                                                                                                                                                                                                                                                                                                   | MIT                        | Synteettisiä viestejä                                                                |
| [kudzaiprichard/aura-phishing-email-corpus](https://huggingface.co/datasets/kudzaiprichard/aura-phishing-email-corpus) (SpamAssassin, Nazario, Nigerian fraud)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | CC-BY-4.0                  | Postituslistoja, uutiskirjeitä, roskapostia, tietojenkalastelua ja huijausviestejä   |
| [anmolshrivastav/scam_ham_india_14_languages](https://huggingface.co/datasets/anmolshrivastav/scam_ham_india_14_languages)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | MIT                        | Viestejä 14:llä Intian kielellä                                                      |
| [chairulridjal/high-accuracy-email-classifier-indonesian](https://huggingface.co/datasets/chairulridjal/high-accuracy-email-classifier-indonesian)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Apache-2.0                 | Indonesiankielisiä sähköposteja luokittain                                           |
| [JeisonJimenez/emails_2025](https://huggingface.co/datasets/JeisonJimenez/emails_2025)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Apache-2.0                 | Yhden yrityksen posti espanjaksi                                                     |
| [imnim/multiclass-email-classification](https://huggingface.co/datasets/imnim/multiclass-email-classification), [weijianzhg/email-triage-action-seed](https://huggingface.co/datasets/weijianzhg/email-triage-action-seed), [dedsec995/Email_Classification_Text](https://huggingface.co/datasets/dedsec995/Email_Classification_Text), [vpakarinen/open-wiki-email-templates](https://huggingface.co/datasets/vpakarinen/open-wiki-email-templates), [neurocheckout-ai/synthetic-abandoned-cart-email-examples](https://huggingface.co/datasets/neurocheckout-ai/synthetic-abandoned-cart-email-examples), [dhnanjay/MarketMail-AI-Dataset](https://huggingface.co/datasets/dhnanjay/MarketMail-AI-Dataset) | MIT, Apache-2.0, CC-BY-4.0 | Tavallista postia: laskuja, varauksia, uutiskirjeitä, tarjouksia ja tili-ilmoituksia |
| [AmazonScience/massive](https://huggingface.co/datasets/AmazonScience/massive)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | CC-BY-4.0                  | Mitä ihmiset pyytävät avustajalta, 20 kielellä                                       |
| [sinabis-group/sinabis-100k-synthetic-emails](https://huggingface.co/datasets/sinabis-group/sinabis-100k-synthetic-emails)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | CC-BY-4.0                  | Keksityn yrityksen posti ranskaksi                                                   |
| [scripts/everyday-mail](https://github.com/spamscanner/spamscanner/tree/master/scripts/everyday-mail)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Tämän projektin mukana     | Arkipostia ja huijauksia 23 kielellä, kirjoitettu tätä projektia varten              |

Ham sisältää tavallista yritys- ja kauppapostia (laskuja, tilaus- ja tili-ilmoituksia, uutiskirjeitä, tarjouksia), joten sellainen posti ei yksinään näytä roskapostilta.

Aineistojen palautusviestit (bounce) jätetään pois: niitä on vain roskapostin joukossa, mikä opettaisi luokittimelle, että jokainen palautusviesti on roskapostia.

Kolme viimeistä riviä ovat tavallista tekstiä kielillä, joista muissa aineistoissa on lähinnä roskapostia (ranska, portugali, hollanti, pohjoismaiset kielet, puola, turkki, arabia, japani, korea, kiina ja muita) ja joissa jokainen tavallinen sana luettaisiin muuten roskapostiksi. Kymmenestätuhannesta 20 kielen tavallisesta tekstistä, joilla mallia ei ole koulutettu, 1,4 % saa todennäköisyyden 80 % tai enemmän (4,8 % ilman näitä rivejä) ja 0,1 % todennäköisyyden 99 % tai enemmän. Tämä teksti ei ole oikeaa postia, ja kullekin kielelle kirjoitettuja huijauksia on vähän: luokitin on näiden kielten tavallisesta postista varmempi ja saa niiden roskapostista kiinni vain hieman enemmän.

Se oppi 81 254 roskapostiviestistä ja 133 317 ham-viestistä. Skripti jättää erilleen joka kymmenennen viestin, kouluttaa loput ja mittaa pelkän luokittimen ilman muita tarkistuksia:

| Erilleen jätetty testi | Viestit | Tarkkuus | Saanti | Väärät positiiviset | Epävarmat |
| ---------------------- | ------: | -------: | -----: | ------------------: | --------: |
| Englanti               |   8 481 |  100,0 % | 96,3 % |               0,0 % |     2,6 % |
| Venäjä                 |   1 680 |  100,0 % | 97,4 % |               0,0 % |     2,2 % |
| Italia                 |   1 392 |   99,0 % | 81,0 % |               0,9 % |    12,6 % |
| Saksa                  |   1 314 |   97,9 % | 71,4 % |               1,9 % |    22,3 % |
| Espanja                |   2 088 |   98,7 % | 53,3 % |               0,4 % |    16,2 % |
| Enron-Spam             |   2 870 |  100,0 % | 95,2 % |               0,0 % |     2,6 % |
| all-scam-spam          |   4 222 |   99,9 % | 92,2 % |               0,0 % |     9,1 % |
| Kaikki                 |  21 329 |   99,6 % | 76,6 % |               0,2 % |    14,2 % |

Roskaposti tarkoittaa tässä luokittimen todennäköisyyttä 99 % tai enemmän, eli kohtaa, jossa pelkkä luokitin saavuttaa roskapostirajan. Tarkistuksessa roskaposti, josta luokitin on vähemmän varma, saa silti pisteitä, ja muut tarkistukset lisäävät omansa.

Saksan, espanjan ja italian tulokset tulevat synteettisistä aineistoista, joissa on lähes identtisiä viestejä, jotka on luokiteltu sekä roskapostiksi että hamiksi: osa virheestä on luokittelussa, ei mallissa. Paras korjaus on posti omilla kielilläsi. Luvut kaikkine kielineen ja aineistoineen ovat mallin kentässä `metadata.metrics`.

### Lisää kieliä

`npm run model:train -- --with multilingual-sms` lisää [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset) -aineiston: SMS Spam Collectionin konekäännettynä 21 kielelle. Se on jätetty pois mukana tulevasta mallista, koska sen kuvauskortti ilmoittaa GPL-lisenssin; tarkista, sopiiko se tapaan, jolla jaat mallin. Sen kanssa koulutettuna erilleen jätettyjen viestien tulokset kielille, joita mukana tuleva malli tuskin tuntee, olivat:

| Kieli  | Viestit | Tarkkuus | Saanti | Väärät positiiviset |
| ------ | ------: | -------: | -----: | ------------------: |
| Kiina  |     432 |  100,0 % | 86,1 % |               0,0 % |
| Arabia |     432 |  100,0 % | 83,1 % |               0,0 % |
| Korea  |     412 |  100,0 % | 78,3 % |               0,0 % |
| Japani |     486 |   96,1 % | 87,5 % |               0,5 % |
| Hindi  |     494 |  100,0 % | 76,2 % |               0,0 % |
| Ranska |     511 |   98,7 % | 88,6 % |               0,6 % |
| Turkki |     222 |  100,0 % | 70,4 % |               0,0 % |

### Uudelleenkoulutus

```sh
npm run model:train                       # downloads the datasets into data/ the first time; needs 4 GB of memory
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## Mallitiedosto

Malli on JSON-tiedosto: opittujen roskaposti- ja ham-viestien määrä sekä jokaiselle tiivistetylle piirteelle se, kuinka moni roskaposti- ja ham-viesti sisälsi sen, lajiteltuna ja base64-koodattuna. Se ei sisällä sanoja eikä viestien tekstiä. `--max-features` säilyttää vain yleisimmät piirteet ja `--min-count` pudottaa harvinaiset, jolloin tarkkuudesta tingitään koon hyväksi; mukana tuleva malli säilyttää 400 000 piirrettä noin 6 Mt:ssä.

Spam Scanner 6:n ja sitä vanhempien versioiden malleja ei voi ladata: ne tiivistivät eri piirteitä. Kouluta uusi malli samasta postista.
