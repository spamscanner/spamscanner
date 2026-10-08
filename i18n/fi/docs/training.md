<!-- source: 7cc30ff4ad91 -->

# Koulutus

Mukana tuleva malli toimii heti. Omalla postillasi koulutettu malli toimii paremmin, koska se oppii, miltä sinun hamisi näyttää: uutiskirjeesi, kollegojesi kirjoitustyyli, kielet, joilla saat postia.


## Mallin kouluttaminen

Osoita `train` roskaposti- ja ham-kansioihin:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --ham ~/Maildir/.Archive --out my-model.json
```

Lähteet voivat olla:

* **mbox**-tiedostoja, myös gzip-pakattuja (`.mbox.gz`),
* **Maildir** (sen `cur`- ja `new`-kansiot luetaan, `tmp` ohitetaan),
* `.eml`-tiedostojen **kansio**, luettuna rekursiivisesti,
* **aineisto**: CSV- tai JSON Lines -tiedosto, jossa on tekstisarake ja luokkasarake (`--dataset`). Sarakkeet, joiden nimi on `text`, `message`, `body`, `email` tai `content`, sekä `label`, `category`, `class`, `spam` tai `is_spam`, löydetään automaattisesti; muussa tapauksessa käytä valitsimia `--text-column` ja `--label-column`. Luokat kuten `spam`, `1`, `phishing` ja `ham`, `0`, `not_spam`, `legitimate` ymmärretään.

Päällekkäiset viestit lasketaan kerran. Jos haluat rakentaa mukana tulevan mallin päälle tyhjästä aloittamisen sijaan, lisää `--merge`.

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
Precision: 89.72%   Recall: 11.18%   F1: 19.89%
False positives: 167 (0.18% of ham)   False negatives: 132
Unsure: 91247 (86.54%)
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

| Aineisto                                                                                                                                                                                                                                                                                                                   | Lisenssi                | Sisältö                              |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- | ------------------------------------ |
| [FredZhang7/all-scam-spam](https://huggingface.co/datasets/FredZhang7/all-scam-spam)                                                                                                                                                                                                                                       | Apache-2.0              | Viestejä ja sähköposteja 43 kielellä |
| [SetFit/enron_spam](https://huggingface.co/datasets/SetFit/enron_spam)                                                                                                                                                                                                                                                     | Julkinen tutkimuskorpus | Enron-Spam-korpus                    |
| [alt-gnome/telegram-spam](https://huggingface.co/datasets/alt-gnome/telegram-spam)                                                                                                                                                                                                                                         | CC0-1.0                 | Venäjänkielisiä Telegram-viestejä    |
| [tanaos/synthetic-spam-detection-dataset-german](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-german), [-italian](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-italian), [-spanish](https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-spanish) | MIT                     | Synteettisiä viestejä                |

Se oppi 62 480 roskapostiviestistä ja 76 489 ham-viestistä. Skripti jättää erilleen joka kymmenennen viestin, kouluttaa loput ja mittaa pelkän luokittimen ilman muita tarkistuksia:

| Erilleen jätetty testi | Viestit | Tarkkuus | Saanti | Väärät positiiviset | Epävarmat |
| ---------------------- | ------: | -------: | -----: | ------------------: | --------: |
| Englanti               |   6 564 |  100,0 % | 97,0 % |               0,0 % |     2,4 % |
| Venäjä                 |   1 682 |  100,0 % | 97,4 % |               0,0 % |     2,2 % |
| Italia                 |   1 389 |   98,1 % | 85,3 % |               1,8 % |    10,9 % |
| Saksa                  |   1 309 |   97,7 % | 76,1 % |               2,2 % |    20,7 % |
| Espanja                |   1 281 |   97,5 % | 82,5 % |               2,6 % |    16,8 % |
| Enron-Spam             |   2 888 |  100,0 % | 93,1 % |               0,0 % |     4,5 % |
| all-scam-spam          |   4 236 |  100,0 % | 88,8 % |               0,0 % |    11,2 % |
| Kaikki                 |  13 840 |   99,2 % | 85,1 % |               0,5 % |    12,4 % |

Roskaposti tarkoittaa tässä luokittimen todennäköisyyttä 99 % tai enemmän, eli kohtaa, jossa pelkkä luokitin saavuttaa roskapostirajan. Tarkistuksessa roskaposti, josta luokitin on vähemmän varma, saa silti pisteitä, ja muut tarkistukset lisäävät omansa.

Saksan, espanjan ja italian tulokset tulevat synteettisistä aineistoista, joissa on lähes identtisiä viestejä, jotka on luokiteltu sekä roskapostiksi että hamiksi: osa virheestä on luokittelussa, ei mallissa. Paras korjaus on posti omilla kielilläsi. Luvut kaikkine kielineen ja aineistoineen ovat mallin kentässä `metadata.metrics`.

### Lisää kieliä

`npm run model:train -- --with multilingual-sms` lisää [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset) -aineiston: SMS Spam Collectionin konekäännettynä 21 kielelle. Se on jätetty pois mukana tulevasta mallista, koska sen kuvauskortti ilmoittaa GPL-lisenssin; tarkista, sopiiko se tapaan, jolla jaat mallin. Sen kanssa koulutettuna erilleen jätettyjen viestien tulokset kielille, joita mukana tuleva malli tuskin tuntee, olivat:

| Kieli  | Viestit | Tarkkuus | Saanti | Väärät positiiviset |
| ------ | ------: | -------: | -----: | ------------------: |
| Kiina  |     430 |  100,0 % | 82,3 % |               0,0 % |
| Arabia |     430 |  100,0 % | 84,6 % |               0,0 % |
| Korea  |     412 |  100,0 % | 80,4 % |               0,0 % |
| Japani |     486 |   96,0 % | 85,7 % |               0,5 % |
| Hindi  |     412 |  100,0 % | 63,9 % |               0,0 % |
| Ranska |     480 |   98,6 % | 94,2 % |               0,6 % |
| Turkki |     220 |  100,0 % | 73,1 % |               0,0 % |

### Uudelleenkoulutus

```sh
npm run model:train                       # downloads the datasets into data/ the first time
npm run model:train -- --no-download      # reuse data/
npm run model:train -- --out /tmp/model.json --max-features 200000
```


## Mallitiedosto

Malli on JSON-tiedosto: opittujen roskaposti- ja ham-viestien määrä sekä jokaiselle tiivistetylle piirteelle se, kuinka moni roskaposti- ja ham-viesti sisälsi sen, lajiteltuna ja base64-koodattuna. Se ei sisällä sanoja eikä viestien tekstiä. `--max-features` säilyttää vain yleisimmät piirteet ja `--min-count` pudottaa harvinaiset, jolloin tarkkuudesta tingitään koon hyväksi; mukana tuleva malli säilyttää 400 000 piirrettä noin 6 Mt:ssä.

Spam Scanner 6:n ja sitä vanhempien versioiden malleja ei voi ladata: ne tiivistivät eri piirteitä. Kouluta uusi malli samasta postista.
