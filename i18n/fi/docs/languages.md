<!-- source: 9537a0e62eb0 -->

# Kielet

Roskapostia tulee kaikilla kielillä, ja niin tulee tavallista postiakin. Spam Scanner lukee molempia, ja se on varovainen kielten suhteen, joista se tietää vähän: roskapostisuodatin, joka merkitsee jokaisen arabian- tai kiinankielisen viestin, on huonompi kuin ei suodatinta lainkaan.


## Jokaisen kirjoitusjärjestelmän lukeminen

* **Sanat.** Teksti pilkotaan `Intl.Segmenter`illä, joka noudattaa Unicoden sanarajasääntöjä ja käyttää sanakirjoja kiinalle, japanille, thaille, laolle, khmerille ja burmalle, eli ilman välilyöntejä kirjoitettaville kirjoitusjärjestelmille. Pitkät tekstit pilkotaan ensin osiin, koska Node.js 18:n segmentoija hidastuu hyvin pitkillä merkkijonoilla.
* **Normalisointi.** Unicode NFKC muuntaa täysleveät kirjaimet ja useimmat tyylitellyt kirjaimet (𝐅𝐑𝐄𝐄, Ⓕⓡⓔⓔ) tavallisiksi. Teksti muunnetaan pienaakkosiksi Unicoden sääntöjen mukaan.
* **Naamioinnit.** Sanojen sisällä olevat näkymättömät merkit (`free`, jossa on nollalevyinen välilyönti kahden kirjaimen välissä, tavutusvihjeet) poistetaan ja lasketaan. Aakkostoja sekoittavat sanat, kuten `pаypal` kyrillisellä а:lla, palautetaan yhteen aakkostoon ja lasketaan. Kirjaimina käytetyt numerot (`v1agra`) muunnetaan. Jokainen naamiointi on oma piirteensä, ja kolme tai useampi näkymätöntä merkkiä tai kaksi tai useampi sekoitettua sanaa lisäävät myös pisteitä.


## Kielen tunnistaminen

Kunkin viestin kieli tunnistetaan sen kirjoitusjärjestelmästä ja, monen kielen yhteisten kirjoitusjärjestelmien kohdalla, sen kirjaimista:

* Hangul on koreaa; hiragana ja katakana tarkoittavat japania; thai, kreikka, heprea, armenia, georgia, bengali, tamili ja muut yhden kielen käyttämät kirjoitusjärjestelmät nimeävät kielen suoraan.
* Vain yhdessä kielessä esiintyvät kyrilliset kirjaimet ratkaisevat ukrainan (і, ї, є, ґ), valkovenäjän (ў), serbian (ђ, ћ, џ), makedonian (ѓ, ќ, ѕ) ja venäjän (ы, э, ё) välillä.
* Usean kielen yhteisillä kirjoitusjärjestelmillä (latinalainen, kyrillinen, arabialainen, devanagari ja muut) kirjoitettu teksti menee, kun se on arvioitavaksi tarpeeksi pitkä, [francille](https://github.com/wooorm/franc), rajattuna sähköpostissa yleisiin kieliin, jotta lyhyitä viestejä ei merkitä harvinaisilla kielillä.

Kieli ilmoitetaan kentässä `result.language`, ja `allowedLanguages: ['en', 'de']` (`--allow-language en,de`) lisää 3 pistettä postille, joka on varmuudella tunnistettu millä tahansa muulla kielellä kirjoitetuksi.


## Kielet, joista malli tietää vähän

Luokitin oppii esimerkeistä. Julkisissa roskapostiaineistoissa on paljon enemmän vieraskielistä roskapostia kuin vieraskielistä hamia, joten naiivi luokitin oppii, että kiinan- tai arabiankielinen teksti itsessään tarkoittaa roskapostia. Spam Scanner korjaa tämän kolmella tavalla:

1. **Kieli ei koskaan ole todiste.** Tunnistettua kieltä ja kirjoitusjärjestelmää ei käytetä vihjeinä.
2. **Sanoja punnitaan oman kielensä sisällä.** Sanan roskapostitodennäköisyys lasketaan niiden roskaposti- ja ham-viestien määrää vasten, jotka luokitin näki viestin kielellä, ei kaikilla kielillä. Arkinen portugalinkielinen sana pysyy neutraalina mallissa, joka näki enimmäkseen portugalinkielistä roskapostia.
3. **Varmuus seuraa kattavuutta.** Tulosta vedetään kohti arvoa "epävarma" suhteessa siihen, kuinka monta kunkin lajin viestiä luokitin näki kyseisellä kielellä: täysi varmuus vaatii 1 000 kumpaakin (tai pienille henkilökohtaisille malleille 2 % pienemmästä luokasta). Kieli, jolla koulutusaineistossa ei ole lainkaan hamia, saa aina tuloksen "epävarma".

Mukana tuleva malli ei koskaan nähnyt [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset) -aineistoa, joka koostuu 21 kielelle konekäännetyistä tekstiviesteistä. Ennen näitä sääntöjä se merkitsi 5,7 % aineiston hamista roskapostiksi, mukaan lukien 55 % portugalinkielisistä ja 41 % ranskankielisistä. Niiden kanssa osuus on 0,18 %: ei yhtään kiinaksi, arabiaksi, koreaksi, japaniksi, hindiksi, portugaliksi, ranskaksi tai 20 muulla kielellä, ja 0,27 % englanniksi.


## Roskapostin tunnistaminen näillä kielillä

Epävarma on turvallinen, mutta se ei tunnista roskapostia. Kolme asiaa tunnistaa:

* **Muut tarkistukset** eivät riipu kielestä: samannäköiset verkkotunnukset, harhaanjohtavat linkit, suoritettavat tiedostot, makrot, todennus, estolistat, säännöt.
* **Kielimalli.** Nykyiset avoimet mallit lukevat 100–200 kieltä, ja Spam Scanner kysyy yhdeltä aina, kun luokitin on epävarma. Päästä päähän -testit tarkistavat, että `qwen3.5:4b` tunnistaa roskapostin ja päästää hamin läpi kiinaksi, arabiaksi, koreaksi, hindiksi ja thaiksi. [Kielimallit](llm.md)
* **Koulutus omalla postillasi.** Omalla postillasi koulutetussa mallissa muutama sata kunkin lajin viestiä kielellä antaa luokittimelle täyden varmuuden kyseisellä kielellä. [Koulutus](training.md) ja [valinnainen aineisto](training.md#more-languages), joka lisää 21 kieltä.
