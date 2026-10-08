<!-- source: c56969e779c4 -->

# Spam Scannerin dokumentaatio

Spam Scanner on roskapostisuodatin Node.js:lle ja komentoriville, ja sen lähdekoodi on GitHubissa. Se lukee raakamuotoisen sähköpostiviestin ja päättää millä tahansa kielellä, onko viesti roskapostia, tietojenkalastelua tai huijaus tai sisältääkö se haittaohjelman. Se toimii kirjastona, komentorivityökaluna, Postfixin tai Sendmailin milterinä, Postfixin sisältösuodattimena, SpamAssassin-yhteensopivana spamd-palvelimena, HTTP API:na tai TCP-palvelimena.

Sen on tehnyt [Forward Email](https://forwardemail.net) omille postipalvelimilleen.


## Miten viesti arvioidaan

Jokainen tarkistus lisää tai vähentää pisteitä. Kokonaissumma ratkaisee lopputuloksen:

| Pisteet   | Toiminto | Mitä postipalvelin tekee               |
| --------- | -------- | -------------------------------------- |
| Alle 5    | `accept` | Toimittaa viestin perille              |
| 5–14,9    | `tag`    | Toimittaa sen roskapostiksi merkittynä |
| 15 ja yli | `reject` | Hylkää sen SMTP-istunnon aikana        |

Molempia rajoja voi muuttaa. Jokainen tulos luettelee lauenneet testit pisteineen ja syineen, joten päätös voidaan aina perustella.

Tarkistukset:

* **Koulutettu luokitin** lukee viestin sanat millä tahansa kirjoitusjärjestelmällä, sen linkkien muodon, lähettäjän ja liitteet. Se toimitetaan julkisilla aineistoilla koulutettuna ja oppii omasta postistasi. [Miten luokitin toimii](how-it-works.md#the-classifier)
* **Tietojenkalastelun tarkistukset** tunnistavat samannäköiset verkkotunnukset (`paypa1.com`, `pаypal.com` kyrillisellä а:lla), linkit, joiden teksti näyttää yhden osoitteen ja joiden kohde on toinen, sekä näyttönimet, jotka väittävät edustavansa tuotemerkkiä. [Tietojenkalastelu](how-it-works.md#phishing)
* **Liitetarkistukset** löytävät suoritettavat tiedostot, asiakirjoiksi nimetyt suoritettavat tiedostot, kaksoispäätteet, oikealta vasemmalle -tiedostonimitempput, ZIP-tiedostojen sisällä olevat suoritettavat tiedostot, Office-makrot ja aktiivisen PDF-sisällön. ClamAV voi tarkistaa liitteet virusten varalta. [Liitteet](how-it-works.md#attachments)
* **Todennus**: SPF, DKIM, DMARC ja ARC, kun asiakkaan IP-osoite tiedetään. [Todennus](how-it-works.md#authentication)
* **DNS-estolistat** asiakkaan IP-osoitteelle ja linkkien verkkotunnuksille sekä Cloudflaren suodattavat DNS-palvelut tunnetuille haittaohjelma- ja aikuissivustoille. [Estolistat](how-it-works.md#blocklists)
* **Säännöt** malleille, joita luokittimen ei tarvitse oppia: GTUBE-testimerkkijono, seksuaalista kiristystä koskevat aiherivit, PayPal-laskuhuijaukset, oman verkkotunnuksen väärentäminen ja tekoälysuodattimille piilotetut ohjeet. [Säännöt](scoring.md#rules)
* **Kielimalli**, valinnainen, antaa toisen mielipiteen epäselvissä tapauksissa: paikallinen malli Ollaman tai minkä tahansa OpenAI-yhteensopivan palvelimen kautta tai Claude, ChatGPT, Gemini ja muut. [Kielimallit](llm.md)


## Mistä aloittaa

* [Aloittaminen](getting-started.md): asenna se ja tarkista ensimmäinen viesti.
* [Komentorivi](cli.md): kaikki komennot ja valitsimet.
* [Postfix ja Sendmail](postfix.md): suodata postipalvelinta milterillä tai sisältösuodattimella.
* [Muut postipalvelimet](mail-servers.md): Exim, Haraka, Dovecot, procmail ja kaikki, mikä osaa kutsua HTTP API:a.
* [Koulutus](training.md): opeta sille oma postisi ja mittaa tulos.
* [Kielimallit](llm.md): palveluntarjoajat, suositellut avoimet mallit, yksityisyys ja kehoteinjektio.
* [Kielet](languages.md): miten se lukee kiinaa, arabiaa, thaita ja kaikkia muita kirjoitusjärjestelmiä.
* [Forward Email](forward-email.md): miten Forward Email käyttää sitä ja miten päivität versiosta 5 tai 6.
* [API-viite](api.md) ja [testit ja pisteet](scoring.md).
* [Tietoturva ja yksityisyys](security.md): mitä koneelta lähtee ja miten sen voi estää.
