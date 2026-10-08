<!-- source: 60f00f92b5aa -->

# Tietoturva ja yksityisyys

Spam Scanner lukee postia, joka on yksityistä, lähettäjiltä, jotka voivat olla vihamielisiä. Tämä sivu luettelee, mitä se lähettää minnekään ja miten se käsittelee lukemaansa.


## Mitä koneelta lähtee

Oletuksena yksi asia: viestin **linkkien isäntänimet** tarkistetaan Cloudflaren suodattavista DNS-palveluista 1.1.1.2 ja 1.0.0.2 (haittaohjelmat ja tietojenkalastelu) sekä 1.1.1.3 ja 1.0.0.3 (myös aikuissisältö). Nämä ovat tavallisia DNS-kyselyjä nimille kuten `example.com`; mitään osaa viestistä tai sen osoitteista ei lähetetä. Poista ne käytöstä valinnalla `phishing: {cloudflare: false}` tai `--no-cloudflare`, tai pelkkä aikuissisällön tarkistus valinnalla `phishing: {adult: false}`.

Kaikki muu on pois käytöstä, kunnes se määritetään:

| Tarkistus           | Lähettää                                                                             | Kohde                                                                               |
| ------------------- | ------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------- |
| `authentication`    | DNS-kyselyt lähettäjän SPF-, DKIM-, DMARC- ja ARC-tietueista                         | Oma DNS-palvelimesi tai `dnsServers`                                                |
| `dnsbl`             | Asiakkaan IP-osoitteen käännettynä sekä linkkien verkkotunnukset DNS-kyselyinä       | Estolistojen nimipalvelimet oman DNS-palvelimesi tai `dns.servers`-asetuksen kautta |
| `llm`               | Tiivistelmän viestistä, josta on poistettu henkilötiedot etäpalveluntarjoajia varten | Nimeämäsi kielimallipalvelin ([yksityisyys](llm.md#privacy))                        |
| `reputation.apiUrl` | Lähettäjän IP-osoitteen, verkkotunnuksen ja osoitteen                                | Nimeämäsi palvelu                                                                   |
| `clamav`            | Liitteet                                                                             | Oma clamd-palvelusi sen socketin kautta                                             |

Telemetriaa, päivitystarkistusta tai ajonaikaisia latauksia ei ole. Malli toimitetaan paketin sisällä.


## Mitä se säilyttää

Ei mitään, ellei pyydetä. Tarkistuksia ei kirjata lokiin eikä tallenneta. `learn()` muuttaa luokitinta muistissa; se kirjoitetaan levylle vain funktiolla `saveModel()`, komennolla `spamscanner learn` tai palvelinten valitsimella `--out`. Mallitiedosto sisältää tiivistettyjen piirteiden määriä, ei sanoja eikä viestien tekstiä.

Kielimallin vastaukset tallennetaan välimuistiin muistissa avaimena lähetetyn sisällön tiiviste, joten saman viestin toistuvista kopioista kysytään vain kerran. DNS-vastaukset tallennetaan välimuistiin muistissa kymmeneksi minuutiksi.


## Vihamielinen syöte

* Liitteet tunnistetaan niiden tavuista, eikä niitä koskaan suoriteta tai avata toisella ohjelmalla. ZIP-arkistot luetaan niiden keskushakemistosta, ja merkintöjen määrälle on raja; sisäkkäisiä arkistoja ei pureta.
* Leipätekstiä luetaan enintään `maxLength` (100 000 merkkiä), ja palvelimet hyväksyvät enintään 25 Mt:n viestit.
* Jokaisella verkkotarkistuksella on aikakatkaisu (`timeout`, oletuksena 10 sekuntia). Epäonnistunut tai aikakatkaistu tarkistus ohitetaan, ja tarkistus valmistuu ilman sitä.
* Milter, sisältösuodatin ja `--headers` poistavat viestissä jo olevat `X-Spam-*`-otsakkeet, joten lähettäjät eivät voi merkitä omaa postiaan puhtaaksi.
* Microsoftin roskapostituomio-otsakkeisiin luotetaan vain, kun viesti tuli suoraan Microsoftin palvelimilta, eikä Received-otsakkeita koskaan käytetä päättämään, mistä viesti tuli.
* Tekoälysuodattimia puhutteleva teksti pisteytetään roskapostiksi, ja kielimallille kerrotaan, että viesti on dataa, ei ohjeita. [Kehoteinjektio](llm.md#prompt-injection)


## Palvelimet

Milter-, HTTP-, TCP- ja spamd-palvelimet kuuntelevat osoitetta 127.0.0.1, ellei `--host` määrää muuta. HTTP API vertaa tunnistettaan vakioajassa ja hylkää polun `/learn` ilman sitä. Mikään niistä ei puhu TLS:ää: jos haluat käyttää niitä verkon yli, käytä yksityistä verkkoa, SSH-tunnelia tai TLS:ää käyttävää käänteistä välityspalvelinta.

Aja niitä etuoikeudettomana käyttäjänä. [Postfix-oppaan systemd-yksikkö](postfix.md#1-run-the-milter) lisää tavanomaiset koventamisasetukset.


## Haavoittuvuudesta ilmoittaminen

Ilmoita tietoturvaongelmista yksityisesti [GitHubin haavoittuvuusilmoitusten](https://github.com/spamscanner/spamscanner/security/advisories/new) kautta, ei julkisissa issueissa.
