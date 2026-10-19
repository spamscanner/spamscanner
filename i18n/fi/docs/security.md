<!-- source: 1d7373f991c2 -->

# Tietoturva ja yksityisyys

Spam Scanner lukee postia, joka on yksityistä, lähettäjiltä, jotka voivat olla vihamielisiä. Tämä sivu luettelee, mitä se lähettää minnekään ja miten se käsittelee lukemaansa.


## Mitä koneelta lähtee

Oletuksena yksi asia: viestin **linkkien isäntänimet** tarkistetaan Cloudflaren suodattavista DNS-palveluista 1.1.1.2 ja 1.0.0.2 (haittaohjelmat ja tietojenkalastelu) sekä 1.1.1.3 ja 1.0.0.3 (myös aikuissisältö). Nämä ovat tavallisia DNS-kyselyjä nimille kuten `example.com`; mitään osaa viestistä tai sen osoitteista ei lähetetä. Poista ne käytöstä valinnalla `phishing: {cloudflare: false}` tai `--no-cloudflare`, tai pelkkä aikuissisällön tarkistus valinnalla `phishing: {adult: false}`.

Kaikki muu on pois käytöstä, kunnes se määritetään:

| Tarkistus           | Lähettää                                                                                                                      | Kohde                                                                               |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| `authentication`    | DNS-kyselyt lähettäjän SPF-, DKIM-, DMARC- ja ARC-tietueista                                                                  | Oma DNS-palvelimesi tai `dnsServers`                                                |
| `dnsbl`             | Asiakkaan IP-osoitteen käännettynä sekä linkkien verkkotunnukset DNS-kyselyinä                                                | Estolistojen nimipalvelimet oman DNS-palvelimesi tai `dns.servers`-asetuksen kautta |
| `llm`               | Tiivistelmän viestistä, josta on poistettu henkilötiedot etäpalveluntarjoajia varten                                          | Nimeämäsi kielimallipalvelin ([yksityisyys](llm.md#privacy))                        |
| `reputation.apiUrl` | Asiakkaan IP-osoitteen ja varmennetun isäntänimen sekä From-, kirjekuoren lähettäjä- ja Reply-To-osoitteet verkkotunnuksineen | Nimeämäsi palvelu                                                                   |
| `clamav`            | Liitteet                                                                                                                      | Oma clamd-palvelusi sen socketin kautta                                             |

Telemetriaa, päivitystarkistusta tai ajonaikaisia latauksia ei ole. Malli toimitetaan paketin sisällä.


## Mitä se säilyttää

Ei mitään, ellei pyydetä. Tarkistuksia ei kirjata lokiin eikä tallenneta. `learn()` muuttaa luokitinta muistissa; se kirjoitetaan levylle vain funktiolla `saveModel()`, komennolla `spamscanner learn` tai palvelinten valitsimella `--out`. Mallitiedosto sisältää tiivistettyjen piirteiden määriä, ei sanoja eikä viestien tekstiä.

Kielimallin vastaukset tallennetaan välimuistiin muistissa avaimena lähetetyn sisällön tiiviste, joten saman viestin toistuvista kopioista kysytään vain kerran. DNS-vastaukset tallennetaan välimuistiin muistissa kymmeneksi minuutiksi ja mainepalvelun vastaukset viideksi (`reputation.cacheTtl`; epäonnistunut pyyntö minuutiksi).


## Vihamielinen syöte

* Liitteet tunnistetaan niiden tavuista, eikä niitä koskaan suoriteta tai avata toisella ohjelmalla. ZIP-arkistot luetaan niiden keskushakemistosta, ja merkintöjen määrälle (2000) ja niiden nimien tavuille (1 MiB; yli 1 KiB:n nimestä säilytetään ensimmäiset ja viimeiset 512 tavua, ja havainnot näyttävät nimestä enintään 100 merkkiä) on rajat, ja kukin merkintä luetaan kerran, vaikka siihen osoittaisi kuinka monta hakemistomerkintää tahansa; mitään ei pureta, joten sisäkkäisten tai pakattujen arkistojen sisällä olevia ohjelmia ei nähdä. Liitetyt viestit (`message/rfc822` tai liitteet, joiden tiedostonimi päättyy `.eml`) avataan enintään kolmen tason syvyyteen, enintään 100 niiden liitteeseen ja yhteensä 25 Mt:hen liitettyjä viestejä asti; viestin omat liitteet tarkastetaan aina kaikki. Viestistä, joka ylittää MIME-jäsentimen rajat (yli 1000 osaa tai osan otsake yli 1 Mt), luetaan niin paljon kuin jäsennin sallii (sen ensimmäiset osat, ja liian suuri otsake lyhennettynä, jotta sen lähettäjä yhä lasketaan), ja se saa `MIME_TOO_COMPLEX`-pisteet, joita mikään hyvitys ei kumoa; ClamAV lukee sen kokonaan. Myös liitetty viesti, jonka jäsentäminen epäonnistuu, saa ne, eikä se koskaan kaada tarkistusta. Osoitekentät luetaan enintään 16 kt:n verran kukin (2000 osoitetta, 16 sisäkkäistä ryhmää) ja yhteensä enintään 64 kt viestiä kohden, ja ne katkaistaan vain kokonaisen osoitteen lopusta, koska osoitejäsentimen käyttämä aika kasvaa osoitteiden määrän neliönä; myös mailauth lukee From- ja Return-Path-kentät näin rajattuina (muut kentät sellaisinaan, jotta niiden yli laskettu allekirjoitus pätee), ja otsake, jonka lukeminen veisi enemmän kuin lineaarisen ajan (tuhansia taitettuja rivejä tai allekirjoituksia, jotka nimeävät tuhansia kenttiä), lyhennetään ennen kuin se annetaan mailauthille. Katkaistu From-kenttä kaataa DMARCin eikä vastaa mitään sallittujen listalla. HTML luetaan Spam Scannerin omalla jäsentimellä lineaarisessa ajassa, olipa se kuinka syvälle sisäkkäinen tahansa.
* Leipätekstiä luetaan enintään `maxLength` (100 000 merkkiä), ja palvelimet hyväksyvät enintään 25 Mt:n viestit. Linkit luetaan enintään `phishing.maxLength` merkkiin asti (1 000 000 merkkiä).
* Jokaisella verkkotarkistuksella on aikakatkaisu (`timeout`, oletuksena 10 sekuntia). Epäonnistunut tai aikakatkaistu tarkistus ohitetaan, ja tarkistus valmistuu ilman sitä. Todennus ja kuvamalli (10 ensimmäistä kuvaa) valmistuvat kukin kokonaisuudessaan tämän ajan kuluessa: todennus ei lähetä sen jälkeen yhtään DNS-kyselyä eikä enempää kuin 300 yhtä viestiä kohden (tilaa SPF:lle RFC 7208:n rajoilla sekä DKIM:lle, ARC:lle, DMARCille ja BIMI:lle), ja se tarkistaa vain viestin 8 ensimmäistä DKIM-allekirjoitusta (mailauth itse lukee enintään 50 ARC-joukkoa). Milterin lisäämä `Authentication-Results`-otsake sisältää enintään 8 KiB tuloksia. ClamAV:lla (neljä liitettä kerrallaan) on oma rajansa kaikille viestin liitteille (`clamav.timeout`, 60 sekuntia), ja liitteet, joita se ei voinut tarkistaa, luetellaan kohdassa `results.virusScanErrors`. Kielimallilla on oma aikarajansa (`llm.timeout`).
* Sallittujen lista luottaa vain siihen, mitä lähettäjä ei voi väärentää: asiakkaan osoitteeseen ja varmennettuun isäntänimeen sekä lähettäjien verkkotunnuksiin, jotka todennus vahvistaa. [Sallittujen ja estettyjen lista](api.md#allowlist-and-denylist)
* Milter, sisältösuodatin ja `--headers` poistavat viestissä jo olevat `X-Spam-*`-otsakkeet, joten lähettäjät eivät voi merkitä omaa postiaan puhtaaksi.
* Microsoftin roskapostituomio-otsakkeisiin luotetaan vain, kun viesti tuli suoraan Microsoftin palvelimilta, eikä Received-otsakkeita koskaan käytetä päättämään, mistä viesti tuli.
* Tekoälysuodattimia puhutteleva teksti pisteytetään roskapostiksi, ja kielimallille kerrotaan, että viesti on dataa, ei ohjeita. [Kehoteinjektio](llm.md#prompt-injection)


## Palvelimet

Milter-, HTTP-, TCP- ja spamd-palvelimet kuuntelevat osoitetta 127.0.0.1, ellei `--host` määrää muuta. HTTP API vertaa tunnistettaan vakioajassa ja hylkää polun `/learn` ilman sitä. Mikään niistä ei puhu TLS:ää: jos haluat käyttää niitä verkon yli, käytä yksityistä verkkoa, SSH-tunnelia tai TLS:ää käyttävää käänteistä välityspalvelinta.

Aja niitä etuoikeudettomana käyttäjänä. [Postfix-oppaan systemd-yksikkö](postfix.md#1-run-the-milter) lisää tavanomaiset koventamisasetukset.


## Haavoittuvuudesta ilmoittaminen

Ilmoita tietoturvaongelmista yksityisesti [GitHubin haavoittuvuusilmoitusten](https://github.com/spamscanner/spamscanner/security/advisories/new) kautta, ei julkisissa issueissa.
