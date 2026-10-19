<!-- source: 599bd320e55a -->

<!--
label: Tietoja
title: Tietoja Spam Scannerista, lisenssistä ja tietosuojasta
description: Kuka tekee Spam Scannerin, miten ilmoitat virheestä tai haavoittuvuudesta, mikä sen lisenssi on ja mitä tämä sivusto kerää: ei evästeitä eikä analytiikkaa.
keywords: tietoja Spam Scannerista, Forward Email, Spam Scanner lisenssi, BUSL-1.1, Spam Scanner yhteystiedot, Spam Scanner tietosuoja
-->

# Tietoja Spam Scannerista

Spam Scanner on sähköpostin roskapostisuodatin, jonka on tehnyt [Forward Email](https://forwardemail.net), yksityisyyttä korostava sähköpostipalvelu, omille sähköpostipalvelimilleen. Lähdekoodi, ilmoitukset ja julkaisut ovat [GitHubissa](https://github.com/spamscanner/spamscanner), ja paketti on [npm:ssä](https://www.npmjs.com/package/spamscanner).


## Kuka sen tekee

Forward Emailin tiimi kirjoittaa ja ylläpitää Spam Scanneria. Forward Email ei säilytä lokeja viestien sisällöstä, joten se ei voinut lähettää postia ulkoiselle suodatuspalvelulle: suodattimen piti toimia omilla palvelimilla ja perustella jokainen päätös ilman, että kukaan lukee postia. [Miten Forward Email käyttää sitä](../../docs/forward-email.md)

Myös Forward Email on avointa lähdekoodia osoitteessa [github.com/forwardemail/forwardemail.net](https://github.com/forwardemail/forwardemail.net). Sen perustaja oli yksi DuckDuckGon ensimmäisistä työntekijöistä.


## Yhteystiedot

* **Kysymykset, virheet ja ominaisuustoiveet:** avaa ilmoitus [GitHubissa](https://github.com/spamscanner/spamscanner/issues).
* **Tietoturvahaavoittuvuudet:** ilmoita niistä yksityisesti [GitHubin haavoittuvuusilmoituksella](https://github.com/spamscanner/spamscanner/security/advisories/new), ei julkisissa ilmoituksissa. Sama osoite on tiedostossa [security.txt](https://spamscanner.net/.well-known/security.txt).
* **Muut lisenssit:** ota yhteyttä [Forward Emailiin](https://forwardemail.net).


## Lisenssiehdot

Spam Scannerin [lisenssi](https://github.com/spamscanner/spamscanner/blob/master/LICENSE) on Business Source License 1.1, ja sen Change License on Apache License 2.0. Lisenssissä nimetty Change Date on jo mennyt, ja siitä päivästä alkaen lisenssi antaa sinulle Apache License 2.0:n mukaiset oikeudet.


## Tietosuoja

Tämä sivusto ei aseta evästeitä eikä lataa analytiikkaa, seurantaa, mainoksia, fontteja tai skriptejä muilta sivustoilta. Jokainen tiedosto tulee osoitteesta spamscanner.net.

* Teema, valitsemasi kieli ja Mastodon-palvelin, jolle jaat, tallennetaan selaimesi paikalliseen tallennustilaan, eikä niitä lähetetä minnekään.
* Video latautuu vasta, kun toistat sen.
* Jakolinkit ovat tavallisia linkkejä, joten mitään näistä verkoista ei lataudu ennen kuin seuraat yhtä.
* Sivusto toimii GitHub Pagesissa, ja GitHub kirjaa jokaisen kävijän IP-osoitteen tietoturvasyistä. Katso [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages) ja [GitHubin tietosuojaseloste](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).


## Mitä ohjelmisto lähettää

Spam Scanner ei lähetä telemetriaa eikä tarkista päivityksiä. Oletuksena se hakee viestin linkkien isäntänimet Cloudflaren suodattavilta DNS-palvelimilta, eikä mitään muuta lähde koneelta. Sen muut verkkotarkistukset ovat pois päältä, kunnes otat ne käyttöön. [Tietoturva ja tietosuoja](../../docs/security.md)


## Julkaisut

GitHub Actions kääntää erilliset binäärit julkisesta repositoriosta. Jokainen julkaisu luettelee niiden tiivisteet `SHA256SUMS`-tiedostossa, jonka asennusskripti tarkistaa, ja jokaisella binäärillä on allekirjoitettu koontiversion alkuperätodistus. Julkaisut ja niiden muistiinpanot ovat [GitHubissa](https://github.com/spamscanner/spamscanner/releases).
