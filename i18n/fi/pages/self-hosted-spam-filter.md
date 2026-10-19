<!-- source: 988243aec4f3 -->

<!--
label: Oma roskapostisuodatin
title: Itse ylläpidetty roskapostisuodatin omalle sähköpostipalvelimelle
description: Roskapostisuodatin omalla palvelimellasi. Spam Scanner pitää sähköpostit koneella, sisältää mallinsa paketissa, ei lähetä telemetriaa ja toimii Postfixin tai Eximin kanssa.
keywords: itse ylläpidetty roskapostisuodatin, oma roskapostisuodatin, yksityinen roskapostisuodatin, paikallinen roskapostisuodatin, roskapostisuodatin sähköpostipalvelimelle, roskapostisuodatin ilman pilveä
-->

# Itse ylläpidetty roskapostisuodatin

Spam Scanner toimii omalla palvelimellasi ja pitää sähköpostit siellä. Luokittimen malli on paketissa, telemetriaa tai päivitysten tarkistusta ei ole, ja oletuksena se lähettää vain DNS-kyselyn kunkin linkin isäntänimestä.


## Mitä palvelimelta lähtee

Oletuksena vain viestin linkkien isäntänimet. Ne haetaan Cloudflaren suodattavilta nimipalvelimilta (1.1.1.2 ja 1.1.1.3) tavallisina DNS-kyselyinä, eikä mitään osaa viestistä tai sen osoitteista lähetetä. `--no-cloudflare` poistaa tämänkin käytöstä.

Kaikki muut verkkoa käyttävät tarkistukset ovat pois päältä, kunnes otat ne käyttöön:

| Tarkistus             | Käyttöön valitsimella | Mitä se lähettää                                                 |
| --------------------- | --------------------- | ---------------------------------------------------------------- |
| SPF, DKIM, DMARC, ARC | `--auth`              | DNS-kyselyt lähettäjän tietueista                                |
| DNS-estolistat        | `--dnsbl`, `--uribl`  | Asiakkaan IP-osoitteen ja linkkien verkkotunnukset DNS-kyselyinä |
| ClamAV                | `--clamav`            | Liitteet omalle clamd:llesi                                      |
| Kielimalli            | `--llm`               | Viestin tiivistelmän nimeämällesi palvelimelle                   |

Tarkistuksia ei kirjata lokiin eikä tallenneta. [Tietoturva ja tietosuoja](../../docs/security.md)


## Asennus palvelimelle

```sh
npm install --global spamscanner
```

Tai erillinen binääri, jossa Node.js ja malli ovat mukana:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Asennusskripti tarkistaa binäärin julkaisun `SHA256SUMS`-tiedostoa vasten ennen asennusta, ja jokaisella binäärillä on allekirjoitettu koontiversion alkuperätodistus, jonka `gh attestation verify` tarkistaa. Binäärit ovat saatavilla Linuxille (x64 ja arm64), macOS:lle ja Windowsille. Linux-binäärit tarvitsevat glibc:n, joten asenna Alpinella npm:llä. [Aloitus](../../docs/getting-started.md)

Päivitysten tarkistusta ei ole. Päivitä ajamalla asennuskomento uudelleen: molemmat komennot asentavat uusimman julkaisun.


## Ajaminen palveluna

Milter-, HTTP-, TCP- ja spamd-palvelimet kuuntelevat osoitteessa 127.0.0.1, ellei `--host` muuta kerro. Aja ne käyttäjänä ilman oikeuksia, esimerkiksi systemd:n alla:

```ini
[Service]
ExecStart=/usr/local/bin/spamscanner milter --port 7831 --auth --subject-tag [SPAM]
User=spamscanner
Group=spamscanner
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
```

[Koko yksikkö ja sen käyttöönotto](../../docs/postfix.md#1-run-the-milter) löytyvät Postfix-oppaasta. Mikään palvelimista ei puhu TLS:ää, joten käytä toiselta koneelta yhdistäessä yksityistä verkkoa, SSH-tunnelia tai käänteistä välityspalvelinta TLS:llä.


## Sähköpostipalvelimen liittäminen

| Sähköpostipalvelin                         | Komento                                 | Portti |
| ------------------------------------------ | --------------------------------------- | ------ |
| Postfix tai Sendmail                       | `spamscanner milter`                    | 7831   |
| Postfix, hylkäämättä koskaan postia        | `spamscanner filter`, sisältösuodatin   | ei ole |
| Exim, Haraka tai spamc                     | `spamscanner spamd`                     | 783    |
| Mikä tahansa, joka puhuu HTTP:tä           | `spamscanner http`                      | 7832   |
| Yksinkertainen TCP-asiakas                 | `spamscanner server`                    | 7830   |
| Node.js:llä kirjoitettu sähköpostipalvelin | `import SpamScanner from 'spamscanner'` | ei ole |

Palvelimet voivat lisätä viestiin otsakkeet `X-Spam-Flag`, `X-Spam-Score` ja `X-Spam-Status`, ja kirjasto palauttaa pisteet ja jokaisen lauenneen testin. Oppaat: [roskapostisuodatin Postfixille](/postfix-spam-filter/), [muut sähköpostipalvelimet](../../docs/mail-servers.md) ja [HTTP-rajapinta](../../docs/http-api.md).


## Kielimallit paikallisesti

Kielimalli on valinnainen ja lukee vain rajatapaukset: selvä roskaposti ja selvä ham eivät koskaan päädy sille. Ollaman kanssa se toimii samalla palvelimella, joten mikään viesti ei lähde sieltä:

```sh
ollama pull qwen3.5:4b
spamscanner milter --llm ollama --llm-model qwen3.5:4b
```

`qwen3.5:4b` toimii suorittimella. Palveluna tarjottua mallia käytettäessä henkilötiedot poistetaan viestistä ennen lähettämistä. [Kielimallit](../../docs/llm.md)


## Opetus omalla sähköpostilla

Mukana tuleva malli on opetettu julkisilla aineistoilla. Malli, joka on opetettu palvelimesi vastaanottamalla postilla, toimii paremmin, ja se pysyy palvelimella:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out /var/lib/spamscanner/model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

Mallitiedosto sisältää hajautettuja piirteiden lukumääriä, ei sanoja eikä viestien tekstiä. [Opetus](../../docs/training.md)


## Vaatimukset

Node.js 18 tai uudempi Linuxissa, macOS:ssä tai Windowsissa, tai ei mitään erillisellä binäärillä. ClamAV ja Ollama ovat valinnaisia ja toimivat omina palveluinaan.
