<!-- source: c061da9312ad -->

# Komentorivi

```text
spamscanner <command> [options]
```

| Komento                                    | Mitä se tekee                                                                                     |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------- |
| `scan [file\|-]`                           | Tarkistaa viestin tiedostosta tai vakiosyötteestä                                                 |
| `filter -f <sender> -- <recipients...>`    | Postfixin sisältösuodatin: tarkistaa vakiosyötteen, lisää otsakkeet ja välittää viestin eteenpäin |
| `milter`                                   | Milter Postfixille ja Sendmailille, portti 7831                                                   |
| `http`                                     | HTTP API, portti 7832                                                                             |
| `server`                                   | Pelkkä TCP-palvelin, portti 7830                                                                  |
| `spamd`                                    | SpamAssassin-yhteensopiva spamd-palvelin, portti 783                                              |
| `train`                                    | Kouluttaa mallin mbox-tiedostoista, Maildir-hakemistoista, kansioista tai aineistoista            |
| `eval`                                     | Mittaa mallin luokitellulla postilla                                                              |
| `learn spam\|ham [file\|-] --model <file>` | Opettaa mallille yhden viestin                                                                    |
| `llm-test`                                 | Tarkistaa kielimallin asetukset kolmella esimerkkiviestillä                                       |
| `models`                                   | Luettelee suositellut avoimet mallit                                                              |
| `version`, `help`                          |                                                                                                   |


## scan

```sh
spamscanner scan message.eml
spamscanner scan - < message.eml
spamscanner scan message.eml --json
spamscanner scan message.eml --headers > tagged.eml
spamscanner scan message.eml --subject-tag "[SPAM]" > tagged.eml
```

| Valitsin                   | Merkitys                                                     |
| -------------------------- | ------------------------------------------------------------ |
| `--json`                   | Tulostaa koko tuloksen JSON-muodossa                         |
| `--headers`                | Tulostaa viestin, johon on lisätty `X-Spam-*`-otsakkeet      |
| `--subject-tag <tag>`      | Lisää myös etuliitteen roskapostin aiheriville               |
| `--verbose`                | Näyttää jokaisen testin ja luokittimen vahvimmat vihjeet     |
| `--threshold <n>`          | Pistemäärä, josta alkaen posti on roskapostia (oletus 5)     |
| `--reject-threshold <n>`   | Pistemäärä, josta alkaen posti hylätään (oletus 15)          |
| `--model <file>`           | Mallitiedosto mukana tulevan sijaan                          |
| `--no-classifier`          | Ei käytä luokitinta                                          |
| `--config <file>`          | JSON-tiedosto, jossa on [kirjaston valinnat](api.md#options) |
| `--allow-language <codes>` | Hyväksytyt kielet, esimerkiksi `en,de,fr`                    |

Paluukoodit: 0 ham, 1 roskaposti, 2 virhe.

### SMTP-istunto

| Valitsin            | Merkitys                                        |
| ------------------- | ----------------------------------------------- |
| `--ip <address>`    | Viestin lähettäneen asiakkaan IP-osoite         |
| `--hostname <name>` | Asiakkaan varmennettu käänteisen DNS:n nimi     |
| `--helo <name>`     | Nimi, jonka se antoi HELO- tai EHLO-komennossa  |
| `--from <address>`  | Kirjekuoren lähettäjä (MAIL FROM)               |
| `--to <address>`    | Kirjekuoren vastaanottaja; toista useita varten |

### Tarkistukset

| Valitsin              | Merkitys                                                                           |
| --------------------- | ---------------------------------------------------------------------------------- |
| `--auth`              | Tarkistaa SPF:n, DKIM:n, DMARC:n ja ARC:n (vaatii valitsimen `--ip`)               |
| `--dnsbl <zone>`      | IP-estolista, esimerkiksi `zen.spamhaus.org`; toistettavissa                       |
| `--uribl <zone>`      | Linkkien verkkotunnusten estolista, esimerkiksi `dbl.spamhaus.org`; toistettavissa |
| `--dns-server <ip>`   | DNS-tarkistusten nimipalvelin; toistettavissa                                      |
| `--no-cloudflare`     | Ei kysy Cloudflaren suodattavilta DNS-palveluilta linkeistä                        |
| `--clamav [socket]`   | Tarkistaa liitteet clamd:llä, sen oletussocketissa tai annetussa                   |
| `--allowlist <value>` | Hyväksyy aina tämän IP-osoitteen, verkkotunnuksen tai osoitteen; toistettavissa    |
| `--denylist <value>`  | Hylkää aina tämän IP-osoitteen, verkkotunnuksen tai osoitteen; toistettavissa      |

### Kielimalli

| Valitsin                                                   | Merkitys                                                                                                                                               |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `--llm <provider>`                                         | `ollama`, `clef-flash`, `jev`, `openai`, `anthropic` ja muut ([luettelo](llm.md#providers))                                                            |
| `--llm-model <name>`                                       | Malli, esimerkiksi `qwen3.5:4b` tai `claude-haiku-4-5`                                                                                                 |
| `--llm-method <method>`                                    | `decision` (todennäköisyys kullekin tuomiolle yhdellä askeleella; oletus, kun saatavilla) tai `generate` ([menetelmät](llm.md#decision-or-generation)) |
| `--llm-account <id>`                                       | Cloudflare-tilin tunnus, palveluntarjoajille `clef` ja `clef-flash`                                                                                    |
| `--llm-url <url>`                                          | Perus-URL, esimerkiksi `http://10.0.0.5:11434`                                                                                                         |
| `--llm-host`, `--llm-port`, `--llm-path`, `--llm-protocol` | Muuttaa yhden osan palveluntarjoajan URL-osoitteesta                                                                                                   |
| `--llm-api-key <key>`                                      | API-avain; katso myös alla olevat ympäristömuuttujat                                                                                                   |
| `--llm-auth <type>`                                        | `bearer`, `x-api-key`, `api-key`, `basic`, `header` tai `none`                                                                                         |
| `--llm-auth-header <name>`                                 | Avaimen otsake, kun käytössä on `--llm-auth header`                                                                                                    |
| `--llm-username`, `--llm-password`                         | Valitsimelle `--llm-auth basic`                                                                                                                        |
| `--llm-header "Name: value"`                               | Ylimääräinen pyynnön otsake; toistettavissa                                                                                                            |
| `--llm-mode <mode>`                                        | `auto` (vain epäselvät tapaukset, oletus) tai `always`                                                                                                 |
| `--llm-timeout <ms>`                                       | Oletus 30000                                                                                                                                           |
| `--llm-policy <text>`                                      | Lisäsääntöjä mallille, esimerkiksi "Emme koskaan lähetä laskuja"                                                                                       |
| `--llm-redact`, `--no-llm-redact`                          | Poistaa ensin henkilötiedot; oletuksena käytössä etäpalveluntarjoajille                                                                                |


## filter

[Postfixin sisältösuodatin](postfix.md#content-filter). Se lukee viestin vakiosyötteestä, lisää `X-Spam-*`-otsakkeet ja välittää viestin sendmailille samalla kirjekuorella.

```sh
spamscanner filter -f "$sender" -- "$recipient"
```

| Valitsin              | Merkitys                                                                                       |
| --------------------- | ---------------------------------------------------------------------------------------------- |
| `--sendmail <path>`   | Oletus `/usr/sbin/sendmail`                                                                    |
| `--subject-tag <tag>` | Lisää etuliitteen roskapostin aiheriville                                                      |
| `--reject`            | Palauttaa hylkäysrajan ylittävän postin lähettäjälle sen sijaan, että välittäisi sen eteenpäin |
| `--discard`           | Pudottaa hylkäysrajan ylittävän postin sen sijaan, että välittäisi sen eteenpäin               |

Paluukoodit noudattavat sendmailin käytäntöjä, joita Postfix lukee: 0 toimitettu (tai pudotettu), 64 vastaanottajia ei annettu, 69 hylätty roskapostina (Postfix palauttaa sen lähettäjälle), 75 mikä tahansa virhe, jolloin Postfix säilyttää viestin ja yrittää myöhemmin uudelleen.


## milter, http, server ja spamd

```sh
spamscanner milter --port 7831 --reject --subject-tag "[SPAM]"
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
spamscanner server --port 7830
spamscanner spamd --port 783
```

Portti 783 on SpamAssassin-asiakkaiden oletusportti. Alle 1024:n portit vaativat root-oikeudet tai `CAP_NET_BIND_SERVICE`-kyvyn; käytä muuta porttia, kuten `--port 7833`, ja kerro se asiakkaalle.

| Valitsin              | Merkitys                                                                                |
| --------------------- | --------------------------------------------------------------------------------------- |
| `--port <n>`          | TCP-portti                                                                              |
| `--host <ip>`         | Kuunneltava osoite (oletus 127.0.0.1)                                                   |
| `--socket <path>`     | Kuuntelee sen sijaan Unix-socketissa                                                    |
| `--reject`            | Milter: hylkää hylkäysrajan ylittävän postin                                            |
| `--reject-code <n>`   | Milter: 451, yritä myöhemmin uudelleen (oletus), tai 550                                |
| `--quarantine`        | Milter: pitää roskapostin postipalvelimen karanteenissa                                 |
| `--name <hostname>`   | Milter: tämän palvelimen nimi Authentication-Results-otsakkeessa                        |
| `--token <secret>`    | HTTP: vaatii otsakkeen `Authorization: Bearer <secret>`; tarvitaan polulle `/learn`     |
| `--allow-tell`        | spamd: hyväksyy TELL-pyynnöt (`spamc -L spam`) oppimista varten                         |
| `--out <file>`        | HTTP ja spamd: tallentaa opitun tähän mallitiedostoon                                   |
| `--subject-tag <tag>` | Milter ja spamd: lisää etuliitteen roskapostin aiheriville                              |
| `--verbose`           | Milter: kirjaa jokaisen tarkistuksen lokiin. TCP-palvelin: vastaa yhdellä tekstirivillä |

Yllä olevat tarkistusvalitsimet koskevat myös palvelimia. [Milter](postfix.md#milter), [HTTP API, TCP-palvelin ja spamd](http-api.md).


## train, eval ja learn

```sh
spamscanner train --spam ~/Mail/Junk --ham ~/Mail/Archive --out my-model.json
spamscanner eval --model my-model.json --spam test/spam.mbox --ham test/ham.mbox
spamscanner learn spam message.eml --model my-model.json
```

| Valitsin                                        | Merkitys                                                                             |
| ----------------------------------------------- | ------------------------------------------------------------------------------------ |
| `--spam <path>`                                 | Roskaposti: mbox-tiedosto, Maildir tai `.eml`-tiedostojen kansio; toistettavissa     |
| `--ham <path>`                                  | Ham, samoin; toistettavissa                                                          |
| `--dataset <file>`                              | CSV- tai JSON Lines -tiedosto, jossa on teksti- ja luokkasarakkeet; toistettavissa   |
| `--text-column <name>`, `--label-column <name>` | Sarakkeiden nimet, kun niitä ei tunnisteta                                           |
| `--out <file>`                                  | Minne malli kirjoitetaan (oletus `spamscanner-model.json`)                           |
| `--merge`                                       | Aloittaa mukana tulevasta mallista (tai valitsimen `--model` mallista) tyhjän sijaan |

`learn` päivittää mallitiedoston paikallaan ja luo sen ensimmäisellä kerralla mukana tulevasta mallista. [Koulutus](training.md)


## llm-test ja models

```sh
spamscanner models
spamscanner llm-test --llm ollama --llm-model qwen3.5:4b
```

`llm-test` lähettää mallille yhden tavallisen viestin ja kaksi huijausta, englanniksi ja italiaksi, tulostaa sen tuomiot, kunkin viemän ajan, käytetyn menetelmän ja laitteiston sekä päättyy koodiin 0 vain, jos kaikki kolme ovat oikein.


## Asetustiedosto

`--config file.json` (tai ympäristömuuttuja `SPAMSCANNER_CONFIG`) lataa [kirjaston valinnat](api.md#options). Komentorivin valitsimet ohittavat tiedoston.

```json
{
  "threshold": 6,
  "authentication": true,
  "dnsbl": {"ip": ["zen.spamhaus.org"], "domain": ["dbl.spamhaus.org"]},
  "dns": {"servers": ["127.0.0.1"]},
  "clamav": {"socket": "/var/run/clamav/clamd.ctl"},
  "llm": {"provider": "ollama", "model": "qwen3.5:4b"},
  "scores": {"deceptiveLink": 4, "FROM_NAME_BRAND": 3}
}
```


## Ympäristömuuttujat

| Muuttuja                                                                                                                                                                                                                                                                                                                    | Merkitys                                                |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| `SPAMSCANNER_CONFIG`                                                                                                                                                                                                                                                                                                        | Asetustiedosto                                          |
| `SPAMSCANNER_MODEL`                                                                                                                                                                                                                                                                                                         | Mallitiedosto, jota käytetään mukana tulevan sijaan     |
| `SPAMSCANNER_TOKEN`                                                                                                                                                                                                                                                                                                         | HTTP API:n tunniste                                     |
| `SPAMSCANNER_LLM_API_KEY`                                                                                                                                                                                                                                                                                                   | API-avain mille tahansa kielimallin palveluntarjoajalle |
| `CLOUDFLARE_API_TOKEN` ja `CLOUDFLARE_ACCOUNT_ID`, `TYPESAFE_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY`, `XAI_API_KEY`, `TOGETHER_API_KEY`, `FIREWORKS_API_KEY`, `CEREBRAS_API_KEY`, `HF_TOKEN`, `AZURE_OPENAI_API_KEY` | Kunkin palveluntarjoajan oma avain                      |
| `NODE_DEBUG=spamscanner*`                                                                                                                                                                                                                                                                                                   | Vianetsintäloki                                         |
