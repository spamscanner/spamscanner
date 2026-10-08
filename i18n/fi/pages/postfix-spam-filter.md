<!-- source: f33722183f00 -->

<!--
label: Postfix-roskapostisuodatin
title: Postfix-roskapostisuodatin milterinä tai sisältösuodattimena
description: Suodata roskaposti Postfix-palvelimella Spam Scannerin milterillä tai sisältösuodattimella: asennus, systemd-yksikkö, 4xx- tai 5xx-hylkäys ja Junk-kansio.
keywords: Postfix roskapostisuodatin, Postfix milter, smtpd_milters, Postfix sisältösuodatin, Postfix roskapostin esto, roskapostin hylkääminen Postfix
-->

# Postfix-roskapostisuodatin

Spam Scanner saadaan suodattamaan Postfix-palvelinta noin viidessä minuutissa. Se toimii milterinä, joten Postfix kysyy siltä jokaisesta viestistä SMTP-istunnon aikana ja voi hylätä roskapostin ennen sen vastaanottamista.


## Asennus ja käynnistys

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]"
```

`--auth` tarkistaa SPF:n, DKIM:n, DMARC:n ja ARC:n; `--subject-tag` merkitsee roskapostin aiheriville. Jokainen viesti saa `X-Spam-Flag`-, `X-Spam-Score`-, `X-Spam-Status`- ja `X-Spam-Action`-otsakkeet, ja kaikki lähettäjän lisäämät `X-Spam-*`-otsakkeet poistetaan ensin.


## Postfixin yhdistäminen

```ini
# /etc/postfix/main.cf
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
milter_default_action = accept
```

```sh
sudo postfix reload
```

`milter_default_action = accept` päästää postin läpi suodattamattomana, jos milter ei ole käynnissä; `tempfail` pyytää sen sijaan lähettäjiä yrittämään uudelleen.


## Roskapostin hylkääminen SMTP-istunnon aikana

```sh
spamscanner milter --port 7831 --auth --reject
```

Hylkäysrajan (15 pistettä) ylittävät viestit hylätään vastauksella `451 4.7.1 Message rejected as spam`. 451 on väliaikainen: lähettäjä säilyttää viestin ja yrittää uudelleen, joten väärä päätös maksaa viiveen eikä hukattua viestiä. Kun tulokset näyttävät oikeilta, `--reject-code 550` tekee hylkäyksestä pysyvän.


## Ilman milteriä

Sisältösuodatin toimii sen jälkeen, kun Postfix on ottanut viestin vastaan: Postfix putkittaa sen komennolle `spamscanner filter`, joka lisää otsakkeet ja palauttaa viestin. Istunnon aikana mitään ei koskaan hylätä, ja virhe aina lykkää toimitusta sen sijaan, että viesti palautettaisiin lähettäjälle. [Sisältösuodattimen määrittäminen](../../docs/postfix.md#content-filter)


## Roskaposti Junk-kansioon

Dovecotin kanssa Sieve-sääntö siirtää merkityn postin:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" { fileinto "Junk"; stop; }
```


## Testattu oikeaa Postfixia vastaan

Projektin päästä päähän -testit ajavat Postfixia milterin ja sisältösuodattimen kanssa: ham toimitetaan otsakkeineen ja väärennetty `X-Spam-Flag` poistettuna, roskaposti merkitään, ja GTUBE hylätään koodilla 550 SMTP-istunnon aikana.

Seuraavaksi: [koko Postfix- ja Sendmail-opas](../../docs/postfix.md), jossa on systemd-yksikkö ja Sendmailin `INPUT_MAIL_FILTER`.
