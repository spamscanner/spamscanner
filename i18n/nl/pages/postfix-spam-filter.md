<!-- source: f33722183f00 -->

<!--
label: Postfix-spamfilter
title: Postfix-spamfilter met een milter of contentfilter
description: Filter spam op een Postfix-server met de milter of het contentfilter van Spam Scanner: installatie, systemd-unit, weigeren met 4xx of 5xx en een Junk-map.
keywords: Postfix spamfilter, Postfix milter, smtpd_milters, Postfix content filter, Postfix antispam, spam weigeren Postfix
-->

# Postfix-spamfilter

Spam Scanner filtert een Postfix-server in ongeveer vijf minuten. Het draait als milter, zodat Postfix het tijdens de SMTP-sessie over elk bericht raadpleegt en spam kan weigeren voordat die wordt geaccepteerd.


## Installeren en draaien

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]"
```

`--auth` controleert SPF, DKIM, DMARC en ARC; `--subject-tag` markeert spam in het onderwerp. Elk bericht krijgt de headers `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Status` en `X-Spam-Action`, en elke `X-Spam-*`-header die de afzender erin zette, wordt eerst verwijderd.


## Postfix koppelen

```ini
# /etc/postfix/main.cf
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
milter_default_action = accept
```

```sh
sudo postfix reload
```

`milter_default_action = accept` laat mail ongefilterd door als de milter niet draait; `tempfail` vraagt afzenders in plaats daarvan het opnieuw te proberen.


## Spam weigeren tijdens de SMTP-sessie

```sh
spamscanner milter --port 7831 --auth --reject
```

Berichten op de weigerdrempel (15 punten) worden geweigerd met `451 4.7.1 Message rejected as spam`. Een 451 is tijdelijk: de afzender houdt het bericht vast en probeert het opnieuw, dus een verkeerde beslissing kost vertraging, geen verloren bericht. Zodra de resultaten kloppen, maakt `--reject-code 550` de weigering definitief.


## Zonder milter

Een contentfilter draait nadat Postfix een bericht heeft geaccepteerd: Postfix geeft het via een pipe door aan `spamscanner filter`, dat headers toevoegt en het teruggeeft. Er wordt tijdens de sessie nooit iets geweigerd, en een fout stelt de bezorging altijd uit in plaats van de mail terug te sturen. [Contentfilter instellen](../../docs/postfix.md#content-filter)


## Spam naar Junk

Met Dovecot zet een Sieve-regel gemarkeerde mail apart:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" { fileinto "Junk"; stop; }
```


## Getest tegen een echte Postfix

De end-to-endtests van het project draaien Postfix met de milter en het contentfilter: ham wordt met headers bezorgd en een vervalste `X-Spam-Flag` wordt verwijderd, spam wordt gemarkeerd, en GTUBE wordt tijdens de SMTP-sessie met een 550 geweigerd.

Volgende stap: [de volledige handleiding voor Postfix en Sendmail](../../docs/postfix.md), met een systemd-unit en `INPUT_MAIL_FILTER` van Sendmail.
