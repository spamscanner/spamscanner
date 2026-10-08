<!-- source: f33722183f00 -->

<!--
label: Postfix-spamfilter
title: Postfix-spamfilter med en milter eller et indholdsfilter
description: Filtrér spam på en Postfix-server med Spam Scanners milter eller indholdsfilter: opsætning, systemd-unit, afvisning med 4xx eller 5xx og en Junk-mappe.
keywords: Postfix spamfilter, Postfix milter, smtpd_milters, Postfix indholdsfilter, Postfix antispam, afvis spam Postfix
-->

# Postfix-spamfilter

Spam Scanner filtrerer en Postfix-server på omkring fem minutter. Den kører som en milter, så Postfix spørger den om hver besked under SMTP-sessionen og kan afvise spam, før den modtages.


## Installér og kør

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]"
```

`--auth` tjekker SPF, DKIM, DMARC og ARC; `--subject-tag` markerer spam i emnefeltet. Hver besked får headerne `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Status` og `X-Spam-Action`, og enhver `X-Spam-*`-header, som afsenderen har sat ind, fjernes først.


## Forbind Postfix

```ini
# /etc/postfix/main.cf
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
milter_default_action = accept
```

```sh
sudo postfix reload
```

`milter_default_action = accept` lukker post igennem ufiltreret, hvis milteren er nede; `tempfail` beder i stedet afsendere om at prøve igen.


## Afvis spam under SMTP-sessionen

```sh
spamscanner milter --port 7831 --auth --reject
```

Beskeder ved afvisningsgrænsen (15 point) afvises med `451 4.7.1 Message rejected as spam`. En 451 er midlertidig: afsenderen beholder beskeden og prøver igen, så en forkert afgørelse koster en forsinkelse og ikke en tabt besked. Når resultaterne ser rigtige ud, gør `--reject-code 550` afvisningen permanent.


## Uden en milter

Et indholdsfilter kører, efter at Postfix har modtaget en besked: Postfix sender den videre til `spamscanner filter`, som tilføjer headere og giver den tilbage. Intet afvises nogensinde under sessionen, og en fejl udsætter altid leveringen i stedet for at sende beskeden retur. [Opsætning af indholdsfilter](../../docs/postfix.md#content-filter)


## Spam i Junk-mappen

Med Dovecot lægger en Sieve-regel markeret post i Junk:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" { fileinto "Junk"; stop; }
```


## Testet mod en rigtig Postfix

Projektets end-to-end-test kører Postfix med milteren og indholdsfilteret: ham leveres med headere og med en forfalsket `X-Spam-Flag` fjernet, spam markeres, og GTUBE afvises med en 550 under SMTP-sessionen.

Næste: [den fulde vejledning til Postfix og Sendmail](../../docs/postfix.md) med en systemd-unit og Sendmails `INPUT_MAIL_FILTER`.
