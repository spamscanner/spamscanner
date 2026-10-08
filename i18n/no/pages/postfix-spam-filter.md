<!-- source: f33722183f00 -->

<!--
label: Spamfilter for Postfix
title: Spamfilter for Postfix med milter eller innholdsfilter
description: Filtrer spam på en Postfix-server med milteren eller innholdsfilteret i Spam Scanner: oppsett, systemd-enhet, avvisning med 4xx eller 5xx og en Junk-mappe.
keywords: spamfilter Postfix, Postfix milter, smtpd_milters, innholdsfilter Postfix, Postfix antispam, avvise spam Postfix
-->

# Spamfilter for Postfix

Spam Scanner filtrerer en Postfix-server på omtrent fem minutter. Det kjører som en milter, så Postfix spør det om hver melding under SMTP-økten og kan avvise spam før den mottas.


## Installer og kjør

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]"
```

`--auth` sjekker SPF, DKIM, DMARC og ARC; `--subject-tag` merker spam i emnet. Hver melding får hodene `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Status` og `X-Spam-Action`, og alle `X-Spam-*`-hoder avsenderen har lagt inn, fjernes først.


## Koble til Postfix

```ini
# /etc/postfix/main.cf
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
milter_default_action = accept
```

```sh
sudo postfix reload
```

`milter_default_action = accept` slipper e-post gjennom ufiltrert hvis milteren er nede; `tempfail` ber i stedet avsendere om å prøve igjen.


## Avvis spam under SMTP-økten

```sh
spamscanner milter --port 7831 --auth --reject
```

Meldinger ved avvisningsterskelen (15 poeng) avvises med `451 4.7.1 Message rejected as spam`. En 451 er midlertidig: avsenderen beholder meldingen og prøver igjen, så en feil avgjørelse koster en forsinkelse, ikke en tapt melding. Når resultatene ser riktige ut, gjør `--reject-code 550` avvisningen permanent.


## Uten milter

Et innholdsfilter kjører etter at Postfix har mottatt en melding: Postfix sender den gjennom en pipe til `spamscanner filter`, som legger til hoder og leverer den tilbake. Ingenting avvises noen gang under økten, og en feil utsetter alltid leveringen i stedet for å returnere meldingen. [Oppsett av innholdsfilter](../../docs/postfix.md#content-filter)


## Spam til Junk

Med Dovecot legger en Sieve-regel merket e-post i riktig mappe:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" { fileinto "Junk"; stop; }
```


## Testet mot en ekte Postfix

Ende-til-ende-testene i prosjektet kjører Postfix med milteren og innholdsfilteret: ham leveres med hoder og med et forfalsket `X-Spam-Flag` fjernet, spam merkes, og GTUBE avvises med 550 under SMTP-økten.

Neste: [hele veiledningen for Postfix og Sendmail](../../docs/postfix.md), med en systemd-enhet og `INPUT_MAIL_FILTER` for Sendmail.
