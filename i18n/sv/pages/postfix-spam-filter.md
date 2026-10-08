<!-- source: f33722183f00 -->

<!--
label: Spamfilter för Postfix
title: Spamfilter för Postfix med milter eller innehållsfilter
description: Filtrera spam i Postfix med Spam Scanners milter eller innehållsfilter: installation, systemd-enhet, avvisning med 4xx eller 5xx och en skräppostmapp.
keywords: Postfix spamfilter, Postfix milter, smtpd_milters, Postfix innehållsfilter, Postfix antispam, avvisa spam Postfix
-->

# Spamfilter för Postfix

Spam Scanner filtrerar en Postfix-server på ungefär fem minuter. Det körs som en milter, så Postfix frågar det om varje meddelande under SMTP-sessionen och kan neka spam innan den tas emot.


## Installera och kör

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]"
```

`--auth` kontrollerar SPF, DKIM, DMARC och ARC; `--subject-tag` markerar spam i ämnesraden. Varje meddelande får huvudena `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Status` och `X-Spam-Action`, och alla `X-Spam-*`-huvuden som avsändaren lagt in tas bort först.


## Anslut Postfix

```ini
# /etc/postfix/main.cf
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
milter_default_action = accept
```

```sh
sudo postfix reload
```

`milter_default_action = accept` släpper igenom e-post ofiltrerad om miltern är nere; `tempfail` ber i stället avsändarna att försöka igen.


## Neka spam under SMTP-sessionen

```sh
spamscanner milter --port 7831 --auth --reject
```

Meddelanden som når gränsen för avvisning (15 poäng) nekas med `451 4.7.1 Message rejected as spam`. En 451 är tillfällig: avsändaren behåller meddelandet och försöker igen, så ett felaktigt beslut kostar en fördröjning, inte ett förlorat meddelande. När resultaten ser rätt ut gör `--reject-code 550` avvisningen permanent.


## Utan milter

Ett innehållsfilter körs efter att Postfix har tagit emot ett meddelande: Postfix skickar det vidare till `spamscanner filter`, som lägger till huvuden och lämnar tillbaka det. Ingenting nekas någonsin under sessionen, och ett fel skjuter alltid upp leveransen i stället för att studsa meddelandet. [Installera innehållsfilter](../../docs/postfix.md#content-filter)


## Spam till skräpposten

Med Dovecot sorterar en Sieve-regel märkt e-post:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" { fileinto "Junk"; stop; }
```


## Testat mot en riktig Postfix

Projektets end-to-end-tester kör Postfix med miltern och innehållsfiltret: ham levereras med huvuden och med ett förfalskat `X-Spam-Flag` borttaget, spam märks, och GTUBE nekas med 550 under SMTP-sessionen.

Nästa: [den fullständiga guiden för Postfix och Sendmail](../../docs/postfix.md), med en systemd-enhet och Sendmails `INPUT_MAIL_FILTER`.
