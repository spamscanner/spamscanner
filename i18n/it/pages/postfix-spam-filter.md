<!-- source: f33722183f00 -->

<!--
label: Filtro antispam per Postfix
title: Filtro antispam per Postfix con milter o content filter
description: Filtra lo spam su Postfix con il milter o il content filter di Spam Scanner: configurazione, unità systemd, rifiuto con 4xx o 5xx e cartella Junk.
keywords: filtro antispam Postfix, milter Postfix, smtpd_milters, content filter Postfix, antispam Postfix, rifiutare spam Postfix
-->

# Filtro antispam per Postfix

Spam Scanner filtra un server Postfix in circa cinque minuti. Funziona come milter, quindi Postfix lo interpella su ogni messaggio durante la sessione SMTP e può rifiutare lo spam prima di accettarlo.


## Installazione e avvio

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]"
```

`--auth` controlla SPF, DKIM, DMARC e ARC; `--subject-tag` segnala lo spam nell'oggetto. Ogni messaggio riceve le intestazioni `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Status` e `X-Spam-Action`, e qualsiasi intestazione `X-Spam-*` inserita dal mittente viene prima rimossa.


## Collegare Postfix

```ini
# /etc/postfix/main.cf
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
milter_default_action = accept
```

```sh
sudo postfix reload
```

`milter_default_action = accept` lascia passare la posta senza filtro se il milter non è attivo; `tempfail` chiede invece ai mittenti di riprovare.


## Rifiutare lo spam durante la sessione SMTP

```sh
spamscanner milter --port 7831 --auth --reject
```

I messaggi che raggiungono la soglia di rifiuto (15 punti) vengono rifiutati con `451 4.7.1 Message rejected as spam`. Un 451 è temporaneo: il mittente conserva il messaggio e riprova, quindi una decisione sbagliata costa un ritardo, non un messaggio perso. Quando i risultati sembrano corretti, `--reject-code 550` rende il rifiuto permanente.


## Senza milter

Un content filter interviene dopo che Postfix ha accettato un messaggio: Postfix lo passa tramite pipe a `spamscanner filter`, che aggiunge le intestazioni e lo restituisce. Durante la sessione non viene mai rifiutato nulla, e un errore rinvia sempre la consegna invece di generare un bounce. [Configurazione del content filter](../../docs/postfix.md#content-filter)


## Lo spam nella cartella Junk

Con Dovecot, una regola Sieve archivia la posta marcata:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" { fileinto "Junk"; stop; }
```


## Testato con un vero Postfix

I test end-to-end del progetto eseguono Postfix con il milter e il content filter: l'ham viene consegnato con le intestazioni e con un `X-Spam-Flag` falsificato rimosso, lo spam viene marcato e il GTUBE viene rifiutato con un 550 durante la sessione SMTP.

Prossimo passo: [la guida completa a Postfix e Sendmail](../../docs/postfix.md), con un'unità systemd e `INPUT_MAIL_FILTER` di Sendmail.
