<!-- source: 1562b843d858 -->

<!--
label: Alternativa a SpamAssassin
title: Un'alternativa a SpamAssassin che parla il protocollo spamd
description: Sostituisci lo spamd di SpamAssassin con Spam Scanner: spamc, Exim e Haraka continuano a funzionare, le intestazioni X-Spam restano e ogni lingua è supportata.
keywords: alternativa a SpamAssassin, sostituto di spamd, spamc, filtro antispam Exim, Haraka spamassassin, alternativa a rspamd, X-Spam-Status
-->

# Un'alternativa a SpamAssassin che parla il protocollo spamd

Spam Scanner risponde al protocollo spamd di SpamAssassin, quindi il software scritto per SpamAssassin lo usa senza modifiche: spamc, la condizione `spam` di Exim, il plugin `spamassassin` di Haraka e altri.


## Sostituirlo

```sh
sudo systemctl disable --now spamd       # or spamassassin
npm install --global spamscanner
spamscanner spamd --port 783 --auth
```

```sh
spamc -c < message.eml     # prints the score, exits 1 for spam
spamc -R < message.eml     # the report, one line per test
spamc < message.eml        # the message with X-Spam-* headers
```

Risponde a `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` e, con `--allow-tell`, a `TELL` per l'apprendimento. I test end-to-end del progetto lo verificano con lo spamc di SpamAssassin.


## Cosa resta uguale

* Le intestazioni: `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Level` e `X-Spam-Status` nel formato di SpamAssassin, quindi le regole esistenti di Sieve, procmail e dei client di posta continuano a funzionare.
* Un punteggio con soglia 5, composto da test con nome e punti: `BAYES_99`, `RBL_ZEN`, `SPF_FAIL`, `DKIM_PASS` e così via.
* I punteggi dei singoli test si possono modificare in base al nome del test.


## Cosa cambia

* **Lingue.** Le parole vengono segmentate con le regole Unicode, quindi cinese, giapponese e thailandese vengono letti come parole e non come una lunga stringa, e camuffamenti come caratteri invisibili o lettere cirilliche in parole latine vengono annullati prima.
* **Phishing.** Domini sosia, link ingannevoli e nomi di marchi nei nomi visualizzati vengono controllati senza regole aggiuntive.
* **Allegati**: vengono identificati dai loro byte, e un eseguibile rinominato in `.pdf` resta un eseguibile.
* **Modelli linguistici.** I casi dubbi possono passare a un modello locale tramite Ollama o a uno in hosting.
* **Node.js.** Un solo `npm install`, oppure un binario autonomo; nessun modulo Perl o aggiornamento delle regole da gestire.

Spam Scanner non esegue i file di regole di SpamAssassin, e il formato del suo database bayesiano è proprio: addestralo sulla stessa posta con `spamscanner train`.


## Exim

```text
spamd_address = 127.0.0.1 783

# in the DATA ACL
warn  spam       = nobody:true
      add_header = X-Spam-Score: $spam_score
defer spam       = nobody:true
      condition  = ${if >={$spam_score_int}{150}}
      message    = Message rejected as spam
```

[Exim, Haraka, Dovecot e procmail](../../docs/mail-servers.md)
