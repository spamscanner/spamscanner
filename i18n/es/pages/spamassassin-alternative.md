<!-- source: 1562b843d858 -->

<!--
label: Alternativa a SpamAssassin
title: Una alternativa a SpamAssassin que habla spamd
description: Sustituye el spamd de SpamAssassin por Spam Scanner. spamc, Exim y Haraka siguen funcionando, los encabezados X-Spam no cambian y admite todos los idiomas.
keywords: alternativa a SpamAssassin, sustituto de spamd, spamc, filtro de spam para Exim, Haraka spamassassin, alternativa a rspamd, X-Spam-Status
-->

# Una alternativa a SpamAssassin que habla spamd

Spam Scanner responde al protocolo spamd de SpamAssassin, así que el software escrito para SpamAssassin lo usa sin cambios: spamc, la condición `spam` de Exim, el complemento `spamassassin` de Haraka y otros.


## Sustituirlo

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

Responde a `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` y, con `--allow-tell`, a `TELL` para aprender. Las pruebas de extremo a extremo del proyecto ejecutan contra él el propio spamc de SpamAssassin.


## Lo que sigue igual

* Los encabezados: `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Level` y `X-Spam-Status` en el formato de SpamAssassin, así que las reglas existentes de Sieve, procmail y los clientes de correo siguen funcionando.
* Una puntuación con un umbral de 5, formada por pruebas con nombre y puntos: `BAYES_99`, `RBL_ZEN`, `SPF_FAIL`, `DKIM_PASS`, etcétera.
* Las puntuaciones de cada prueba se pueden cambiar por el nombre de la prueba.


## Lo que es distinto

* **Idiomas.** Las palabras se segmentan con las reglas de Unicode, así que el chino, el japonés y el tailandés se leen como palabras en lugar de como una cadena larga, y los disfraces como los caracteres invisibles o las letras cirílicas en palabras latinas se deshacen primero.
* **Phishing.** Los dominios parecidos, los enlaces engañosos y los nombres de marca en los nombres visibles se comprueban sin reglas adicionales.
* **Los adjuntos** se identifican por sus bytes: un ejecutable renombrado a `.pdf` sigue siendo un ejecutable.
* **Modelos de lenguaje.** Los casos dudosos pueden pasar a un modelo local a través de Ollama o a uno alojado.
* **Node.js.** Un solo `npm install`, o un binario independiente; sin módulos de Perl ni actualizaciones de reglas que gestionar.

Spam Scanner no ejecuta los archivos de reglas de SpamAssassin, y el formato de su base de datos bayesiana es propio: entrénalo con el mismo correo con `spamscanner train`.


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

[Exim, Haraka, Dovecot y procmail](../../docs/mail-servers.md)
