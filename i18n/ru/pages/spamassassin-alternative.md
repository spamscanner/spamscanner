<!-- source: 1562b843d858 -->

<!--
label: Альтернатива SpamAssassin
title: Альтернатива SpamAssassin с поддержкой протокола spamd
description: Замените spamd из SpamAssassin на Spam Scanner. spamc, Exim и Haraka продолжают работать, заголовки X-Spam сохраняют имена, поддерживается любой язык.
keywords: альтернатива SpamAssassin, замена spamd, spamc, спам-фильтр для Exim, Haraka spamassassin, альтернатива rspamd, X-Spam-Status, замена SpamAssassin
-->

# Альтернатива SpamAssassin с поддержкой протокола spamd

Spam Scanner отвечает по протоколу spamd из SpamAssassin, поэтому программы, написанные для SpamAssassin, используют его без изменений: spamc, условие `spam` в Exim, плагин `spamassassin` в Haraka и другие.


## Замена

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

Он отвечает на `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` и, с `--allow-tell`, на `TELL` для обучения. Сквозные тесты проекта проверяют его с помощью собственного spamc из SpamAssassin.


## Что остаётся прежним

* Заголовки: `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Level` и `X-Spam-Status` в формате SpamAssassin, поэтому существующие правила Sieve, procmail и почтовых клиентов продолжают работать.
* Оценка с порогом 5, составленная из именованных тестов с баллами: `BAYES_99`, `RBL_ZEN`, `SPF_FAIL`, `DKIM_PASS` и так далее.
* Баллы отдельных тестов можно менять по имени теста.


## Что отличается

* **Языки.** Слова выделяются по правилам Unicode, поэтому китайский, японский и тайский читаются как слова, а не как одна длинная строка, а маскировка вроде невидимых символов или кириллических букв в латинских словах сначала снимается.
* **Фишинг.** Похожие домены, обманные ссылки и названия брендов в отображаемых именах проверяются без дополнительных правил.
* **Вложения** определяются по байтам: исполняемый файл, переименованный в `.pdf`, остаётся исполняемым файлом.
* **Языковые модели.** Спорные случаи можно передавать локальной модели через Ollama или облачной.
* **Node.js.** Один `npm install` или автономный исполняемый файл; никаких модулей Perl и обновлений правил.

Spam Scanner не выполняет файлы правил SpamAssassin, а формат его байесовской базы данных собственный: обучите его на той же почте с помощью `spamscanner train`.


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

[Exim, Haraka, Dovecot и procmail](../../docs/mail-servers.md)
