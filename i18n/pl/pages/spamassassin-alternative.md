<!-- source: 1562b843d858 -->

<!--
label: Alternatywa dla SpamAssassin
title: Alternatywa dla SpamAssassin zgodna z protokołem spamd
description: Zastąp spamd ze SpamAssassin przez Spam Scanner. spamc, Exim i Haraka działają dalej, nagłówki X-Spam zachowują nazwy, a obsługiwany jest każdy język.
keywords: alternatywa dla SpamAssassin, zamiennik spamd, spamc, filtr antyspamowy Exim, Haraka spamassassin, alternatywa dla rspamd, X-Spam-Status
-->

# Alternatywa dla SpamAssassin zgodna z protokołem spamd

Spam Scanner odpowiada w protokole spamd ze SpamAssassin, więc oprogramowanie napisane dla SpamAssassin korzysta z niego bez zmian: spamc, warunek `spam` w Exim, wtyczka `spamassassin` w Haraka i inne.


## Podmiana

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

Odpowiada na `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` oraz, z `--allow-tell`, `TELL` do nauki. Testy end-to-end projektu uruchamiają na nim oryginalny spamc ze SpamAssassin.


## Co zostaje bez zmian

* Nagłówki: `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Level` i `X-Spam-Status` w formacie SpamAssassin, więc istniejące reguły Sieve, procmail i klientów poczty działają dalej.
* Wynik z progiem 5, złożony z nazwanych testów z punktami: `BAYES_99`, `RBL_ZEN`, `SPF_FAIL`, `DKIM_PASS` i tak dalej.
* Punkty poszczególnych testów można zmieniać według nazwy testu.


## Co jest inne

* **Języki.** Słowa są wyznaczane według reguł Unicode, więc chiński, japoński i tajski są czytane jako słowa, a nie jeden długi ciąg, a maskowanie, takie jak niewidoczne znaki czy litery cyrylicy w słowach łacińskich, jest najpierw odwracane.
* **Phishing.** Podobne domeny, mylące linki i nazwy marek w nazwach wyświetlanych są sprawdzane bez dodatkowych reguł.
* **Załączniki** są rozpoznawane po bajtach: plik wykonywalny przemianowany na `.pdf` nadal jest plikiem wykonywalnym.
* **Modele językowe.** Trudne przypadki mogą trafić do lokalnego modelu przez Ollama lub do modelu hostowanego.
* **Node.js.** Jedno `npm install` lub samodzielny plik binarny; żadnych modułów Perl ani aktualizacji reguł do pilnowania.

Spam Scanner nie uruchamia plików reguł SpamAssassin, a jego format bazy Bayesa jest własny: wytrenuj go na tej samej poczcie przez `spamscanner train`.


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

[Exim, Haraka, Dovecot i procmail](../../docs/mail-servers.md)
