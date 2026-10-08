<!-- source: f33722183f00 -->

<!--
label: Filtr antyspamowy Postfix
title: Filtr antyspamowy Postfix z milterem lub filtrem treści
description: Filtruj spam na serwerze Postfix milterem lub filtrem treści Spam Scanner: konfiguracja, jednostka systemd, odrzucanie kodem 4xx lub 5xx i folder Junk.
keywords: filtr antyspamowy Postfix, Postfix milter, smtpd_milters, filtr treści Postfix, Postfix antyspam, odrzucanie spamu Postfix, konfiguracja Postfix spam
-->

# Filtr antyspamowy Postfix

Spam Scanner zaczyna filtrować serwer Postfix w około pięć minut. Działa jako milter, więc Postfix pyta go o każdą wiadomość w trakcie sesji SMTP i może odrzucić spam, zanim go przyjmie.


## Instalacja i uruchomienie

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]"
```

`--auth` sprawdza SPF, DKIM, DMARC i ARC; `--subject-tag` oznacza spam w temacie. Każda wiadomość dostaje nagłówki `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Status` i `X-Spam-Action`, a każdy nagłówek `X-Spam-*` dodany przez nadawcę jest najpierw usuwany.


## Podłączenie Postfix

```ini
# /etc/postfix/main.cf
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
milter_default_action = accept
```

```sh
sudo postfix reload
```

`milter_default_action = accept` przepuszcza pocztę bez filtrowania, gdy milter nie działa; `tempfail` prosi zamiast tego nadawców o ponowienie próby.


## Odrzucanie spamu w trakcie sesji SMTP

```sh
spamscanner milter --port 7831 --auth --reject
```

Wiadomości na progu odrzucenia (15 punktów) są odrzucane z `451 4.7.1 Message rejected as spam`. Kod 451 jest tymczasowy: nadawca zatrzymuje wiadomość i ponawia próbę, więc błędna decyzja kosztuje opóźnienie, a nie utraconą wiadomość. Gdy wyniki będą wyglądać poprawnie, `--reject-code 550` sprawia, że odrzucenie jest trwałe.


## Bez miltera

Filtr treści działa po przyjęciu wiadomości przez Postfix: Postfix przekazuje ją potokiem do `spamscanner filter`, który dodaje nagłówki i oddaje ją z powrotem. W trakcie sesji nic nie jest odrzucane, a błąd zawsze odkłada dostarczenie zamiast odbijać pocztę. [Konfiguracja filtra treści](../../docs/postfix.md#content-filter)


## Spam do folderu Junk

Z Dovecot reguła Sieve przenosi oznaczoną pocztę:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" { fileinto "Junk"; stop; }
```


## Przetestowany na prawdziwym Postfix

Testy end-to-end projektu uruchamiają Postfix z milterem i filtrem treści: ham jest dostarczany z nagłówkami, a podrobiony `X-Spam-Flag` usuwany, spam jest oznaczany, a GTUBE jest odrzucany kodem 550 w trakcie sesji SMTP.

Dalej: [pełny poradnik Postfix i Sendmail](../../docs/postfix.md), z jednostką systemd i `INPUT_MAIL_FILTER` dla Sendmail.
