<!-- source: 988243aec4f3 -->

<!--
label: Własny filtr antyspamowy
title: Własny filtr antyspamowy na Twoim serwerze pocztowym
description: Filtr antyspamowy na własnym serwerze. Spam Scanner trzyma pocztę na maszynie, ma model w pakiecie, nie wysyła telemetrii i współpracuje z Postfixem lub Eximem.
keywords: self-hosted filtr antyspamowy, własny filtr antyspamowy, prywatny filtr antyspamowy, lokalny filtr antyspamowy, filtr antyspamowy dla serwera pocztowego, filtr antyspamowy bez chmury
-->

# Własny filtr antyspamowy

Spam Scanner działa na Twoim serwerze i trzyma tam pocztę. Model klasyfikatora jest w pakiecie, nie ma telemetrii ani sprawdzania aktualizacji, a domyślnie jedyne, co wysyła, to zapytanie DNS o nazwę hosta każdego linku.


## Co opuszcza serwer

Domyślnie tylko nazwy hostów z linków w wiadomości. Są sprawdzane w filtrujących resolverach Cloudflare (1.1.1.2 i 1.1.1.3) zwykłymi zapytaniami DNS i żadna część wiadomości ani jej adresów nie jest wysyłana. `--no-cloudflare` wyłącza także to.

Każdy inny test korzystający z sieci jest wyłączony, dopóki go nie włączysz:

| Test                  | Włącz przez          | Co wysyła                                                   |
| --------------------- | -------------------- | ----------------------------------------------------------- |
| SPF, DKIM, DMARC, ARC | `--auth`             | Zapytania DNS o rekordy nadawcy                             |
| Listy blokowanych DNS | `--dnsbl`, `--uribl` | Adres IP klienta i domeny linków, jako zapytania DNS        |
| ClamAV                | `--clamav`           | Załączniki, do Twojego clamd                                |
| Model językowy        | `--llm`              | Streszczenie wiadomości, do wskazanego przez Ciebie serwera |

Skany nie są logowane ani zapisywane. [Bezpieczeństwo i prywatność](../../docs/security.md)


## Instalacja na serwerze

```sh
npm install --global spamscanner
```

Albo samodzielny plik binarny z wbudowanym Node.js i modelem:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Skrypt instalacyjny sprawdza plik binarny z plikiem `SHA256SUMS` wydania przed instalacją, a każdy plik binarny ma podpisane poświadczenie pochodzenia kompilacji, które sprawdza `gh attestation verify`. Pliki binarne są dla Linuksa (x64 i arm64), macOS i Windows. Pliki dla Linuksa wymagają glibc, więc na Alpine instaluj przez npm. [Pierwsze kroki](../../docs/getting-started.md)

Nie ma sprawdzania aktualizacji. Aby zaktualizować, uruchom polecenie instalacji ponownie: oba polecenia instalują najnowsze wydanie.


## Uruchamianie jako usługa

Serwery milter, HTTP, TCP i spamd nasłuchują na 127.0.0.1, chyba że `--host` wskazuje inaczej. Uruchamiaj je jako użytkownik bez uprawnień, na przykład pod systemd:

```ini
[Service]
ExecStart=/usr/local/bin/spamscanner milter --port 7831 --auth --subject-tag [SPAM]
User=spamscanner
Group=spamscanner
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
```

[Pełna jednostka i jej konfiguracja](../../docs/postfix.md#1-run-the-milter) są w przewodniku po Postfixie. Żaden z serwerów nie obsługuje TLS, więc aby połączyć się z innej maszyny, użyj sieci prywatnej, tunelu SSH lub odwrotnego proxy z TLS.


## Podłączenie serwera pocztowego

| Serwer pocztowy                    | Polecenie                               | Port |
| ---------------------------------- | --------------------------------------- | ---- |
| Postfix lub Sendmail               | `spamscanner milter`                    | 7831 |
| Postfix, bez odrzucania poczty     | `spamscanner filter`, filtr treści      | brak |
| Exim, Haraka lub spamc             | `spamscanner spamd`                     | 783  |
| Wszystko, co obsługuje HTTP        | `spamscanner http`                      | 7832 |
| Prosty klient TCP                  | `spamscanner server`                    | 7830 |
| Serwer pocztowy napisany w Node.js | `import SpamScanner from 'spamscanner'` | brak |

Serwery mogą dodać do wiadomości nagłówki `X-Spam-Flag`, `X-Spam-Score` i `X-Spam-Status`, a biblioteka zwraca wynik i każdy test, który zadziałał. Przewodniki: [filtr antyspamowy dla Postfixa](/postfix-spam-filter/), [inne serwery pocztowe](../../docs/mail-servers.md) i [API HTTP](../../docs/http-api.md).


## Lokalne modele językowe

Model językowy jest opcjonalny i czyta tylko przypadki graniczne: oczywisty spam i oczywisty ham nigdy do niego nie trafiają. Z Ollamą działa na tym samym serwerze, więc żadna wiadomość go nie opuszcza:

```sh
ollama pull qwen3.5:4b
spamscanner milter --llm ollama --llm-model qwen3.5:4b
```

`qwen3.5:4b` działa na CPU. Przy dostawcy hostowanym dane osobowe są usuwane z wiadomości przed wysłaniem. [Modele językowe](../../docs/llm.md)


## Trenowanie na własnej poczcie

Dołączony model jest wytrenowany na publicznych zbiorach danych. Model wytrenowany na poczcie, którą odbiera Twój serwer, działa lepiej i zostaje na tym serwerze:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out /var/lib/spamscanner/model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

Plik modelu zawiera zahaszowane liczniki cech, a nie słowa ani tekst wiadomości. [Trenowanie](../../docs/training.md)


## Wymagania

Node.js 18 lub nowszy na Linuksie, macOS albo Windows, a z samodzielnym plikiem binarnym nic. ClamAV i Ollama są opcjonalne i działają jako osobne usługi.
