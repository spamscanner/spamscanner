<!-- source: 599bd320e55a -->

<!--
label: O projekcie
title: O Spam Scanner, licencji i prywatności
description: Kto tworzy Spam Scanner, jak zgłosić błąd lub podatność, jaka jest jego licencja i co zbiera ta strona: żadnych ciasteczek ani analityki.
keywords: o Spam Scanner, Forward Email, licencja Spam Scanner, BUSL-1.1, kontakt Spam Scanner, prywatność Spam Scanner
-->

# O Spam Scanner

Spam Scanner to filtr antyspamowy do poczty stworzony przez [Forward Email](https://forwardemail.net), usługę pocztową nastawioną na prywatność, na potrzeby jej własnych serwerów pocztowych. Kod źródłowy, zgłoszenia i wydania są na [GitHubie](https://github.com/spamscanner/spamscanner), a pakiet w [npm](https://www.npmjs.com/package/spamscanner).


## Kto go tworzy

Zespół Forward Email pisze i utrzymuje Spam Scanner. Forward Email nie przechowuje logów treści wiadomości, więc nie mógł wysyłać poczty do zewnętrznej usługi filtrującej: filtr musiał działać na własnych serwerach i uzasadniać każdą decyzję bez czytania poczty przez człowieka. [Jak używa go Forward Email](../../docs/forward-email.md)

Forward Email także jest open source, pod adresem [github.com/forwardemail/forwardemail.net](https://github.com/forwardemail/forwardemail.net). Jego założyciel był jednym z pierwszych pracowników DuckDuckGo.


## Kontakt

* **Pytania, błędy i prośby o funkcje:** otwórz zgłoszenie na [GitHubie](https://github.com/spamscanner/spamscanner/issues).
* **Podatności bezpieczeństwa:** zgłaszaj je prywatnie przez [zgłaszanie podatności na GitHubie](https://github.com/spamscanner/spamscanner/security/advisories/new), nie w publicznych zgłoszeniach. Ten sam adres jest w pliku [security.txt](https://spamscanner.net/.well-known/security.txt).
* **Inne licencje:** skontaktuj się z [Forward Email](https://forwardemail.net).


## Warunki licencji

[Licencja](https://github.com/spamscanner/spamscanner/blob/master/LICENSE) Spam Scannera to Business Source License 1.1, a jej Change License to Apache License 2.0. Change Date podana w licencji już minęła i od tej daty licencja przyznaje ci prawa na warunkach Apache License 2.0.


## Prywatność

Ta strona nie ustawia ciasteczek i nie ładuje analityki, trackerów, reklam, czcionek ani skryptów z innych stron. Każdy plik pochodzi z spamscanner.net.

* Motyw, wybrany język i serwer Mastodon, na który udostępniasz, są zapisywane w lokalnej pamięci przeglądarki i nigdzie nie są wysyłane.
* Wideo ładuje się dopiero, gdy je odtworzysz.
* Linki do udostępniania to zwykłe linki, więc nic z tych sieci nie ładuje się, dopóki w któryś nie klikniesz.
* Strona jest hostowana na GitHub Pages, a GitHub ze względów bezpieczeństwa zapisuje adres IP każdego odwiedzającego. Zobacz [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages) i [oświadczenie o prywatności GitHuba](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).


## Co wysyła oprogramowanie

Spam Scanner nie wysyła telemetrii i nie sprawdza aktualizacji. Domyślnie sprawdza nazwy hostów z linków wiadomości w filtrujących resolverach DNS Cloudflare i nic innego nie opuszcza maszyny. Pozostałe testy sieciowe są wyłączone, dopóki ich nie włączysz. [Bezpieczeństwo i prywatność](../../docs/security.md)


## Wydania

Samodzielne pliki binarne buduje GitHub Actions z publicznego repozytorium. Każde wydanie podaje ich skróty w pliku `SHA256SUMS`, który sprawdza skrypt instalacyjny, a każdy plik binarny ma podpisane poświadczenie pochodzenia kompilacji. Wydania i ich opisy są na [GitHubie](https://github.com/spamscanner/spamscanner/releases).
