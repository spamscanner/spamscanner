<!-- source: 60f00f92b5aa -->

# Bezpieczeństwo i prywatność

Spam Scanner czyta pocztę, która jest prywatna, od nadawców, którzy mogą być wrogo nastawieni. Ta strona wymienia, co i dokąd wysyła oraz jak traktuje to, co czyta.


## Co opuszcza komputer

Domyślnie jedna rzecz: **nazwy hostów z linków** w wiadomości są sprawdzane w filtrujących resolverach Cloudflare, 1.1.1.2 i 1.0.0.2 (złośliwe oprogramowanie i phishing) oraz 1.1.1.3 i 1.0.0.3 (także treści dla dorosłych). To zwykłe zapytania DNS o nazwy takie jak `example.com`; żadna część wiadomości ani jej adresów nie jest wysyłana. Wyłącz je przez `phishing: {cloudflare: false}` lub `--no-cloudflare` albo samą kontrolę treści dla dorosłych przez `phishing: {adult: false}`.

Wszystko inne jest wyłączone, dopóki nie zostanie skonfigurowane:

| Kontrola            | Wysyła                                                                        | Dokąd                                                                               |
| ------------------- | ----------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| `authentication`    | Zapytania DNS o rekordy SPF, DKIM, DMARC i ARC nadawcy                        | Do twojego resolvera lub `dnsServers`                                               |
| `dnsbl`             | Odwrócony adres IP klienta i domeny z linków, jako zapytania DNS              | Do serwerów nazw czarnych list, przez twój resolver lub `dns.servers`               |
| `llm`               | Podsumowanie wiadomości, z usuniętymi danymi osobowymi dla zdalnych dostawców | Do wskazanego przez ciebie serwera modelu językowego ([prywatność](llm.md#privacy)) |
| `reputation.apiUrl` | Adres IP, domenę i adres e-mail nadawcy                                       | Do wskazanej przez ciebie usługi                                                    |
| `clamav`            | Załączniki                                                                    | Do twojego clamd, przez jego gniazdo                                                |

Nie ma telemetrii, sprawdzania aktualizacji ani pobierania czegokolwiek w trakcie działania. Model jest dostarczany w pakiecie.


## Co przechowuje

Nic, chyba że zostanie o to poproszony. Skanowania nie są logowane ani zapisywane. `learn()` zmienia klasyfikator w pamięci; na dysk zapisują go tylko `saveModel()`, `spamscanner learn` lub opcja `--out` serwerów. Plik modelu zawiera haszowane liczniki cech, a nie słowa czy tekst wiadomości.

Odpowiedzi modelu językowego są zapamiętywane w pamięci pod kluczem będącym haszem tego, co wysłano, więc o powtarzające się kopie tej samej wiadomości model jest pytany raz. Odpowiedzi DNS są zapamiętywane w pamięci przez dziesięć minut.


## Wrogie dane wejściowe

* Załączniki są rozpoznawane po bajtach, nigdy nie są uruchamiane ani otwierane przez inny program. Archiwa ZIP są czytane z ich katalogu centralnego, z limitem liczby wpisów; zagnieżdżone archiwa nie są rozpakowywane.
* Treść jest czytana do `maxLength` (100 000 znaków), a serwery przyjmują wiadomości do 25 MB.
* Każda kontrola sieciowa ma limit czasu (`timeout`, domyślnie 10 sekund). Kontrola, która zawiedzie lub przekroczy limit czasu, jest pomijana, a skanowanie kończy się bez niej.
* Nagłówki `X-Spam-*`, które już są w wiadomości, usuwają milter, filtr treści i `--headers`, więc nadawcy nie mogą sami oznaczyć swojej poczty jako czystej.
* Nagłówkom werdyktu spamu Microsoft ufa się tylko wtedy, gdy wiadomość przyszła bezpośrednio z serwerów Microsoft, a nagłówki Received nigdy nie służą do ustalania, skąd wiadomość przyszła.
* Tekst skierowany do filtrów AI jest punktowany jako spam, a model językowy dostaje informację, że wiadomość to dane, a nie instrukcje. [Prompt injection](llm.md#prompt-injection)


## Serwery

Serwery milter, HTTP, TCP i spamd nasłuchują na 127.0.0.1, chyba że `--host` wskazuje inaczej. HTTP API porównuje swój token w stałym czasie i odrzuca `/learn` bez tokenu. Żaden z nich nie obsługuje TLS: aby łączyć się z nimi przez sieć, użyj sieci prywatnej, tunelu SSH lub reverse proxy z TLS.

Uruchamiaj je jako nieuprzywilejowany użytkownik. [Jednostka systemd w poradniku Postfix](postfix.md#1-run-the-milter) dodaje typowe zabezpieczenia.


## Zgłaszanie podatności

Problemy z bezpieczeństwem zgłaszaj prywatnie przez [zgłaszanie podatności w GitHub](https://github.com/spamscanner/spamscanner/security/advisories/new), a nie w publicznych zgłoszeniach.
