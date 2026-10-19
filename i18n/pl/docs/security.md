<!-- source: 1d7373f991c2 -->

# Bezpieczeństwo i prywatność

Spam Scanner czyta pocztę, która jest prywatna, od nadawców, którzy mogą być wrogo nastawieni. Ta strona wymienia, co i dokąd wysyła oraz jak traktuje to, co czyta.


## Co opuszcza komputer

Domyślnie jedna rzecz: **nazwy hostów z linków** w wiadomości są sprawdzane w filtrujących resolverach Cloudflare, 1.1.1.2 i 1.0.0.2 (złośliwe oprogramowanie i phishing) oraz 1.1.1.3 i 1.0.0.3 (także treści dla dorosłych). To zwykłe zapytania DNS o nazwy takie jak `example.com`; żadna część wiadomości ani jej adresów nie jest wysyłana. Wyłącz je przez `phishing: {cloudflare: false}` lub `--no-cloudflare` albo samą kontrolę treści dla dorosłych przez `phishing: {adult: false}`.

Wszystko inne jest wyłączone, dopóki nie zostanie skonfigurowane:

| Kontrola            | Wysyła                                                                                                        | Dokąd                                                                               |
| ------------------- | ------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| `authentication`    | Zapytania DNS o rekordy SPF, DKIM, DMARC i ARC nadawcy                                                        | Do twojego resolvera lub `dnsServers`                                               |
| `dnsbl`             | Odwrócony adres IP klienta i domeny z linków, jako zapytania DNS                                              | Do serwerów nazw czarnych list, przez twój resolver lub `dns.servers`               |
| `llm`               | Podsumowanie wiadomości, z usuniętymi danymi osobowymi dla zdalnych dostawców                                 | Do wskazanego przez ciebie serwera modelu językowego ([prywatność](llm.md#privacy)) |
| `reputation.apiUrl` | Adres IP i zweryfikowaną nazwę hosta klienta oraz adresy From, nadawcy koperty i Reply-To wraz z ich domenami | Do wskazanej przez ciebie usługi                                                    |
| `clamav`            | Załączniki                                                                                                    | Do twojego clamd, przez jego gniazdo                                                |

Nie ma telemetrii, sprawdzania aktualizacji ani pobierania czegokolwiek w trakcie działania. Model jest dostarczany w pakiecie.


## Co przechowuje

Nic, chyba że zostanie o to poproszony. Skanowania nie są logowane ani zapisywane. `learn()` zmienia klasyfikator w pamięci; na dysk zapisują go tylko `saveModel()`, `spamscanner learn` lub opcja `--out` serwerów. Plik modelu zawiera haszowane liczniki cech, a nie słowa czy tekst wiadomości.

Odpowiedzi modelu językowego są zapamiętywane w pamięci pod kluczem będącym haszem tego, co wysłano, więc o powtarzające się kopie tej samej wiadomości model jest pytany raz. Odpowiedzi DNS są zapamiętywane w pamięci przez dziesięć minut, a odpowiedzi usługi reputacji przez pięć (`reputation.cacheTtl`; nieudane żądanie przez minutę).


## Wrogie dane wejściowe

* Załączniki są rozpoznawane po bajtach, nigdy nie są uruchamiane ani otwierane przez inny program. Archiwa ZIP są czytane z ich katalogu centralnego, z limitami liczby wpisów (2000) i bajtów ich nazw (1 MiB; nazwa dłuższa niż 1 KiB zachowuje pierwsze i ostatnie 512 bajtów, a wyniki pokazują najwyżej 100 znaków jednej nazwy), przy czym każdy wpis jest czytany raz, bez względu na to, ile katalogów na niego wskazuje; nic nie jest dekompresowane, więc programy wewnątrz zagnieżdżonych lub skompresowanych archiwów nie są widoczne. Załączone wiadomości (`message/rfc822` lub załączniki, których nazwa pliku kończy się na `.eml`) są otwierane do trzech poziomów w głąb, dla najwyżej 100 ich załączników i łącznie 25 MB załączonych wiadomości; własne załączniki wiadomości są zawsze sprawdzane wszystkie. Wiadomość przekraczająca limity parsera MIME (ponad 1000 części lub nagłówek części ponad 1 MB) jest czytana na tyle, na ile pozwala parser (jej pierwsze części, ze zbyt dużym nagłówkiem skróconym tak, by nadawca nadal się liczył), i otrzymuje `MIME_TOO_COMPLEX`, którego nie równoważy żaden kredyt; ClamAV czyta ją w całości. Otrzymuje go też załączona wiadomość, na której parser zawodzi, i nigdy nie powoduje ona niepowodzenia skanowania. Pola adresowe są czytane do 16 KB każde (2000 adresów, 16 zagnieżdżonych grup) i łącznie do 64 KB dla każdej wiadomości, obcinane tylko na końcu całego adresu, ponieważ czas pracy parsera adresów rośnie z kwadratem liczby adresów; mailauth czyta From i Return-Path z tymi samymi ograniczeniami (pozostałe pola takie, jakie są, aby podpis obejmujący je pozostał ważny), a nagłówek, którego przeczytanie zajęłoby więcej niż czas liniowy (tysiące zawiniętych wierszy albo podpisy wymieniające tysiące pól), jest skracany. Obcięte pole From nie przechodzi DMARC i nie pasuje do żadnej listy dozwolonych. HTML jest czytany własnym parserem Spam Scanner, w czasie liniowym, niezależnie od głębokości zagnieżdżenia.
* Treść jest czytana do `maxLength` (100 000 znaków), a serwery przyjmują wiadomości do 25 MB. Linki są odczytywane do `phishing.maxLength` (1 000 000 znaków).
* Każda kontrola sieciowa ma limit czasu (`timeout`, domyślnie 10 sekund). Kontrola, która zawiedzie lub przekroczy limit czasu, jest pomijana, a skanowanie kończy się bez niej. Uwierzytelnianie i model obrazów (pierwsze 10 obrazów) kończą się każde w całości w tym limicie: uwierzytelnianie nie wysyła po nim żadnego zapytania DNS ani więcej niż 300 dla jednej wiadomości (zapas dla SPF na granicach RFC 7208, z DKIM, ARC, DMARC i BIMI) i sprawdza tylko pierwsze 8 podpisów DKIM wiadomości (sam mailauth czyta najwyżej 50 zestawów ARC). Nagłówek `Authentication-Results` dodawany przez milter zawiera najwyżej 8 KiB wyników. ClamAV (cztery załączniki naraz) ma własny limit na wszystkie załączniki wiadomości (`clamav.timeout`, 60 sekund), a załączniki, których nie zdołał przeskanować, są wymienione w `results.virusScanErrors`. Model językowy ma własny limit (`llm.timeout`).
* Lista dozwolonych ufa tylko temu, czego nadawca nie może sfałszować: adresowi i zweryfikowanej nazwie hosta klienta oraz domenom nadawców potwierdzonym przez uwierzytelnianie. [Listy dozwolonych i blokowanych](api.md#allowlist-and-denylist)
* Nagłówki `X-Spam-*`, które już są w wiadomości, usuwają milter, filtr treści i `--headers`, więc nadawcy nie mogą sami oznaczyć swojej poczty jako czystej.
* Nagłówkom werdyktu spamu Microsoft ufa się tylko wtedy, gdy wiadomość przyszła bezpośrednio z serwerów Microsoft, a nagłówki Received nigdy nie służą do ustalania, skąd wiadomość przyszła.
* Tekst skierowany do filtrów AI jest punktowany jako spam, a model językowy dostaje informację, że wiadomość to dane, a nie instrukcje. [Prompt injection](llm.md#prompt-injection)


## Serwery

Serwery milter, HTTP, TCP i spamd nasłuchują na 127.0.0.1, chyba że `--host` wskazuje inaczej. HTTP API porównuje swój token w stałym czasie i odrzuca `/learn` bez tokenu. Żaden z nich nie obsługuje TLS: aby łączyć się z nimi przez sieć, użyj sieci prywatnej, tunelu SSH lub reverse proxy z TLS.

Uruchamiaj je jako nieuprzywilejowany użytkownik. [Jednostka systemd w poradniku Postfix](postfix.md#1-run-the-milter) dodaje typowe zabezpieczenia.


## Zgłaszanie podatności

Problemy z bezpieczeństwem zgłaszaj prywatnie przez [zgłaszanie podatności w GitHub](https://github.com/spamscanner/spamscanner/security/advisories/new), a nie w publicznych zgłoszeniach.
