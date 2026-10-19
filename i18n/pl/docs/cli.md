<!-- source: ff86d06bdcd0 -->

# Wiersz poleceń

```text
spamscanner <command> [options]
```

| Polecenie                                  | Co robi                                                                              |
| ------------------------------------------ | ------------------------------------------------------------------------------------ |
| `scan [file\|-]`                           | Skanuje wiadomość z pliku lub standardowego wejścia                                  |
| `filter -f <sender> -- <recipients...>`    | Filtr treści Postfix: skanuje standardowe wejście, dodaje nagłówki, przekazuje dalej |
| `milter`                                   | Milter dla Postfix i Sendmail, port 7831                                             |
| `http`                                     | HTTP API, port 7832                                                                  |
| `server`                                   | Zwykły serwer TCP, port 7830                                                         |
| `spamd`                                    | Serwer spamd zgodny ze SpamAssassin, port 783                                        |
| `train`                                    | Trenuje model z plików mbox, katalogów Maildir, folderów lub zbiorów danych          |
| `eval`                                     | Mierzy model na oznaczonej poczcie                                                   |
| `learn spam\|ham [file\|-] --model <file>` | Uczy model jednej wiadomości                                                         |
| `llm-test`                                 | Sprawdza ustawienia modelu językowego na trzech przykładowych wiadomościach          |
| `models`                                   | Wyświetla zalecane otwarte modele                                                    |
| `version`, `help`                          |                                                                                      |


## scan

```sh
spamscanner scan message.eml
spamscanner scan - < message.eml
spamscanner scan message.eml --json
spamscanner scan message.eml --headers > tagged.eml
spamscanner scan message.eml --subject-tag "[SPAM]" > tagged.eml
```

| Opcja                      | Znaczenie                                                   |
| -------------------------- | ----------------------------------------------------------- |
| `--json`                   | Wypisuje pełny wynik jako JSON                              |
| `--headers`                | Wypisuje wiadomość z dodanymi nagłówkami `X-Spam-*`         |
| `--subject-tag <tag>`      | Dodatkowo dopisuje prefiks do tematu spamu                  |
| `--verbose`                | Pokazuje każdy test i najsilniejsze wskazówki klasyfikatora |
| `--threshold <n>`          | Wynik, od którego poczta jest spamem (domyślnie 5)          |
| `--reject-threshold <n>`   | Wynik, od którego poczta jest odrzucana (domyślnie 15)      |
| `--model <file>`           | Plik modelu zamiast dołączonego                             |
| `--no-classifier`          | Nie używa klasyfikatora                                     |
| `--config <file>`          | Plik JSON z [opcjami biblioteki](api.md#options)            |
| `--allow-language <codes>` | Akceptowane języki, na przykład `en,de,fr`                  |
| `--max-size <bytes>`       | Największa czytana wiadomość (domyślnie 26214400, 25 MiB)   |

Kody wyjścia: 0 ham, 1 spam, 2 błąd.

`scan` i `learn` czytają najwyżej `--max-size` bajtów wiadomości, z pliku lub standardowego wejścia; serwery mają ten sam limit. Większa wiadomość jest błędem (kod wyjścia 2), a jej reszta nie jest czytana.

Standardowe wyjście zawiera tylko wynik (lub wiadomość): wszystko, co biblioteka wypisuje podczas działania polecenia, na przykład uwagi mailauth o długościach treści w DKIM, trafia na standardowe wyjście błędów.

### Sesja SMTP

| Opcja               | Znaczenie                                  |
| ------------------- | ------------------------------------------ |
| `--ip <address>`    | Adres IP klienta, który wysłał wiadomość   |
| `--hostname <name>` | Zweryfikowana odwrotna nazwa DNS klienta   |
| `--helo <name>`     | Nazwa podana przez klienta w HELO lub EHLO |
| `--from <address>`  | Nadawca z koperty (MAIL FROM)              |
| `--to <address>`    | Odbiorca z koperty; powtórz dla kilku      |

### Kontrole

| Opcja                 | Znaczenie                                                                                                                                          |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--auth`              | Sprawdza SPF, DKIM, DMARC i ARC (wymaga `--ip`)                                                                                                    |
| `--dnsbl <zone>`      | Czarna lista IP, na przykład `zen.spamhaus.org`; można powtarzać                                                                                   |
| `--uribl <zone>`      | Czarna lista domen dla linków, na przykład `dbl.spamhaus.org`; można powtarzać                                                                     |
| `--dns-server <ip>`   | Serwer nazw dla kontroli DNS; można powtarzać                                                                                                      |
| `--no-cloudflare`     | Nie pyta filtrujących resolverów Cloudflare o linki                                                                                                |
| `--clamav[=socket]`   | Skanuje załączniki przez clamd, na domyślnym gnieździe lub podanym                                                                                 |
| `--allowlist <value>` | Zawsze akceptuj ten adres IP lub nazwę hosta klienta albo tę domenę lub adres, gdy uwierzytelnianie potwierdza nadawcę (`--auth`); można powtarzać |
| `--denylist <value>`  | Zawsze odrzuca ten adres IP, domenę lub adres e-mail; można powtarzać                                                                              |

### Model językowy

| Opcja                                                      | Znaczenie                                                                                                                                                    |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `--llm <provider>`                                         | `ollama`, `clef-flash`, `jev`, `openai`, `anthropic` i inne ([lista](llm.md#providers))                                                                      |
| `--llm-model <name>`                                       | Model, na przykład `qwen3.5:4b` lub `claude-haiku-4-5`                                                                                                       |
| `--llm-method <method>`                                    | `decision` (prawdopodobieństwo każdego werdyktu w jednym kroku; domyślnie tam, gdzie jest dostępne) lub `generate` ([metody](llm.md#decision-or-generation)) |
| `--llm-account <id>`                                       | Identyfikator konta Cloudflare, dla `clef` i `clef-flash`                                                                                                    |
| `--llm-url <url>`                                          | Bazowy URL, na przykład `http://10.0.0.5:11434`                                                                                                              |
| `--llm-host`, `--llm-port`, `--llm-path`, `--llm-protocol` | Zmienia jedną część URL dostawcy                                                                                                                             |
| `--llm-api-key <key>`                                      | Klucz API; zobacz też zmienne środowiskowe poniżej                                                                                                           |
| `--llm-auth <type>`                                        | `bearer`, `x-api-key`, `api-key`, `basic`, `header` lub `none`                                                                                               |
| `--llm-auth-header <name>`                                 | Nagłówek z kluczem, przy `--llm-auth header`                                                                                                                 |
| `--llm-username`, `--llm-password`                         | Dla `--llm-auth basic`                                                                                                                                       |
| `--llm-header "Name: value"`                               | Dodatkowy nagłówek żądania; można powtarzać                                                                                                                  |
| `--llm-mode <mode>`                                        | `auto` (tylko trudne przypadki, domyślnie), `always` lub `off`                                                                                               |
| `--llm-timeout <ms>`                                       | Domyślnie 30000                                                                                                                                              |
| `--llm-policy <text>`                                      | Dodatkowe reguły dla modelu, na przykład „Nigdy nie wysyłamy faktur”                                                                                         |
| `--llm-redact`, `--no-llm-redact`                          | Najpierw usuwa dane osobowe; domyślnie włączone dla zdalnych dostawców                                                                                       |


## filter

[Filtr treści Postfix](postfix.md#content-filter). Czyta wiadomość ze standardowego wejścia, dodaje nagłówki `X-Spam-*` i przekazuje ją do sendmail z tą samą kopertą.

```sh
spamscanner filter -f "$sender" -- "$recipient"
```

| Opcja                 | Znaczenie                                                                                  |
| --------------------- | ------------------------------------------------------------------------------------------ |
| `--sendmail <path>`   | Domyślnie `/usr/sbin/sendmail`                                                             |
| `--subject-tag <tag>` | Dopisuje prefiks do tematu spamu                                                           |
| `--reject`            | Odbija pocztę na progu odrzucenia zamiast przekazywać ją dalej                             |
| `--discard`           | Porzuca pocztę na progu odrzucenia zamiast przekazywać ją dalej                            |
| `--on-error <answer>` | Dla poczty, której nie udało się w pełni przeskanować: `tempfail` (domyślnie) lub `accept` |
| `--max-size <bytes>`  | Największa skanowana wiadomość (domyślnie 26214400, 25 MiB)                                |

Kody wyjścia są zgodne z konwencjami sendmail, które odczytuje Postfix: 0 dostarczono (lub porzucono), 64 nie podano odbiorców, 69 odrzucono jako spam (Postfix ją odbija), 75 dowolny błąd, więc Postfix zatrzymuje wiadomość i ponawia próbę później. Wiadomość z załącznikiem, którego ClamAV nie zdołał przeskanować, to również błąd. Z `--on-error accept` taka wiadomość albo wiadomość, której skanowanie się nie powiodło, jest przekazywana dalej z `X-Spam-Virus-Scan: failed` i bez żadnych nagłówków `X-Spam-*` dodanych przez nadawcę.

Wiadomość większa niż `--max-size` nie jest skanowana ani przechowywana w całości w pamięci. Jest odkładana (75) albo, z `--on-error accept`, przekazywana dalej bez skanowania w miarę czytania, oznaczona i bez nagłówków `X-Spam-*` nadawcy, jak wyżej. `message_size_limit` w Postfix (domyślnie 10 MB) utrzymuje pocztę poniżej domyślnego limitu; jeśli podniesiesz go powyżej 25 MiB, podnieś też `--max-size`.


## milter, http, server i spamd

```sh
spamscanner milter --port 7831 --reject --subject-tag "[SPAM]"
spamscanner http --port 7832    # token in SPAMSCANNER_TOKEN
spamscanner server --port 7830
spamscanner spamd --port 783
```

API HTTP odczytuje swój token ze zmiennej środowiskowej `SPAMSCANNER_TOKEN`. `--token` też działa, ale inni użytkownicy komputera widzą opcje wiersza poleceń w `ps`.

Port 783 to port, którego klienci SpamAssassin używają domyślnie. Porty poniżej 1024 wymagają uprawnień roota lub uprawnienia `CAP_NET_BIND_SERVICE`; użyj innego portu, na przykład `--port 7833`, i podaj go klientowi.

| Opcja                   | Znaczenie                                                                                                                                                                                                    |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `--port <n>`            | Port TCP                                                                                                                                                                                                     |
| `--host <ip>`           | Adres nasłuchiwania (domyślnie 127.0.0.1)                                                                                                                                                                    |
| `--socket <path>`       | Nasłuchuje zamiast tego na gnieździe Unix                                                                                                                                                                    |
| `--max-size <bytes>`    | Największa przyjmowana wiadomość (domyślnie 26214400, 25 MiB). Milter skanuje początek dłuższej treści, a gdy już sama koperta i nagłówki są większe, odpowiada jak przy nieudanym skanowaniu (`--on-error`) |
| `--max-connections <n>` | Połączenia otwarte jednocześnie (domyślnie 200); kolejne są od razu zamykane. HTTP: także żądania obsługiwane jednocześnie, kolejne dostają `503`                                                            |
| `--reject`              | Milter: odrzuca pocztę na progu odrzucenia                                                                                                                                                                   |
| `--reject-code <n>`     | Milter: kod 4xx, spróbuj ponownie później (451, domyślnie), lub kod 5xx, taki jak 550                                                                                                                        |
| `--quarantine`          | Milter: zatrzymuje spam w kwarantannie serwera pocztowego                                                                                                                                                    |
| `--on-error <answer>`   | Milter: dla poczty, której nie udało się w pełni przeskanować, `tempfail` (domyślnie) lub `accept`                                                                                                           |
| `--name <hostname>`     | Milter: nazwa tego serwera w Authentication-Results                                                                                                                                                          |
| `--token <secret>`      | HTTP: wymaga `Authorization: Bearer <secret>`; potrzebne dla `/learn`                                                                                                                                        |
| `--allow-tell`          | spamd: przyjmuje żądania TELL (`spamc -L spam`) do nauki                                                                                                                                                     |
| `--out <file>`          | HTTP i spamd: zapisuje to, czego się nauczył, do tego pliku modelu                                                                                                                                           |
| `--subject-tag <tag>`   | Milter i spamd: dopisuje prefiks do tematu spamu                                                                                                                                                             |
| `--verbose`             | Milter: loguje każde skanowanie. Serwer TCP: odpowiada jedną linią tekstu                                                                                                                                    |

Powyższe opcje skanowania dotyczą też serwerów. [Milter](postfix.md#milter), [HTTP API, serwer TCP i spamd](http-api.md).

Klienci spamd i TCP nie wysyłają adresu IP klienta, który nadał wiadomość, a klienci HTTP wysyłają go tylko z `?ip=`, więc `--auth` i `--dnsbl` działają tylko z milterem i z żądaniami HTTP, które go podają. Serwery informują o tym, gdy uruchamia się je z tymi opcjami.


## train, eval i learn

```sh
spamscanner train --spam ~/Mail/Junk --ham ~/Mail/Archive --out my-model.json
spamscanner eval --model my-model.json --spam test/spam.mbox --ham test/ham.mbox
spamscanner learn spam message.eml --model my-model.json
```

| Opcja                                           | Znaczenie                                                                  |
| ----------------------------------------------- | -------------------------------------------------------------------------- |
| `--spam <path>`                                 | Spam: plik mbox, katalog Maildir lub folder plików `.eml`; można powtarzać |
| `--ham <path>`                                  | Ham, tak samo; można powtarzać                                             |
| `--dataset <file>`                              | Plik CSV lub JSON Lines z kolumnami tekstu i etykiety; można powtarzać     |
| `--text-column <name>`, `--label-column <name>` | Nazwy kolumn, gdy nie zostaną wykryte                                      |
| `--out <file>`                                  | Gdzie zapisać model (domyślnie `spamscanner-model.json`)                   |
| `--merge`                                       | Zaczyna od dołączonego modelu (lub `--model`) zamiast od pustego           |

`learn` aktualizuje plik modelu w miejscu, a za pierwszym razem tworzy go z dołączonego modelu. [Trenowanie](training.md)

Gdy podano zarówno `--model`, jak i `--out`, `learn` zaczyna od pliku `--model` i zapisuje wynik do `--out`.


## llm-test i models

```sh
spamscanner models
spamscanner llm-test --llm ollama --llm-model qwen3.5:4b
```

`llm-test` wysyła do modelu jedną zwykłą wiadomość i dwa oszustwa, po angielsku i po włosku, wypisuje jego werdykty, czas każdego z nich, użytą metodę oraz, dla modelu na tym komputerze, sprzęt, i kończy z kodem 0 tylko wtedy, gdy wszystkie trzy są poprawne.


## Plik konfiguracyjny

`--config file.json` (lub zmienna środowiskowa `SPAMSCANNER_CONFIG`) wczytuje [opcje biblioteki](api.md#options). Opcje wiersza poleceń mają pierwszeństwo przed plikiem.

```json
{
  "threshold": 6,
  "authentication": true,
  "dnsbl": {"ip": ["zen.spamhaus.org"], "domain": ["dbl.spamhaus.org"]},
  "dns": {"servers": ["127.0.0.1"]},
  "clamav": {"socket": "/var/run/clamav/clamd.ctl"},
  "llm": {"provider": "ollama", "model": "qwen3.5:4b"},
  "scores": {"deceptiveLink": 4, "FROM_NAME_BRAND": 3}
}
```


## Zmienne środowiskowe

| Zmienna                                                                                                                                                                                                                                                                                                                    | Znaczenie                                          |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| `SPAMSCANNER_CONFIG`                                                                                                                                                                                                                                                                                                       | Plik konfiguracyjny                                |
| `SPAMSCANNER_MODEL`                                                                                                                                                                                                                                                                                                        | Plik modelu używany zamiast dołączonego            |
| `SPAMSCANNER_TOKEN`                                                                                                                                                                                                                                                                                                        | Token dla HTTP API                                 |
| `SPAMSCANNER_LLM_API_KEY`                                                                                                                                                                                                                                                                                                  | Klucz API dla dowolnego dostawcy modelu językowego |
| `CLOUDFLARE_API_TOKEN` i `CLOUDFLARE_ACCOUNT_ID`, `TYPESAFE_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY`, `XAI_API_KEY`, `TOGETHER_API_KEY`, `FIREWORKS_API_KEY`, `CEREBRAS_API_KEY`, `HF_TOKEN`, `AZURE_OPENAI_API_KEY` | Własny klucz każdego dostawcy                      |
| `NODE_DEBUG=spamscanner*`                                                                                                                                                                                                                                                                                                  | Logowanie debugowania                              |
