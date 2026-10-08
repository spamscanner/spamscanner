<!-- source: c061da9312ad -->

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

Kody wyjścia: 0 ham, 1 spam, 2 błąd.

### Sesja SMTP

| Opcja               | Znaczenie                                  |
| ------------------- | ------------------------------------------ |
| `--ip <address>`    | Adres IP klienta, który wysłał wiadomość   |
| `--hostname <name>` | Zweryfikowana odwrotna nazwa DNS klienta   |
| `--helo <name>`     | Nazwa podana przez klienta w HELO lub EHLO |
| `--from <address>`  | Nadawca z koperty (MAIL FROM)              |
| `--to <address>`    | Odbiorca z koperty; powtórz dla kilku      |

### Kontrole

| Opcja                 | Znaczenie                                                                      |
| --------------------- | ------------------------------------------------------------------------------ |
| `--auth`              | Sprawdza SPF, DKIM, DMARC i ARC (wymaga `--ip`)                                |
| `--dnsbl <zone>`      | Czarna lista IP, na przykład `zen.spamhaus.org`; można powtarzać               |
| `--uribl <zone>`      | Czarna lista domen dla linków, na przykład `dbl.spamhaus.org`; można powtarzać |
| `--dns-server <ip>`   | Serwer nazw dla kontroli DNS; można powtarzać                                  |
| `--no-cloudflare`     | Nie pyta filtrujących resolverów Cloudflare o linki                            |
| `--clamav [socket]`   | Skanuje załączniki przez clamd, na domyślnym gnieździe lub podanym             |
| `--allowlist <value>` | Zawsze przyjmuje ten adres IP, domenę lub adres e-mail; można powtarzać        |
| `--denylist <value>`  | Zawsze odrzuca ten adres IP, domenę lub adres e-mail; można powtarzać          |

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
| `--llm-mode <mode>`                                        | `auto` (tylko trudne przypadki, domyślnie) lub `always`                                                                                                      |
| `--llm-timeout <ms>`                                       | Domyślnie 30000                                                                                                                                              |
| `--llm-policy <text>`                                      | Dodatkowe reguły dla modelu, na przykład „Nigdy nie wysyłamy faktur”                                                                                         |
| `--llm-redact`, `--no-llm-redact`                          | Najpierw usuwa dane osobowe; domyślnie włączone dla zdalnych dostawców                                                                                       |


## filter

[Filtr treści Postfix](postfix.md#content-filter). Czyta wiadomość ze standardowego wejścia, dodaje nagłówki `X-Spam-*` i przekazuje ją do sendmail z tą samą kopertą.

```sh
spamscanner filter -f "$sender" -- "$recipient"
```

| Opcja                 | Znaczenie                                                       |
| --------------------- | --------------------------------------------------------------- |
| `--sendmail <path>`   | Domyślnie `/usr/sbin/sendmail`                                  |
| `--subject-tag <tag>` | Dopisuje prefiks do tematu spamu                                |
| `--reject`            | Odbija pocztę na progu odrzucenia zamiast przekazywać ją dalej  |
| `--discard`           | Porzuca pocztę na progu odrzucenia zamiast przekazywać ją dalej |

Kody wyjścia są zgodne z konwencjami sendmail, które odczytuje Postfix: 0 dostarczono (lub porzucono), 64 nie podano odbiorców, 69 odrzucono jako spam (Postfix ją odbija), 75 dowolny błąd, więc Postfix zatrzymuje wiadomość i ponawia próbę później.


## milter, http, server i spamd

```sh
spamscanner milter --port 7831 --reject --subject-tag "[SPAM]"
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
spamscanner server --port 7830
spamscanner spamd --port 783
```

Port 783 to port, którego klienci SpamAssassin używają domyślnie. Porty poniżej 1024 wymagają uprawnień roota lub uprawnienia `CAP_NET_BIND_SERVICE`; użyj innego portu, na przykład `--port 7833`, i podaj go klientowi.

| Opcja                 | Znaczenie                                                                 |
| --------------------- | ------------------------------------------------------------------------- |
| `--port <n>`          | Port TCP                                                                  |
| `--host <ip>`         | Adres nasłuchiwania (domyślnie 127.0.0.1)                                 |
| `--socket <path>`     | Nasłuchuje zamiast tego na gnieździe Unix                                 |
| `--reject`            | Milter: odrzuca pocztę na progu odrzucenia                                |
| `--reject-code <n>`   | Milter: 451, spróbuj ponownie później (domyślnie), lub 550                |
| `--quarantine`        | Milter: zatrzymuje spam w kwarantannie serwera pocztowego                 |
| `--name <hostname>`   | Milter: nazwa tego serwera w Authentication-Results                       |
| `--token <secret>`    | HTTP: wymaga `Authorization: Bearer <secret>`; potrzebne dla `/learn`     |
| `--allow-tell`        | spamd: przyjmuje żądania TELL (`spamc -L spam`) do nauki                  |
| `--out <file>`        | HTTP i spamd: zapisuje to, czego się nauczył, do tego pliku modelu        |
| `--subject-tag <tag>` | Milter i spamd: dopisuje prefiks do tematu spamu                          |
| `--verbose`           | Milter: loguje każde skanowanie. Serwer TCP: odpowiada jedną linią tekstu |

Powyższe opcje skanowania dotyczą też serwerów. [Milter](postfix.md#milter), [HTTP API, serwer TCP i spamd](http-api.md).


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


## llm-test i models

```sh
spamscanner models
spamscanner llm-test --llm ollama --llm-model qwen3.5:4b
```

`llm-test` wysyła do modelu jedną zwykłą wiadomość i dwa oszustwa, po angielsku i po włosku, wypisuje jego werdykty, czas każdego z nich, użytą metodę i sprzęt, i kończy z kodem 0 tylko wtedy, gdy wszystkie trzy są poprawne.


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
