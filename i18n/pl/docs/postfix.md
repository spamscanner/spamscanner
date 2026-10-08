<!-- source: f1043eb5fc58 -->

# Postfix i Sendmail

Spam Scanner łączy się z Postfix na dwa sposoby:

* **Jako milter** (zalecane). Postfix pyta go o każdą wiadomość w trakcie sesji SMTP, zanim ją przyjmie. Spam można odrzucić odpowiedzią 4xx lub 5xx, więc zajmuje się nim serwer wysyłający, a nie twój. Sendmail używa tego samego protokołu.
* **Jako filtr treści.** Postfix przyjmuje wiadomość i przekazuje ją potokiem do `spamscanner filter`, który dodaje nagłówki i oddaje ją z powrotem przez sendmail. W trakcie sesji SMTP nic nie jest odrzucane.

Oba sposoby dodają do każdej wiadomości te nagłówki:

```text
X-Spam-Flag: YES
X-Spam-Score: 8.0
X-Spam-Level: ********
X-Spam-Status: Yes, score=8.0 required=5.0 tests=BAYES_99,DECEPTIVE_LINK version=7.0.0
X-Spam-Action: tag
```

Nagłówki `X-Spam-*`, które już są w wiadomości, są najpierw usuwane, więc nadawca nie może sam oznaczyć swojej poczty jako czystej.


## Milter

### 1. Uruchom milter

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]" --verbose
```

Z `--reject` wiadomości na progu odrzucenia (15 punktów) są odrzucane z `451 4.7.1 Message rejected as spam`. Kod 451 jest tymczasowy: nadawca ponawia próbę później, a pomyłkę wciąż można naprawić zmianą ustawienia. Gdy wyniki będą wyglądać poprawnie, użyj `--reject-code 550`, aby odrzucać na stałe. Z `--quarantine` spam trafia zamiast tego do kolejki wstrzymanych (hold) w Postfix.

Jako usługa systemd, w `/etc/systemd/system/spamscanner-milter.service`:

```ini
[Unit]
Description=Spam Scanner milter
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/spamscanner milter --port 7831 --auth --subject-tag [SPAM]
User=spamscanner
Group=spamscanner
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin spamscanner
sudo systemctl daemon-reload
sudo systemctl enable --now spamscanner-milter
```

### 2. Wskaż go w Postfix

W `/etc/postfix/main.cf`:

```ini
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
# If the milter is down: accept mail unfiltered (accept) or ask senders to retry (tempfail).
milter_default_action = accept
# Long enough for a language model, if one is configured.
milter_content_timeout = 120s
```

```sh
sudo postfix reload
```

`smtpd_milters` obejmuje pocztę przychodzącą przez SMTP. Zostaw `non_smtpd_milters` puste, chyba że skanowana ma być też poczta wysyłana poleceniem `sendmail`.

### 3. Przetestuj

[swaks](https://www.jetmore.org/john/code/swaks/) wysyła wiadomości testowe. GTUBE to ciąg testowy, który każdy filtr antyspamowy traktuje jako spam:

```sh
swaks --to you@example.com --server 127.0.0.1 \
  --body 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
```

Bez `--reject` wiadomość jest dostarczana z `X-Spam-Flag: YES` i oznaczonym tematem. Z `--reject` swaks pokazuje odpowiedź 451 lub 550.


## Filtr treści

Użyj go, gdy poczta nigdy nie może być odrzucana w trakcie sesji SMTP, albo dla serwera, który nie obsługuje milterów.

W `/etc/postfix/master.cf` dodaj usługę filtra i użyj jej w nasłuchu SMTP:

```text
smtp      inet  n       -       n       -       -       smtpd
  -o content_filter=spamscanner:dummy
spamscanner unix -      n       n       -       10      pipe
  flags=Rq user=spamscanner null_sender=
  argv=/usr/bin/node /usr/local/lib/node_modules/spamscanner/dist/esm/cli.js filter --subject-tag [SPAM] -f ${sender} -- ${recipient}
```

Postfix uruchamia filtr w prawie pustym środowisku, więc `argv` podaje Node.js i skrypt pełnymi ścieżkami (pokazują je `command -v node` i `npm root --global`). Następnie:

```sh
sudo postfix reload
```

Filtr oddaje wiadomość przez `sendmail -G -i`. Poczta wysłana w ten sposób nie przechodzi ponownie przez nasłuch `smtp`, więc nie jest filtrowana dwa razy.

Kody wyjścia mówią Postfix, co się stało: 0 dostarczono, 69 odrzucono (z `--reject`: Postfix odbija ją do nadawcy), 75 błąd tymczasowy (Postfix zatrzymuje wiadomość i ponawia próbę). Każdy błąd skanowania lub dostarczenia to 75, więc błędne ustawienie nigdy nie powoduje utraty ani odbicia poczty.


## Sendmail

W `sendmail.mc`:

```text
INPUT_MAIL_FILTER(`spamscanner', `S=inet:7831@127.0.0.1, F=T, T=S:30s;R:30s;E:5m')
```

`F=T` sprawia, że Sendmail odpowiada błędem tymczasowym, gdy milter jest niedostępny; usuń to, aby zamiast tego przyjmować pocztę bez filtrowania. Przebuduj `sendmail.cf` i zrestartuj Sendmail.


## Przenoszenie spamu do folderu Junk

Samo oznaczanie dostarcza spam do skrzynki odbiorczej. Z Dovecot przenosi go reguła Sieve:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

[Inne serwery pocztowe](mail-servers.md) opisują Dovecot, Exim, Haraka i procmail, a [trenowanie](training.md#learning-from-reports) pokazuje, jak uczyć się z poczty, którą użytkownicy przenoszą do Junk i z Junk.


## Przetestowane

Testy end-to-end w repozytorium uruchamiają prawdziwy Postfix: ham jest dostarczany z nagłówkami, podrobiony `X-Spam-Flag` jest usuwany, spam jest oznaczany, GTUBE jest odrzucany kodem 550 w trakcie sesji SMTP, a filtr treści oznacza pocztę na drugim porcie. `scripts/e2e-postfix.sh` konfiguruje ten Postfix, a `test/e2e/postfix.test.js` wysyła pocztę.
