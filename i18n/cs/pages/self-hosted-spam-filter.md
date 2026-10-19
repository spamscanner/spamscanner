<!-- source: 988243aec4f3 -->

<!--
label: Vlastní spamový filtr
title: Vlastní spamový filtr pro váš poštovní server
description: Spamový filtr na vašem vlastním serveru. Spam Scanner nechává poštu na stroji, má model v balíčku, neposílá telemetrii a funguje s Postfixem nebo Eximem.
keywords: self-hosted spamový filtr, vlastní spamový filtr, soukromý spamový filtr, lokální spamový filtr, spamový filtr pro poštovní server, spamový filtr bez cloudu
-->

# Vlastní spamový filtr

Spam Scanner běží na vašem vlastním serveru a nechává tam poštu. Model klasifikátoru je součástí balíčku, není tu žádná telemetrie ani kontrola aktualizací a ve výchozím stavu odesílá jen dotaz DNS na název hostitele každého odkazu.


## Co opouští server

Ve výchozím stavu jen názvy hostitelů z odkazů ve zprávě. Ty se vyhledají ve filtrujících resolverech Cloudflare (1.1.1.2 a 1.1.1.3) jako běžné dotazy DNS a žádná část zprávy ani jejích adres se neodesílá. `--no-cloudflare` vypne i to.

Každá další kontrola, která používá síť, je vypnutá, dokud ji nezapnete:

| Kontrola              | Zapnete přes         | Co odesílá                                         |
| --------------------- | -------------------- | -------------------------------------------------- |
| SPF, DKIM, DMARC, ARC | `--auth`             | Dotazy DNS na záznamy odesílatele                  |
| Blokovací seznamy DNS | `--dnsbl`, `--uribl` | IP adresu klienta a domény odkazů, jako dotazy DNS |
| ClamAV                | `--clamav`           | Přílohy, vašemu vlastnímu clamd                    |
| Jazykový model        | `--llm`              | Shrnutí zprávy, serveru, který určíte              |

Kontroly se nelogují ani neukládají. [Zabezpečení a soukromí](../../docs/security.md)


## Instalace na server

```sh
npm install --global spamscanner
```

Nebo samostatný binární soubor s vestavěným Node.js a modelem:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Instalační skript před instalací ověří binární soubor podle souboru `SHA256SUMS` daného vydání a každý binární soubor má podepsané osvědčení o původu sestavení, které ověří `gh attestation verify`. Binární soubory jsou pro Linux (x64 a arm64), macOS a Windows. Linuxové soubory potřebují glibc, proto na Alpine instalujte přes npm. [Začínáme](../../docs/getting-started.md)

Kontrola aktualizací neexistuje. Pro aktualizaci spusťte instalační příkaz znovu: oba příkazy nainstalují nejnovější vydání.


## Spuštění jako služba

Servery milter, HTTP, TCP a spamd naslouchají na 127.0.0.1, pokud `--host` neurčí jinak. Spouštějte je pod uživatelem bez oprávnění, například pod systemd:

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

[Celá jednotka a její nastavení](../../docs/postfix.md#1-run-the-milter) jsou v průvodci Postfixem. Žádný ze serverů nepodporuje TLS, takže pro přístup z jiného stroje použijte privátní síť, tunel SSH nebo reverzní proxy s TLS.


## Připojení poštovního serveru

| Poštovní server                   | Příkaz                                  | Port  |
| --------------------------------- | --------------------------------------- | ----- |
| Postfix nebo Sendmail             | `spamscanner milter`                    | 7831  |
| Postfix, bez odmítání pošty       | `spamscanner filter`, obsahový filtr    | žádný |
| Exim, Haraka nebo spamc           | `spamscanner spamd`                     | 783   |
| Cokoli, co mluví HTTP             | `spamscanner http`                      | 7832  |
| Jednoduchý klient TCP             | `spamscanner server`                    | 7830  |
| Poštovní server napsaný v Node.js | `import SpamScanner from 'spamscanner'` | žádný |

Servery mohou ke zprávě přidat hlavičky `X-Spam-Flag`, `X-Spam-Score` a `X-Spam-Status` a knihovna vrací skóre a každý test, který se spustil. Průvodci: [spamový filtr pro Postfix](/postfix-spam-filter/), [další poštovní servery](../../docs/mail-servers.md) a [HTTP API](../../docs/http-api.md).


## Jazykové modely lokálně

Jazykový model je volitelný a čte jen hraniční případy: jasný spam a jasný ham se k němu nikdy nedostanou. S Ollamou běží na stejném serveru, takže žádná zpráva server neopustí:

```sh
ollama pull qwen3.5:4b
spamscanner milter --llm ollama --llm-model qwen3.5:4b
```

`qwen3.5:4b` běží na CPU. U hostovaného poskytovatele se osobní údaje před odesláním ze zprávy odstraní. [Jazykové modely](../../docs/llm.md)


## Trénování na vlastní poště

Přibalený model je natrénovaný na veřejných datových sadách. Model natrénovaný na poště, kterou váš server přijímá, funguje lépe a zůstává na tomto serveru:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out /var/lib/spamscanner/model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

Soubor modelu obsahuje hašované počty příznaků, ne slova ani text zpráv. [Trénování](../../docs/training.md)


## Požadavky

Node.js 18 nebo novější na Linuxu, macOS nebo Windows, se samostatným binárním souborem nic. ClamAV a Ollama jsou volitelné a běží jako samostatné služby.
