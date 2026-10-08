<!-- source: f1043eb5fc58 -->

# Postfix a Sendmail

Spam Scanner se k Postfixu připojuje dvěma způsoby:

* **Jako milter** (doporučeno). Postfix se ho na každou zprávu ptá během relace SMTP, ještě před jejím přijetím. Spam lze odmítnout odpovědí 4xx nebo 5xx, takže se s ním vypořádá odesílající server, ne ten váš. Sendmail používá stejný protokol.
* **Jako obsahový filtr.** Postfix zprávu přijme a předá ji rourou do `spamscanner filter`, který přidá hlavičky a vrátí ji zpět přes sendmail. Během relace SMTP se nikdy nic neodmítne.

Oba způsoby přidávají ke každé zprávě tyto hlavičky:

```text
X-Spam-Flag: YES
X-Spam-Score: 8.0
X-Spam-Level: ********
X-Spam-Status: Yes, score=8.0 required=5.0 tests=BAYES_99,DECEPTIVE_LINK version=7.0.0
X-Spam-Action: tag
```

Hlavičky `X-Spam-*`, které už zpráva obsahuje, se nejprve odstraní, takže odesílatel nemůže svou vlastní poštu označit jako čistou.


## Milter

### 1. Spusťte milter

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]" --verbose
```

S `--reject` se zprávy na prahu odmítnutí (15 bodů) odmítají s `451 4.7.1 Message rejected as spam`. Kód 451 je dočasný: odesílatel to zkusí později znovu a chybu lze ještě opravit změnou nastavení. Až budou výsledky vypadat správně, použijte `--reject-code 550` pro trvalé odmítnutí. S `--quarantine` jde spam místo toho do fronty hold v Postfixu.

Jako služba systemd v `/etc/systemd/system/spamscanner-milter.service`:

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

### 2. Nasměrujte na něj Postfix

V `/etc/postfix/main.cf`:

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

`smtpd_milters` pokrývá poštu přicházející přes SMTP. `non_smtpd_milters` nechte prázdné, pokud nemá být kontrolována i pošta odeslaná příkazem `sendmail`.

### 3. Vyzkoušejte ho

[swaks](https://www.jetmore.org/john/code/swaks/) posílá testovací zprávy. GTUBE je testovací řetězec, který každý spamový filtr považuje za spam:

```sh
swaks --to you@example.com --server 127.0.0.1 \
  --body 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
```

Bez `--reject` se zpráva doručí s `X-Spam-Flag: YES` a označeným předmětem. S `--reject` ukáže swaks odpověď 451 nebo 550.


## Obsahový filtr

Použijte ho, když se pošta nesmí během relace SMTP nikdy odmítnout, nebo pro server, který neumí používat miltery.

V `/etc/postfix/master.cf` přidejte službu filtru a použijte ji na naslouchači SMTP:

```text
smtp      inet  n       -       n       -       -       smtpd
  -o content_filter=spamscanner:dummy
spamscanner unix -      n       n       -       10      pipe
  flags=Rq user=spamscanner null_sender=
  argv=/usr/bin/node /usr/local/lib/node_modules/spamscanner/dist/esm/cli.js filter --subject-tag [SPAM] -f ${sender} -- ${recipient}
```

Postfix spouští filtr s téměř prázdným prostředím, proto `argv` uvádí Node.js i skript plnými cestami (ukážou je `command -v node` a `npm root --global`). Potom:

```sh
sudo postfix reload
```

Filtr vrací zprávu zpět pomocí `sendmail -G -i`. Pošta odeslaná tímto způsobem znovu neprochází naslouchačem `smtp`, takže se nefiltruje dvakrát.

Návratové kódy říkají Postfixu, co se stalo: 0 doručeno, 69 odmítnuto (s `--reject`: Postfix zprávu vrátí odesílateli), 75 dočasné selhání (Postfix zprávu ponechá a zkusí to znovu). Jakékoli selhání kontroly nebo doručení vrací 75, takže chybné nastavení nikdy poštu neztratí ani nevrátí.


## Sendmail

V `sendmail.mc`:

```text
INPUT_MAIL_FILTER(`spamscanner', `S=inet:7831@127.0.0.1, F=T, T=S:30s;R:30s;E:5m')
```

`F=T` zajistí, že Sendmail odpovídá dočasným selháním, dokud je milter nedostupný; když tuto volbu vynecháte, pošta se místo toho přijme nefiltrovaná. Znovu sestavte `sendmail.cf` a restartujte Sendmail.


## Třídění spamu do složky Junk

Samotné označení doručí spam do doručené pošty. S Dovecotem ho přesune pravidlo Sieve:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

[Další poštovní servery](mail-servers.md) popisují Dovecot, Exim, Haraka a procmail a [trénování](training.md#learning-from-reports) ukazuje, jak se učit z pošty, kterou uživatelé přesouvají do složky Junk a z ní.


## Otestováno

Testy end-to-end v repozitáři spouštějí skutečný Postfix: ham se doručí s hlavičkami, podvržená `X-Spam-Flag` se odstraní, spam se označí, GTUBE se během relace SMTP odmítne s kódem 550 a obsahový filtr označuje poštu na druhém portu. `scripts/e2e-postfix.sh` tento Postfix nastaví a `test/e2e/postfix.test.js` posílá poštu.
