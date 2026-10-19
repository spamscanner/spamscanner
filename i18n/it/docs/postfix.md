<!-- source: 6675649d593a -->

# Postfix e Sendmail

Spam Scanner si collega a Postfix in due modi:

* **Come milter** (consigliato). Postfix lo interpella su ogni messaggio durante la sessione SMTP, prima di accettarlo. Lo spam può essere rifiutato con una risposta 4xx o 5xx, quindi se ne occupa il server mittente, non il tuo. Sendmail usa lo stesso protocollo.
* **Come content filter.** Postfix accetta il messaggio e lo passa tramite pipe a `spamscanner filter`, che aggiunge le intestazioni e lo restituisce con sendmail. Durante la sessione SMTP non viene mai rifiutato nulla.

Entrambi aggiungono queste intestazioni a ogni messaggio:

```text
X-Spam-Flag: YES
X-Spam-Score: 8.0
X-Spam-Level: ********
X-Spam-Status: Yes, score=8.0 required=5.0 tests=BAYES_99,DECEPTIVE_LINK version=7.0.3
X-Spam-Action: tag
```

Le intestazioni `X-Spam-*` già presenti nel messaggio vengono prima rimosse, quindi un mittente non può segnare la propria posta come pulita.

Un messaggio con un allegato che ClamAV non ha potuto analizzare può contenere un virus, quindi entrambi lo rinviano (Postfix o il mittente riprova più tardi), come fanno quando un'analisi fallisce. Con `--on-error accept` viene inoltrato con l'aggiunta di `X-Spam-Virus-Scan: failed`.


## Milter

### 1. Avviare il milter

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]" --verbose
```

Con `--reject`, i messaggi che raggiungono la soglia di rifiuto (15 punti) vengono rifiutati con `451 4.7.1 Message rejected as spam`. Un 451 è temporaneo: il mittente riprova più tardi e un errore si può ancora correggere cambiando un'impostazione. Usa `--reject-code 550` per un rifiuto permanente quando i risultati sembrano corretti. Con `--quarantine`, lo spam va invece nella coda hold di Postfix. Un messaggio che il milter non ha potuto analizzare completamente riceve una risposta 4xx; `--on-error accept` lo lascia invece passare.

Come servizio systemd, in `/etc/systemd/system/spamscanner-milter.service`:

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

### 2. Far puntare Postfix al milter

In `/etc/postfix/main.cf`:

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

`smtpd_milters` riguarda la posta che arriva tramite SMTP. Lascia vuoto `non_smtpd_milters`, a meno che non debba essere analizzata anche la posta inviata con il comando `sendmail`.

### 3. Provarlo

[swaks](https://www.jetmore.org/john/code/swaks/) invia messaggi di prova. GTUBE è una stringa di test che ogni filtro antispam tratta come spam:

```sh
swaks --to you@example.com --server 127.0.0.1 \
  --body 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
```

Senza `--reject` il messaggio viene consegnato con `X-Spam-Flag: YES` e un oggetto marcato. Con `--reject`, swaks mostra la risposta 451 o 550.


## Content filter

Usalo quando la posta non deve mai essere rifiutata durante la sessione SMTP, o per un server che non può usare i milter.

In `/etc/postfix/master.cf`, aggiungi un servizio di filtro e usalo sul listener SMTP:

```text
smtp      inet  n       -       n       -       -       smtpd
  -o content_filter=spamscanner:dummy
spamscanner unix -      n       n       -       10      pipe
  flags=Rq user=spamscanner null_sender=
  argv=/usr/bin/node /usr/local/lib/node_modules/spamscanner/dist/esm/cli.js filter --subject-tag [SPAM] --from=${sender} -- ${recipient}
```

Postfix esegue il filtro con un ambiente quasi vuoto, quindi `argv` indica Node.js e lo script con i loro percorsi completi (`command -v node` e `npm root --global` li mostrano). Poi:

```sh
sudo postfix reload
```

Il filtro restituisce il messaggio con `sendmail -G -i`. La posta inviata in questo modo non ripassa dal listener `smtp`, quindi non viene filtrata due volte.

I codici di uscita dicono a Postfix cosa è successo: 0 consegnato, 69 rifiutato (con `--reject`: Postfix lo rimanda al mittente con un bounce), 75 errore temporaneo (Postfix conserva il messaggio e riprova). Qualsiasi errore di analisi o di consegna dà 75, e così anche un messaggio con un allegato che ClamAV non ha potuto analizzare, quindi un'impostazione sbagliata non fa mai perdere o rimbalzare la posta. Con `--on-error accept`, un messaggio la cui analisi è fallita, o che ClamAV non ha potuto analizzare del tutto, viene invece inoltrato, contrassegnato con `X-Spam-Virus-Scan: failed` (vedi [la CLI](cli.md#filter)).


## Sendmail

In `sendmail.mc`:

```text
INPUT_MAIL_FILTER(`spamscanner', `S=inet:7831@127.0.0.1, F=T, T=S:30s;R:30s;E:5m')
```

`F=T` fa rispondere Sendmail con un errore temporaneo mentre il milter non è disponibile; toglilo per accettare invece la posta senza filtro. Ricompila `sendmail.cf` e riavvia Sendmail.

Il nome host del client può mettere un messaggio nella lista consentiti solo quando è verificato. Postfix lo invia solo quando il nome DNS inverso del client si risolve di nuovo nel suo indirizzo, e `unknown` altrimenti. Sendmail invia il nome DNS inverso anche quando non si risolve all'indietro (un nome che chiunque abbia il DNS inverso per il proprio indirizzo può scegliere), e lo indica nella sua macro `{client_resolve}`, che per impostazione predefinita non invia. Aggiungila alle macro inviate alla connessione, prima di `INPUT_MAIL_FILTER`, in modo che conti solo un nome host che indica come `OK`:

```text
define(`confMILTER_MACROS_CONNECT', `j, _, {daemon_name}, {if_name}, {if_addr}, {client_resolve}')
```


## Smistare lo spam in una cartella Junk

La sola marcatura consegna lo spam nella posta in arrivo. Con Dovecot, una regola Sieve lo sposta:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

[Altri server di posta](mail-servers.md) tratta Dovecot, Exim, Haraka e procmail, e [l'addestramento](training.md#learning-from-reports) mostra come imparare dalla posta che gli utenti spostano dentro e fuori da Junk.


## Testato

I test end-to-end del repository eseguono un vero Postfix: l'ham viene consegnato con le intestazioni, un `X-Spam-Flag` falsificato viene rimosso, lo spam viene marcato, il GTUBE viene rifiutato con un 550 durante la sessione SMTP e il content filter marca la posta su una seconda porta. `scripts/e2e-postfix.sh` configura quel Postfix e `test/e2e/postfix.test.js` invia la posta.
