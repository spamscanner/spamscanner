<!-- source: f1043eb5fc58 -->

# Postfix e Sendmail

O Spam Scanner se conecta ao Postfix de duas formas:

* **Como milter** (recomendado). O Postfix o consulta sobre cada mensagem durante a sessão SMTP, antes de aceitá-la. O spam pode ser recusado com uma resposta 4xx ou 5xx, então o servidor de envio, e não o seu, lida com ele. O Sendmail usa o mesmo protocolo.
* **Como filtro de conteúdo.** O Postfix aceita a mensagem e a envia por um pipe para o `spamscanner filter`, que adiciona os cabeçalhos e a devolve com o sendmail. Nada é recusado durante a sessão SMTP.

Os dois adicionam estes cabeçalhos a toda mensagem:

```text
X-Spam-Flag: YES
X-Spam-Score: 8.0
X-Spam-Level: ********
X-Spam-Status: Yes, score=8.0 required=5.0 tests=BAYES_99,DECEPTIVE_LINK version=7.0.0
X-Spam-Action: tag
```

Os cabeçalhos `X-Spam-*` que já estão na mensagem são removidos antes, então um remetente não consegue marcar os próprios e-mails como limpos.


## Milter

### 1. Execute o milter

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]" --verbose
```

Com `--reject`, as mensagens que atingem o limite de rejeição (15 pontos) são recusadas com `451 4.7.1 Message rejected as spam`. Um 451 é temporário: o remetente tenta de novo mais tarde, e um erro ainda pode ser corrigido mudando uma configuração. Use `--reject-code 550` para uma recusa permanente quando os resultados parecerem corretos. Com `--quarantine`, o spam vai para a fila de retenção (hold) do Postfix.

Como serviço do systemd, em `/etc/systemd/system/spamscanner-milter.service`:

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

### 2. Aponte o Postfix para ele

Em `/etc/postfix/main.cf`:

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

O `smtpd_milters` cobre os e-mails que chegam por SMTP. Deixe `non_smtpd_milters` vazio, a menos que os e-mails enviados com o comando `sendmail` também devam ser analisados.

### 3. Teste

O [swaks](https://www.jetmore.org/john/code/swaks/) envia mensagens de teste. O GTUBE é uma sequência de teste que todo filtro de spam trata como spam:

```sh
swaks --to you@example.com --server 127.0.0.1 \
  --body 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
```

Sem `--reject`, a mensagem é entregue com `X-Spam-Flag: YES` e o assunto marcado. Com `--reject`, o swaks mostra a resposta 451 ou 550.


## Filtro de conteúdo

Use esta opção quando os e-mails nunca puderem ser recusados durante a sessão SMTP, ou em um servidor que não pode usar milters.

Em `/etc/postfix/master.cf`, adicione um serviço de filtro e use-o no listener SMTP:

```text
smtp      inet  n       -       n       -       -       smtpd
  -o content_filter=spamscanner:dummy
spamscanner unix -      n       n       -       10      pipe
  flags=Rq user=spamscanner null_sender=
  argv=/usr/bin/node /usr/local/lib/node_modules/spamscanner/dist/esm/cli.js filter --subject-tag [SPAM] -f ${sender} -- ${recipient}
```

O Postfix executa o filtro com um ambiente quase vazio, então o `argv` indica o Node.js e o script pelos caminhos completos (`command -v node` e `npm root --global` os mostram). Depois:

```sh
sudo postfix reload
```

O filtro devolve a mensagem com `sendmail -G -i`. Os e-mails enviados dessa forma não passam de novo pelo listener `smtp`, então não são filtrados duas vezes.

Os códigos de saída dizem ao Postfix o que aconteceu: 0, entregue; 69, recusado (com `--reject`: o Postfix devolve a mensagem ao remetente); 75, falha temporária (o Postfix guarda a mensagem e tenta de novo). Qualquer falha de análise ou de entrega retorna 75, então uma configuração quebrada nunca perde nem devolve e-mails.


## Sendmail

Em `sendmail.mc`:

```text
INPUT_MAIL_FILTER(`spamscanner', `S=inet:7831@127.0.0.1, F=T, T=S:30s;R:30s;E:5m')
```

O `F=T` faz o Sendmail responder com uma falha temporária enquanto o milter está indisponível; remova-o para aceitar os e-mails sem filtragem. Gere de novo o `sendmail.cf` e reinicie o Sendmail.


## Separar o spam em uma pasta Junk

Apenas marcar entrega o spam na caixa de entrada. Com o Dovecot, uma regra Sieve o move:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" {
  fileinto "Junk";
  stop;
}
```

[Outros servidores de e-mail](mail-servers.md) cobre Dovecot, Exim, Haraka e procmail, e [treinamento](training.md#learning-from-reports) mostra como aprender com os e-mails que os usuários movem para dentro e para fora da pasta Junk.


## Testado

Os testes de ponta a ponta do repositório executam um Postfix real: o ham é entregue com os cabeçalhos, um `X-Spam-Flag` forjado é removido, o spam é marcado, o GTUBE é recusado com um 550 durante a sessão SMTP e o filtro de conteúdo marca os e-mails em uma segunda porta. O `scripts/e2e-postfix.sh` configura esse Postfix e o `test/e2e/postfix.test.js` envia os e-mails.
