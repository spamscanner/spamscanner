<!-- source: faf44f093f8b -->

# API HTTP, servidor TCP e spamd


## API HTTP

```sh
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
```

Ela escuta em 127.0.0.1, a menos que o `--host` diga outra coisa. Com um token, toda requisição, exceto `/health`, precisa de `Authorization: Bearer <token>`. Coloque-a atrás de um proxy reverso com TLS antes de expô-la para fora da máquina.

| Método e caminho   | Corpo            | Resposta                                                                   |
| ------------------ | ---------------- | -------------------------------------------------------------------------- |
| `GET /health`      |                  | `{"ok": true, "version": "7.0.0"}`                                         |
| `POST /scan`       | A mensagem bruta | O [resultado da análise](api.md#the-result) em JSON                        |
| `POST /check`      | A mensagem bruta | A mensagem com os cabeçalhos `X-Spam-*` adicionados, como `message/rfc822` |
| `POST /learn/spam` | A mensagem bruta | `{"ok": true, "learned": "spam"}`; precisa de um token                     |
| `POST /learn/ham`  | A mensagem bruta | `{"ok": true, "learned": "ham"}`; precisa de um token                      |

Os parâmetros de consulta descrevem a sessão SMTP:

| Parâmetro    | Significado                                                        |
| ------------ | ------------------------------------------------------------------ |
| `ip`         | O endereço IP do cliente                                           |
| `hostname`   | O seu nome DNS reverso verificado                                  |
| `helo`       | O seu nome HELO ou EHLO                                            |
| `from`       | O remetente do envelope                                            |
| `to`         | Um destinatário; repita o parâmetro ou separe vários com vírgulas  |
| `verbose=1`  | `/scan`: também retorna a lista de palavras e o assunto            |
| `subjectTag` | `/check`: prefixo para o assunto do spam, por exemplo `%5BSPAM%5D` |

O `/check` também retorna `X-Spam-Flag`, `X-Spam-Score` e `X-Spam-Action` como cabeçalhos da resposta, então um cliente pode decidir sem analisar a mensagem.

Mensagens maiores que 25 MB recebem `413`. Uma análise que falha recebe `500` com `{"error": "..."}`.

```sh
curl -s -X POST -H "Authorization: Bearer $SPAMSCANNER_TOKEN" \
  --data-binary @message.eml "http://127.0.0.1:7832/scan?ip=203.0.113.5&to=bob@example.org" | jq '.isSpam, .score, .tests'
```

Com `--out model.json`, o que o `/learn` ensina é salvo nesse arquivo após cada requisição. Sem essa opção, o aprendizado dura até o servidor reiniciar.

No Node.js:

```js
const response = await fetch('http://127.0.0.1:7832/scan?ip=203.0.113.5', {
  method: 'POST',
  headers: {authorization: `Bearer ${process.env.SPAMSCANNER_TOKEN}`},
  body: rawMessage,
});
const {isSpam, score, action} = await response.json();
```

Em Python:

```python
import os, urllib.request

request = urllib.request.Request(
    'http://127.0.0.1:7832/scan',
    data=open('message.eml', 'rb').read(),
    headers={'Authorization': f"Bearer {os.environ['SPAMSCANNER_TOKEN']}"},
    method='POST',
)
print(urllib.request.urlopen(request).read().decode())
```


## Servidor TCP

```sh
spamscanner server --port 7830
```

Envie a mensagem bruta, feche o lado de envio da conexão e leia uma linha de JSON:

```sh
nc -N 127.0.0.1 7830 < message.eml
```

Com `--verbose`, a resposta passa a ser uma linha de texto: `SPAM 16.3/5.0 BAYES_999,PHISHING_LOOKALIKE_DOMAIN,DECEPTIVE_LINK,FROM_NAME_BRAND` ou `HAM -2.5/5.0 BAYES_00`.


## spamd

```sh
spamscanner spamd --port 783
```

Um servidor compatível com o SpamAssassin para spamc, Exim, Haraka e outros clientes do SpamAssassin. [Configuração do Exim e do Haraka](mail-servers.md#a-drop-in-for-spamassassins-spamd)

| Comando         | Resposta                                                                    |
| --------------- | --------------------------------------------------------------------------- |
| `CHECK`         | `Spam: True ; 16.3 / 5.0`                                                   |
| `SYMBOLS`       | O veredito e os nomes dos testes acionados                                  |
| `REPORT`        | O veredito e uma tabela de testes, pontos e motivos                         |
| `REPORT_IFSPAM` | Como `REPORT`, com um relatório vazio para ham                              |
| `PROCESS`       | O veredito e a mensagem com os cabeçalhos `X-Spam-*`                        |
| `HEADERS`       | O veredito e o bloco de cabeçalhos da mensagem com os cabeçalhos `X-Spam-*` |
| `PING`          | `PONG`                                                                      |
| `SKIP`          | Nada                                                                        |
| `TELL`          | Aprende spam ou ham, com `--allow-tell`; salva em `--out`                   |

Requisições compactadas (`Compress: zlib`) são recusadas.
