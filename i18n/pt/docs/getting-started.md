<!-- source: 8263c06f1dab -->

# Primeiros passos

O Spam Scanner precisa do Node.js 18 ou mais recente, ou de nada com o binário independente.


## Instalação

Como ferramenta de linha de comando:

```sh
npm install --global spamscanner
spamscanner version
```

Como biblioteca em um projeto Node.js:

```sh
npm install spamscanner
```

Como binário independente para Linux ou macOS, com o Node.js e o modelo embutidos:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

Binários para Linux (x64 e arm64), macOS (Intel e Apple silicon) e Windows acompanham cada [versão](https://github.com/spamscanner/spamscanner/releases).


## Analisar uma mensagem

Salve uma mensagem como arquivo (a maioria dos programas de e-mail chama isso de “Salvar como” ou “Mostrar original”) e analise-a:

```sh
spamscanner scan message.eml
```

```text
SPAM  score 16.3 (spam at 5.0, reject at 15.0)  action: reject  language: en
     +6.3  BAYES_999                    Classifier spam probability 99.9%
     +5.0  PHISHING_LOOKALIKE_DOMAIN    "paypa1-secure.top" imitates paypal by swapping characters
     +3.0  DECEPTIVE_LINK               A link shows "https://www.paypal.com/signin" but goes to paypa1-secure.top
     +2.0  FROM_NAME_BRAND              Display name says "paypal" but the message is from paypa1-secure.top
```

O código de saída é 0 para ham, 1 para spam e 2 para erro, então os scripts podem usá-lo diretamente. O `--json` imprime o resultado completo e o `--headers` imprime a mensagem com os cabeçalhos `X-Spam-*` adicionados.

As mensagens também podem vir da entrada padrão:

```sh
cat message.eml | spamscanner scan -
```


## Usar no Node.js

```js
import SpamScanner from 'spamscanner';
import {readFile} from 'node:fs/promises';

const scanner = new SpamScanner();
const result = await scanner.scan(await readFile('message.eml'));

console.log(result.isSpam, result.score, result.action);
for (const test of result.tests) {
  console.log(test.name, test.score, test.description);
}
```

O CommonJS também funciona:

```js
const SpamScanner = require('spamscanner');
```

O `scan()` recebe a mensagem bruta como Buffer, string, Uint8Array ou stream legível. Uma string é sempre o texto da mensagem: o Spam Scanner nunca lê um arquivo só porque uma string parece um caminho. Use `scanner.scanFile(path)` para arquivos.


## Informar a sessão SMTP

O endereço IP do cliente, o seu nome de host verificado, o nome HELO e o envelope tornam o resultado mais preciso: a autenticação precisa do endereço IP, e a regra de autofalsificação precisa dos destinatários.

```js
const result = await scanner.scan(raw, {
  session: {
    remoteAddress: '203.0.113.5',
    resolvedClientHostname: 'mail.example.com',
    helo: 'mail.example.com',
    envelope: {
      mailFrom: {address: 'alice@example.com'},
      rcptTo: [{address: 'bob@example.org'}],
    },
  },
});
```

O mesmo pela linha de comando:

```sh
spamscanner scan message.eml --ip 203.0.113.5 --helo mail.example.com \
  --from alice@example.com --to bob@example.org --auth
```


## Ativar mais verificações

Nenhuma delas vem ativada por padrão, porque cada uma precisa de um serviço ou de uma decisão:

| Verificação                             | Opção da biblioteca                              | Linha de comando            |
| --------------------------------------- | ------------------------------------------------ | --------------------------- |
| SPF, DKIM, DMARC, ARC                   | `authentication: true`                           | `--auth`                    |
| Lista de bloqueio de IPs                | `dnsbl: {ip: ['zen.spamhaus.org']}`              | `--dnsbl zen.spamhaus.org`  |
| Lista de bloqueio de domínios dos links | `dnsbl: {domain: ['dbl.spamhaus.org']}`          | `--uribl dbl.spamhaus.org`  |
| ClamAV                                  | `clamav: true` ou `clamav: {socket}`             | `--clamav [socket]`         |
| Um modelo de linguagem                  | `llm: {provider: 'ollama', model: 'qwen3.5:4b'}` | `--llm ollama`              |
| Listas de permissão e de bloqueio       | `allowlist: [...]`, `denylist: [...]`            | `--allowlist`, `--denylist` |

Os resolvedores com filtragem da Cloudflare (1.1.1.2 para malware, 1.1.1.3 para conteúdo adulto) são consultados sobre os hosts dos links por padrão. Desative isso com `phishing: {cloudflare: false}` ou `--no-cloudflare`. [O que sai da máquina](security.md)

O Spamhaus e algumas outras listas de bloqueio não respondem a consultas enviadas por resolvedores públicos como 8.8.8.8 ou 1.1.1.1. Use-os com um resolvedor local com cache e confira os termos de uso para o seu volume.


## Próximos passos

* Coloque-o na frente de um servidor de e-mail: [Postfix e Sendmail](postfix.md), [outros servidores](mail-servers.md).
* Ensine os seus próprios e-mails ao modelo: [treinamento](training.md).
* Adicione um modelo de linguagem para os casos duvidosos: [modelos de linguagem](llm.md).
