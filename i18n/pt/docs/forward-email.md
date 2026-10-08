<!-- source: dc9016edd59e -->

# Forward Email

O Spam Scanner foi desenvolvido pelo [Forward Email](https://forwardemail.net), o serviço de e-mail de código aberto focado em privacidade, para os seus próprios servidores de e-mail. O Forward Email não guarda registros do conteúdo das mensagens, então nenhum serviço de filtragem externo serviria: o filtro precisava rodar nos seus próprios servidores e explicar cada decisão sem que uma pessoa lesse o e-mail.

Esta página mostra como um servidor de e-mail como o do Forward Email o usa e o que mudou para o código escrito para o Spam Scanner 5 ou 6.


## Em um servidor de recebimento de e-mails

O Forward Email recebe e-mails com o [smtp-server](https://nodemailer.com/extras/smtp-server/). O padrão, para qualquer servidor construído com ele:

```js
const SpamScanner = require('spamscanner');

const scanner = new SpamScanner({
  clamav: true,                  // clamd on its default socket
  authentication: true,          // SPF, DKIM, DMARC, ARC
  dnsbl: {ip: ['zen.spamhaus.org'], domain: ['dbl.spamhaus.org']},
  dns: {servers: ['127.0.0.1']}, // a local caching resolver
});

async function onData(stream, session, callback) {
  const scan = await scanner.scan(stream, {
    session: {
      remoteAddress: session.remoteAddress,
      resolvedClientHostname: session.clientHostname,
      helo: session.hostNameAppearsAs,
      envelope: session.envelope,
    },
  });

  if (scan.results.viruses.length > 0) {
    return callback(Object.assign(new Error(`Message contains a virus: ${scan.results.viruses[0]}`), {responseCode: 554}));
  }

  if (scan.action === 'reject') {
    // A temporary error: the sender retries, and a wrong decision can be undone.
    return callback(Object.assign(new Error(`Message rejected as spam: ${scan.message}`), {responseCode: 421}));
  }

  // scan.isSpam: deliver to the Junk folder, or add scan's headers (spamHeaders) and forward.
  callback();
}
```

O `scanner.scan()` aceita o stream SMTP diretamente. Se você já tem os resultados do [mailauth](https://github.com/postalsys/mailauth), pule o `authentication` e passe apenas o endereço IP.

Uma resposta 421 ou 451 faz o servidor de envio colocar a mensagem na fila e tentar de novo mais tarde. Novas regras de rejeição podem começar com um código temporário e passar para 550 depois que os seus resultados forem conferidos, sem perder e-mails nesse meio-tempo.


## Atualizando a partir da versão 5 ou 6

A versão 7 é uma reescrita. O construtor, o `scan()` e os campos do resultado que o código das versões 5 e 6 lê continuam funcionando; o classificador, o modelo e as verificações opcionais com TensorFlow mudaram.

### Continua igual

* `new SpamScanner(options)` e `await scanner.scan(source)`.
* `require('spamscanner')` retorna a classe, e `import SpamScanner from 'spamscanner'` funciona.
* `result.isSpam`, `result.message` e `result.results.classification`, `.phishing`, `.executables`, `.arbitrary`, `.viruses`, `.macros` e `.idnHomographAttack`.
* Cada item de `results.phishing`, `.executables`, `.arbitrary` e `.viruses` é convertido no mesmo tipo de string de mensagem de antes (`String(item)`, template literals, `message.includes('adult-related content')`). Agora eles são objetos com `type`, `message` e detalhes.
* `getTokensAndMailFromSource()`, `getClassification()` e `getTokens()`.
* Estas opções correspondem aos novos nomes: `clamscan` para `clamav`, `enableMacroDetection: false` para `macros: false`, `enableArbitraryDetection: false` para `arbitrary: false`, `enableAuthentication` com `authOptions` para `authentication` e `session`, `enableReputation` com `reputationOptions.apiUrl` para `reputation`, `strictIDNDetection` para `phishing.homograph.strictMode`, e `allowlist` e `denylist`. `logger` e `memoize` são aceitas e ignoradas.

### Mudou

| Antes                                                                                      | Agora                                                                                                                                                                            |
| ------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan('path/to/file.eml')` lia o arquivo                                                   | Uma string é texto de mensagem. Use `scanFile(path)` ou passe um Buffer                                                                                                          |
| Um modelo naive Bayes de palavras (`classifier.json`), que não pode mais ser carregado     | Um novo classificador e um novo formato de modelo; treine de novo com `spamscanner train` ([treinamento](training.md))                                                           |
| As verificações de toxicidade e NSFW carregavam modelos TensorFlow da rede no primeiro uso | Traga o seu próprio modelo: `toxicity: {model}` e `nsfw: {model}` aceitam qualquer objeto com um método `classify()`, por exemplo do `@tensorflow-models/toxicity` e do `nsfwjs` |
| `results.arbitrary` listava todos os padrões que casavam                                   | Ele lista as regras fortes o bastante para marcar spam sozinhas; todas as regras estão em `result.tests`                                                                         |
| Uma resposta sim ou não                                                                    | `result.score`, `result.action` (`accept`, `tag` ou `reject`) e `result.tests`, cada um com pontos e um motivo                                                                   |
| `isSpam` decidido pelo classificador ou por qualquer verificação isolada                   | `isSpam` é uma pontuação de 5 ou mais; os limites e os pontos podem ser alterados                                                                                                |
| Verificações de reputação contra um endpoint do Forward Email                              | Um serviço de reputação genérico, desligado a menos que `reputation.apiUrl` seja definido                                                                                        |

### Novidades

* [Modelos de linguagem](llm.md) para os casos duvidosos, locais ou hospedados.
* SPF, DKIM, DMARC e ARC; listas de bloqueio no DNS; os resolvedores com filtragem da Cloudflare.
* Verificações de anexos pelo conteúdo: executáveis disfarçados, arquivos compactados, macros, PDFs ativos.
* Um [milter, uma API HTTP, um servidor TCP e um servidor spamd](mail-servers.md), e uma [linha de comando](cli.md).
* Treinamento, avaliação e aprendizado a partir de denúncias, pela linha de comando ou pela API.
