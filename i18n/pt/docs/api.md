<!-- source: b3cc9f949acd -->

# Referência da API

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Crie um único scanner e reutilize-o: ele carrega o modelo uma vez e mantém em cache as respostas DNS e as do modelo de linguagem.


## Opções

Todas as opções podem ser passadas ao construtor. A maioria também pode ser passada ao `scan()` para uma única mensagem, e elas se sobrepõem às do construtor.

| Opção                   | Padrão                           | Significado                                                                                                           |
| ----------------------- | -------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Pontuação a partir da qual uma mensagem é spam                                                                        |
| `rejectThreshold`       | `15`                             | Pontuação a partir da qual `action` é `reject`                                                                        |
| `scores`                | `{}`                             | Pontos por teste: chaves de configuração ou nomes de testes ([testes e pontuações](scoring.md))                       |
| `classifier`            | modelo incluído                  | Um `Classifier`, um objeto de modelo, o caminho de um arquivo de modelo ou `false`                                    |
| `classifierOptions`     | `{}`                             | Opções para o modelo incluído (veja [Classificador](#classifier))                                                     |
| `allowedLanguages`      | `[]`                             | Códigos ISO 639-1; os outros idiomas recebem `LANGUAGE_NOT_ALLOWED`                                                   |
| `phishing.cloudflare`   | `true`                           | Consultar os resolvedores com filtragem da Cloudflare sobre os hosts dos links                                        |
| `phishing.adult`        | `true`                           | Consultar também o resolvedor familiar, que bloqueia sites adultos                                                    |
| `phishing.maxHosts`     | `25`                             | Hosts de links consultados por mensagem                                                                               |
| `phishing.homograph`    | `{}`                             | `brands` (substitui a lista embutida), `extraBrands`, `allowlist` (domínios nunca marcados), `strictMode`             |
| `dnsbl`                 | `{ip: [], domain: []}`           | Zonas de listas de bloqueio no DNS para o IP do cliente e para os domínios dos links                                  |
| `dns`                   | `{servers: null, timeout: 3000}` | Servidores de nomes para as verificações DNS (padrão: os do sistema)                                                  |
| `attachments`           | `true`                           | Inspecionar os anexos                                                                                                 |
| `macros`                | `true`                           | Marcar macros, PDFs ativos e objetos RTF                                                                              |
| `arbitrary`             | `true`                           | Executar as [regras](scoring.md#rules)                                                                                |
| `authentication`        | `false`                          | `true`, ou `{dnsServers, timeout, mta, weights}`: SPF, DKIM, DMARC, ARC                                               |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout}`                                                                     |
| `allowlist`, `denylist` |                                  | Endereços IP, domínios ou endereços; atalho para `reputation`                                                         |
| `clamav`                | `false`                          | `true` (socket padrão), `{socket}` ou `{host, port}`                                                                  |
| `llm`                   | `null`                           | [Configurações do modelo de linguagem](llm.md#any-server-port-and-authentication), com `mode`, `minScore`, `maxScore` |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: um modelo cujo `classify([text])` responde como o `@tensorflow-models/toxicity`           |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: um modelo cujo `classify(imageBuffer)` responde como o `nsfwjs`                           |
| `maxLength`             | `100000`                         | Caracteres do texto do corpo que são lidos                                                                            |
| `timeout`               | `10000`                          | Milissegundos permitidos para cada verificação de rede                                                                |
| `session`               | `{}`                             | Detalhes padrão da sessão SMTP                                                                                        |

O `scan()` também recebe `session`:

```js
await scanner.scan(raw, {
  session: {
    remoteAddress: '203.0.113.5',             // the client's IP address
    resolvedClientHostname: 'mx.example.com', // its verified reverse DNS name
    helo: 'mx.example.com',
    envelope: {
      mailFrom: {address: 'alice@example.com'},
      rcptTo: [{address: 'bob@example.org'}],
    },
  },
});
```


## Métodos

| Método                               | Retorna                                                                                |
| ------------------------------------ | -------------------------------------------------------------------------------------- |
| `scan(source, options)`              | O resultado. `source` é um Buffer, uma string, um Uint8Array ou um stream legível      |
| `scanFile(path, options)`            | O resultado para um arquivo de mensagem                                                |
| `learn(source, 'spam' \| 'ham')`     | Ensina uma mensagem ao classificador                                                   |
| `unlearn(source, 'spam' \| 'ham')`   | Desfaz o `learn`                                                                       |
| `saveModel(path, options)`           | Grava o classificador em um arquivo (`options`: `minCount`, `maxFeatures`, `metadata`) |
| `getClassifier()`                    | O `Classifier` em uso, ou `null`                                                       |
| `getClassification(features)`        | O veredito do classificador para as características de `getFeatures`                   |
| `getFeatures(mail)`                  | `{features, words, language, script, links}` para uma mensagem já interpretada         |
| `getTokens(text, locale)`            | As palavras de um texto                                                                |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                             |
| `parse(source)`                      | `{raw, mail}`, com `mail` vindo do mailparser                                          |

O `scanner.metrics` guarda `totalScans`, `averageTime` e `lastScanTime`.


## O resultado

```js
{
  isSpam: true,
  score: 16.25,
  threshold: 5,
  rejectThreshold: 15,
  action: 'reject',                       // 'accept', 'tag' or 'reject'
  message: 'Spam (BAYES_999, PHISHING_LOOKALIKE_DOMAIN, DECEPTIVE_LINK, FROM_NAME_BRAND)',
  tests: [
    {name: 'BAYES_999', score: 6.25, description: 'Classifier spam probability 99.9%'},
    {name: 'PHISHING_LOOKALIKE_DOMAIN', score: 5, description: '"paypa1-secure.top" imitates paypal by swapping characters'},
    // ...
  ],
  results: {
    classification: {probability, category, spam, ham, clues, coverage},
    phishing: [],        // lookalike domains, deceptive links, Cloudflare and URIBL findings
    attachments: [],     // every attachment finding
    executables: [],     // the executable findings among them
    macros: [],          // macros, active PDFs, RTF objects
    viruses: [],         // ClamAV findings: {filename, virus: [names], message}
    arbitrary: [],       // rules strong enough to mark spam alone
    obfuscation: {invisible, mixed, styled},
    authentication: null, // mailauth's results with a score, when checked
    reputation: null,
    dnsbl: [],           // {zone, value} for each listing
    language: {language, script, notAllowed},
    llm: null,           // the language model's verdict, when asked
    toxicity: [],
    nsfw: [],
    idnHomographAttack: {detected, domains, riskScore},
  },
  links: ['http://paypa1-secure.top/login'],
  language: 'en',
  tokens: ['dear', 'customer', /* ... */],
  mail: {/* the parsed message, from mailparser */},
  version: '7.0.0',
  metrics: {totalTime: 42},
}
```

Os achados em `phishing`, `attachments`, `executables`, `macros`, `viruses` e `arbitrary` são objetos com um `type` e uma `message`. `String(finding)` é a mensagem.


## Exportações

```js
import SpamScanner, {
  Classifier, getFeatures, segmentWords, detectLanguage,
  LLMClassifier, PROVIDERS, RECOMMENDED_MODELS, CLASSIFIER_MODELS,
  DEFAULT_SCORES, scoreResults, spamHeaders, rewriteMessage,
  loadModel, saveModel, defaultModelPath, loadDefaultModel,
  train, evaluate, readExamples,
  MilterServer, createHttpServer, createTcpServer, createSpamdServer,
  DEFAULTS, VERSION,
} from 'spamscanner';

import ArfParser from 'spamscanner/arf';
```

### Classificador

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| Opção                                  | Padrão         | Significado                                                                       |
| -------------------------------------- | -------------- | --------------------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`  | Os s e x de Robinson: com que força as características raras são puxadas para 0,5 |
| `minDistance`                          | `0.1`          | Características mais perto de 0,5 do que isso são ignoradas                       |
| `maxClues`                             | `150`          | Características mais fortes combinadas por mensagem                               |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | Limites da faixa `unsure`                                                         |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Mensagens de cada classe necessárias em um idioma para a confiança total          |
| `languagePrior`                        | `true`         | Avaliar as palavras com base nas contagens do próprio idioma                      |

`merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` e `entries()` também estão disponíveis.

### Treinamento

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

O `evaluate(classifier, examples)` recebe itens `{label, features}`, ou `readExamples(sources)`, que lê as mesmas fontes que o `train`, e retorna as contagens, a precisão, a revocação, o F1, a acurácia e as taxas de falsos positivos, falsos negativos e incertos.

### Servidores

```js
import SpamScanner, {MilterServer, createHttpServer, createSpamdServer} from 'spamscanner';

const scanner = new SpamScanner({authentication: true});
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

### Relatórios ARF

O `spamscanner/arf` lê e escreve relatórios de feedback de abuso (RFC 5965), o formato que os provedores de caixas de e-mail usam para relatar reclamações de spam:

```js
import ArfParser from 'spamscanner/arf';

const report = await ArfParser.parse(rawReport);
console.log(report.feedbackType, report.sourceIp, report.originalHeaders.subject);

const raw = ArfParser.create({
  feedbackType: 'abuse', userAgent: 'MyService/1.0',
  from: 'abuse@example.com', to: 'fbl@example.net',
  originalMessage, sourceIp: '192.0.2.1',
});
```

O `ArfParser.tryParse()` retorna `null` em vez de lançar um erro para mensagens que não são relatórios, e o `isArfMessage(mail)` verifica uma mensagem já interpretada.
