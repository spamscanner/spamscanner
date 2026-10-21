<!-- source: e15795fd8287 -->

# Referência da API

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Crie um único scanner e reutilize-o: ele carrega o modelo uma vez e mantém em cache as respostas DNS e as do modelo de linguagem.

As declarações de tipos estão incluídas. Elas exigem TypeScript 4.7 ou posterior com `import`, e 5.3 ou posterior com `require`.


## Opções

Todas as opções podem ser passadas ao construtor. A maioria também pode ser passada ao `scan()` para uma única mensagem, e elas se sobrepõem às do construtor. Opções passadas como `undefined` mantêm o valor padrão. `classifier`, `classifierOptions`, `dns`, `phishing.homograph` e `strictIDNDetection` são lidas apenas pelo construtor; um arquivo ou objeto de modelo dado em `classifier` é lido ali, então um modelo ausente ou danificado lança um erro na hora.

| Opção                   | Padrão                           | Significado                                                                                                                                                                                           |
| ----------------------- | -------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Pontuação a partir da qual uma mensagem é spam                                                                                                                                                        |
| `rejectThreshold`       | `15`                             | Pontuação a partir da qual `action` é `reject`                                                                                                                                                        |
| `scores`                | `{}`                             | Pontos por teste: chaves de configuração ou nomes de testes ([testes e pontuações](scoring.md))                                                                                                       |
| `classifier`            | modelo incluído                  | Um `Classifier`, um objeto de modelo, o caminho de um arquivo de modelo ou `false`                                                                                                                    |
| `classifierOptions`     | `{}`                             | Opções para o modelo incluído (veja [Classificador](#classifier))                                                                                                                                     |
| `allowedLanguages`      | `[]`                             | Códigos ISO 639-1 (`no` é lido como `nb`, `fil` como `tl`, e os antigos `iw`, `in`, `ji` como `he`, `id`, `yi`); os outros idiomas recebem `LANGUAGE_NOT_ALLOWED`                                     |
| `phishing.cloudflare`   | `true`                           | Consultar os resolvedores com filtragem da Cloudflare sobre os hosts dos links                                                                                                                        |
| `phishing.adult`        | `true`                           | Consultar também o resolvedor familiar, que bloqueia sites adultos                                                                                                                                    |
| `phishing.maxHosts`     | `25`                             | Hosts de links consultados por mensagem                                                                                                                                                               |
| `phishing.maxLength`    | `1000000`                        | Caracteres do texto lidos em busca de links (o dobro no HTML); um texto mais longo define `results.linksTruncated`; `Infinity`, ou qualquer coisa que não seja um número positivo, significa o padrão |
| `phishing.homograph`    | `{}`                             | `brands` (substitui a lista embutida), `extraBrands`, `allowlist` (domínios nunca marcados), `strictMode`                                                                                             |
| `dnsbl`                 | `{ip: [], domain: []}`           | Zonas de listas de bloqueio no DNS para o IP do cliente e para os domínios dos links                                                                                                                  |
| `dns`                   | `{servers: null, timeout: 3000}` | Servidores de nomes para as verificações DNS (padrão: os do sistema)                                                                                                                                  |
| `attachments`           | `true`                           | Inspecionar os anexos                                                                                                                                                                                 |
| `macros`                | `true`                           | Marcar macros, PDFs ativos e objetos RTF                                                                                                                                                              |
| `arbitrary`             | `true`                           | Executar as [regras](scoring.md#rules)                                                                                                                                                                |
| `authentication`        | `false`                          | `true`, ou `{dnsServers, timeout, maxDnsQueries, mta, weights, trustedArcSealers}`: SPF, DKIM, DMARC, ARC ([pontuação](scoring.md#authentication))                                                    |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout, concurrency, cacheTtl, cacheSize}`; as respostas são guardadas por serviço e cabeçalhos, e `cacheSize` vale para o scanner inteiro                   |
| `allowlist`, `denylist` |                                  | Endereços IP, domínios ou endereços; atalho para `reputation` → [Lista de permissão e lista de bloqueio](#allowlist-and-denylist)                                                                     |
| `clamav`                | `false`                          | `true` (socket padrão), `{socket}` ou `{host, port}`, com `timeout`: milissegundos para todos os anexos de uma mensagem (`60000`)                                                                     |
| `llm`                   | `null`                           | [Configurações do modelo de linguagem](llm.md#any-server-port-and-authentication), com `mode`, `minScore`, `maxScore`                                                                                 |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: um modelo cujo `classify([text])` responde como o `@tensorflow-models/toxicity`                                                                                           |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: um modelo cujo `classify(imageBuffer)` responde como o `nsfwjs`                                                                                                           |
| `maxLength`             | `100000`                         | Caracteres do texto do corpo que são lidos                                                                                                                                                            |
| `timeout`               | `10000`                          | Milissegundos permitidos para cada verificação de rede; a autenticação e o modelo de imagens têm esse tempo no total (o ClamAV tem o próprio `clamav.timeout`)                                        |
| `session`               | `{}`                             | Detalhes padrão da sessão SMTP                                                                                                                                                                        |

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

Um servidor que já verificou SPF, DKIM, DMARC e ARC (com o [mailauth](https://github.com/postalsys/mailauth)) pode passar os resultados como `authenticationResults`, e eles são pontuados em vez de verificados de novo:

```js
import {authenticate} from 'mailauth';

const auth = await authenticate(raw, {ip, helo, sender, mta});
await scanner.scan(raw, {authenticationResults: auth});
```

### Lista de permissão e lista de bloqueio

A lista de bloqueio compara o endereço IP e o nome de host do cliente, os endereços From, do remetente do envelope e Reply-To, e seus domínios, sejam eles quais forem: um nome abaixo de um domínio da lista de bloqueio corresponde a ele mesmo que não seja um nome de host válido (como `a_b!.evil.example`, ou um com um rótulo de mais de 63 caracteres), pelos seus últimos 127 rótulos e 253 caracteres. A lista de permissão, e a lista de permissão e as fontes confiáveis de um serviço de reputação, comparam apenas o que um remetente não consegue falsificar: o endereço IP e o nome de host verificado do cliente (`remoteAddress`, `resolvedClientHostname`), um endereço From quando o DMARC passa para o seu domínio ou uma assinatura DKIM válida está alinhada com ele (e ele é um nome de host válido; no modo relaxado, como no DMARC: o domínio From e o domínio que assina ou o domínio do SPF têm o mesmo domínio registrável, que o mailauth indica como o domínio DMARC; uma entrada que indica um subdomínio, como `news.example.com`, só conta quando esse domínio, um abaixo dele ou um acima dele assinou a mensagem ou passou no SPF, não outro subdomínio como `evil.example.com`, nem um sufixo público; um DMARC aprovado para o domínio registrável sem os detalhes de alinhamento do mailauth só conta para uma entrada que indica o domínio registrável; com alinhamento estrito, `adkim=s` ou `aspf=s` no registro DMARC do domínio, com quaisquer maiúsculas ou espaços, só conta uma assinatura ou um SPF aprovado do próprio domínio From, e sem um deles o DMARC falha), e o remetente do envelope quando o SPF passa para o seu domínio. Uma assinatura DKIM só do início do corpo (um comprimento de corpo, `l=`, menor que o corpo: qualquer um pode acrescentar texto depois dele) não conta para nada, assim como um DMARC aprovado que se baseia nela, e nenhuma assinatura conta quando o DMARC falha, nem para um campo From longo demais para ser lido inteiro (`mail.from.truncated`). Os resultados passados em `authenticationResults` só contam quando indicam o domínio para o qual passaram, e um domínio que não é um nome de host (como `bank.example/x.attacker.example`, que os parsers de URL leem como `bank.example`) não conta para nenhum, assim como um DMARC aprovado que se baseia nele. Domínios internacionais correspondem em qualquer das formas: `bücher.example` ou `xn--bcher-kva.example`. Reply-To nunca conta. Para permitir um domínio, ative `authentication` ou passe `authenticationResults`.

Cada entrada é um endereço IP, um domínio ou um endereço de e-mail, comparado exatamente: uma entrada de domínio também abrange os seus subdomínios e os endereços neles, mas não há intervalos de endereços (`192.0.2.0/24`), curingas (`*.example.com`) nem padrões (`@example.com`). Endereços IPv6 correspondem em qualquer forma (`2001:0db8::0001` é `2001:db8::1`, a forma da RFC 5952), um endereço IPv4 mapeado em IPv6 (`::ffff:192.0.2.1`) corresponde ao endereço IPv4, e um endereço IPv4 traduzido para IPv6 ou sob o prefixo NAT64 é escrito com esse endereço IPv4 em notação de pontos (`::ffff:0:192.0.2.1`, `64:ff9b::192.0.2.1`), tanto nas entradas quanto nos endereços de clientes.


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
| `getFeatures(mail)`                  | `{features, words, language, script, links, hosts, text, hidden}` de uma mensagem      |
| `getTokens(text, locale)`            | As palavras de um texto                                                                |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                             |
| `parse(source)`                      | `{raw, mail, error}`, com `mail` vindo do mailparser (veja abaixo)                     |

`scan`, `parse`, `learn`, `unlearn` e `getTokensAndMailFromSource` leem todos uma mensagem da mesma forma: uma que excede os limites do parser MIME (mais de 1000 partes, o cabeçalho de uma parte acima de 1 MB) é lida até onde o parser permite. Os campos de endereço (From, To, Cc, Bcc, Sender, Reply-To, Delivered-To, Return-Path, Disposition-Notification-To e List-\*) da mensagem, de suas partes e das mensagens anexadas são lidos até 16 KB cada, 2000 vírgulas e pontos e vírgulas e 16 grupos aninhados, e 64 KB no total por mensagem, sempre até o fim de um endereço inteiro, de modo que nenhum endereço que o campo não traz é lido; um campo cortado é marcado como `truncated` (`mail.to.truncated`), e um campo From cortado não dá crédito pela autenticação do remetente. Um texto cuja primeira linha não é um campo de cabeçalho (`Name: value`, ou a linha `From` que inicia cada mensagem em arquivos mbox) é lido como o corpo de uma mensagem sem cabeçalho, então `mail.text` é esse texto. Outros erros são lançados. `parse` indica em `error` o limite do analisador que uma mensagem ultrapassa, tal como `scan` o indica em `parseError`, e null para uma mensagem lida por inteiro.

Em `getFeatures`, `text` é o texto que um cliente de e-mail mostra, do qual as palavras são lidas, e `hidden` é quantos caracteres de texto o HTML esconde. O mailparser não gera texto a partir do HTML aqui: `mail.text` contém apenas as partes de texto simples e fica vazio para uma mensagem só de HTML; o texto que o HTML dela mostra é `getFeatures(mail).text`.

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
    parseError: null,    // the MIME parser's limit the message, or one attached to it, exceeds, or why an attached message could not be read (MIME_TOO_COMPLEX)
    phishing: [],        // lookalike domains, deceptive links, Cloudflare and URIBL findings
    uncheckedHosts: 0,   // link hosts beyond phishing.maxHosts, not looked up
    timedOutHosts: 0,    // link hosts looked up but not answered (in time, or at all)
    linksTruncated: false, // more text than phishing.maxLength, whose links were not read
    attachments: [],     // every attachment finding
    executables: [],     // the executable findings among them
    macros: [],          // macros, active PDFs, RTF objects
    viruses: [],         // ClamAV findings: {filename, virus: [names], message}
    virusScanErrors: [], // attachments ClamAV could not scan: {filename, error}
    virusScanSkipped: [], // attachments larger than clamd accepts, not scanned: {filename, reason}
    unopenedAttachments: [], // attached messages not opened, past the limits they are read within: {filename, reason}
    arbitrary: [],       // rules strong enough to mark spam alone
    obfuscation: {invisible, mixed, styled},
    authentication: null, // mailauth's results with a score, when checked
    reputation: null,
    dnsbl: [],           // {zone, value, answers} for each listing
    language: {language, script, notAllowed},
    llm: null,           // the language model's verdict, when asked
    toxicity: [],
    nsfw: [],
    idnHomographAttack: {detected, domains, riskScore},
  },
  links: ['http://paypa1-secure.top/login'], // the links checked, of the whole message up to phishing.maxLength
  language: 'en',
  tokens: ['dear', 'customer', /* ... */],
  mail: {/* the parsed message, from mailparser; mail.text: the plain text parts only */},
  version: VERSION,      // this package's version
  metrics: {totalTime: 42},
}
```

Os achados em `phishing`, `attachments`, `executables`, `macros`, `viruses` e `arbitrary` são objetos com um `type` e uma `message`. `String(finding)` é a mensagem. Os anexos de uma mensagem anexada (`message/rfc822`, `.eml`) recebem o nome dela: `fw.eml/invoice.exe`. Um vírus que o ClamAV encontra em um anexo assim é relatado só para ele, não de novo para a mensagem anexada que o contém. `virusScanErrors` lista os anexos que o ClamAV não conseguiu verificar, como `{filename, error}`: uma mensagem assim pode conter um vírus, então retenha-a em vez de entregá-la. O milter e o filtro de conteúdo adiam uma mensagem assim, a menos que `onError` (`--on-error`) seja `accept`, e todos os servidores marcam com `X-Spam-Virus-Scan: failed` uma mensagem assim que repassam. `virusScanSkipped` lista os maiores do que o clamd aceita (o seu `StreamMaxLength`), como `{filename, reason}`: o clamd os recusa a cada tentativa, então, assim como o clamav-milter ignora um arquivo acima do seu `MaxFileSize`, eles não são falhas. Os outros limites dele (`MaxScanSize`, `MaxFiles`, `MaxRecursion`, `MaxScanTime`), que uma bomba de arquivo compactado atinge, são falhas. As mensagens anexadas são abertas até três níveis, com no máximo 100 anexos dentro delas e 25 MB no total; `unopenedAttachments` lista as que não foram abertas por ultrapassarem estes limites, como `{filename, reason}`, cujos anexos não foram inspecionados. Não conta para a pontuação, pois mensagens encaminhadas podem estar aninhadas assim, mas quem precisar de uma mensagem lida por inteiro, por exemplo para bloquear um programa que ela traga, pode recusar uma que tenha alguma.

Cada item de `dnsbl` traz as `answers` da lista (endereços em 127.0.0.0/8, cujo significado cada lista documenta). As respostas que as listas dão a consultas que recusam ou não conseguem responder não são listagens, seja para o endereço do cliente ou para domínios de links (achados `uribl` em `phishing`): 127.255.255.x no Spamhaus (como 127.255.255.254 para uma consulta por um resolvedor público, e 127.255.255.255 para consultas demais), 127.0.1.255 no Spamhaus DBL, 127.0.0.255 em qualquer lista, e 127.0.0.1 no SURBL e no URIBL, que dão essa resposta aos resolvedores que bloqueiam.


## Exportações

```js
import SpamScanner, {
  Classifier, getFeatures, segmentWords, unwrapLink, detectLanguage,
  LLMClassifier, PROVIDERS, RECOMMENDED_MODELS, CLASSIFIER_MODELS, DECISION_MODELS,
  DEFAULT_SCORES, scoreResults, spamHeaders, rewriteMessage,
  loadModel, saveModel, defaultModelPath, loadDefaultModel,
  train, evaluate, readExamples,
  MilterServer, createHttpServer, createTcpServer, createSpamdServer,
  DEFAULTS, VERSION,
} from 'spamscanner';
import {SpamScanner} from 'spamscanner'; // the same class, as a named export
// unwrapLink(address): the URL a link goes to, through Safe Links and
// Proofpoint URL Defense, as the scanner reads it (null for no URL)

import ArfParser from 'spamscanner/arf';
```

### Classificador

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| Opção                                  | Padrão         | Significado                                                                                                                                                       |
| -------------------------------------- | -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`  | Os s e x de Robinson: com que força as características raras são puxadas para 0,5                                                                                 |
| `minDistance`                          | `0.1`          | Características mais perto de 0,5 do que isso são ignoradas                                                                                                       |
| `maxClues`                             | `150`          | Características mais fortes combinadas por mensagem                                                                                                               |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`  | Limites da faixa `unsure`                                                                                                                                         |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02` | Mensagens ham necessárias em um idioma para a confiança total, e um quinto disso em mensagens de spam; menos quando `languageShare` de todo o ham ou spam é menor |
| `languagePrior`                        | `true`         | Avaliar as palavras com base nas contagens do próprio idioma                                                                                                      |

`merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` e `entries()` também estão disponíveis. `Classifier.fromJSON` verifica o modelo e lança um `TypeError` que começa com `Corrupt classifier model` diante de dados danificados. O JSON não tem `Infinity`, então uma opção salva como `Infinity` pela versão 7.0.3 é lida de volta como `null`: ela é lida como `Infinity` para `maxClues`, `minDistance` e `minLanguageExamples`, como `-Infinity` para `hamCutoff` (nunca ham) e `Infinity` para `spamCutoff` (nunca spam), e como o valor padrão para as demais. `toJSON` salva um limite fora de 0 e 1 como -1 ou 2, o que funciona da mesma forma. `loadModel` lê um arquivo de novo quando ele muda, e `saveModel` grava por meio de um novo arquivo temporário, gravado em disco antes de substituir o modelo, que mantém suas permissões.

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
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]', onError: 'tempfail'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

O `onError` do milter é a resposta dele quando uma análise falha ou o ClamAV não conseguiu verificar um anexo: `'tempfail'` (o padrão) ou `'accept'`, que repassa a mensagem marcada com `X-Spam-Virus-Scan: failed`, sem os cabeçalhos `X-Spam-*` que o remetente adicionou.

### Relatórios ARF

O `spamscanner/arf` lê e escreve relatórios de feedback de abuso (RFC 5965), o formato que os provedores de caixas de e-mail usam para relatar reclamações de spam:

```js
import ArfParser from 'spamscanner/arf';

const report = await ArfParser.parse(rawReport);
console.log(report.feedbackType, report.sourceIp, report.originalHeaders?.subject);

const raw = ArfParser.create({
  feedbackType: 'abuse', userAgent: 'MyService/1.0',
  from: 'abuse@example.com', to: 'fbl@example.net',
  originalMessage, sourceIp: '192.0.2.1',
});
```

O `parse()` aceita um Buffer, Uint8Array ou string. O `ArfParser.tryParse()` retorna `null` em vez de lançar um erro para mensagens que não são relatórios, e o `isArfMessage(mail)` verifica uma mensagem já interpretada. O `originalHeaders` é `null` para um relatório sem a mensagem original. O `create()` retorna uma string, ou um `Buffer` quando o `originalMessage` também é um, para que seus bytes sejam preservados qualquer que seja o conjunto de caracteres.
