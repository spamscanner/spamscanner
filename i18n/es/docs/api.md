<!-- source: b3cc9f949acd -->

# Referencia de la API

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Crea un solo analizador y reutilízalo: carga el modelo una vez y guarda en caché las respuestas de DNS y del modelo de lenguaje.


## Opciones

Todas las opciones se pueden pasar al constructor. La mayoría también se pueden pasar a `scan()` para un solo mensaje, y se combinan sobre las del constructor.

| Opción                  | Valor predeterminado             | Significado                                                                                                           |
| ----------------------- | -------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Puntuación a partir de la cual un mensaje es spam                                                                     |
| `rejectThreshold`       | `15`                             | Puntuación a partir de la cual `action` es `reject`                                                                   |
| `scores`                | `{}`                             | Puntos por prueba: claves de configuración o nombres de prueba ([pruebas y puntuaciones](scoring.md))                 |
| `classifier`            | modelo incluido                  | Un `Classifier`, un objeto de modelo, la ruta de un archivo de modelo o `false`                                       |
| `classifierOptions`     | `{}`                             | Opciones para el modelo incluido (consulta [Classifier](#classifier))                                                 |
| `allowedLanguages`      | `[]`                             | Códigos ISO 639-1; los demás idiomas reciben `LANGUAGE_NOT_ALLOWED`                                                   |
| `phishing.cloudflare`   | `true`                           | Consultar a los resolutores de filtrado de Cloudflare por los hosts de los enlaces                                    |
| `phishing.adult`        | `true`                           | Consultar también al resolutor familiar, que bloquea los sitios para adultos                                          |
| `phishing.maxHosts`     | `25`                             | Hosts de enlaces consultados por mensaje                                                                              |
| `phishing.homograph`    | `{}`                             | `brands` (sustituye la lista incorporada), `extraBrands`, `allowlist` (dominios que nunca se marcan), `strictMode`    |
| `dnsbl`                 | `{ip: [], domain: []}`           | Zonas de listas de bloqueo DNS para la IP del cliente y para los dominios de los enlaces                              |
| `dns`                   | `{servers: null, timeout: 3000}` | Servidores de nombres para las comprobaciones DNS (predeterminado: los del sistema)                                   |
| `attachments`           | `true`                           | Inspeccionar los adjuntos                                                                                             |
| `macros`                | `true`                           | Marcar macros, PDF activos y objetos RTF                                                                              |
| `arbitrary`             | `true`                           | Ejecutar las [reglas](scoring.md#rules)                                                                               |
| `authentication`        | `false`                          | `true`, o `{dnsServers, timeout, mta, weights}`: SPF, DKIM, DMARC, ARC                                                |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout}`                                                                     |
| `allowlist`, `denylist` |                                  | Direcciones IP, dominios o direcciones; forma abreviada de `reputation`                                               |
| `clamav`                | `false`                          | `true` (socket predeterminado), `{socket}` o `{host, port}`                                                           |
| `llm`                   | `null`                           | [Configuración del modelo de lenguaje](llm.md#any-server-port-and-authentication), con `mode`, `minScore`, `maxScore` |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: un modelo cuyo `classify([text])` responde como `@tensorflow-models/toxicity`             |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: un modelo cuyo `classify(imageBuffer)` responde como `nsfwjs`                             |
| `maxLength`             | `100000`                         | Caracteres del texto del cuerpo que se leen                                                                           |
| `timeout`               | `10000`                          | Milisegundos permitidos para cada comprobación de red                                                                 |
| `session`               | `{}`                             | Datos predeterminados de la sesión SMTP                                                                               |

`scan()` también recibe `session`:

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

| Método                               | Devuelve                                                                                 |
| ------------------------------------ | ---------------------------------------------------------------------------------------- |
| `scan(source, options)`              | El resultado. `source` es un Buffer, una cadena, un Uint8Array o un flujo legible        |
| `scanFile(path, options)`            | El resultado para un archivo de mensaje                                                  |
| `learn(source, 'spam' \| 'ham')`     | Enseña un mensaje al clasificador                                                        |
| `unlearn(source, 'spam' \| 'ham')`   | Deshace `learn`                                                                          |
| `saveModel(path, options)`           | Escribe el clasificador en un archivo (`options`: `minCount`, `maxFeatures`, `metadata`) |
| `getClassifier()`                    | El `Classifier` en uso, o `null`                                                         |
| `getClassification(features)`        | El veredicto del clasificador para las características de `getFeatures`                  |
| `getFeatures(mail)`                  | `{features, words, language, script, links}` para un mensaje procesado                   |
| `getTokens(text, locale)`            | Las palabras de un texto                                                                 |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                               |
| `parse(source)`                      | `{raw, mail}`, con `mail` de mailparser                                                  |

`scanner.metrics` contiene `totalScans`, `averageTime` y `lastScanTime`.


## El resultado

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

Los hallazgos de `phishing`, `attachments`, `executables`, `macros`, `viruses` y `arbitrary` son objetos con un `type` y un `message`. `String(finding)` es el mensaje.


## Exportaciones

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

### Classifier

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| Opción                                 | Valor predeterminado | Significado                                                                            |
| -------------------------------------- | -------------------- | -------------------------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`        | s y x de Robinson: con qué fuerza se acercan a 0.5 las características poco frecuentes |
| `minDistance`                          | `0.1`                | Se ignoran las características más cercanas a 0.5 que este valor                       |
| `maxClues`                             | `150`                | Características más fuertes que se combinan por mensaje                                |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`        | Límites del rango `unsure`                                                             |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02`       | Mensajes de cada clase necesarios en un idioma para la confianza plena                 |
| `languagePrior`                        | `true`               | Ponderar las palabras con los recuentos de su propio idioma                            |

También están disponibles `merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` y `entries()`.

### Entrenamiento

```js
import {train, evaluate, saveModel} from 'spamscanner';

const {classifier, spam, ham} = await train({
  spam: ['/mail/Junk'],
  ham: ['/mail/Archive', '/mail/archive.mbox'],
  datasets: [{file: 'extra.csv', textColumn: 'body', labelColumn: 'kind'}],
});
saveModel(classifier, 'model.json');
```

`evaluate(classifier, examples)` recibe elementos `{label, features}`, o `readExamples(sources)`, que lee las mismas fuentes que `train`, y devuelve recuentos, precisión, exhaustividad, F1, exactitud y las tasas de falsos positivos, falsos negativos y dudosos.

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

### Informes ARF

`spamscanner/arf` lee y escribe informes de abuso (RFC 5965), el formato que usan los proveedores de buzones para informar de quejas por spam:

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

`ArfParser.tryParse()` devuelve `null` en lugar de lanzar una excepción para los mensajes que no son informes, y `isArfMessage(mail)` comprueba un mensaje procesado.
