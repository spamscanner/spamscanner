<!-- source: 9134d1cd102c -->

# Referencia de la API

```js
import SpamScanner from 'spamscanner';             // ESM
const SpamScanner = require('spamscanner');        // CommonJS

const scanner = new SpamScanner(options);
const result = await scanner.scan(rawMessage, scanOptions);
```

Crea un solo analizador y reutilízalo: carga el modelo una vez y guarda en caché las respuestas de DNS y del modelo de lenguaje.

Se incluyen declaraciones de tipos. Necesitan TypeScript 4.7 o posterior con `import`, y 5.3 o posterior con `require`.


## Opciones

Todas las opciones se pueden pasar al constructor. La mayoría también se pueden pasar a `scan()` para un solo mensaje, y se combinan sobre las del constructor. Las opciones pasadas como `undefined` conservan su valor predeterminado. `classifier`, `classifierOptions`, `dns`, `phishing.homograph` y `strictIDNDetection` solo los lee el constructor; un archivo u objeto de modelo dado como `classifier` se lee allí, así que un modelo ausente o dañado lanza un error de inmediato.

| Opción                  | Valor predeterminado             | Significado                                                                                                                                                                                                           |
| ----------------------- | -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `threshold`             | `5`                              | Puntuación a partir de la cual un mensaje es spam                                                                                                                                                                     |
| `rejectThreshold`       | `15`                             | Puntuación a partir de la cual `action` es `reject`                                                                                                                                                                   |
| `scores`                | `{}`                             | Puntos por prueba: claves de configuración o nombres de prueba ([pruebas y puntuaciones](scoring.md))                                                                                                                 |
| `classifier`            | modelo incluido                  | Un `Classifier`, un objeto de modelo, la ruta de un archivo de modelo o `false`                                                                                                                                       |
| `classifierOptions`     | `{}`                             | Opciones para el modelo incluido (consulta [Classifier](#classifier))                                                                                                                                                 |
| `allowedLanguages`      | `[]`                             | Códigos ISO 639-1 (`no` se lee como `nb`, `fil` como `tl`, y los antiguos `iw`, `in`, `ji` como `he`, `id`, `yi`); los demás idiomas reciben `LANGUAGE_NOT_ALLOWED`                                                   |
| `phishing.cloudflare`   | `true`                           | Consultar a los resolutores de filtrado de Cloudflare por los hosts de los enlaces                                                                                                                                    |
| `phishing.adult`        | `true`                           | Consultar también al resolutor familiar, que bloquea los sitios para adultos                                                                                                                                          |
| `phishing.maxHosts`     | `25`                             | Hosts de enlaces consultados por mensaje                                                                                                                                                                              |
| `phishing.maxLength`    | `1000000`                        | Caracteres del texto leídos en busca de enlaces (el doble en HTML); un texto más largo activa `results.linksTruncated`; `Infinity`, o cualquier cosa que no sea un número positivo, significa el valor predeterminado |
| `phishing.homograph`    | `{}`                             | `brands` (sustituye la lista incorporada), `extraBrands`, `allowlist` (dominios que nunca se marcan), `strictMode`                                                                                                    |
| `dnsbl`                 | `{ip: [], domain: []}`           | Zonas de listas de bloqueo DNS para la IP del cliente y para los dominios de los enlaces                                                                                                                              |
| `dns`                   | `{servers: null, timeout: 3000}` | Servidores de nombres para las comprobaciones DNS (predeterminado: los del sistema)                                                                                                                                   |
| `attachments`           | `true`                           | Inspeccionar los adjuntos                                                                                                                                                                                             |
| `macros`                | `true`                           | Marcar macros, PDF activos y objetos RTF                                                                                                                                                                              |
| `arbitrary`             | `true`                           | Ejecutar las [reglas](scoring.md#rules)                                                                                                                                                                               |
| `authentication`        | `false`                          | `true`, o `{dnsServers, timeout, maxDnsQueries, mta, weights, trustedArcSealers}`: SPF, DKIM, DMARC, ARC ([puntuación](scoring.md#authentication))                                                                    |
| `reputation`            | `false`                          | `{allowlist, denylist, apiUrl, headers, timeout, concurrency, cacheTtl, cacheSize}`; las respuestas se guardan por servicio y cabeceras, y `cacheSize` se aplica a todo el escáner                                    |
| `allowlist`, `denylist` |                                  | Direcciones IP, dominios o direcciones; forma abreviada de `reputation` → [Lista de permitidos y lista de bloqueo](#allowlist-and-denylist)                                                                           |
| `clamav`                | `false`                          | `true` (socket predeterminado), `{socket}` o `{host, port}`, con `timeout`: milisegundos para todos los adjuntos de un mensaje (`60000`)                                                                              |
| `llm`                   | `null`                           | [Configuración del modelo de lenguaje](llm.md#any-server-port-and-authentication), con `mode`, `minScore`, `maxScore`                                                                                                 |
| `toxicity`              | `false`                          | `{model, threshold = 0.7}`: un modelo cuyo `classify([text])` responde como `@tensorflow-models/toxicity`                                                                                                             |
| `nsfw`                  | `false`                          | `{model, threshold = 0.6}`: un modelo cuyo `classify(imageBuffer)` responde como `nsfwjs`                                                                                                                             |
| `maxLength`             | `100000`                         | Caracteres del texto del cuerpo que se leen                                                                                                                                                                           |
| `timeout`               | `10000`                          | Milisegundos permitidos para cada comprobación de red; la autenticación y el modelo de imágenes disponen de ese tiempo en total (ClamAV tiene su propio `clamav.timeout`)                                             |
| `session`               | `{}`                             | Datos predeterminados de la sesión SMTP                                                                                                                                                                               |

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

Un servidor que ya ha comprobado SPF, DKIM, DMARC y ARC (con [mailauth](https://github.com/postalsys/mailauth)) puede pasar sus resultados como `authenticationResults`, y se puntúan en lugar de comprobarse de nuevo:

```js
import {authenticate} from 'mailauth';

const auth = await authenticate(raw, {ip, helo, sender, mta});
await scanner.scan(raw, {authenticationResults: auth});
```

### Lista de permitidos y lista de bloqueo

La lista de bloqueo compara la dirección IP y el nombre de host del cliente, las direcciones From, del remitente del sobre y Reply-To, y sus dominios, sean cuales sean: un nombre bajo un dominio de la lista de bloqueo coincide con él aunque no sea un nombre de host válido (como `a_b!.evil.example`, o uno con una etiqueta de más de 63 caracteres), por sus últimas 127 etiquetas y 253 caracteres. La lista de permitidos, y la lista de permitidos y las fuentes de confianza de un servicio de reputación, solo comparan lo que un remitente no puede falsificar: la dirección IP y el nombre de host verificado del cliente (`remoteAddress`, `resolvedClientHostname`), una dirección From cuando DMARC aprueba su dominio o una firma DKIM válida está alineada con ella (y su dominio es un nombre de host válido; de forma relajada, como en DMARC: el dominio de From y el dominio firmante o de SPF tienen el mismo dominio registrable, que mailauth nombra como dominio DMARC; una entrada que nombra un subdominio, como `news.example.com`, solo cuenta cuando ese dominio, uno por debajo de él o uno por encima de él firmó el mensaje o aprobó SPF, no otro subdominio como `evil.example.com`, ni un sufijo público; una aprobación de DMARC para el dominio registrable sin los detalles de alineación de mailauth solo cuenta para una entrada que nombra el dominio registrable; con alineación estricta, `adkim=s` o `aspf=s` en el registro DMARC del dominio con cualquier combinación de mayúsculas y minúsculas o de espacios, solo cuenta una firma o una aprobación de SPF del propio dominio de From, y DMARC falla sin ella), y el remitente del sobre cuando SPF aprueba su dominio. Una firma DKIM solo del comienzo del cuerpo (una longitud de cuerpo, `l=`, más corta que el cuerpo: cualquiera puede añadir texto después) no cuenta para nada, como tampoco una aprobación de DMARC que se base en ella, y ninguna firma cuenta cuando DMARC falla, ni para un campo From demasiado largo para leerse entero (`mail.from.truncated`). Los resultados pasados en `authenticationResults` solo cuentan cuando nombran el dominio para el que se aprobaron, y un dominio que no es un nombre de host (como `bank.example/x.attacker.example`, que los analizadores de URL leen como `bank.example`) no cuenta para ninguno, como tampoco una aprobación de DMARC que se base en uno. Los dominios internacionales coinciden en cualquiera de sus formas: `bücher.example` o `xn--bcher-kva.example`. Reply-To nunca cuenta. Para permitir un dominio, active `authentication` o pase `authenticationResults`.

Cada entrada es una dirección IP, un dominio o una dirección de correo electrónico, y se compara de forma exacta: una entrada de dominio cubre también sus subdominios y las direcciones en ellos, pero no hay rangos de direcciones (`192.0.2.0/24`), comodines (`*.example.com`) ni patrones (`@example.com`). Las direcciones IPv6 coinciden en cualquier forma (`2001:0db8::0001` es `2001:db8::1`, la forma del RFC 5952), una dirección IPv4 asignada en IPv6 (`::ffff:192.0.2.1`) coincide con la dirección IPv4, y una dirección IPv4 traducida a IPv6 o bajo el prefijo NAT64 se escribe con él en notación decimal con puntos (`::ffff:0:192.0.2.1`, `64:ff9b::192.0.2.1`), tanto en las entradas como en las direcciones de cliente.


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
| `getFeatures(mail)`                  | `{features, words, language, script, links, hosts, text, hidden}` de un mensaje          |
| `getTokens(text, locale)`            | Las palabras de un texto                                                                 |
| `getTokensAndMailFromSource(source)` | `{tokens, features, mail}`                                                               |
| `parse(source)`                      | `{raw, mail, error}`, con `mail` de mailparser (véase más abajo)                         |

`scan`, `parse`, `learn`, `unlearn` y `getTokensAndMailFromSource` leen todos un mensaje de la misma manera: uno que supera los límites del analizador MIME (más de 1000 partes, la cabecera de una parte de más de 1 MB) se lee hasta donde el analizador lo permite. Los campos de dirección (From, To, Cc, Bcc, Sender, Reply-To, Delivered-To, Return-Path, Disposition-Notification-To y List-\*), del mensaje, sus partes y los mensajes adjuntos, se leen hasta 16 KB cada uno, 2000 comas y puntos y comas y 16 grupos anidados, y 64 KB en total por mensaje, siempre hasta el final de una dirección completa, de modo que no se lee ninguna dirección que el campo no dé; un campo recortado se marca como `truncated` (`mail.to.truncated`), y un campo From recortado no da ningún crédito por la autenticación del remitente. Un texto cuya primera línea no es un campo de cabecera (`Name: value`, o la línea `From` con la que empieza cada mensaje en los archivos mbox) se lee como el cuerpo de un mensaje sin cabecera, así que `mail.text` es ese texto. Los demás errores se lanzan. `parse` indica en `error` el límite del analizador que supera un mensaje, igual que `scan` lo indica en `parseError`, y null para un mensaje leído entero.

En `getFeatures`, `text` es el texto que muestra un cliente de correo, del que se leen las palabras, y `hidden`, cuántos caracteres de texto oculta el HTML. Aquí mailparser no extrae texto del HTML: `mail.text` contiene solo las partes de texto plano, y está vacío en un mensaje solo de HTML; el texto que muestra su HTML es `getFeatures(mail).text`.

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

Los hallazgos de `phishing`, `attachments`, `executables`, `macros`, `viruses` y `arbitrary` son objetos con un `type` y un `message`. `String(finding)` es el mensaje. Los adjuntos de un mensaje adjunto (`message/rfc822`, `message/global`, `.eml`, `.u8msg`) reciben su nombre: `fw.eml/invoice.exe`. Un virus que ClamAV encuentra en un adjunto así se notifica solo para él, no de nuevo para el mensaje adjunto que lo contiene. `virusScanErrors` enumera los adjuntos que ClamAV no pudo analizar, como `{filename, error}`: ese mensaje puede contener un virus, así que reténgalo en lugar de entregarlo. El milter y el filtro de contenido lo aplazan salvo que `onError` (`--on-error`) sea `accept`, y todos los servidores marcan ese mensaje, si lo dejan pasar, con `X-Spam-Virus-Scan: failed`. `virusScanSkipped` enumera los que son más grandes de lo que acepta clamd (su `StreamMaxLength`), como `{filename, reason}`: clamd los rechaza en cada intento, así que, igual que clamav-milter omite un archivo que supera su `MaxFileSize`, no son fallos. Sus otros límites (`MaxScanSize`, `MaxFiles`, `MaxRecursion`, `MaxScanTime`), que alcanza una bomba de archivo comprimido, sí son fallos. Los mensajes adjuntos se abren hasta tres niveles, con un máximo de 100 adjuntos dentro y 25 MB en total; `unopenedAttachments` enumera los que no se abrieron por superar estos límites, como `{filename, reason}`, cuyos adjuntos no se inspeccionaron. No puntúa, ya que los mensajes reenviados pueden anidarse así, pero quien necesite un mensaje leído entero, por ejemplo para bloquear un programa que lleve, puede rechazar uno que tenga alguno. Se abren como máximo 100 mensajes adjuntos en total.

Cada elemento de `dnsbl` lleva las `answers` de la lista (direcciones en 127.0.0.0/8, cuyo significado documenta cada lista). Las respuestas que dan las listas a las consultas que rechazan o no pueden responder no son listados, ni para la dirección del cliente ni para los dominios de los enlaces (hallazgos `uribl` en `phishing`): 127.255.255.x en Spamhaus (como 127.255.255.254 para una consulta a través de un resolvedor público, y 127.255.255.255 por demasiadas consultas), 127.0.1.255 en la DBL de Spamhaus, 127.0.0.255 en cualquier lista, y 127.0.0.1 en SURBL y URIBL, que la responden a los resolvedores que bloquean.


## Exportaciones

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

### Classifier

```js
const classifier = new Classifier({spamCutoff: 0.99, hamCutoff: 0.2});
classifier.learn(getFeatures(mail).features, 'spam');
classifier.classify(features); // {probability, category, spam, ham, clues, coverage}
```

| Opción                                 | Valor predeterminado | Significado                                                                                                                                                       |
| -------------------------------------- | -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `strength`, `unknown`                  | `0.45`, `0.5`        | s y x de Robinson: con qué fuerza se acercan a 0.5 las características poco frecuentes                                                                            |
| `minDistance`                          | `0.1`                | Se ignoran las características más cercanas a 0.5 que este valor                                                                                                  |
| `maxClues`                             | `150`                | Características más fuertes que se combinan por mensaje                                                                                                           |
| `hamCutoff`, `spamCutoff`              | `0.2`, `0.99`        | Límites del rango `unsure`                                                                                                                                        |
| `minLanguageExamples`, `languageShare` | `1000`, `0.02`       | Mensajes ham necesarios en un idioma para la confianza plena, y una quinta parte de mensajes spam; menos cuando `languageShare` de todo el ham o el spam es menor |
| `languagePrior`                        | `true`               | Ponderar las palabras con los recuentos de su propio idioma                                                                                                       |

También están disponibles `merge(other)`, `toJSON(options)`, `Classifier.fromJSON(json)`, `size` y `entries()`. `Classifier.fromJSON` comprueba el modelo y lanza un `TypeError` que empieza por `Corrupt classifier model` ante datos dañados. JSON no tiene `Infinity`, así que una opción guardada como `Infinity` por la versión 7.0.3 se vuelve a leer como `null`: se lee como `Infinity` para `maxClues`, `minDistance` y `minLanguageExamples`, como `-Infinity` para `hamCutoff` (nunca ham) e `Infinity` para `spamCutoff` (nunca spam), y como el valor predeterminado para las demás. `toJSON` guarda un umbral más allá de 0 y 1 como -1 o 2, lo que funciona igual. `loadModel` vuelve a leer un archivo cuando cambia, y `saveModel` escribe a través de un archivo temporal nuevo, volcado al disco antes de sustituir el modelo, que conserva sus permisos.

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
const milter = new MilterServer(scanner, {reject: true, rejectCode: 451, subjectTag: '[SPAM]', onError: 'tempfail'});
milter.on('scan', ({session, result}) => console.log(session.remoteAddress, result.score));
await milter.listen(7831);

createHttpServer(scanner, {token: process.env.SPAMSCANNER_TOKEN}).listen(7832, '127.0.0.1');
createSpamdServer(scanner).listen(783, '127.0.0.1');
```

`onError` es la respuesta del milter cuando un análisis falla o ClamAV no pudo analizar un adjunto: `'tempfail'` (el valor predeterminado) o `'accept'`, que deja pasar el mensaje marcado con `X-Spam-Virus-Scan: failed`, sin las cabeceras `X-Spam-*` que añadió el remitente.

### Informes ARF

`spamscanner/arf` lee y escribe informes de abuso (RFC 5965), el formato que usan los proveedores de buzones para informar de quejas por spam:

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

`parse()` acepta un Buffer, un Uint8Array o una cadena. `ArfParser.tryParse()` devuelve `null` en lugar de lanzar una excepción para los mensajes que no son informes, y `isArfMessage(mail)` comprueba un mensaje procesado. `originalHeaders` es `null` en un informe sin el mensaje original. `create()` devuelve una cadena, o un `Buffer` cuando `originalMessage` lo es, para conservar sus bytes sea cual sea su juego de caracteres.
