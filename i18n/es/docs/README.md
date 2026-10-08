<!-- source: c56969e779c4 -->

# Documentación de Spam Scanner

Spam Scanner es un filtro de spam para Node.js y la línea de comandos, con su código fuente en GitHub. Lee un mensaje de correo electrónico sin procesar y decide si es spam, phishing, una estafa o si contiene malware, en cualquier idioma. Funciona como biblioteca, como herramienta de línea de comandos, como milter de Postfix o Sendmail, como filtro de contenido de Postfix, como servidor spamd compatible con SpamAssassin, como API HTTP o como servidor TCP.

Lo desarrolla [Forward Email](https://forwardemail.net) para sus propios servidores de correo.


## Cómo se evalúa un mensaje

Cada comprobación suma o resta puntos. El total decide el resultado:

| Puntuación  | Acción   | Qué hace un servidor de correo    |
| ----------- | -------- | --------------------------------- |
| Menos de 5  | `accept` | Entrega el mensaje                |
| De 5 a 14.9 | `tag`    | Lo entrega marcado como spam      |
| 15 o más    | `reject` | Lo rechaza durante la sesión SMTP |

Los dos umbrales se pueden cambiar. Cada resultado enumera las pruebas que se activaron, con sus puntos y un motivo, así que una decisión siempre se puede explicar.

Las comprobaciones:

* **Un clasificador entrenado** lee las palabras del mensaje en cualquier escritura, la forma de sus enlaces, su remitente y sus adjuntos. Viene entrenado con conjuntos de datos públicos y aprende de tu propio correo. [Cómo funciona el clasificador](how-it-works.md#the-classifier)
* **Las comprobaciones de phishing** detectan dominios parecidos (`paypa1.com`, `pаypal.com` con una а cirílica), enlaces cuyo texto muestra una dirección y cuyo destino es otra, y nombres visibles que dicen ser una marca. [Phishing](how-it-works.md#phishing)
* **Las comprobaciones de adjuntos** encuentran ejecutables, ejecutables renombrados como documentos, extensiones dobles, trucos de nombres de archivo de derecha a izquierda, ejecutables dentro de archivos ZIP, macros de Office y contenido PDF activo. ClamAV puede analizar los adjuntos en busca de virus. [Adjuntos](how-it-works.md#attachments)
* **Autenticación**: SPF, DKIM, DMARC y ARC, cuando se conoce la dirección IP del cliente. [Autenticación](how-it-works.md#authentication)
* **Listas de bloqueo DNS** para la dirección IP del cliente y los dominios de los enlaces, y los resolutores de filtrado de Cloudflare para malware y sitios para adultos conocidos. [Listas de bloqueo](how-it-works.md#blocklists)
* **Reglas** para patrones que ningún clasificador necesita aprender: la cadena de prueba GTUBE, asuntos de sextorsión, estafas con facturas de PayPal, autosuplantación e instrucciones ocultas para filtros de IA. [Reglas](scoring.md#rules)
* **Un modelo de lenguaje**, opcional, da una segunda opinión en los casos dudosos: un modelo local a través de Ollama o de cualquier servidor compatible con OpenAI, o Claude, ChatGPT, Gemini y otros. [Modelos de lenguaje](llm.md)


## Por dónde empezar

* [Primeros pasos](getting-started.md): instálalo y analiza un primer mensaje.
* [Línea de comandos](cli.md): todos los comandos y opciones.
* [Postfix y Sendmail](postfix.md): filtra un servidor de correo con el milter o con un filtro de contenido.
* [Otros servidores de correo](mail-servers.md): Exim, Haraka, Dovecot, procmail y cualquier cosa que pueda llamar a una API HTTP.
* [Entrenamiento](training.md): enséñale tu propio correo y mide el resultado.
* [Modelos de lenguaje](llm.md): proveedores, modelos abiertos recomendados, privacidad e inyección de instrucciones.
* [Idiomas](languages.md): cómo lee el chino, el árabe, el tailandés y cualquier otra escritura.
* [Forward Email](forward-email.md): cómo lo usa Forward Email y cómo actualizar desde la versión 5 o 6.
* [Referencia de la API](api.md) y [pruebas y puntuaciones](scoring.md).
* [Seguridad y privacidad](security.md): qué sale de la máquina y cómo evitarlo.
