<!-- source: c93fa1a3f9c7 -->

<!--
label: Preguntas frecuentes
title: Preguntas frecuentes
description: Respuestas sobre Spam Scanner: su precisión, qué idiomas admite, qué envía por la red, modelos de lenguaje, SpamAssassin y Forward Email.
keywords: preguntas frecuentes Spam Scanner, preguntas sobre filtros de spam, precisión de un filtro de spam, privacidad de un filtro de spam
-->

# Preguntas frecuentes


## ¿Qué es Spam Scanner?

Un filtro de spam para Node.js, la línea de comandos y servidores de correo. Lee un mensaje de correo electrónico sin procesar y decide si es spam, phishing, una estafa o si contiene malware, con una puntuación y la lista de pruebas que lo decidieron. Funciona como biblioteca, como milter para Postfix y Sendmail, como servidor spamd compatible con SpamAssassin, como filtro de contenido de Postfix, como API HTTP o como servidor TCP.


## ¿Es gratuito?

Su [licencia](https://github.com/spamscanner/spamscanner/blob/master/LICENSE), la Business Source License 1.1, permite cualquier uso excepto ofrecer a terceros la detección de spam como servicio, e indica la fecha en la que pasa a ser la Apache License 2.0.


## ¿Qué precisión tiene?

Con mensajes en inglés reservados de sus datos de entrenamiento, el clasificador incluido, por sí solo, no marcó ningún ham como spam y detectó el 97 % del spam; las cifras completas por idioma están en la [guía de entrenamiento](../../docs/training.md#the-bundled-model). Los enlaces, los adjuntos, la autenticación, las listas de bloqueo y un modelo de lenguaje suman a eso. Tu propio correo es la prueba real: `spamscanner eval` mide cualquier modelo con cualquier correo etiquetado.


## ¿Qué idiomas admite?

Todos. Segmenta las palabras con las reglas de Unicode, incluidos el chino, el japonés y el tailandés, que no usan espacios. Cuando el modelo incluido ha visto poco correo en un idioma, se queda en «dudoso» en lugar de marcarlo, y decide un modelo de lenguaje o tu propio entrenamiento. [Idiomas](../../docs/languages.md)


## ¿Envía mi correo a algún sitio?

No. De forma predeterminada consulta los nombres de host de los enlaces en los resolutores DNS de filtrado de Cloudflare, y nada más sale de la máquina. La autenticación, las listas de bloqueo, los modelos de lenguaje y los servicios de reputación están desactivados hasta que se configuran, y los datos personales se eliminan antes de que el correo vaya a un modelo de lenguaje alojado. [Seguridad y privacidad](../../docs/security.md)


## ¿Necesito un modelo de lenguaje?

No. Es una segunda opinión para los casos dudosos. Sin uno, esos mensajes se deciden solo por su puntuación.


## ¿Qué modelo de lenguaje debo usar?

`qwen3.5:4b` a través de Ollama en una CPU, o `qwen3.5:9b` con una GPU. Ambos tienen licencia Apache y leen 201 idiomas. Los modelos alojados de Anthropic, OpenAI, Google y otros también funcionan. [Modelos recomendados](../../docs/llm.md#recommended-open-models)


## ¿Puede sustituir a SpamAssassin?

En la mayoría de las instalaciones, sí: habla el protocolo de spamd, así que spamc, Exim y Haraka funcionan sin cambios, y escribe los mismos encabezados `X-Spam-*`. No ejecuta los archivos de reglas de SpamAssassin. [Alternativa a SpamAssassin](/spamassassin-alternative/)


## ¿Rechazará correo legítimo?

El rechazo de correo está desactivado de forma predeterminada: el milter solo marca. Con `--reject`, solo se rechazan los mensajes con 15 puntos o más, con un error temporal 451, así que los remitentes vuelven a intentarlo y un error se puede corregir cambiando una opción. El filtro de contenido nunca rechaza durante la sesión SMTP.


## ¿Cómo lo entreno con mi correo?

`spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out model.json`, y después `--model model.json`. Funcionan los archivos mbox, los Maildirs, las carpetas de archivos `.eml` y los conjuntos de datos CSV o JSON Lines. [Entrenamiento](../../docs/training.md)


## ¿Funciona sin Node.js?

Sí: los binarios independientes para Linux, macOS y Windows incluyen Node.js y el modelo. `curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash`.


## ¿Quién lo desarrolla?

[Forward Email](https://forwardemail.net), para sus propios servidores de correo.
