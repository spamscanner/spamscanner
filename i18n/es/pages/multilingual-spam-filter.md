<!-- source: 0ad167ddd34e -->

<!--
label: Filtro de spam multilingüe
title: Filtro de spam multilingüe para chino, árabe, ruso y más
description: Cómo filtra Spam Scanner el spam en todos los idiomas: segmentación de palabras de Unicode, disfraces deshechos y sin marcar idiomas poco conocidos.
keywords: filtro de spam multilingüe, filtro de spam en chino, filtro de spam en árabe, filtro de spam en ruso, filtro de spam en japonés, detección de spam Unicode, spam con homoglifos
-->

# Filtro de spam multilingüe

Muchos filtros de spam se crearon para el inglés. El spam en otros idiomas se les escapa, y el correo normal en otros idiomas se marca por su escritura. Spam Scanner está hecho para evitar ambas cosas.


## Leer las palabras

Las palabras se encuentran con `Intl.Segmenter`, las reglas de límites de palabra de Unicode con diccionarios para chino, japonés, tailandés, lao, jemer y birmano. Una frase en chino se convierte en palabras como 恭喜, 获得 y 大奖, no en una cadena larga que nunca se repite.

Los disfraces se deshacen antes de contar: caracteres invisibles dentro de las palabras, letras cirílicas o griegas dentro de palabras latinas (`pаypal`), dígitos en lugar de letras (`v1agra`) y letras matemáticas o encerradas (𝐅𝐑𝐄𝐄). Cada disfraz es además un indicio propio.


## No marcar lo que no conoce

Los conjuntos de datos públicos de spam contienen mucho más spam en otros idiomas que ham en otros idiomas, así que un clasificador ingenuo aprende que el propio texto en árabe o en coreano es spam. Spam Scanner nunca usa el idioma como indicio, pondera cada palabra con los recuentos de spam y ham de su propio idioma y se queda en «dudoso» en proporción a lo poco que ham ha visto en un idioma.

En una prueba con mensajes SMS en 21 idiomas que el modelo incluido nunca vio, esto redujo a cero sus falsos positivos en chino, árabe, coreano, japonés, hindi, bengalí, urdu, turco, ucraniano y sueco.


## Detectar el spam en todos los idiomas

* **Comprobaciones que no leen palabras:** dominios parecidos, enlaces engañosos, ejecutables, macros, SPF, DKIM, DMARC y listas de bloqueo.
* **Un modelo de lenguaje** para los mensajes dudosos. Los modelos abiertos como Qwen 3.5 y Gemma 4 leen de 140 a 200 idiomas; las pruebas de extremo a extremo comprueban spam y ham en chino, árabe, coreano, hindi y tailandés con un modelo real.
* **Tu propio correo.** Unos cientos de mensajes de cada tipo en un idioma le dan a un modelo entrenado con tu correo la confianza plena en ese idioma.

```sh
spamscanner scan message.eml --llm ollama --llm-model qwen3.5:4b
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out my-model.json
```

Para aceptar solo algunos idiomas, `--allow-language en,de` suma puntos al correo detectado con seguridad en cualquier otro.

[Los idiomas en detalle](../../docs/languages.md)
