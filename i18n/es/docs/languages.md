<!-- source: 9537a0e62eb0 -->

# Idiomas

El spam llega en todos los idiomas, y el correo normal también. Spam Scanner lee ambos, y tiene cuidado con los idiomas que conoce poco: un filtro de spam que marca todos los mensajes en árabe o en chino es peor que no tener ninguno.


## Leer cualquier escritura

* **Palabras.** El texto se divide con `Intl.Segmenter`, que sigue las reglas de límites de palabra de Unicode y usa diccionarios para el chino, el japonés, el tailandés, el lao, el jemer y el birmano, escrituras que no usan espacios. Los textos largos se dividen primero en fragmentos, porque el segmentador de Node.js 18 se vuelve lento con cadenas muy largas.
* **Normalización.** Unicode NFKC convierte las letras de ancho completo y la mayoría de las letras estilizadas (𝐅𝐑𝐄𝐄, Ⓕⓡⓔⓔ) en letras simples. El texto se pasa a minúsculas según las reglas de Unicode.
* **Disfraces.** Los caracteres invisibles dentro de las palabras (`free` con un espacio de ancho cero entre dos letras, guiones discrecionales) se eliminan y se cuentan. Las palabras que mezclan alfabetos, como `pаypal` con una а cirílica, se devuelven a un solo alfabeto y se cuentan. Los dígitos usados como letras (`v1agra`) se convierten. Cada disfraz es una característica propia, y tres o más caracteres invisibles, o dos o más palabras mezcladas, también suman puntos.


## Detectar el idioma

El idioma de cada mensaje se detecta por su escritura y, en las escrituras que comparten muchos idiomas, por sus letras:

* El hangul es coreano; el hiragana y el katakana indican japonés; el tailandés, el griego, el hebreo, el armenio, el georgiano, el bengalí, el tamil y otras escrituras que usa un solo idioma lo identifican directamente.
* Las letras cirílicas que solo existen en un idioma deciden entre ucraniano (і, ї, є, ґ), bielorruso (ў), serbio (ђ, ћ, џ), macedonio (ѓ, ќ, ѕ) y ruso (ы, э, ё).
* El texto en escrituras que comparten varios idiomas (latina, cirílica, árabe, devanagari y otras), cuando es lo bastante largo para juzgarlo, pasa a [franc](https://github.com/wooorm/franc), limitado a los idiomas habituales en el correo electrónico para que los mensajes cortos no se etiqueten con idiomas poco frecuentes.

El idioma se indica en `result.language`, y `allowedLanguages: ['en', 'de']` (`--allow-language en,de`) suma 3 puntos al correo detectado con seguridad en cualquier otro idioma.


## Idiomas que el modelo conoce poco

Un clasificador aprende de ejemplos. Los conjuntos de datos públicos de spam contienen mucho más spam en otros idiomas que ham en otros idiomas, así que un clasificador ingenuo aprende que el propio texto en chino o en árabe significa spam. Spam Scanner lo corrige de tres maneras:

1. **El idioma nunca es una prueba.** El idioma y la escritura detectados no se usan como indicios.
2. **Las palabras se ponderan dentro de su idioma.** La probabilidad de spam de una palabra se calcula con el número de mensajes de spam y de ham que el clasificador vio en el idioma del mensaje, no en todos los idiomas. Una palabra cotidiana en portugués, en un modelo que vio sobre todo spam en portugués, se mantiene neutral.
3. **La confianza depende de la cobertura.** El resultado se acerca a «dudoso» en proporción a cuántos mensajes de cada tipo vio el clasificador en ese idioma: la confianza plena necesita 1000 de cada uno (o el 2 % de la clase más pequeña, en los modelos personales pequeños). Un idioma sin ham en los datos de entrenamiento siempre recibe «dudoso».

El modelo incluido nunca vio la [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset), mensajes SMS traducidos automáticamente a 21 idiomas. Antes de estas reglas, marcaba como spam el 5.7 % de ese ham, incluido el 55 % del portugués y el 41 % del francés. Con ellas, el 0.18 %: ninguno en chino, árabe, coreano, japonés, hindi, portugués, francés ni en otros 20 idiomas, y el 0.27 % en inglés.


## Detectar el spam en esos idiomas

«Dudoso» es seguro, pero no detecta el spam. Tres cosas sí lo hacen:

* **Las demás comprobaciones** no dependen del idioma: dominios parecidos, enlaces engañosos, ejecutables, macros, autenticación, listas de bloqueo, las reglas.
* **Un modelo de lenguaje.** Los modelos abiertos actuales leen de 100 a 200 idiomas, y Spam Scanner consulta a uno cada vez que el clasificador tiene dudas. Las pruebas de extremo a extremo comprueban que `qwen3.5:4b` detecta el spam y deja pasar el ham en chino, árabe, coreano, hindi y tailandés. [Modelos de lenguaje](llm.md)
* **Entrenar con tu correo.** En un modelo entrenado con tu propio correo, unos cientos de mensajes de cada tipo en un idioma le dan al clasificador la confianza plena en ese idioma. [Entrenamiento](training.md), y [un conjunto de datos opcional](training.md#more-languages) que añade 21 idiomas.
