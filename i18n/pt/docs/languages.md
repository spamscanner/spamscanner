<!-- source: 9537a0e62eb0 -->

# Idiomas

O spam chega em todos os idiomas, e os e-mails comuns também. O Spam Scanner lê os dois e toma cuidado com os idiomas que conhece pouco: um filtro de spam que marca toda mensagem em árabe ou chinês é pior do que nenhum.


## Lendo todos os sistemas de escrita

* **Palavras.** O texto é dividido com o `Intl.Segmenter`, que segue as regras de limite de palavras do Unicode e usa dicionários para chinês, japonês, tailandês, laosiano, khmer e birmanês, escritas sem espaços. Textos longos são divididos em partes antes, porque o segmentador do Node.js 18 fica lento com sequências muito longas.
* **Normalização.** O Unicode NFKC transforma letras de largura total e a maioria das letras estilizadas (𝐅𝐑𝐄𝐄, Ⓕⓡⓔⓔ) em letras simples. O texto é colocado em minúsculas pelas regras do Unicode.
* **Disfarces.** Caracteres invisíveis dentro das palavras (`free` com um espaço de largura zero entre duas letras, hifens suaves) são removidos e contados. Palavras que misturam alfabetos, como `pаypal` com um а cirílico, são mapeadas de volta para um único alfabeto e contadas. Dígitos usados como letras (`v1agra`) são convertidos. Cada disfarce é uma característica própria, e três ou mais caracteres invisíveis, ou duas ou mais palavras misturadas, também adicionam pontos.


## Detectando o idioma

O idioma de cada mensagem é detectado pelo sistema de escrita e, nos sistemas compartilhados por muitos idiomas, pelas letras:

* Hangul é coreano; hiragana e katakana indicam japonês; tailandês, grego, hebraico, armênio, georgiano, bengali, tâmil e outros sistemas de escrita usados por um único idioma o indicam diretamente.
* Letras cirílicas encontradas em apenas um idioma decidem entre ucraniano (і, ї, є, ґ), bielorrusso (ў), sérvio (ђ, ћ, џ), macedônio (ѓ, ќ, ѕ) e russo (ы, э, ё).
* Textos em sistemas de escrita compartilhados por vários idiomas (latino, cirílico, árabe, devanágari e outros), quando são longos o suficiente para avaliar, vão para o [franc](https://github.com/wooorm/franc), limitado aos idiomas comuns em e-mails para que mensagens curtas não sejam rotuladas com idiomas raros.

O idioma é informado em `result.language`, e `allowedLanguages: ['en', 'de']` (`--allow-language en,de`) adiciona 3 pontos aos e-mails detectados com confiança em qualquer outro idioma.


## Idiomas que o modelo conhece pouco

Um classificador aprende com exemplos. Os conjuntos de dados públicos de spam têm muito mais spam em idiomas estrangeiros do que ham em idiomas estrangeiros, então um classificador ingênuo aprende que o próprio texto em chinês ou árabe significa spam. O Spam Scanner corrige isso de três formas:

1. **O idioma nunca é evidência.** O idioma e o sistema de escrita detectados não são usados como pistas.
2. **As palavras são avaliadas dentro do seu idioma.** A probabilidade de spam de uma palavra é calculada com base no número de mensagens de spam e de ham que o classificador viu no idioma da mensagem, e não em todos os idiomas. Uma palavra cotidiana do português, em um modelo que viu principalmente spam em português, permanece neutra.
3. **A confiança acompanha a cobertura.** O resultado é puxado para “incerto” na proporção de quantas mensagens de cada tipo o classificador viu naquele idioma: a confiança total exige 1.000 de cada (ou 2% da classe menor, no caso de modelos pessoais pequenos). Um idioma sem nenhum ham nos dados de treinamento sempre recebe “incerto”.

O modelo incluído nunca viu a [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset), mensagens SMS traduzidas por máquina para 21 idiomas. Antes dessas regras, ele marcava 5,7% desse ham como spam, incluindo 55% do português e 41% do francês. Com elas, 0,18%: nenhum em chinês, árabe, coreano, japonês, hindi, português, francês ou outros 20 idiomas, e 0,27% em inglês.


## Pegando spam nesses idiomas

Ficar incerto é seguro, mas não pega spam. Três coisas pegam:

* **As outras verificações** não dependem do idioma: domínios parecidos, links enganosos, executáveis, macros, autenticação, listas de bloqueio, as regras.
* **Um modelo de linguagem.** Os modelos abertos modernos leem de 100 a 200 idiomas, e o Spam Scanner consulta um sempre que o classificador está incerto. Os testes de ponta a ponta verificam que o `qwen3.5:4b` pega spam e deixa passar ham em chinês, árabe, coreano, hindi e tailandês. [Modelos de linguagem](llm.md)
* **Treinamento com os seus e-mails.** Em um modelo treinado com os seus próprios e-mails, algumas centenas de mensagens de cada tipo em um idioma dão total confiança ao classificador nesse idioma. [Treinamento](training.md), e [um conjunto de dados opcional](training.md#more-languages) que adiciona 21 idiomas.
