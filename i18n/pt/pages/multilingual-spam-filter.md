<!-- source: 0ad167ddd34e -->

<!--
label: Filtro de spam multilíngue
title: Filtro de spam multilíngue: chinês, árabe, russo e toda escrita
description: Como o Spam Scanner filtra spam em todos os idiomas: segmentação de palavras do Unicode, disfarces desfeitos e nenhuma marcação de um idioma pouco conhecido.
keywords: filtro de spam multilíngue, filtro de spam chinês, filtro de spam árabe, filtro de spam russo, filtro de spam japonês, detecção de spam Unicode, spam com homóglifos
-->

# Filtro de spam multilíngue

Muitos filtros de spam foram feitos para o inglês. O spam em outros idiomas passa por eles, e e-mails comuns em outros idiomas são marcados por causa da sua escrita. O Spam Scanner foi feito para evitar as duas coisas.


## Lendo as palavras

As palavras são encontradas com o `Intl.Segmenter`, as regras de limite de palavras do Unicode, com dicionários para chinês, japonês, tailandês, laosiano, khmer e birmanês. Uma frase em chinês vira palavras como 恭喜, 获得 e 大奖, e não uma única sequência longa que nunca se repete.

Os disfarces são desfeitos antes da contagem: caracteres invisíveis dentro das palavras, letras cirílicas ou gregas dentro de palavras latinas (`pаypal`), dígitos no lugar de letras (`v1agra`) e letras matemáticas ou circuladas (𝐅𝐑𝐄𝐄). Cada disfarce também é uma pista por si só.


## Sem marcar o que ele não conhece

Os conjuntos de dados públicos de spam têm muito mais spam em idiomas estrangeiros do que ham em idiomas estrangeiros, então um classificador ingênuo aprende que o próprio texto em árabe ou coreano é spam. O Spam Scanner nunca usa o idioma como pista, compara cada palavra com as contagens de spam e ham do seu próprio idioma e fica “incerto” na proporção do pouco ham que viu em um idioma.

Em um teste com mensagens SMS em 21 idiomas que o modelo incluído nunca viu, isso zerou os falsos positivos em chinês, árabe, coreano, japonês, hindi, bengali, urdu, turco, ucraniano e sueco.


## Pegando spam em todos os idiomas

* **Verificações que não leem palavras:** domínios parecidos, links enganosos, executáveis, macros, SPF, DKIM, DMARC e listas de bloqueio.
* **Um modelo de linguagem** para as mensagens incertas. Modelos abertos como Qwen 3.5 e Gemma 4 leem de 140 a 200 idiomas; os testes de ponta a ponta verificam spam e ham em chinês, árabe, coreano, hindi e tailandês com um modelo real.
* **Os seus próprios e-mails.** Algumas centenas de mensagens de cada tipo em um idioma dão total confiança nesse idioma a um modelo treinado com os seus e-mails.

```sh
spamscanner scan message.eml --llm ollama --llm-model qwen3.5:4b
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out my-model.json
```

Para aceitar só alguns idiomas, `--allow-language en,de` adiciona pontos aos e-mails detectados com confiança em qualquer outro idioma.

[Idiomas em detalhes](../../docs/languages.md)
