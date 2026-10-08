<!-- source: c93fa1a3f9c7 -->

<!--
label: Perguntas frequentes
title: Perguntas frequentes
description: Respostas sobre o Spam Scanner: precisão, idiomas suportados, o que ele envia pela rede, modelos de linguagem, SpamAssassin e Forward Email.
keywords: Spam Scanner perguntas frequentes, dúvidas sobre filtro de spam, precisão de filtro de spam, privacidade de filtro de spam
-->

# Perguntas frequentes


## O que é o Spam Scanner?

Um filtro de spam para Node.js, a linha de comando e servidores de e-mail. Ele lê uma mensagem de e-mail bruta e decide se ela é spam, phishing, um golpe ou se carrega malware, com uma pontuação e a lista dos testes que tomaram a decisão. Ele roda como biblioteca, como milter para Postfix e Sendmail, como servidor spamd compatível com o SpamAssassin, como filtro de conteúdo do Postfix, como API HTTP ou como servidor TCP.


## Ele é gratuito?

A sua [licença](https://github.com/spamscanner/spamscanner/blob/master/LICENSE), a Business Source License 1.1, permite qualquer uso, exceto oferecer detecção de spam como serviço a terceiros, e informa a data em que ela passa a ser a Apache License 2.0.


## Qual é a precisão dele?

Em mensagens em inglês separadas dos seus dados de treinamento, o classificador incluído, sozinho, não marcou nenhum ham como spam e pegou 97% do spam; os números completos por idioma estão no [guia de treinamento](../../docs/training.md#the-bundled-model). Links, anexos, autenticação, listas de bloqueio e um modelo de linguagem somam a isso. O teste de verdade são os seus próprios e-mails: o `spamscanner eval` mede qualquer modelo com qualquer conjunto de e-mails rotulados.


## Quais idiomas ele suporta?

Todos. Ele segmenta as palavras com as regras do Unicode, inclusive em chinês, japonês e tailandês, que não têm espaços. Onde o modelo incluído viu poucos e-mails em um idioma, ele fica incerto em vez de marcar a mensagem, e um modelo de linguagem ou o seu próprio treinamento decide. [Idiomas](../../docs/languages.md)


## Ele envia os meus e-mails para algum lugar?

Não. Por padrão, ele consulta os nomes de host dos links nos resolvedores DNS com filtragem da Cloudflare, e nada mais sai da máquina. Autenticação, listas de bloqueio, modelos de linguagem e serviços de reputação ficam desligados até serem configurados, e os dados pessoais são removidos antes de um e-mail ir para um modelo de linguagem hospedado. [Segurança e privacidade](../../docs/security.md)


## Preciso de um modelo de linguagem?

Não. Ele é uma segunda opinião para os casos duvidosos. Sem um modelo, essas mensagens são decididas apenas pela pontuação.


## Qual modelo de linguagem devo usar?

O `qwen3.5:4b` via Ollama em uma CPU, ou o `qwen3.5:9b` com uma GPU. Os dois têm licença Apache e leem 201 idiomas. Modelos hospedados da Anthropic, OpenAI, Google e outros também funcionam. [Modelos recomendados](../../docs/llm.md#recommended-open-models)


## Ele pode substituir o SpamAssassin?

Na maioria das configurações, sim: ele fala o protocolo do spamd, então spamc, Exim e Haraka funcionam sem mudanças, e ele escreve os mesmos cabeçalhos `X-Spam-*`. Ele não executa os arquivos de regras do SpamAssassin. [Alternativa ao SpamAssassin](/spamassassin-alternative/)


## Ele vai rejeitar e-mails legítimos?

A recusa de e-mails vem desligada por padrão: o milter apenas marca. Com `--reject`, só as mensagens com pontuação 15 ou mais são recusadas, com um erro temporário 451, então os remetentes tentam de novo e um erro pode ser corrigido mudando uma configuração. O filtro de conteúdo nunca recusa durante a sessão SMTP.


## Como treino o modelo com os meus e-mails?

`spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out model.json` e depois `--model model.json`. Arquivos mbox, Maildirs, pastas de arquivos `.eml` e conjuntos de dados em CSV ou JSON Lines funcionam. [Treinamento](../../docs/training.md)


## Ele funciona sem o Node.js?

Sim: binários independentes para Linux, macOS e Windows incluem o Node.js e o modelo. `curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash`.


## Quem o desenvolve?

O [Forward Email](https://forwardemail.net), para os seus próprios servidores de e-mail.
