<!-- source: c56969e779c4 -->

# Documentação do Spam Scanner

O Spam Scanner é um filtro de spam para Node.js e para a linha de comando, com o código-fonte no GitHub. Ele lê uma mensagem de e-mail bruta e decide se ela é spam, phishing, um golpe ou se carrega malware, em qualquer idioma. Ele roda como biblioteca, ferramenta de linha de comando, milter para Postfix ou Sendmail, filtro de conteúdo do Postfix, servidor spamd compatível com o SpamAssassin, API HTTP ou servidor TCP.

Ele é desenvolvido pelo [Forward Email](https://forwardemail.net) para os seus próprios servidores de e-mail.


## Como uma mensagem é avaliada

Cada verificação adiciona ou remove pontos. O total decide o resultado:

| Pontuação   | Ação     | O que um servidor de e-mail faz         |
| ----------- | -------- | --------------------------------------- |
| Abaixo de 5 | `accept` | Entrega a mensagem                      |
| De 5 a 14,9 | `tag`    | Entrega a mensagem marcada como spam    |
| 15 ou mais  | `reject` | Recusa a mensagem durante a sessão SMTP |

Os dois limites podem ser alterados. Cada resultado lista os testes acionados, com os seus pontos e um motivo, então uma decisão sempre pode ser explicada.

As verificações:

* **Um classificador treinado** lê as palavras da mensagem em qualquer sistema de escrita, a forma dos seus links, o remetente e os anexos. Ele vem treinado com conjuntos de dados públicos e aprende com os seus próprios e-mails. [Como o classificador funciona](how-it-works.md#the-classifier)
* **As verificações de phishing** pegam domínios parecidos (`paypa1.com`, `pаypal.com` com um а cirílico), links cujo texto mostra um endereço e cujo destino é outro e nomes de exibição que alegam ser uma marca. [Phishing](how-it-works.md#phishing)
* **As verificações de anexos** encontram executáveis, executáveis renomeados como documentos, extensões duplas, truques de nome de arquivo da direita para a esquerda, executáveis dentro de arquivos ZIP, macros do Office e conteúdo ativo em PDF. O ClamAV pode analisar os anexos em busca de vírus. [Anexos](how-it-works.md#attachments)
* **Autenticação**: SPF, DKIM, DMARC e ARC, quando o endereço IP do cliente é conhecido. [Autenticação](how-it-works.md#authentication)
* **Listas de bloqueio no DNS** para o endereço IP do cliente e os domínios dos links, e os resolvedores com filtragem da Cloudflare para sites conhecidos de malware e de conteúdo adulto. [Listas de bloqueio](how-it-works.md#blocklists)
* **Regras** para padrões que nenhum classificador precisa aprender: a sequência de teste GTUBE, assuntos de sextorsão, golpes de fatura do PayPal, autofalsificação e instruções escondidas para filtros de IA. [Regras](scoring.md#rules)
* **Um modelo de linguagem**, opcional, dá uma segunda opinião nos casos duvidosos: um modelo local através do Ollama ou de qualquer servidor compatível com a OpenAI, ou Claude, ChatGPT, Gemini e outros. [Modelos de linguagem](llm.md)


## Por onde começar

* [Primeiros passos](getting-started.md): instale e analise uma primeira mensagem.
* [Linha de comando](cli.md): todos os comandos e opções.
* [Postfix e Sendmail](postfix.md): filtre um servidor de e-mail com o milter ou com um filtro de conteúdo.
* [Outros servidores de e-mail](mail-servers.md): Exim, Haraka, Dovecot, procmail e qualquer coisa que consiga chamar uma API HTTP.
* [Treinamento](training.md): ensine os seus próprios e-mails ao modelo e meça o resultado.
* [Modelos de linguagem](llm.md): provedores, modelos abertos recomendados, privacidade e injeção de prompt.
* [Idiomas](languages.md): como ele lê chinês, árabe, tailandês e todos os outros sistemas de escrita.
* [Forward Email](forward-email.md): como o Forward Email o usa e como atualizar a partir da versão 5 ou 6.
* [Referência da API](api.md) e [testes e pontuações](scoring.md).
* [Segurança e privacidade](security.md): o que sai da máquina e como impedir isso.
