<!-- source: 988243aec4f3 -->

<!--
label: Filtro de spam auto-hospedado
title: Filtro de spam auto-hospedado para o seu servidor de e-mail
description: Um filtro de spam no seu próprio servidor. O Spam Scanner mantém o e-mail na máquina, traz o modelo no pacote, não envia telemetria e se conecta ao Postfix ou ao Exim.
keywords: filtro de spam auto-hospedado, filtro de spam local, filtro de spam privado, antispam on-premise, filtro de spam para servidor de e-mail, filtro de spam sem nuvem
-->

# Filtro de spam auto-hospedado

O Spam Scanner roda no seu próprio servidor e mantém o e-mail lá. O modelo do classificador vem dentro do pacote, não há telemetria nem verificação de atualizações e, por padrão, a única coisa que ele envia é uma consulta DNS pelo nome de host de cada link.


## O que sai do servidor

Por padrão, só os nomes de host dos links de uma mensagem. Eles são consultados nos resolvedores com filtragem da Cloudflare (1.1.1.2 e 1.1.1.3) como consultas DNS comuns, e nenhuma parte da mensagem ou dos endereços é enviada. `--no-cloudflare` desliga isso também.

Qualquer outra verificação que usa a rede fica desligada até você ativá-la:

| Verificação            | Ative com            | O que envia                                                          |
| ---------------------- | -------------------- | -------------------------------------------------------------------- |
| SPF, DKIM, DMARC, ARC  | `--auth`             | Consultas DNS dos registros do remetente                             |
| Listas de bloqueio DNS | `--dnsbl`, `--uribl` | O endereço IP do cliente e os domínios dos links, como consultas DNS |
| ClamAV                 | `--clamav`           | Os anexos, para o seu próprio clamd                                  |
| Um modelo de linguagem | `--llm`              | Um resumo da mensagem, para o servidor que você indicar              |

As análises não são registradas nem guardadas. [Segurança e privacidade](../../docs/security.md)


## Instalar em um servidor

```sh
npm install --global spamscanner
```

Ou o binário independente, com o Node.js e o modelo embutidos:

```sh
curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash
```

O script de instalação confere o binário com o arquivo `SHA256SUMS` da versão antes de instalá-lo, e cada binário tem uma atestação de procedência de build assinada que o `gh attestation verify` confere. Há binários para Linux (x64 e arm64), macOS e Windows. Os binários Linux precisam de glibc, então no Alpine instale com npm. [Primeiros passos](../../docs/getting-started.md)

Não há verificação de atualizações. Para atualizar, rode o comando de instalação de novo: os dois comandos instalam a versão mais recente.


## Rodar como serviço

Os servidores milter, HTTP, TCP e spamd escutam em 127.0.0.1, a menos que `--host` diga outra coisa. Rode-os com um usuário sem privilégios, por exemplo com systemd:

```ini
[Service]
ExecStart=/usr/local/bin/spamscanner milter --port 7831 --auth --subject-tag [SPAM]
User=spamscanner
Group=spamscanner
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
```

A [unidade completa e a configuração](../../docs/postfix.md#1-run-the-milter) estão no guia do Postfix. Nenhum dos servidores fala TLS; para acessar um de outra máquina, use uma rede privada, um túnel SSH ou um proxy reverso com TLS.


## Conectar o seu servidor de e-mail

| Servidor de e-mail                       | Comando                                     | Porta   |
| ---------------------------------------- | ------------------------------------------- | ------- |
| Postfix ou Sendmail                      | `spamscanner milter`                        | 7831    |
| Postfix, sem nunca recusar e-mail        | `spamscanner filter`, um filtro de conteúdo | nenhuma |
| Exim, Haraka ou spamc                    | `spamscanner spamd`                         | 783     |
| Qualquer coisa que fale HTTP             | `spamscanner http`                          | 7832    |
| Um cliente TCP simples                   | `spamscanner server`                        | 7830    |
| Um servidor de e-mail escrito em Node.js | `import SpamScanner from 'spamscanner'`     | nenhuma |

Os servidores podem adicionar à mensagem os cabeçalhos `X-Spam-Flag`, `X-Spam-Score` e `X-Spam-Status`, e a biblioteca devolve a pontuação e cada teste acionado. Guias: [filtro de spam para Postfix](/postfix-spam-filter/), [outros servidores de e-mail](../../docs/mail-servers.md) e [a API HTTP](../../docs/http-api.md).


## Manter os modelos de linguagem locais

Um modelo de linguagem é opcional e só lê os casos duvidosos: spam claro e ham claro nunca chegam a ele. Com o Ollama ele roda no mesmo servidor, então nenhuma mensagem sai dele:

```sh
ollama pull qwen3.5:4b
spamscanner milter --llm ollama --llm-model qwen3.5:4b
```

`qwen3.5:4b` roda em uma CPU. Com um provedor hospedado, os dados pessoais são removidos da mensagem antes do envio. [Modelos de linguagem](../../docs/llm.md)


## Treinar com o seu próprio e-mail

O modelo incluído é treinado com conjuntos de dados públicos. Um modelo treinado com o e-mail que o seu servidor recebe se sai melhor, e fica nesse servidor:

```sh
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out /var/lib/spamscanner/model.json
SPAMSCANNER_MODEL=/var/lib/spamscanner/model.json spamscanner milter
```

Um arquivo de modelo guarda contagens de características com hash, não palavras nem texto de mensagens. [Treinamento](../../docs/training.md)


## Requisitos

Node.js 18 ou posterior em Linux, macOS ou Windows, ou nada com um binário independente. ClamAV e Ollama são opcionais e rodam como serviços próprios.
