<!-- source: 1562b843d858 -->

<!--
label: Alternativa ao SpamAssassin
title: Uma alternativa ao SpamAssassin que fala o protocolo do spamd
description: Troque o spamd do SpamAssassin pelo Spam Scanner. spamc, Exim e Haraka seguem funcionando, os cabeçalhos X-Spam mantêm os nomes e todo idioma é suportado.
keywords: alternativa ao SpamAssassin, substituto do spamd, spamc, filtro de spam Exim, Haraka spamassassin, alternativa ao rspamd, X-Spam-Status
-->

# Uma alternativa ao SpamAssassin que fala o protocolo do spamd

O Spam Scanner responde ao protocolo spamd do SpamAssassin, então softwares escritos para o SpamAssassin o usam sem mudanças: o spamc, a condição `spam` do Exim, o plugin `spamassassin` do Haraka e outros.


## Faça a troca

```sh
sudo systemctl disable --now spamd       # or spamassassin
npm install --global spamscanner
spamscanner spamd --port 783 --auth
```

```sh
spamc -c < message.eml     # prints the score, exits 1 for spam
spamc -R < message.eml     # the report, one line per test
spamc < message.eml        # the message with X-Spam-* headers
```

Ele responde a `CHECK`, `SYMBOLS`, `REPORT`, `REPORT_IFSPAM`, `PROCESS`, `HEADERS`, `PING` e, com `--allow-tell`, a `TELL` para aprendizado. Os testes de ponta a ponta do projeto executam o próprio spamc do SpamAssassin contra ele.


## O que continua igual

* Os cabeçalhos: `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Level` e `X-Spam-Status` no formato do SpamAssassin, então as regras existentes do Sieve, do procmail e dos clientes de e-mail continuam funcionando.
* Uma pontuação com limite de 5, formada por testes nomeados com pontos: `BAYES_99`, `RBL_ZEN`, `SPF_FAIL`, `DKIM_PASS` e assim por diante.
* As pontuações de cada teste podem ser alteradas pelo nome do teste.


## O que é diferente

* **Idiomas.** As palavras são segmentadas com as regras do Unicode, então chinês, japonês e tailandês são lidos como palavras, e não como uma única sequência longa, e disfarces como caracteres invisíveis ou letras cirílicas em palavras latinas são desfeitos antes.
* **Phishing.** Domínios parecidos, links enganosos e nomes de marcas em nomes de exibição são verificados sem regras extras.
* **Anexos** são identificados pelos seus bytes: um executável renomeado para `.pdf` continua sendo um executável.
* **Modelos de linguagem.** Os casos duvidosos podem ir para um modelo local através do Ollama ou para um modelo hospedado.
* **Node.js.** Um único `npm install`, ou um binário independente; nada de módulos Perl ou atualizações de regras para gerenciar.

O Spam Scanner não executa os arquivos de regras do SpamAssassin, e o formato do seu banco de dados Bayes é próprio: treine-o com os mesmos e-mails usando `spamscanner train`.


## Exim

```text
spamd_address = 127.0.0.1 783

# in the DATA ACL
warn  spam       = nobody:true
      add_header = X-Spam-Score: $spam_score
defer spam       = nobody:true
      condition  = ${if >={$spam_score_int}{150}}
      message    = Message rejected as spam
```

[Exim, Haraka, Dovecot e procmail](../../docs/mail-servers.md)
