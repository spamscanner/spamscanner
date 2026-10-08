<!-- source: f33722183f00 -->

<!--
label: Filtro de spam para Postfix
title: Filtro de spam para Postfix com milter ou filtro de conteúdo
description: Filtre spam em um servidor Postfix com o milter ou o filtro de conteúdo do Spam Scanner: instalação, unidade systemd, rejeição com 4xx ou 5xx e pasta Junk.
keywords: filtro de spam Postfix, milter Postfix, smtpd_milters, filtro de conteúdo Postfix, antispam Postfix, rejeitar spam no Postfix
-->

# Filtro de spam para Postfix

O Spam Scanner filtra um servidor Postfix em cerca de cinco minutos. Ele roda como milter, então o Postfix o consulta sobre cada mensagem durante a sessão SMTP e pode recusar o spam antes de aceitá-lo.


## Instalar e executar

```sh
npm install --global spamscanner
spamscanner milter --port 7831 --auth --subject-tag "[SPAM]"
```

O `--auth` verifica SPF, DKIM, DMARC e ARC; o `--subject-tag` marca o spam no assunto. Toda mensagem recebe os cabeçalhos `X-Spam-Flag`, `X-Spam-Score`, `X-Spam-Status` e `X-Spam-Action`, e qualquer cabeçalho `X-Spam-*` que o remetente tenha colocado é removido antes.


## Conectar o Postfix

```ini
# /etc/postfix/main.cf
smtpd_milters = inet:127.0.0.1:7831
milter_protocol = 6
milter_default_action = accept
```

```sh
sudo postfix reload
```

O `milter_default_action = accept` deixa o e-mail passar sem filtragem se o milter estiver fora do ar; `tempfail` pede aos remetentes que tentem de novo.


## Recusar spam durante a sessão SMTP

```sh
spamscanner milter --port 7831 --auth --reject
```

As mensagens que atingem o limite de rejeição (15 pontos) são recusadas com `451 4.7.1 Message rejected as spam`. Um 451 é temporário: o remetente guarda a mensagem e tenta de novo, então uma decisão errada custa um atraso, e não uma mensagem perdida. Quando os resultados parecerem corretos, `--reject-code 550` torna a recusa permanente.


## Sem milter

Um filtro de conteúdo roda depois que o Postfix aceita uma mensagem: o Postfix a envia por um pipe para o `spamscanner filter`, que adiciona os cabeçalhos e a devolve. Nada é recusado durante a sessão, e uma falha sempre adia a entrega em vez de devolver a mensagem. [Configuração do filtro de conteúdo](../../docs/postfix.md#content-filter)


## Spam na pasta Junk

Com o Dovecot, uma regra Sieve arquiva os e-mails marcados:

```text
require ["fileinto"];
if header :is "X-Spam-Flag" "YES" { fileinto "Junk"; stop; }
```


## Testado com um Postfix real

Os testes de ponta a ponta do projeto executam o Postfix com o milter e com o filtro de conteúdo: o ham é entregue com os cabeçalhos e com um `X-Spam-Flag` forjado removido, o spam é marcado e o GTUBE é recusado com um 550 durante a sessão SMTP.

Próximo passo: [o guia completo do Postfix e do Sendmail](../../docs/postfix.md), com uma unidade systemd e o `INPUT_MAIL_FILTER` do Sendmail.
