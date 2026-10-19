<!-- source: 599bd320e55a -->

<!--
label: Sobre
title: Sobre o Spam Scanner, sua licença e a privacidade
description: Quem faz o Spam Scanner, como relatar um bug ou uma vulnerabilidade, a licença dele e o que este site coleta: nenhum cookie e nenhuma análise.
keywords: sobre o Spam Scanner, Forward Email, licença do Spam Scanner, BUSL-1.1, contato Spam Scanner, privacidade Spam Scanner
-->

# Sobre o Spam Scanner

O Spam Scanner é um filtro de spam para e-mail feito pela [Forward Email](https://forwardemail.net), o serviço de e-mail focado em privacidade, que o criou para os próprios servidores de e-mail. O código-fonte, as issues e as versões estão no [GitHub](https://github.com/spamscanner/spamscanner), e o pacote está no [npm](https://www.npmjs.com/package/spamscanner).


## Quem faz

A equipe da Forward Email escreve e mantém o Spam Scanner. A Forward Email não guarda registros do conteúdo das mensagens, então não podia enviar o e-mail para um serviço de filtragem externo: o filtro tinha de rodar nos próprios servidores e explicar cada decisão sem que uma pessoa lesse o e-mail. [Como a Forward Email o usa](../../docs/forward-email.md)

A Forward Email também é de código aberto, em [github.com/forwardemail/forwardemail.net](https://github.com/forwardemail/forwardemail.net). O fundador foi um dos primeiros funcionários do DuckDuckGo.


## Contato

* **Dúvidas, bugs e pedidos de recursos:** abra uma issue no [GitHub](https://github.com/spamscanner/spamscanner/issues).
* **Vulnerabilidades de segurança:** relate-as em particular pelo [relato de vulnerabilidades do GitHub](https://github.com/spamscanner/spamscanner/security/advisories/new), não em issues públicas. O mesmo endereço está no [security.txt](https://spamscanner.net/.well-known/security.txt).
* **Outras licenças:** fale com a [Forward Email](https://forwardemail.net).


## Termos da licença

A [licença](https://github.com/spamscanner/spamscanner/blob/master/LICENSE) do Spam Scanner é a Business Source License 1.1, com a Apache License 2.0 como Change License. A Change Date indicada na licença já passou e, desde essa data, a licença concede a você direitos nos termos da Apache License 2.0.


## Privacidade

Este site não define cookies e não carrega análises, rastreadores, anúncios, fontes nem scripts de outros sites. Todos os arquivos vêm de spamscanner.net.

* O tema, o idioma que você escolhe e o servidor Mastodon para o qual você compartilha ficam salvos no armazenamento local do navegador e não são enviados a lugar nenhum.
* O vídeo só carrega quando você o reproduz.
* Os links de compartilhamento são links comuns, então nada dessas redes carrega até você seguir um deles.
* O site é hospedado no GitHub Pages, e o GitHub registra o endereço IP de cada visitante por motivos de segurança. Veja [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages) e a [declaração de privacidade do GitHub](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).


## O que o software envia

O Spam Scanner não envia telemetria nem procura atualizações. Por padrão, ele consulta os nomes de host dos links de uma mensagem nos resolvedores DNS com filtragem da Cloudflare, e nada mais sai da máquina. As outras verificações de rede ficam desligadas até você ativá-las. [Segurança e privacidade](../../docs/security.md)


## Versões

O GitHub Actions compila os binários independentes a partir do repositório público. Cada versão lista os hashes deles em um arquivo `SHA256SUMS`, que o script de instalação confere, e cada binário traz uma atestação de procedência de build assinada. As versões e suas notas estão no [GitHub](https://github.com/spamscanner/spamscanner/releases).
