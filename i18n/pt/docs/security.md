<!-- source: 1d7373f991c2 -->

# Segurança e privacidade

O Spam Scanner lê e-mails, que são privados, vindos de remetentes, que podem ser hostis. Esta página lista o que ele envia para qualquer lugar e como trata o que lê.


## O que sai da máquina

Por padrão, uma coisa: os **nomes de host dos links** de uma mensagem são consultados nos resolvedores com filtragem da Cloudflare, 1.1.1.2 e 1.0.0.2 (malware e phishing) e 1.1.1.3 e 1.0.0.3 (também conteúdo adulto). São consultas DNS comuns para nomes como `example.com`; nenhuma parte da mensagem ou dos seus endereços é enviada. Desative-as com `phishing: {cloudflare: false}` ou `--no-cloudflare`, ou apenas a verificação de conteúdo adulto com `phishing: {adult: false}`.

Todo o resto fica desligado até ser configurado:

| Verificação         | Envia                                                                                                                             | Para                                                                                         |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `authentication`    | Consultas DNS dos registros SPF, DKIM, DMARC e ARC do remetente                                                                   | O seu resolvedor, ou `dnsServers`                                                            |
| `dnsbl`             | O endereço IP do cliente, invertido, e os domínios dos links, como consultas DNS                                                  | Os servidores de nomes das listas de bloqueio, através do seu resolvedor ou de `dns.servers` |
| `llm`               | Um resumo da mensagem, com os dados pessoais removidos para provedores remotos                                                    | O servidor de modelo de linguagem que você indicar ([privacidade](llm.md#privacy))           |
| `reputation.apiUrl` | O endereço IP e o nome de host verificado do cliente, e os endereços From, do remetente do envelope e Reply-To, com seus domínios | O serviço que você indicar                                                                   |
| `clamav`            | Os anexos                                                                                                                         | O seu clamd, pelo socket dele                                                                |

Não há telemetria, verificação de atualizações nem downloads durante a execução. O modelo vem dentro do pacote.


## O que ele guarda

Nada, a menos que seja pedido. As análises não são registradas nem armazenadas. O `learn()` altera o classificador na memória; ele só é gravado em disco pelo `saveModel()`, pelo `spamscanner learn` ou pela opção `--out` dos servidores. Um arquivo de modelo guarda contagens de características com hash, e não palavras ou texto de mensagens.

As respostas do modelo de linguagem ficam em cache na memória, indexadas por um hash do que foi enviado, então cópias repetidas da mesma mensagem são consultadas uma única vez. As respostas DNS ficam em cache na memória por dez minutos, e as de um serviço de reputação por cinco (`reputation.cacheTtl`; uma solicitação que falhou, por um minuto).


## Entradas hostis

* Os anexos são identificados pelos seus bytes, nunca executados nem abertos por outro programa. Os arquivos ZIP são lidos a partir do diretório central, com limites no número de entradas (2000) e nos bytes de seus nomes (1 MiB; um nome acima de 1 KiB mantém seus primeiros e últimos 512 bytes, e as constatações mostram no máximo 100 caracteres de um nome), cada entrada lida uma vez, não importa quantos diretórios apontem para ela; nada é descompactado, então programas dentro de arquivos compactados aninhados ou comprimidos não são vistos. Mensagens anexadas (`message/rfc822`, ou anexos cujo nome de arquivo termina em `.eml`) são abertas até três níveis de profundidade, para no máximo 100 dos seus anexos e 25 MB de mensagens anexadas no total; os anexos da própria mensagem são sempre todos inspecionados. Uma mensagem que excede os limites do parser MIME (mais de 1000 partes, ou o cabeçalho de uma parte acima de 1 MB) é lida até onde o parser permite (as primeiras partes, com um cabeçalho grande demais reduzido para que o remetente ainda conte) e recebe `MIME_TOO_COMPLEX`, que nenhum crédito compensa; o ClamAV a lê inteira. Uma mensagem anexada em que o parser falha também o recebe, e nunca faz a verificação falhar. Os campos de endereço são lidos até 16 KB cada (2000 endereços, 16 grupos aninhados) e 64 KB no total por mensagem, cortados só no fim de um endereço inteiro, pois o parser de endereços leva um tempo que cresce com o quadrado do número de endereços; o mailauth também lê From e Return-Path assim limitados (os demais campos como estão, para que uma assinatura sobre eles continue válida), e um cabeçalho que levaria mais que tempo linear para ler (milhares de linhas dobradas, ou assinaturas que citam milhares de campos) é reduzido. Um campo From cortado falha no DMARC e não conta para nenhuma lista de permissões. O HTML é lido pelo próprio parser do Spam Scanner, em tempo linear, por mais aninhado que esteja.
* O texto do corpo é lido até `maxLength` (100.000 caracteres), e os servidores aceitam mensagens de até 25 MB. Os links são lidos até `phishing.maxLength` (1.000.000 caracteres).
* Toda verificação de rede tem um tempo limite (`timeout`, 10 segundos por padrão). Uma verificação que falha ou estoura o tempo é ignorada, e a análise termina sem ela. A autenticação e o modelo de imagens (as 10 primeiras imagens) terminam cada um por inteiro dentro desse limite: a autenticação não envia nenhuma consulta DNS depois dele, nem mais de 300 por mensagem (espaço para o SPF nos limites da RFC 7208, com DKIM, ARC, DMARC e BIMI), e verifica só as 8 primeiras assinaturas DKIM de uma mensagem (o próprio mailauth lê no máximo 50 conjuntos ARC). O cabeçalho `Authentication-Results` que o milter adiciona contém no máximo 8 KiB de resultados. O ClamAV (quatro anexos por vez) tem o próprio limite para todos os anexos de uma mensagem (`clamav.timeout`, 60 segundos), e os anexos que ele não conseguiu verificar ficam listados em `results.virusScanErrors`. O modelo de linguagem tem o próprio limite (`llm.timeout`).
* A lista de permissão só confia no que um remetente não consegue falsificar: o endereço e o nome de host verificado do cliente, e os domínios de remetente que a autenticação confirma. [Listas de permissão e de bloqueio](api.md#allowlist-and-denylist)
* Os cabeçalhos `X-Spam-*` que já estão em uma mensagem são removidos pelo milter, pelo filtro de conteúdo e pelo `--headers`, então os remetentes não conseguem marcar os próprios e-mails como limpos.
* Os cabeçalhos de veredito de spam da Microsoft só são considerados confiáveis quando a mensagem veio diretamente dos servidores da Microsoft, e os cabeçalhos Received nunca são usados para decidir de onde uma mensagem veio.
* Textos dirigidos a filtros de IA são pontuados como spam, e o modelo de linguagem é avisado de que a mensagem é dado, e não instrução. [Injeção de prompt](llm.md#prompt-injection)


## Servidores

Os servidores milter, HTTP, TCP e spamd escutam em 127.0.0.1, a menos que o `--host` diga outra coisa. A API HTTP compara o seu token em tempo constante e recusa o `/learn` sem um token. Nenhum deles fala TLS: para acessá-los por uma rede, use uma rede privada, um túnel SSH ou um proxy reverso com TLS.

Execute-os com um usuário sem privilégios. A [unidade systemd do guia do Postfix](postfix.md#1-run-the-milter) adiciona o endurecimento habitual.


## Relatar uma vulnerabilidade

Relate problemas de segurança de forma privada pelo [sistema de relato de vulnerabilidades do GitHub](https://github.com/spamscanner/spamscanner/security/advisories/new), e não em issues públicas.
