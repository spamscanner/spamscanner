<!-- source: 60f00f92b5aa -->

# Segurança e privacidade

O Spam Scanner lê e-mails, que são privados, vindos de remetentes, que podem ser hostis. Esta página lista o que ele envia para qualquer lugar e como trata o que lê.


## O que sai da máquina

Por padrão, uma coisa: os **nomes de host dos links** de uma mensagem são consultados nos resolvedores com filtragem da Cloudflare, 1.1.1.2 e 1.0.0.2 (malware e phishing) e 1.1.1.3 e 1.0.0.3 (também conteúdo adulto). São consultas DNS comuns para nomes como `example.com`; nenhuma parte da mensagem ou dos seus endereços é enviada. Desative-as com `phishing: {cloudflare: false}` ou `--no-cloudflare`, ou apenas a verificação de conteúdo adulto com `phishing: {adult: false}`.

Todo o resto fica desligado até ser configurado:

| Verificação         | Envia                                                                            | Para                                                                                         |
| ------------------- | -------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `authentication`    | Consultas DNS dos registros SPF, DKIM, DMARC e ARC do remetente                  | O seu resolvedor, ou `dnsServers`                                                            |
| `dnsbl`             | O endereço IP do cliente, invertido, e os domínios dos links, como consultas DNS | Os servidores de nomes das listas de bloqueio, através do seu resolvedor ou de `dns.servers` |
| `llm`               | Um resumo da mensagem, com os dados pessoais removidos para provedores remotos   | O servidor de modelo de linguagem que você indicar ([privacidade](llm.md#privacy))           |
| `reputation.apiUrl` | O endereço IP, o domínio e o endereço do remetente                               | O serviço que você indicar                                                                   |
| `clamav`            | Os anexos                                                                        | O seu clamd, pelo socket dele                                                                |

Não há telemetria, verificação de atualizações nem downloads durante a execução. O modelo vem dentro do pacote.


## O que ele guarda

Nada, a menos que seja pedido. As análises não são registradas nem armazenadas. O `learn()` altera o classificador na memória; ele só é gravado em disco pelo `saveModel()`, pelo `spamscanner learn` ou pela opção `--out` dos servidores. Um arquivo de modelo guarda contagens de características com hash, e não palavras ou texto de mensagens.

As respostas do modelo de linguagem ficam em cache na memória, indexadas por um hash do que foi enviado, então cópias repetidas da mesma mensagem são consultadas uma única vez. As respostas DNS ficam em cache na memória por dez minutos.


## Entradas hostis

* Os anexos são identificados pelos seus bytes, nunca executados nem abertos por outro programa. Os arquivos ZIP são lidos a partir do diretório central, com um limite no número de entradas; arquivos compactados aninhados não são descompactados.
* O texto do corpo é lido até `maxLength` (100.000 caracteres), e os servidores aceitam mensagens de até 25 MB.
* Toda verificação de rede tem um tempo limite (`timeout`, 10 segundos por padrão). Uma verificação que falha ou estoura o tempo é ignorada, e a análise termina sem ela.
* Os cabeçalhos `X-Spam-*` que já estão em uma mensagem são removidos pelo milter, pelo filtro de conteúdo e pelo `--headers`, então os remetentes não conseguem marcar os próprios e-mails como limpos.
* Os cabeçalhos de veredito de spam da Microsoft só são considerados confiáveis quando a mensagem veio diretamente dos servidores da Microsoft, e os cabeçalhos Received nunca são usados para decidir de onde uma mensagem veio.
* Textos dirigidos a filtros de IA são pontuados como spam, e o modelo de linguagem é avisado de que a mensagem é dado, e não instrução. [Injeção de prompt](llm.md#prompt-injection)


## Servidores

Os servidores milter, HTTP, TCP e spamd escutam em 127.0.0.1, a menos que o `--host` diga outra coisa. A API HTTP compara o seu token em tempo constante e recusa o `/learn` sem um token. Nenhum deles fala TLS: para acessá-los por uma rede, use uma rede privada, um túnel SSH ou um proxy reverso com TLS.

Execute-os com um usuário sem privilégios. A [unidade systemd do guia do Postfix](postfix.md#1-run-the-milter) adiciona o endurecimento habitual.


## Relatar uma vulnerabilidade

Relate problemas de segurança de forma privada pelo [sistema de relato de vulnerabilidades do GitHub](https://github.com/spamscanner/spamscanner/security/advisories/new), e não em issues públicas.
