<!-- source: a59bc5927d86 -->

# Linha de comando

```text
spamscanner <command> [options]
```

| Comando                                    | O que faz                                                                                            |
| ------------------------------------------ | ---------------------------------------------------------------------------------------------------- |
| `scan [file\|-]`                           | Analisa uma mensagem de um arquivo ou da entrada padrão                                              |
| `filter -f <sender> -- <recipients...>`    | Filtro de conteúdo do Postfix: analisa a entrada padrão, adiciona os cabeçalhos e repassa a mensagem |
| `milter`                                   | Milter para Postfix e Sendmail, porta 7831                                                           |
| `http`                                     | API HTTP, porta 7832                                                                                 |
| `server`                                   | Servidor TCP simples, porta 7830                                                                     |
| `spamd`                                    | Servidor spamd compatível com o SpamAssassin, porta 783                                              |
| `train`                                    | Treina um modelo a partir de arquivos mbox, Maildirs, pastas ou conjuntos de dados                   |
| `eval`                                     | Mede um modelo com e-mails rotulados                                                                 |
| `learn spam\|ham [file\|-] --model <file>` | Ensina uma mensagem a um modelo                                                                      |
| `llm-test`                                 | Confere as configurações do modelo de linguagem com três mensagens de exemplo                        |
| `models`                                   | Lista os modelos abertos recomendados                                                                |
| `version`, `help`                          |                                                                                                      |


## scan

```sh
spamscanner scan message.eml
spamscanner scan - < message.eml
spamscanner scan message.eml --json
spamscanner scan message.eml --headers > tagged.eml
spamscanner scan message.eml --subject-tag "[SPAM]" > tagged.eml
```

| Opção                      | Significado                                                     |
| -------------------------- | --------------------------------------------------------------- |
| `--json`                   | Imprime o resultado completo em JSON                            |
| `--headers`                | Imprime a mensagem com os cabeçalhos `X-Spam-*` adicionados     |
| `--subject-tag <tag>`      | Também adiciona um prefixo ao assunto do spam                   |
| `--verbose`                | Mostra todos os testes e as pistas mais fortes do classificador |
| `--threshold <n>`          | Pontuação a partir da qual o e-mail é spam (padrão 5)           |
| `--reject-threshold <n>`   | Pontuação a partir da qual o e-mail é rejeitado (padrão 15)     |
| `--model <file>`           | Um arquivo de modelo no lugar do incluído                       |
| `--no-classifier`          | Não usa o classificador                                         |
| `--config <file>`          | Um arquivo JSON com [opções da biblioteca](api.md#options)      |
| `--allow-language <codes>` | Idiomas aceitos, por exemplo `en,de,fr`                         |

Códigos de saída: 0 ham, 1 spam, 2 erro.

### Sessão SMTP

| Opção               | Significado                                  |
| ------------------- | -------------------------------------------- |
| `--ip <address>`    | Endereço IP do cliente que enviou a mensagem |
| `--hostname <name>` | O nome DNS reverso verificado do cliente     |
| `--helo <name>`     | O nome que ele informou no HELO ou EHLO      |
| `--from <address>`  | Remetente do envelope (MAIL FROM)            |
| `--to <address>`    | Destinatário do envelope; repita para vários |

### Verificações

| Opção                 | Significado                                                                                 |
| --------------------- | ------------------------------------------------------------------------------------------- |
| `--auth`              | Verifica SPF, DKIM, DMARC e ARC (precisa de `--ip`)                                         |
| `--dnsbl <zone>`      | Lista de bloqueio de IPs, por exemplo `zen.spamhaus.org`; pode ser repetida                 |
| `--uribl <zone>`      | Lista de bloqueio de domínios para links, por exemplo `dbl.spamhaus.org`; pode ser repetida |
| `--dns-server <ip>`   | Servidor de nomes para as verificações DNS; pode ser repetida                               |
| `--no-cloudflare`     | Não consulta os resolvedores com filtragem da Cloudflare sobre os links                     |
| `--clamav [socket]`   | Analisa os anexos com o clamd, no socket padrão ou no informado                             |
| `--allowlist <value>` | Sempre aceita este endereço IP, domínio ou endereço; pode ser repetida                      |
| `--denylist <value>`  | Sempre rejeita este endereço IP, domínio ou endereço; pode ser repetida                     |

### Modelo de linguagem

| Opção                                                      | Significado                                                                    |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `--llm <provider>`                                         | `ollama`, `openai`, `anthropic`, `gemini` e outros ([lista](llm.md#providers)) |
| `--llm-model <name>`                                       | Modelo, por exemplo `qwen3.5:4b` ou `claude-haiku-4-5`                         |
| `--llm-url <url>`                                          | URL base, por exemplo `http://10.0.0.5:11434`                                  |
| `--llm-host`, `--llm-port`, `--llm-path`, `--llm-protocol` | Altera uma parte da URL do provedor                                            |
| `--llm-api-key <key>`                                      | Chave de API; veja também as variáveis de ambiente abaixo                      |
| `--llm-auth <type>`                                        | `bearer`, `x-api-key`, `api-key`, `basic`, `header` ou `none`                  |
| `--llm-auth-header <name>`                                 | Cabeçalho para a chave, com `--llm-auth header`                                |
| `--llm-username`, `--llm-password`                         | Para `--llm-auth basic`                                                        |
| `--llm-header "Name: value"`                               | Cabeçalho extra na requisição; pode ser repetida                               |
| `--llm-mode <mode>`                                        | `auto` (só os casos duvidosos, o padrão) ou `always`                           |
| `--llm-timeout <ms>`                                       | Padrão 30000                                                                   |
| `--llm-policy <text>`                                      | Regras extras para o modelo, por exemplo “Nunca enviamos faturas”              |
| `--llm-redact`, `--no-llm-redact`                          | Remove os dados pessoais antes; ativado por padrão para provedores remotos     |


## filter

Um [filtro de conteúdo do Postfix](postfix.md#content-filter). Ele lê uma mensagem da entrada padrão, adiciona os cabeçalhos `X-Spam-*` e a repassa ao sendmail com o mesmo envelope.

```sh
spamscanner filter -f "$sender" -- "$recipient"
```

| Opção                 | Significado                                                                |
| --------------------- | -------------------------------------------------------------------------- |
| `--sendmail <path>`   | Padrão `/usr/sbin/sendmail`                                                |
| `--subject-tag <tag>` | Adiciona um prefixo ao assunto do spam                                     |
| `--reject`            | Devolve os e-mails que atingem o limite de rejeição em vez de repassá-los  |
| `--discard`           | Descarta os e-mails que atingem o limite de rejeição em vez de repassá-los |

Os códigos de saída seguem as convenções do sendmail, que o Postfix lê: 0, entregue (ou descartado); 64, nenhum destinatário informado; 69, rejeitado como spam (o Postfix o devolve); 75, qualquer falha, então o Postfix guarda a mensagem e tenta de novo mais tarde.


## milter, http, server e spamd

```sh
spamscanner milter --port 7831 --reject --subject-tag "[SPAM]"
spamscanner http --port 7832 --token "$SPAMSCANNER_TOKEN"
spamscanner server --port 7830
spamscanner spamd --port 783
```

A porta 783 é a que os clientes do SpamAssassin usam por padrão. Portas abaixo de 1024 exigem root ou a capability `CAP_NET_BIND_SERVICE`; use outra porta, como `--port 7833`, e informe-a ao cliente.

| Opção                 | Significado                                                                  |
| --------------------- | ---------------------------------------------------------------------------- |
| `--port <n>`          | Porta TCP                                                                    |
| `--host <ip>`         | Endereço em que escutar (padrão 127.0.0.1)                                   |
| `--socket <path>`     | Escuta em um socket Unix                                                     |
| `--reject`            | Milter: recusa os e-mails que atingem o limite de rejeição                   |
| `--reject-code <n>`   | Milter: 451, tente de novo mais tarde (o padrão), ou 550                     |
| `--quarantine`        | Milter: retém o spam na quarentena do servidor de e-mail                     |
| `--name <hostname>`   | Milter: o nome deste servidor no Authentication-Results                      |
| `--token <secret>`    | HTTP: exige `Authorization: Bearer <secret>`; necessário para `/learn`       |
| `--allow-tell`        | spamd: aceita requisições TELL (`spamc -L spam`) para aprendizado            |
| `--out <file>`        | HTTP e spamd: salva o que é aprendido neste arquivo de modelo                |
| `--subject-tag <tag>` | Milter e spamd: adiciona um prefixo ao assunto do spam                       |
| `--verbose`           | Milter: registra cada análise. Servidor TCP: responde com uma linha de texto |

As opções de análise acima também valem para os servidores. [O milter](postfix.md#milter), [a API HTTP, o servidor TCP e o spamd](http-api.md).


## train, eval e learn

```sh
spamscanner train --spam ~/Mail/Junk --ham ~/Mail/Archive --out my-model.json
spamscanner eval --model my-model.json --spam test/spam.mbox --ham test/ham.mbox
spamscanner learn spam message.eml --model my-model.json
```

| Opção                                           | Significado                                                                          |
| ----------------------------------------------- | ------------------------------------------------------------------------------------ |
| `--spam <path>`                                 | Spam: um arquivo mbox, um Maildir ou uma pasta de arquivos `.eml`; pode ser repetida |
| `--ham <path>`                                  | Ham, da mesma forma; pode ser repetida                                               |
| `--dataset <file>`                              | Um arquivo CSV ou JSON Lines com colunas de texto e de rótulo; pode ser repetida     |
| `--text-column <name>`, `--label-column <name>` | Nomes das colunas, quando não são detectados                                         |
| `--out <file>`                                  | Onde gravar o modelo (padrão `spamscanner-model.json`)                               |
| `--merge`                                       | Parte do modelo incluído (ou de `--model`) em vez de um modelo vazio                 |

O `learn` atualiza o arquivo de modelo no próprio lugar e o cria a partir do modelo incluído na primeira vez. [Treinamento](training.md)


## llm-test e models

```sh
spamscanner models
spamscanner llm-test --llm ollama --llm-model qwen3.5:4b
```

O `llm-test` envia ao modelo uma mensagem comum e dois golpes, em inglês e em italiano, imprime os vereditos e sai com 0 somente se os três estiverem corretos.


## Arquivo de configuração

O `--config file.json` (ou a variável de ambiente `SPAMSCANNER_CONFIG`) carrega [opções da biblioteca](api.md#options). As opções da linha de comando têm prioridade sobre o arquivo.

```json
{
  "threshold": 6,
  "authentication": true,
  "dnsbl": {"ip": ["zen.spamhaus.org"], "domain": ["dbl.spamhaus.org"]},
  "dns": {"servers": ["127.0.0.1"]},
  "clamav": {"socket": "/var/run/clamav/clamd.ctl"},
  "llm": {"provider": "ollama", "model": "qwen3.5:4b"},
  "scores": {"deceptiveLink": 4, "FROM_NAME_BRAND": 3}
}
```


## Variáveis de ambiente

| Variável                                                                                                                                                                                                                                             | Significado                                                |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| `SPAMSCANNER_CONFIG`                                                                                                                                                                                                                                 | Arquivo de configuração                                    |
| `SPAMSCANNER_MODEL`                                                                                                                                                                                                                                  | Arquivo de modelo usado no lugar do incluído               |
| `SPAMSCANNER_TOKEN`                                                                                                                                                                                                                                  | Token da API HTTP                                          |
| `SPAMSCANNER_LLM_API_KEY`                                                                                                                                                                                                                            | Chave de API para qualquer provedor de modelo de linguagem |
| `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `DEEPSEEK_API_KEY`, `XAI_API_KEY`, `TOGETHER_API_KEY`, `FIREWORKS_API_KEY`, `CEREBRAS_API_KEY`, `HF_TOKEN`, `AZURE_OPENAI_API_KEY` | A chave de cada provedor                                   |
| `NODE_DEBUG=spamscanner*`                                                                                                                                                                                                                            | Logs de depuração                                          |
