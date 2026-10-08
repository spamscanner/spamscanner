<!-- source: 6f6b765c5fc1 -->

# Testes e pontuações

Uma mensagem é spam com 5 pontos e é rejeitada com 15. Cada teste abaixo adiciona ou remove pontos; o resultado lista os que foram acionados.

Altere os limites com `threshold` e `rejectThreshold`. Altere os pontos com `scores`, pela chave de configuração (`scores: {deceptiveLink: 4}`) ou pelo nome do teste, o que fixa os pontos desse teste (`scores: {FROM_NAME_BRAND: 4}`).


## Classificador

| Teste                    | Pontos       | Significado                                                                                                                                                                                                                                                                                                                                                                           |
| ------------------------ | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BAYES_00` a `BAYES_999` | -2,5 a +6,25 | A probabilidade de spam do classificador, em escala de log-odds: 2,4 pontos com 90%, 5 com 99% e 6,25 com 99,9%, então o classificador só marca spam sozinho quando tem pelo menos 99% de certeza. O nome indica a faixa: `BAYES_999` é 99,9% ou mais, `BAYES_99` de 99% a 99,9%, `BAYES_50` de 40% a 60%. As chaves de configuração `bayesHam` e `bayesSpam` definem as duas pontas. |


## Phishing e links

| Teste                       | Pontos | Chave de configuração | Significado                                                                           |
| --------------------------- | -----: | --------------------- | ------------------------------------------------------------------------------------- |
| `PHISHING_LOOKALIKE_DOMAIN` |      5 | `homograph`           | O domínio de um link imita uma marca com caracteres parecidos ou trocados             |
| `MIXED_SCRIPT_DOMAIN`       |      3 | `mixedScriptDomain`   | Um rótulo de domínio mistura alfabetos                                                |
| `BRAND_IN_DOMAIN`           |    1,5 | `brandInDomain`       | Um nome de marca dentro do domínio de outra pessoa                                    |
| `TYPO_DOMAIN`               |      1 | `typoDomain`          | A uma letra de distância do domínio de uma marca                                      |
| `DECEPTIVE_LINK`            |      3 | `deceptiveLink`       | Um link mostra um endereço e leva a outro                                             |
| `MALICIOUS_DOMAIN`          |      6 | `maliciousDomain`     | O resolvedor de malware da Cloudflare bloqueia um domínio linkado                     |
| `ADULT_DOMAIN`              |      2 | `adultDomain`         | O resolvedor familiar da Cloudflare bloqueia um domínio linkado                       |
| `URIBL_<LIST>`              |      5 | `uriblListed`         | Um domínio linkado está em uma lista de bloqueio de domínios, por exemplo `URIBL_DBL` |


## Anexos

| Teste                   | Pontos | Chave de configuração                    | Significado                                                         |
| ----------------------- | -----: | ---------------------------------------- | ------------------------------------------------------------------- |
| `EXECUTABLE_ATTACHMENT` |     10 | `executable`                             | Um programa ou script                                               |
| `DISGUISED_EXECUTABLE`  |     12 | `disguisedExecutable`                    | Um programa com nome de documento ou imagem                         |
| `DOUBLE_EXTENSION`      |      6 | `doubleExtension`                        | Um nome como `invoice.pdf.exe`                                      |
| `RTL_OVERRIDE_FILENAME` |      6 | `rtlOverride`                            | Uma substituição da direita para a esquerda esconde a extensão real |
| `EXECUTABLE_IN_ARCHIVE` |      8 | `executableInArchive`                    | Um programa dentro de um arquivo ZIP                                |
| `ENCRYPTED_ARCHIVE`     |      2 | `encryptedArchive`                       | Um arquivo compactado que os analisadores não conseguem abrir       |
| `MACRO_ATTACHMENT`      |      4 | `macro`                                  | Um arquivo do Office com macros                                     |
| `PDF_ACTIVE_CONTENT`    |      3 | `pdfActive`                              | Um PDF com JavaScript, ações de execução ou arquivos incorporados   |
| `RTF_EMBEDDED_OBJECT`   |      4 | `rtfObject`                              | Um arquivo RTF com objetos incorporados                             |
| `HTML_ATTACHMENT`       | 1 ou 3 | `htmlAttachment`, `activeHtmlAttachment` | Um arquivo HTML; 3 quando tem scripts ou formulários                |
| `VIRUS`                 |    100 | `virus`                                  | O ClamAV encontrou um vírus                                         |


## Regras

| Teste                     | Pontos | Significado                                                                                                             |
| ------------------------- | -----: | ----------------------------------------------------------------------------------------------------------------------- |
| `GTUBE`                   |   1000 | A sequência de teste GTUBE                                                                                              |
| `SEXTORTION_SUBJECT`      |      6 | Um assunto usado em golpes de sextorsão e de sequestro de conta                                                         |
| `PAYPAL_INVOICE`          |      6 | Uma fatura ou um pedido de dinheiro do PayPal, um canal usado para golpes                                               |
| `MICROSOFT_SPAM_VERDICT`  |      5 | A Microsoft marcou a mensagem como spam antes de retransmiti-la (só é confiável quando vem dos servidores da Microsoft) |
| `MICROSOFT_HIGH_SCL`      |      3 | A Microsoft deu a ela um nível alto de confiança de spam (idem)                                                         |
| `PROMPT_INJECTION`        |      3 | Texto dirigido a um filtro de IA                                                                                        |
| `SELF_SPOOF`              |      3 | Alega vir do próprio domínio do destinatário e não se autentica                                                         |
| `FROM_NAME_OTHER_ADDRESS` |    2,5 | O nome de exibição contém um endereço de e-mail diferente                                                               |
| `FROM_NAME_BRAND`         |      2 | O nome de exibição alega uma marca à qual o endereço não pertence                                                       |
| `DATE_IN_FUTURE`          |      1 | Datada com mais de um dia de antecedência                                                                               |
| `MISSING_DATE`            |    0,5 | Sem cabeçalho Date                                                                                                      |
| `MISSING_MESSAGE_ID`      |    0,5 | Sem cabeçalho Message-ID                                                                                                |

As regras que valem pelo menos o limite de spam também aparecem em `results.arbitrary`, como nas versões anteriores.


## Ofuscação e idioma

| Teste                  | Pontos | Chave de configuração | Significado                                                    |
| ---------------------- | -----: | --------------------- | -------------------------------------------------------------- |
| `INVISIBLE_CHARACTERS` |      2 | `invisibleCharacters` | Três ou mais caracteres invisíveis dentro do texto             |
| `MIXED_SCRIPT_WORDS`   |    2,5 | `mixedScriptWords`    | Duas ou mais palavras misturam letras de alfabetos diferentes  |
| `STYLED_LETTERS`       |    1,5 | `styledLetters`       | Letras matemáticas ou circuladas se passando por texto simples |
| `LANGUAGE_NOT_ALLOWED` |      3 | `languageNotAllowed`  | Não está em `allowedLanguages`                                 |


## Autenticação

Precisa do endereço IP do cliente e de `authentication: true`.

| Teste          | Pontos | Chave de configuração (em `authentication.weights`) |
| -------------- | -----: | --------------------------------------------------- |
| `SPF_PASS`     |   -0,5 | `spfPass`                                           |
| `SPF_FAIL`     |      2 | `spfFail`                                           |
| `SPF_SOFTFAIL` |      1 | `spfSoftfail`                                       |
| `DKIM_PASS`    |   -0,5 | `dkimPass`                                          |
| `DKIM_FAIL`    |      1 | `dkimFail`                                          |
| `DMARC_PASS`   |   -1,5 | `dmarcPass`                                         |
| `DMARC_FAIL`   |    3,5 | `dmarcFail`                                         |
| `ARC_PASS`     |   -0,5 | `arcPass`                                           |
| `ARC_FAIL`     |      1 | `arcFail`                                           |


## Reputação e listas de bloqueio

| Teste          | Pontos | Chave de configuração | Significado                                                                   |
| -------------- | -----: | --------------------- | ----------------------------------------------------------------------------- |
| `DENYLISTED`   |    100 | `denylisted`          | O endereço IP, o domínio ou o endereço do remetente está na lista de bloqueio |
| `ALLOWLISTED`  |    -20 | `allowlisted`         | Está na lista de permissão                                                    |
| `TRUTH_SOURCE` |     -5 | `truthSource`         | Um serviço de reputação marca o remetente como confiável                      |
| `RBL_<LIST>`   |      4 | `rblListed`           | O endereço IP do cliente está em uma lista de bloqueio, por exemplo `RBL_ZEN` |


## Modelo de linguagem e modelos opcionais

| Teste                                                 | Pontos | Chave de configuração | Significado                                               |
| ----------------------------------------------------- | ------ | --------------------- | --------------------------------------------------------- |
| `LLM_SPAM`, `LLM_PHISHING`, `LLM_SCAM`, `LLM_MALWARE` | até +6 | `llmSpam`             | O veredito do modelo, multiplicado pela sua confiança     |
| `LLM_HAM`                                             | até -3 | `llmHam`              | Idem                                                      |
| `TOXIC_CONTENT`                                       | 3      | `toxicity`            | Um modelo de toxicidade fornecido por você marcou o texto |
| `NSFW_IMAGE`                                          | 3      | `nsfw`                | Um modelo de imagem fornecido por você marcou uma imagem  |
