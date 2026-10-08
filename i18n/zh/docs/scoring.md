<!-- source: 6f6b765c5fc1 -->

# 测试与分值

邮件达到 5 分即为垃圾邮件，达到 15 分即被拒收。下面每项测试都会加分或减分；结果会列出触发的测试。

用 `threshold` 和 `rejectThreshold` 修改阈值。用 `scores` 修改分值，既可以按设置键（`scores: {deceptiveLink: 4}`），也可以按测试名称，后者会固定该测试的分值（`scores: {FROM_NAME_BRAND: 4}`）。


## 分类器

| 测试                       | 分值           | 含义                                                                                                                                                                                                              |
| ------------------------ | ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BAYES_00` 到 `BAYES_999` | -2.5 到 +6.25 | 分类器的垃圾邮件概率，按对数几率换算：90% 时为 2.4 分，99% 时为 5 分，99.9% 时为 6.25 分，因此分类器只有在至少 99% 确定时才会单独判定为垃圾邮件。名称表示所在区间：`BAYES_999` 为 99.9% 或以上，`BAYES_99` 为 99% 到 99.9%，`BAYES_50` 为 40% 到 60%。设置键 `bayesHam` 和 `bayesSpam` 设定两端的分值。 |


## 钓鱼和链接

| 测试                          |  分值 | 设置键                 | 含义                          |
| --------------------------- | --: | ------------------- | --------------------------- |
| `PHISHING_LOOKALIKE_DOMAIN` |   5 | `homograph`         | 链接的域名用形似或调换的字符模仿某个品牌        |
| `MIXED_SCRIPT_DOMAIN`       |   3 | `mixedScriptDomain` | 域名标签混用多种字母表                 |
| `BRAND_IN_DOMAIN`           | 1.5 | `brandInDomain`     | 品牌名出现在他人的域名中                |
| `TYPO_DOMAIN`               |   1 | `typoDomain`        | 与某个品牌的域名相差一个字母              |
| `DECEPTIVE_LINK`            |   3 | `deceptiveLink`     | 链接显示一个地址，却指向另一个地址           |
| `MALICIOUS_DOMAIN`          |   6 | `maliciousDomain`   | Cloudflare 的恶意软件解析器拦截了链接的域名 |
| `ADULT_DOMAIN`              |   2 | `adultDomain`       | Cloudflare 的家庭解析器拦截了链接的域名   |
| `URIBL_<LIST>`              |   5 | `uriblListed`       | 链接的域名在域名黑名单上，例如 `URIBL_DBL` |


## 附件

| 测试                      |    分值 | 设置键                                     | 含义                          |
| ----------------------- | ----: | --------------------------------------- | --------------------------- |
| `EXECUTABLE_ATTACHMENT` |    10 | `executable`                            | 程序或脚本                       |
| `DISGUISED_EXECUTABLE`  |    12 | `disguisedExecutable`                   | 名称伪装成文档或图片的程序               |
| `DOUBLE_EXTENSION`      |     6 | `doubleExtension`                       | 例如 `invoice.pdf.exe` 这样的名称  |
| `RTL_OVERRIDE_FILENAME` |     6 | `rtlOverride`                           | 从右到左覆盖字符隐藏了真实扩展名            |
| `EXECUTABLE_IN_ARCHIVE` |     8 | `executableInArchive`                   | ZIP 文件中的程序                  |
| `ENCRYPTED_ARCHIVE`     |     2 | `encryptedArchive`                      | 扫描程序无法打开的压缩包                |
| `MACRO_ATTACHMENT`      |     4 | `macro`                                 | 带宏的 Office 文件               |
| `PDF_ACTIVE_CONTENT`    |     3 | `pdfActive`                             | 带 JavaScript、启动动作或嵌入文件的 PDF |
| `RTF_EMBEDDED_OBJECT`   |     4 | `rtfObject`                             | 带嵌入对象的 RTF 文件               |
| `HTML_ATTACHMENT`       | 1 或 3 | `htmlAttachment`、`activeHtmlAttachment` | HTML 文件；含脚本或表单时为 3          |
| `VIRUS`                 |   100 | `virus`                                 | ClamAV 发现了病毒                |


## 规则

| 测试                        |   分值 | 含义                                                  |
| ------------------------- | ---: | --------------------------------------------------- |
| `GTUBE`                   | 1000 | GTUBE 测试字符串                                         |
| `SEXTORTION_SUBJECT`      |    6 | 性勒索和账户劫持诈骗使用的主题                                     |
| `PAYPAL_INVOICE`          |    6 | PayPal 账单或收款请求，这一渠道常被用于诈骗                           |
| `MICROSOFT_SPAM_VERDICT`  |    5 | Microsoft 在转发邮件之前已将其标记为垃圾邮件（仅信任来自 Microsoft 服务器的邮件） |
| `MICROSOFT_HIGH_SCL`      |    3 | Microsoft 给出了较高的垃圾邮件置信度级别（同上）                       |
| `PROMPT_INJECTION`        |    3 | 针对 AI 过滤器的文字                                        |
| `SELF_SPOOF`              |    3 | 声称来自收件人自己的域名，却未通过身份验证                               |
| `FROM_NAME_OTHER_ADDRESS` |  2.5 | 显示名称包含另一个电子邮件地址                                     |
| `FROM_NAME_BRAND`         |    2 | 显示名称自称某个品牌，而地址并不属于该品牌                               |
| `DATE_IN_FUTURE`          |    1 | 日期超前一天以上                                            |
| `MISSING_DATE`            |  0.5 | 没有 Date 邮件头                                         |
| `MISSING_MESSAGE_ID`      |  0.5 | 没有 Message-ID 邮件头                                   |

分值至少达到垃圾邮件阈值的规则也会像早期版本一样出现在 `results.arbitrary` 中。


## 混淆和语言

| 测试                     |  分值 | 设置键                   | 含义                      |
| ---------------------- | --: | --------------------- | ----------------------- |
| `INVISIBLE_CHARACTERS` |   2 | `invisibleCharacters` | 文本中有三个或更多不可见字符          |
| `MIXED_SCRIPT_WORDS`   | 2.5 | `mixedScriptWords`    | 两个或更多词语混用了不同字母表的字母      |
| `STYLED_LETTERS`       | 1.5 | `styledLetters`       | 冒充普通文字的数学字母或带圈字母        |
| `LANGUAGE_NOT_ALLOWED` |   3 | `languageNotAllowed`  | 不在 `allowedLanguages` 中 |


## 身份验证

需要客户端的 IP 地址和 `authentication: true`。

| 测试             |   分值 | 设置键（在 `authentication.weights` 中） |
| -------------- | ---: | --------------------------------- |
| `SPF_PASS`     | -0.5 | `spfPass`                         |
| `SPF_FAIL`     |    2 | `spfFail`                         |
| `SPF_SOFTFAIL` |    1 | `spfSoftfail`                     |
| `DKIM_PASS`    | -0.5 | `dkimPass`                        |
| `DKIM_FAIL`    |    1 | `dkimFail`                        |
| `DMARC_PASS`   | -1.5 | `dmarcPass`                       |
| `DMARC_FAIL`   |  3.5 | `dmarcFail`                       |
| `ARC_PASS`     | -0.5 | `arcPass`                         |
| `ARC_FAIL`     |    1 | `arcFail`                         |


## 信誉和黑名单

| 测试             |  分值 | 设置键           | 含义                           |
| -------------- | --: | ------------- | ---------------------------- |
| `DENYLISTED`   | 100 | `denylisted`  | 发件人的 IP 地址、域名或地址在拒绝列表上       |
| `ALLOWLISTED`  | -20 | `allowlisted` | 发件人在允许列表上                    |
| `TRUTH_SOURCE` |  -5 | `truthSource` | 信誉服务将发件人标记为可信                |
| `RBL_<LIST>`   |   4 | `rblListed`   | 客户端的 IP 地址在黑名单上，例如 `RBL_ZEN` |


## 语言模型和可选模型

| 测试                                                 | 分值    | 设置键        | 含义              |
| -------------------------------------------------- | ----- | ---------- | --------------- |
| `LLM_SPAM`、`LLM_PHISHING`、`LLM_SCAM`、`LLM_MALWARE` | 最多 +6 | `llmSpam`  | 模型的判定乘以其置信度     |
| `LLM_HAM`                                          | 最多 -3 | `llmHam`   | 同上              |
| `TOXIC_CONTENT`                                    | 3     | `toxicity` | 你提供的毒性模型标记了该文本  |
| `NSFW_IMAGE`                                       | 3     | `nsfw`     | 你提供的图像模型标记了某张图片 |
