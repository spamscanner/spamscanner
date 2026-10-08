# Tests and scores

A message is spam at 5 points and rejected at 15. Each test below adds or removes points; the result lists the ones that fired.

Change the thresholds with `threshold` and `rejectThreshold`. Change points with `scores`, either by setting key (`scores: {deceptiveLink: 4}`) or by test name, which fixes that test's points (`scores: {FROM_NAME_BRAND: 4}`).


## Classifier

| Test                      | Points        | Meaning                                                                                                                                                                                                                                                                                                                                            |
| ------------------------- | ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `BAYES_00` to `BAYES_999` | -2.5 to +6.25 | The classifier's spam probability, on a log-odds scale: 2.4 points at 90%, 5 at 99% and 6.25 at 99.9%, so the classifier marks spam on its own only when it is at least 99% sure. The name gives the band: `BAYES_999` is 99.9% or more, `BAYES_99` 99% to 99.9%, `BAYES_50` 40% to 60%. Setting keys `bayesHam` and `bayesSpam` set the two ends. |


## Phishing and links

| Test                        | Points | Setting key         | Meaning                                                               |
| --------------------------- | -----: | ------------------- | --------------------------------------------------------------------- |
| `PHISHING_LOOKALIKE_DOMAIN` |      5 | `homograph`         | A link's domain imitates a brand with lookalike or swapped characters |
| `MIXED_SCRIPT_DOMAIN`       |      3 | `mixedScriptDomain` | A domain label mixes alphabets                                        |
| `BRAND_IN_DOMAIN`           |    1.5 | `brandInDomain`     | A brand name inside someone else's domain                             |
| `TYPO_DOMAIN`               |      1 | `typoDomain`        | One letter away from a brand's domain                                 |
| `DECEPTIVE_LINK`            |      3 | `deceptiveLink`     | A link shows one address and goes to another                          |
| `MALICIOUS_DOMAIN`          |      6 | `maliciousDomain`   | Cloudflare's malware resolver blocks a linked domain                  |
| `ADULT_DOMAIN`              |      2 | `adultDomain`       | Cloudflare's family resolver blocks a linked domain                   |
| `URIBL_<LIST>`              |      5 | `uriblListed`       | A linked domain is on a domain blocklist, for example `URIBL_DBL`     |


## Attachments

| Test                    | Points | Setting key                              | Meaning                                                 |
| ----------------------- | -----: | ---------------------------------------- | ------------------------------------------------------- |
| `EXECUTABLE_ATTACHMENT` |     10 | `executable`                             | A program or script                                     |
| `DISGUISED_EXECUTABLE`  |     12 | `disguisedExecutable`                    | A program named like a document or image                |
| `DOUBLE_EXTENSION`      |      6 | `doubleExtension`                        | A name such as `invoice.pdf.exe`                        |
| `RTL_OVERRIDE_FILENAME` |      6 | `rtlOverride`                            | A right-to-left override hides the real extension       |
| `EXECUTABLE_IN_ARCHIVE` |      8 | `executableInArchive`                    | A program inside a ZIP file                             |
| `ENCRYPTED_ARCHIVE`     |      2 | `encryptedArchive`                       | An archive scanners cannot open                         |
| `MACRO_ATTACHMENT`      |      4 | `macro`                                  | An Office file with macros                              |
| `PDF_ACTIVE_CONTENT`    |      3 | `pdfActive`                              | A PDF with JavaScript, launch actions or embedded files |
| `RTF_EMBEDDED_OBJECT`   |      4 | `rtfObject`                              | An RTF file with embedded objects                       |
| `HTML_ATTACHMENT`       | 1 or 3 | `htmlAttachment`, `activeHtmlAttachment` | An HTML file; 3 when it has scripts or forms            |
| `VIRUS`                 |    100 | `virus`                                  | ClamAV found a virus                                    |


## Rules

| Test                      | Points | Meaning                                                                                         |
| ------------------------- | -----: | ----------------------------------------------------------------------------------------------- |
| `GTUBE`                   |   1000 | The GTUBE test string                                                                           |
| `SEXTORTION_SUBJECT`      |      6 | A subject used by sextortion and account takeover scams                                         |
| `PAYPAL_INVOICE`          |      6 | A PayPal invoice or money request, a channel abused for scams                                   |
| `MICROSOFT_SPAM_VERDICT`  |      5 | Microsoft marked the message as spam before relaying it (trusted only from Microsoft's servers) |
| `MICROSOFT_HIGH_SCL`      |      3 | Microsoft gave it a high spam confidence level (likewise)                                       |
| `PROMPT_INJECTION`        |      3 | Text addressed to an AI filter                                                                  |
| `SELF_SPOOF`              |      3 | Claims to be from the recipient's own domain and does not authenticate                          |
| `FROM_NAME_OTHER_ADDRESS` |    2.5 | The display name contains a different email address                                             |
| `FROM_NAME_BRAND`         |      2 | The display name claims a brand the address does not belong to                                  |
| `DATE_IN_FUTURE`          |      1 | Dated more than a day ahead                                                                     |
| `MISSING_DATE`            |    0.5 | No Date header                                                                                  |
| `MISSING_MESSAGE_ID`      |    0.5 | No Message-ID header                                                                            |

Rules worth at least the spam threshold also appear in `results.arbitrary`, as in earlier versions.


## Obfuscation and language

| Test                   | Points | Setting key           | Meaning                                                |
| ---------------------- | -----: | --------------------- | ------------------------------------------------------ |
| `INVISIBLE_CHARACTERS` |      2 | `invisibleCharacters` | Three or more invisible characters inside the text     |
| `MIXED_SCRIPT_WORDS`   |    2.5 | `mixedScriptWords`    | Two or more words mix letters from different alphabets |
| `STYLED_LETTERS`       |    1.5 | `styledLetters`       | Mathematical or enclosed letters posing as plain text  |
| `LANGUAGE_NOT_ALLOWED` |      3 | `languageNotAllowed`  | Not in `allowedLanguages`                              |


## Authentication

Needs the client's IP address and `authentication: true`.

| Test           | Points | Setting key (in `authentication.weights`) |
| -------------- | -----: | ----------------------------------------- |
| `SPF_PASS`     |   -0.5 | `spfPass`                                 |
| `SPF_FAIL`     |      2 | `spfFail`                                 |
| `SPF_SOFTFAIL` |      1 | `spfSoftfail`                             |
| `DKIM_PASS`    |   -0.5 | `dkimPass`                                |
| `DKIM_FAIL`    |      1 | `dkimFail`                                |
| `DMARC_PASS`   |   -1.5 | `dmarcPass`                               |
| `DMARC_FAIL`   |    3.5 | `dmarcFail`                               |
| `ARC_PASS`     |   -0.5 | `arcPass`                                 |
| `ARC_FAIL`     |      1 | `arcFail`                                 |


## Reputation and blocklists

| Test           | Points | Setting key   | Meaning                                                          |
| -------------- | -----: | ------------- | ---------------------------------------------------------------- |
| `DENYLISTED`   |    100 | `denylisted`  | The sender's IP address, domain or address is on the denylist    |
| `ALLOWLISTED`  |    -20 | `allowlisted` | It is on the allowlist                                           |
| `TRUTH_SOURCE` |     -5 | `truthSource` | A reputation service marks the sender as trusted                 |
| `RBL_<LIST>`   |      4 | `rblListed`   | The client's IP address is on a blocklist, for example `RBL_ZEN` |


## Language model and optional models

| Test                                                  | Points     | Setting key | Meaning                                      |
| ----------------------------------------------------- | ---------- | ----------- | -------------------------------------------- |
| `LLM_SPAM`, `LLM_PHISHING`, `LLM_SCAM`, `LLM_MALWARE` | up to +6   | `llmSpam`   | The model's verdict, times its confidence    |
| `LLM_HAM`                                             | down to -3 | `llmHam`    | Likewise                                     |
| `TOXIC_CONTENT`                                       | 3          | `toxicity`  | A toxicity model you supply flagged the text |
| `NSFW_IMAGE`                                          | 3          | `nsfw`      | An image model you supply flagged an image   |
