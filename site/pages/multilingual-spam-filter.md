<!--
label: Multilingual spam filter
title: Multilingual spam filter for Chinese, Arabic, Russian and every other script
description: How Spam Scanner filters spam in every language: Unicode word segmentation, undoing disguises, and never flagging a language the model knows little about.
keywords: multilingual spam filter, Chinese spam filter, Arabic spam filter, Russian spam filter, Japanese spam filter, Unicode spam detection, homoglyph spam
-->

# Multilingual spam filter

Many spam filters were built for English. Spam in other languages slips past them, and ordinary mail in other languages gets flagged for its script. Spam Scanner is built to avoid both.


## Reading the words

Words are found with `Intl.Segmenter`, the Unicode word-boundary rules with dictionaries for Chinese, Japanese, Thai, Lao, Khmer and Burmese. A Chinese sentence becomes words such as 恭喜, 获得 and 大奖, not one long string that never repeats.

Disguises are undone before counting: invisible characters inside words, Cyrillic or Greek letters inside Latin words (`pаypal`), digits for letters (`v1agra`), and mathematical or enclosed letters (𝐅𝐑𝐄𝐄). Each disguise is also a clue of its own.


## Not flagging what it does not know

Public spam datasets hold far more foreign-language spam than foreign-language ham, so a naive classifier learns that Arabic or Korean text itself is spam. Spam Scanner never uses the language as a clue, weighs each word against the spam and ham counts of its own language, and stays "unsure" in proportion to how little ham it has seen in a language.

In a test on SMS messages in 21 languages that the bundled model never saw, this took its false positives in Chinese, Arabic, Korean, Japanese, Hindi, Bengali, Urdu, Turkish, Ukrainian and Swedish to zero.


## Catching spam in every language

* **Checks that do not read words:** lookalike domains, deceptive links, executables, macros, SPF, DKIM, DMARC and blocklists.
* **A language model** for unsure messages. Open models such as Qwen 3.5 and Gemma 4 read 140 to 200 languages; the end-to-end tests check spam and ham in Chinese, Arabic, Korean, Hindi and Thai with a real model.
* **Your own mail.** A few hundred messages of each kind in a language give a model trained on your mail full confidence there.

```sh
spamscanner scan message.eml --llm ollama --llm-model qwen3.5:4b
spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out my-model.json
```

To accept only some languages, `--allow-language en,de` adds points to mail confidently detected in any other.

[Languages in detail](../../docs/languages.md)
