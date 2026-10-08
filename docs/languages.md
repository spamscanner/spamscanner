# Languages

Spam arrives in every language, and so does ordinary mail. Spam Scanner reads both, and it is careful about languages it knows little about: a spam filter that flags every Arabic or Chinese message is worse than none.


## Reading every script

* **Words.** Text is split with `Intl.Segmenter`, which follows the Unicode word-boundary rules and uses dictionaries for Chinese, Japanese, Thai, Lao, Khmer and Burmese, scripts written without spaces. Long texts are split into pieces first, because the segmenter in Node.js 18 slows down on very long strings.
* **Normalization.** Unicode NFKC turns full-width letters and most styled letters (𝐅𝐑𝐄𝐄, Ⓕⓡⓔⓔ) into plain ones. Text is lowercased by Unicode rules.
* **Disguises.** Invisible characters inside words (`free` with a zero-width space between two letters, soft hyphens) are removed and counted. Words that mix alphabets, such as `pаypal` with a Cyrillic а, are mapped back to one alphabet and counted. Digits used as letters (`v1agra`) are folded. Each disguise is a feature of its own, and three or more invisible characters, or two or more mixed words, also add points.


## Detecting the language

The language of each message is detected from its script and, for scripts shared by many languages, from its letters:

* Hangul is Korean; Hiragana and Katakana mean Japanese; Thai, Greek, Hebrew, Armenian, Georgian, Bengali, Tamil and other scripts used by one language name it directly.
* Cyrillic letters found in only one language decide between Ukrainian (і, ї, є, ґ), Belarusian (ў), Serbian (ђ, ћ, џ), Macedonian (ѓ, ќ, ѕ) and Russian (ы, э, ё).
* Text in scripts shared by several languages (Latin, Cyrillic, Arabic, Devanagari and others), when long enough to judge, goes to [franc](https://github.com/wooorm/franc), limited to languages common in email so that short messages are not labelled with rare ones.

The language is reported as `result.language`, and `allowedLanguages: ['en', 'de']` (`--allow-language en,de`) adds 3 points to mail confidently detected in any other language.


## Languages the model knows little about

A classifier learns from examples. Public spam datasets contain far more foreign-language spam than foreign-language ham, so a naive classifier learns that Chinese or Arabic text itself means spam. Spam Scanner corrects for this in three ways:

1. **The language is never evidence.** The detected language and script are not used as clues.
2. **Words are weighed within their language.** A word's spam probability is computed against the number of spam and ham messages the classifier saw in the message's language, not in all languages. An everyday Portuguese word in a model that saw mostly Portuguese spam stays neutral.
3. **Confidence follows coverage.** The result is pulled toward "unsure" in proportion to how many messages of each kind the classifier saw in that language: full confidence takes 1,000 of each (or 2% of the smaller class, for small personal models). A language with no ham in the training data always gets "unsure".

The bundled model never saw the [SMS Spam Multilingual Collection](https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset), SMS messages machine-translated into 21 languages. Before these rules, it marked 5.7% of that ham as spam, including 55% of the Portuguese and 41% of the French. With them, 0.18%: none in Chinese, Arabic, Korean, Japanese, Hindi, Portuguese, French or 20 other languages, and 0.27% in English.


## Catching spam in those languages

Unsure is safe, but it does not catch spam. Three things do:

* **The other checks** do not depend on language: lookalike domains, deceptive links, executables, macros, authentication, blocklists, the rules.
* **A language model.** Modern open models read 100 to 200 languages, and Spam Scanner asks one whenever the classifier is unsure. The end-to-end tests check that `qwen3.5:4b` catches spam and passes ham in Chinese, Arabic, Korean, Hindi and Thai. [Language models](llm.md)
* **Training on your mail.** In a model trained on your own mail, a few hundred messages of each kind in a language give the classifier full confidence there. [Training](training.md), and [an optional dataset](training.md#more-languages) that adds 21 languages.
