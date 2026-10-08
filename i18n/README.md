# Translations

spamscanner.net is translated into the languages in [`locales.json`](locales.json). English is the source: the build reads the English pages and falls back to them for anything not translated yet, marking those copies `noindex`.

```text
i18n/
  locales.json            the languages
  source/ui.json          every interface string, written by npm run site:build
  source/hashes.json      a hash of each English page, written by npm run site:build
  <code>/ui.json          interface strings: the English string is the key
  <code>/docs/<name>.md   docs/<name>.md, translated
  <code>/pages/<name>.md  site/pages/<name>.md, translated
```


## Translating a page

A translated page starts with the hash of the English file it was translated from, then a blank line, then the translation:

```md
<!-- source: f33722183f00 -->

<!--
label: …
title: …
description: …
keywords: …
-->

# …
```

The hash is in `source/hashes.json`. When the English page changes, its hash changes, and the site shows English for that page until the translation is updated and its first line changed to the new hash.

Keep from the English page:

* every heading, at the same level and in the same order (translate the text),
* every code block exactly as it is, comments included,
* every piece of inline code, such as `--model` or `BAYES_999`,
* every link and image address, anchors included (translate the link text),
* the front matter keys (translate the values).

Product, protocol and test names stay as they are: Spam Scanner, Postfix, Ollama, milter, spamd, SPF, `PHISHING_LOOKALIKE_DOMAIN`.


## Interface strings

`<code>/ui.json` has every key in `source/ui.json`. Keep placeholders such as `{duration}` and `{link}`.


## Checking

```sh
npm run site:build
npm run i18n:check          # every language
npm run i18n:check -- de    # one
```

The check fails on a missing or outdated translation, a missing string, changed placeholders, and on headings, code, inline code, links or front matter that differ from the English page.
