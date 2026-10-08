<!-- source: c93fa1a3f9c7 -->

<!--
label: FAQ
title: Najczęściej zadawane pytania
description: Odpowiedzi o Spam Scanner: jaka jest jego skuteczność, jakie języki obsługuje, co wysyła przez sieć, modele językowe, SpamAssassin i Forward Email.
keywords: Spam Scanner FAQ, pytania o filtr antyspamowy, skuteczność filtra antyspamowego, prywatność filtra antyspamowego
-->

# Najczęściej zadawane pytania


## Czym jest Spam Scanner?

To filtr antyspamowy dla Node.js, wiersza poleceń i serwerów pocztowych. Czyta surową wiadomość e-mail i rozstrzyga, czy jest spamem, phishingiem, oszustwem lub czy zawiera złośliwe oprogramowanie, podając wynik i listę testów, które o tym przesądziły. Działa jako biblioteka, milter dla Postfix i Sendmail, serwer spamd zgodny ze SpamAssassin, filtr treści Postfix, HTTP API lub serwer TCP.


## Czy jest darmowy?

Jego [licencja](https://github.com/spamscanner/spamscanner/blob/master/LICENSE), Business Source License 1.1, pozwala na każde użycie z wyjątkiem oferowania wykrywania spamu innym jako usługi i podaje datę, w której zmienia się na Apache License 2.0.


## Jaka jest jego skuteczność?

Na odłożonych angielskich wiadomościach z danych treningowych sam dołączony klasyfikator nie oznaczył jako spam żadnego hamu i wyłapał 97% spamu; pełne liczby dla każdego języka są w [poradniku trenowania](../../docs/training.md#the-bundled-model). Linki, załączniki, uwierzytelnianie, czarne listy i model językowy dokładają swoje. Prawdziwym testem jest twoja własna poczta: `spamscanner eval` mierzy dowolny model na dowolnej oznaczonej poczcie.


## Jakie języki obsługuje?

Wszystkie. Dzieli tekst na słowa według reguł Unicode, także po chińsku, japońsku i tajsku, gdzie nie ma spacji. Tam, gdzie dołączony model widział mało poczty w danym języku, pozostaje niepewny zamiast ją oznaczać, a decyduje model językowy lub twoje własne trenowanie. [Języki](../../docs/languages.md)


## Czy wysyła gdzieś moją pocztę?

Nie. Domyślnie sprawdza nazwy hostów z linków w filtrujących resolverach DNS Cloudflare i nic więcej nie opuszcza komputera. Uwierzytelnianie, czarne listy, modele językowe i usługi reputacji są wyłączone, dopóki nie zostaną skonfigurowane, a dane osobowe są usuwane, zanim poczta trafi do hostowanego modelu językowego. [Bezpieczeństwo i prywatność](../../docs/security.md)


## Czy potrzebuję modelu językowego?

Nie. To druga opinia w trudnych przypadkach. Bez niego o takich wiadomościach decyduje sam wynik.


## Jakiego modelu językowego użyć?

`qwen3.5:4b` przez Ollama na CPU lub `qwen3.5:9b` z GPU. Oba są na licencji Apache i czytają 201 języków. Działają też modele hostowane od Anthropic, OpenAI, Google i innych. [Zalecane modele](../../docs/llm.md#recommended-open-models)


## Czy może zastąpić SpamAssassin?

W większości konfiguracji tak: obsługuje protokół spamd, więc spamc, Exim i Haraka działają bez zmian, i zapisuje te same nagłówki `X-Spam-*`. Nie uruchamia plików reguł SpamAssassin. [Alternatywa dla SpamAssassin](/spamassassin-alternative/)


## Czy będzie odrzucać prawidłową pocztę?

Odrzucanie poczty jest domyślnie wyłączone: milter tylko oznacza. Z `--reject` odrzucane są tylko wiadomości z wynikiem 15 lub więcej, tymczasowym błędem 451, więc nadawcy ponawiają próbę, a pomyłkę można naprawić zmianą ustawienia. Filtr treści nigdy nie odrzuca w trakcie sesji SMTP.


## Jak wytrenować go na mojej poczcie?

`spamscanner train --spam ~/Maildir/.Junk --ham ~/Maildir/cur --out model.json`, a następnie `--model model.json`. Działają pliki mbox, katalogi Maildir, foldery z plikami `.eml` oraz zbiory danych CSV lub JSON Lines. [Trenowanie](../../docs/training.md)


## Czy działa bez Node.js?

Tak: samodzielne pliki binarne dla Linux, macOS i Windows zawierają Node.js i model. `curl -fsSL https://github.com/spamscanner/spamscanner/releases/latest/download/install.sh | bash`.


## Kto go tworzy?

[Forward Email](https://forwardemail.net), na potrzeby własnych serwerów pocztowych.
