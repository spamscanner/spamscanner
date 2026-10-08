<!-- source: c56969e779c4 -->

# Dokumentacja Spam Scanner

Spam Scanner to filtr antyspamowy dla Node.js i wiersza poleceń, z kodem źródłowym na GitHub. Czyta surową wiadomość e-mail i rozstrzyga, czy jest spamem, phishingiem, oszustwem lub czy zawiera złośliwe oprogramowanie, w dowolnym języku. Działa jako biblioteka, narzędzie wiersza poleceń, milter dla Postfix lub Sendmail, filtr treści Postfix, serwer spamd zgodny ze SpamAssassin, HTTP API lub serwer TCP.

Tworzy go [Forward Email](https://forwardemail.net) na potrzeby własnych serwerów pocztowych.


## Jak oceniana jest wiadomość

Każda kontrola dodaje lub odejmuje punkty. O wyniku decyduje suma:

| Wynik        | Akcja    | Co robi serwer pocztowy          |
| ------------ | -------- | -------------------------------- |
| Poniżej 5    | `accept` | Dostarcza wiadomość              |
| Od 5 do 14,9 | `tag`    | Dostarcza ją oznaczoną jako spam |
| 15 i więcej  | `reject` | Odrzuca ją w trakcie sesji SMTP  |

Oba progi można zmienić. Każdy wynik wymienia testy, które zadziałały, z ich punktami i powodem, więc każdą decyzję zawsze da się wyjaśnić.

Kontrole:

* **Wytrenowany klasyfikator** czyta słowa wiadomości w dowolnym piśmie, kształt jej linków, nadawcę i załączniki. Jest dostarczany wytrenowany na publicznych zbiorach danych i uczy się z twojej własnej poczty. [Jak działa klasyfikator](how-it-works.md#the-classifier)
* **Kontrole phishingu** wyłapują podobne domeny (`paypa1.com`, `pаypal.com` z cyrylickim а), linki, których tekst pokazuje jeden adres, a cel jest inny, oraz nazwy wyświetlane podające się za markę. [Phishing](how-it-works.md#phishing)
* **Kontrole załączników** znajdują pliki wykonywalne, pliki wykonywalne przemianowane na dokumenty, podwójne rozszerzenia, sztuczki z nazwami plików pisanymi od prawej do lewej, pliki wykonywalne w plikach ZIP, makra Office i aktywną zawartość PDF. ClamAV może skanować załączniki w poszukiwaniu wirusów. [Załączniki](how-it-works.md#attachments)
* **Uwierzytelnianie**: SPF, DKIM, DMARC i ARC, gdy znany jest adres IP klienta. [Uwierzytelnianie](how-it-works.md#authentication)
* **Czarne listy DNS** dla adresu IP klienta i domen w linkach oraz filtrujące resolvery Cloudflare dla znanych witryn ze złośliwym oprogramowaniem i treściami dla dorosłych. [Czarne listy](how-it-works.md#blocklists)
* **Reguły** dla wzorców, których żaden klasyfikator nie musi się uczyć: ciąg testowy GTUBE, tematy sextortion, oszustwa na faktury PayPal, podszywanie się pod własną domenę i instrukcje ukryte dla filtrów AI. [Reguły](scoring.md#rules)
* **Model językowy**, opcjonalny, daje drugą opinię w trudnych przypadkach: lokalny model przez Ollama lub dowolny serwer zgodny z OpenAI albo Claude, ChatGPT, Gemini i inne. [Modele językowe](llm.md)


## Od czego zacząć

* [Pierwsze kroki](getting-started.md): instalacja i skanowanie pierwszej wiadomości.
* [Wiersz poleceń](cli.md): wszystkie polecenia i opcje.
* [Postfix i Sendmail](postfix.md): filtrowanie serwera pocztowego przez milter lub filtr treści.
* [Inne serwery pocztowe](mail-servers.md): Exim, Haraka, Dovecot, procmail i wszystko, co potrafi wywołać HTTP API.
* [Trenowanie](training.md): nauka na twojej własnej poczcie i pomiar wyniku.
* [Modele językowe](llm.md): dostawcy, zalecane otwarte modele, prywatność i prompt injection.
* [Języki](languages.md): jak czyta chiński, arabski, tajski i każde inne pismo.
* [Forward Email](forward-email.md): jak korzysta z niego Forward Email i jak przejść z wersji 5 lub 6.
* [Dokumentacja API](api.md) oraz [testy i punkty](scoring.md).
* [Bezpieczeństwo i prywatność](security.md): co opuszcza komputer i jak to zatrzymać.
