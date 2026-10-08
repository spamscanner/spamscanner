<!-- source: c56969e779c4 -->

# Dokumentation för Spam Scanner

Spam Scanner är ett spamfilter för Node.js och kommandoraden, med källkoden på GitHub. Det läser ett rått e-postmeddelande och avgör om det är spam, nätfiske, ett bedrägeri eller innehåller skadlig kod, på vilket språk som helst. Det körs som ett bibliotek, ett kommandoradsverktyg, en milter för Postfix eller Sendmail, ett innehållsfilter för Postfix, en SpamAssassin-kompatibel spamd-server, ett HTTP-API eller en TCP-server.

Det är byggt av [Forward Email](https://forwardemail.net) för dess egna e-postservrar.


## Hur ett meddelande bedöms

Varje kontroll lägger till eller drar av poäng. Summan avgör utfallet:

| Poäng        | Åtgärd   | Vad en e-postserver gör        |
| ------------ | -------- | ------------------------------ |
| Under 5      | `accept` | Levererar meddelandet          |
| 5 till 14,9  | `tag`    | Levererar det märkt som spam   |
| 15 och uppåt | `reject` | Nekar det under SMTP-sessionen |

Båda gränsvärdena kan ändras. Varje resultat listar de tester som slog till, med deras poäng och en orsak, så ett beslut kan alltid förklaras.

Kontrollerna:

* **En tränad klassificerare** läser meddelandets ord i alla skriftsystem, formen på dess länkar, avsändaren och bilagorna. Den levereras tränad på offentliga dataset och lär sig av din egen e-post. [Så fungerar klassificeraren](how-it-works.md#the-classifier)
* **Kontroller av nätfiske** fångar förväxlingsbara domäner (`paypa1.com`, `pаypal.com` med ett kyrilliskt а), länkar vars text visar en adress och vars mål är en annan, samt visningsnamn som utger sig för att vara ett varumärke. [Nätfiske](how-it-works.md#phishing)
* **Kontroller av bilagor** hittar körbara filer, körbara filer som bytt namn till dokument, dubbla filändelser, filnamnsknep med höger-till-vänster-tecken, körbara filer i ZIP-filer, Office-makron och aktivt PDF-innehåll. ClamAV kan skanna bilagor efter virus. [Bilagor](how-it-works.md#attachments)
* **Autentisering**: SPF, DKIM, DMARC och ARC, när klientens IP-adress är känd. [Autentisering](how-it-works.md#authentication)
* **DNS-blocklistor** för klientens IP-adress och domänerna i länkar, samt Cloudflares filtrerande resolvrar för kända webbplatser med skadlig kod och vuxeninnehåll. [Blocklistor](how-it-works.md#blocklists)
* **Regler** för mönster som ingen klassificerare behöver lära sig: teststrängen GTUBE, ämnesrader för sextortion, bedrägerier med PayPal-fakturor, självförfalskning och instruktioner gömda för AI-filter. [Regler](scoring.md#rules)
* **En språkmodell**, valfri, ger en andra åsikt om gränsfall: en lokal modell via Ollama eller en OpenAI-kompatibel server, eller Claude, ChatGPT, Gemini med flera. [Språkmodeller](llm.md)


## Var du ska börja

* [Kom igång](getting-started.md): installera och skanna ett första meddelande.
* [Kommandorad](cli.md): alla kommandon och alternativ.
* [Postfix och Sendmail](postfix.md): filtrera en e-postserver med miltern eller ett innehållsfilter.
* [Andra e-postservrar](mail-servers.md): Exim, Haraka, Dovecot, procmail och allt som kan anropa ett HTTP-API.
* [Träning](training.md): lär den din egen e-post och mät resultatet.
* [Språkmodeller](llm.md): leverantörer, rekommenderade öppna modeller, integritet och promptinjektion.
* [Språk](languages.md): hur den läser kinesiska, arabiska, thailändska och alla andra skriftsystem.
* [Forward Email](forward-email.md): hur Forward Email använder den, och uppgradering från version 5 eller 6.
* [API-referens](api.md) och [tester och poäng](scoring.md).
* [Säkerhet och integritet](security.md): vad som lämnar datorn och hur du stoppar det.
