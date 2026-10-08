<!-- source: c56969e779c4 -->

# Dokumentation til Spam Scanner

Spam Scanner er et spamfilter til Node.js og kommandolinjen med kildekoden på GitHub. Det læser en rå e-mailbesked og afgør, om den er spam, phishing eller svindel eller indeholder malware, på ethvert sprog. Det kører som et bibliotek, et kommandolinjeværktøj, en milter til Postfix eller Sendmail, et Postfix-indholdsfilter, en SpamAssassin-kompatibel spamd-server, et HTTP API eller en TCP-server.

Det er bygget af [Forward Email](https://forwardemail.net) til deres egne mailservere.


## Sådan bedømmes en besked

Hvert tjek lægger point til eller trækker point fra. Summen afgør udfaldet:

| Score         | Handling | Hvad en mailserver gør           |
| ------------- | -------- | -------------------------------- |
| Under 5       | `accept` | Leverer beskeden                 |
| 5 til 14,9    | `tag`    | Leverer den markeret som spam    |
| 15 og derover | `reject` | Afviser den under SMTP-sessionen |

Begge grænser kan ændres. Hvert resultat viser de test, der slog til, med deres point og en begrundelse, så en afgørelse altid kan forklares.

Tjekkene:

* **En trænet klassifikator** læser beskedens ord i ethvert skriftsystem, formen på dens links, dens afsender og dens vedhæftede filer. Den leveres trænet på offentlige datasæt og lærer af din egen post. [Sådan virker klassifikatoren](how-it-works.md#the-classifier)
* **Phishingtjek** fanger forvekslelige domæner (`paypa1.com`, `pаypal.com` med et kyrillisk а), links, hvis tekst viser én adresse og hvis mål er en anden, og visningsnavne, der udgiver sig for at være et varemærke. [Phishing](how-it-works.md#phishing)
* **Tjek af vedhæftede filer** finder programfiler, programfiler omdøbt til dokumenter, dobbelte filendelser, filnavnstricks med højre-mod-venstre-tegn, programfiler i ZIP-filer, Office-makroer og aktivt PDF-indhold. ClamAV kan scanne vedhæftede filer for virus. [Vedhæftede filer](how-it-works.md#attachments)
* **Godkendelse**: SPF, DKIM, DMARC og ARC, når klientens IP-adresse er kendt. [Godkendelse](how-it-works.md#authentication)
* **DNS-blokeringslister** for klientens IP-adresse og domænerne i links samt Cloudflares filtrerende resolvere for kendte malware- og voksenwebsteder. [Blokeringslister](how-it-works.md#blocklists)
* **Regler** for mønstre, ingen klassifikator behøver at lære: GTUBE-teststrengen, emnelinjer med sextortion, svindel med PayPal-fakturaer, selvforfalskning og instruktioner gemt til AI-filtre. [Regler](scoring.md#rules)
* **En sprogmodel**, valgfri, giver en second opinion om tvivlstilfælde: en lokal model via Ollama eller enhver OpenAI-kompatibel server eller Claude, ChatGPT, Gemini og andre. [Sprogmodeller](llm.md)


## Hvor du skal begynde

* [Kom i gang](getting-started.md): installér det, og scan en første besked.
* [Kommandolinje](cli.md): alle kommandoer og indstillinger.
* [Postfix og Sendmail](postfix.md): filtrér en mailserver med milteren eller et indholdsfilter.
* [Andre mailservere](mail-servers.md): Exim, Haraka, Dovecot, procmail og alt, der kan kalde et HTTP API.
* [Træning](training.md): lær det op på din egen post, og mål resultatet.
* [Sprogmodeller](llm.md): udbydere, anbefalede åbne modeller, privatliv og prompt injection.
* [Sprog](languages.md): sådan læser det kinesisk, arabisk, thai og alle andre skriftsystemer.
* [Forward Email](forward-email.md): sådan bruger Forward Email det, og opgradering fra version 5 eller 6.
* [API-reference](api.md) og [test og scorer](scoring.md).
* [Sikkerhed og privatliv](security.md): hvad der forlader maskinen, og hvordan du stopper det.
