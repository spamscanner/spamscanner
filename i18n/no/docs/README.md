<!-- source: c56969e779c4 -->

# Dokumentasjon for Spam Scanner

Spam Scanner er et spamfilter for Node.js og kommandolinjen, med kildekoden på GitHub. Det leser en rå e-postmelding og avgjør om den er spam, phishing eller svindel, eller om den inneholder skadevare, på alle språk. Det kjører som et bibliotek, et kommandolinjeverktøy, en milter for Postfix eller Sendmail, et innholdsfilter for Postfix, en SpamAssassin-kompatibel spamd-server, et HTTP API eller en TCP-server.

Det er laget av [Forward Email](https://forwardemail.net) for selskapets egne e-postservere.


## Slik vurderes en melding

Hver sjekk legger til eller trekker fra poeng. Summen avgjør utfallet:

| Poengsum   | Handling | Hva en e-postserver gjør     |
| ---------- | -------- | ---------------------------- |
| Under 5    | `accept` | Leverer meldingen            |
| 5 til 14,9 | `tag`    | Leverer den merket som spam  |
| 15 og over | `reject` | Avviser den under SMTP-økten |

Begge tersklene kan endres. Hvert resultat lister opp testene som slo ut, med poeng og en begrunnelse, så en avgjørelse alltid kan forklares.

Sjekkene:

* **En trent klassifiserer** leser ordene i meldingen i alle skriftsystemer, formen på lenkene, avsenderen og vedleggene. Den leveres trent på offentlige datasett og lærer av din egen e-post. [Slik virker klassifisereren](how-it-works.md#the-classifier)
* **Phishing-sjekker** fanger forvekslingsdomener (`paypa1.com`, `pаypal.com` med en kyrillisk а), lenker der teksten viser én adresse og målet er en annen, og visningsnavn som utgir seg for å være et merkenavn. [Phishing](how-it-works.md#phishing)
* **Vedleggssjekker** finner kjørbare filer, kjørbare filer omdøpt til dokumenter, doble filendelser, triks med høyre-til-venstre-tegn i filnavn, kjørbare filer i ZIP-filer, Office-makroer og aktivt PDF-innhold. ClamAV kan skanne vedlegg for virus. [Vedlegg](how-it-works.md#attachments)
* **Autentisering**: SPF, DKIM, DMARC og ARC, når klientens IP-adresse er kjent. [Autentisering](how-it-works.md#authentication)
* **DNS-blokkeringslister** for klientens IP-adresse og domenene i lenker, og Cloudflares filtrerende resolvere for kjent skadevare og voksennettsteder. [Blokkeringslister](how-it-works.md#blocklists)
* **Regler** for mønstre ingen klassifiserer trenger å lære: GTUBE-teststrengen, emnelinjer for sextortion, fakturasvindel via PayPal, forfalskning av eget domene og instruksjoner skjult for KI-filtre. [Regler](scoring.md#rules)
* **En språkmodell**, valgfri, gir en ekstra vurdering av vanskelige tilfeller: en lokal modell via Ollama eller en hvilken som helst OpenAI-kompatibel server, eller Claude, ChatGPT, Gemini og andre. [Språkmodeller](llm.md)


## Hvor du begynner

* [Kom i gang](getting-started.md): installer det og skann en første melding.
* [Kommandolinje](cli.md): alle kommandoer og alternativer.
* [Postfix og Sendmail](postfix.md): filtrer en e-postserver med milteren eller et innholdsfilter.
* [Andre e-postservere](mail-servers.md): Exim, Haraka, Dovecot, procmail og alt som kan kalle et HTTP API.
* [Trening](training.md): lær det opp på din egen e-post og mål resultatet.
* [Språkmodeller](llm.md): leverandører, anbefalte åpne modeller, personvern og prompt injection.
* [Språk](languages.md): hvordan det leser kinesisk, arabisk, thai og alle andre skriftsystemer.
* [Forward Email](forward-email.md): hvordan Forward Email bruker det, og oppgradering fra versjon 5 eller 6.
* [API-referanse](api.md) og [tester og poeng](scoring.md).
* [Sikkerhet og personvern](security.md): hva som forlater maskinen, og hvordan du stopper det.
