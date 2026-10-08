<!-- source: 8860e232d858 -->

# Documentatie van Spam Scanner

Spam Scanner is een spamfilter voor Node.js en de opdrachtregel, met de broncode op GitHub. Het leest een ruw e-mailbericht en beslist of het spam, phishing of oplichting is of malware bevat, in elke taal. Het draait als bibliotheek, als opdrachtregeltool, als milter voor Postfix of Sendmail, als contentfilter voor Postfix, als spamd-server die compatibel is met SpamAssassin, als HTTP API of als TCP-server.

Het is gebouwd door [Forward Email](https://forwardemail.net) voor de eigen mailservers.


## Hoe een bericht wordt beoordeeld

Elke controle voegt punten toe of trekt ze af. Het totaal bepaalt de uitkomst:

| Score       | Actie    | Wat een mailserver doet            |
| ----------- | -------- | ---------------------------------- |
| Onder 5     | `accept` | Bezorgt het bericht                |
| 5 tot 14,9  | `tag`    | Bezorgt het, gemarkeerd als spam   |
| 15 en hoger | `reject` | Weigert het tijdens de SMTP-sessie |

Beide drempels zijn aan te passen. Elk resultaat noemt de tests die afgingen, met hun punten en een reden, zodat een beslissing altijd uit te leggen is.

De controles:

* **Een getrainde classifier** leest de woorden van het bericht in elk schrift, de vorm van de links, de afzender en de bijlagen. Hij wordt geleverd getraind op openbare datasets en leert van je eigen mail. [Hoe de classifier werkt](how-it-works.md#the-classifier)
* **Controles op phishing** vangen lookalike-domeinen (`paypa1.com`, `pаypal.com` met een Cyrillische а), links waarvan de tekst het ene adres toont en het doel een ander is, en weergavenamen die zich op een merk beroepen. [Phishing](how-it-works.md#phishing)
* **Controles op bijlagen** vinden uitvoerbare bestanden, uitvoerbare bestanden die als document zijn hernoemd, dubbele extensies, trucs met van-rechts-naar-links in bestandsnamen, uitvoerbare bestanden in ZIP-bestanden, Office-macro's en actieve pdf-inhoud. ClamAV kan bijlagen op virussen scannen. [Bijlagen](how-it-works.md#attachments)
* **Authenticatie**: SPF, DKIM, DMARC en ARC, als het IP-adres van de client bekend is. [Authenticatie](how-it-works.md#authentication)
* **DNS-blocklists** voor het IP-adres van de client en de domeinen in links, en de filterende resolvers van Cloudflare voor bekende malware- en volwassenensites. [Blocklists](how-it-works.md#blocklists)
* **Regels** voor patronen die een classifier niet hoeft te leren: de GTUBE-teststring, onderwerpregels van sextortion, factuuroplichting via PayPal, self-spoofing en instructies die voor AI-filters verborgen zijn. [Regels](scoring.md#rules)
* **Een taalmodel**, optioneel, geeft een tweede mening bij twijfelgevallen: een lokaal model via Ollama of een met OpenAI compatibele server, een beslismodel zoals Clef van Cloudflare, of Claude, ChatGPT, Gemini en andere. Standaard geeft het in één stap een kans voor elk oordeel terug in plaats van een antwoord te schrijven. [Taalmodellen](llm.md)


## Waar te beginnen

* [Aan de slag](getting-started.md): installeer het en scan een eerste bericht.
* [Opdrachtregel](cli.md): elke opdracht en optie.
* [Postfix en Sendmail](postfix.md): filter een mailserver met de milter of een contentfilter.
* [Andere mailservers](mail-servers.md): Exim, Haraka, Dovecot, procmail en alles wat een HTTP API kan aanroepen.
* [Training](training.md): leer het je eigen mail en meet het resultaat.
* [Taalmodellen](llm.md): beslissen en genereren, gemeten nauwkeurigheid en snelheid, beslismodellen, aanbieders, aanbevolen open modellen, privacy en prompt injection.
* [Talen](languages.md): hoe het Chinees, Arabisch, Thai en elk ander schrift leest.
* [Forward Email](forward-email.md): hoe Forward Email het gebruikt, en upgraden vanaf versie 5 of 6.
* [API-referentie](api.md) en [tests en scores](scoring.md).
* [Beveiliging en privacy](security.md): wat de machine verlaat en hoe je dat tegenhoudt.
