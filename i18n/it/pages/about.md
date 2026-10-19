<!-- source: 599bd320e55a -->

<!--
label: Informazioni
title: Informazioni su Spam Scanner, licenza e privacy
description: Chi fa Spam Scanner, come segnalare un bug o una vulnerabilità, la sua licenza e cosa raccoglie questo sito: niente cookie e niente analytics.
keywords: informazioni su Spam Scanner, Forward Email, licenza Spam Scanner, BUSL-1.1, contatti Spam Scanner, privacy Spam Scanner
-->

# Informazioni su Spam Scanner

Spam Scanner è un filtro antispam per la posta creato da [Forward Email](https://forwardemail.net), il servizio di posta attento alla privacy, che lo ha costruito per i propri server di posta. Il codice sorgente, le issue e le release sono su [GitHub](https://github.com/spamscanner/spamscanner), e il pacchetto è su [npm](https://www.npmjs.com/package/spamscanner).


## Chi lo sviluppa

Il team di Forward Email scrive e mantiene Spam Scanner. Forward Email non conserva log del contenuto dei messaggi, quindi non poteva inviare la posta a un servizio di filtraggio esterno: il filtro doveva girare sui suoi server e spiegare ogni decisione senza che una persona leggesse la posta. [Come lo usa Forward Email](../../docs/forward-email.md)

Anche Forward Email è open source, su [github.com/forwardemail/forwardemail.net](https://github.com/forwardemail/forwardemail.net). Il suo fondatore è stato uno dei primi dipendenti di DuckDuckGo.


## Contatti

* **Domande, bug e richieste di funzionalità:** apri una issue su [GitHub](https://github.com/spamscanner/spamscanner/issues).
* **Vulnerabilità di sicurezza:** segnalale in privato tramite [la segnalazione di vulnerabilità di GitHub](https://github.com/spamscanner/spamscanner/security/advisories/new), non in issue pubbliche. Lo stesso indirizzo è in [security.txt](https://spamscanner.net/.well-known/security.txt).
* **Altre licenze:** contatta [Forward Email](https://forwardemail.net).


## Termini di licenza

La [licenza](https://github.com/spamscanner/spamscanner/blob/master/LICENSE) di Spam Scanner è la Business Source License 1.1, con la Apache License 2.0 come Change License. La Change Date indicata nella licenza è passata, e da quella data la licenza ti concede i diritti della Apache License 2.0.


## Privacy

Questo sito non imposta cookie e non carica analytics, tracker, pubblicità, font o script da altri siti. Ogni file arriva da spamscanner.net.

* Il tema, la lingua che scegli e il server Mastodon su cui condividi vengono salvati nell'archivio locale del browser e non vengono inviati da nessuna parte.
* Il video si carica solo quando lo avvii.
* I link di condivisione sono semplici link, quindi nulla di quelle reti si carica finché non ne segui uno.
* Il sito è ospitato su GitHub Pages, e GitHub registra l'indirizzo IP di ogni visitatore per motivi di sicurezza. Vedi [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages) e l'[informativa sulla privacy di GitHub](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).


## Cosa invia il software

Spam Scanner non invia telemetria e non cerca aggiornamenti. Di default cerca i nomi host dei link di un messaggio sui resolver DNS con filtro di Cloudflare, e nient'altro esce dalla macchina. Gli altri controlli di rete restano spenti finché non li attivi. [Sicurezza e privacy](../../docs/security.md)


## Release

I binari autonomi sono compilati da GitHub Actions a partire dal repository pubblico. Ogni release elenca i loro hash in un file `SHA256SUMS`, che lo script di installazione verifica, e ogni binario ha un'attestazione di provenienza della build firmata. Le release e le loro note sono su [GitHub](https://github.com/spamscanner/spamscanner/releases).
