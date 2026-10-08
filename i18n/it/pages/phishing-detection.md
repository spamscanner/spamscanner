<!-- source: 0378a5e0f12b -->

<!--
label: Rilevamento del phishing
title: Rilevamento del phishing: domini sosia, link ingannevoli, spoofing
description: Come Spam Scanner rileva il phishing: domini sosia Unicode, link ingannevoli, marchi nei nomi visualizzati, resolver antimalware di Cloudflare e DMARC.
keywords: rilevamento phishing, filtro phishing email, attacco omografico, omografi IDN, rilevamento domini sosia, link ingannevoli, furto di identità del marchio email
-->

# Rilevamento del phishing nella posta elettronica

Il phishing funziona facendosi passare per qualcun altro. Spam Scanner controlla i punti in cui il travestimento si vede.


## Domini sosia

Ogni dominio in un link viene ridotto a uno scheletro con la tabella Unicode dei caratteri confondibili e confrontato con quasi 100 marchi comunemente imitati:

| Dominio                             | Riconosciuto come                    |
| ----------------------------------- | ------------------------------------ |
| `pаypal.com` (а cirillica)          | Caratteri confondibili               |
| `paypa1-secure.top`                 | Caratteri scambiati                  |
| `xn--pple-43d.com`                  | Punycode per `аpple.com`             |
| `paypal.com.account-verify.example` | Marchio nel dominio di qualcun altro |
| `paypall.com`                       | Una lettera di differenza            |

Si possono aggiungere marchi, e i domini di tua proprietà possono essere inseriti in una lista di consenso.


## Link ingannevoli

Un link HTML il cui testo è un indirizzo e la cui destinazione è un altro, come il testo `https://www.paypal.com/signin` che punta a `http://paypa1-secure.top/login`, aggiunge 3 punti.


## Nomi visualizzati e spoofing

* Un nome visualizzato che contiene un marchio ("PayPal Security") da un indirizzo di un altro dominio.
* Un nome visualizzato che contiene un indirizzo email diverso.
* Posta che dichiara di provenire dal dominio del destinatario e non supera SPF, DKIM e DMARC.


## Siti malevoli noti

Gli host dei link vengono cercati sul resolver 1.1.1.2 di Cloudflare, che blocca i siti di malware e phishing noti, e facoltativamente su blocklist di domini come Spamhaus DBL.


## Allegati

Il phishing arriva anche come allegati HTML che disegnano una falsa pagina di accesso offline, e come eseguibili rinominati in `.pdf`. Entrambi vengono individuati dal loro contenuto.

```sh
spamscanner scan message.eml
```

```text
SPAM  score 16.3 (spam at 5.0, reject at 15.0)  action: reject  language: en
     +6.3  BAYES_999                    Classifier spam probability 99.9%
     +5.0  PHISHING_LOOKALIKE_DOMAIN    "paypa1-secure.top" imitates paypal by swapping characters
     +3.0  DECEPTIVE_LINK               A link shows "https://www.paypal.com/signin" but goes to paypa1-secure.top
     +2.0  FROM_NAME_BRAND              Display name says "paypal" but the message is from paypa1-secure.top
```

[Come funzionano i controlli](../../docs/how-it-works.md#phishing)
