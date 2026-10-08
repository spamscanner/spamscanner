<!--
label: Phishing detection
title: Phishing detection for email: lookalike domains, deceptive links and spoofing
description: How Spam Scanner detects phishing email: Unicode lookalike domains, links that show one address and go to another, brand display names, Cloudflare's malware resolver and DMARC.
keywords: phishing detection, email phishing filter, homograph attack, IDN homograph, lookalike domain detection, deceptive link, brand impersonation email
-->

# Phishing detection for email

Phishing works by looking like someone else. Spam Scanner checks the places where the disguise shows.


## Lookalike domains

Each domain in a link is reduced to a skeleton with the Unicode confusables table and compared with nearly 100 commonly impersonated brands:

| Domain                              | Caught as                      |
| ----------------------------------- | ------------------------------ |
| `pаypal.com` (Cyrillic а)           | Confusable characters          |
| `paypa1-secure.top`                 | Swapped characters             |
| `xn--pple-43d.com`                  | Punycode for `аpple.com`       |
| `paypal.com.account-verify.example` | Brand in someone else's domain |
| `paypall.com`                       | One letter away                |

Brands can be added, and domains you own can be allowlisted.


## Deceptive links

An HTML link whose text is one address and whose target is another, such as text `https://www.paypal.com/signin` pointing at `http://paypa1-secure.top/login`, adds 3 points.


## Display names and spoofing

* A display name containing a brand ("PayPal Security") from an address at another domain.
* A display name containing a different email address.
* Mail claiming to come from the recipient's own domain that fails SPF, DKIM and DMARC.


## Known bad sites

Link hosts are looked up on Cloudflare's 1.1.1.2 resolver, which blocks known malware and phishing sites, and optionally on domain blocklists such as Spamhaus DBL.


## Attachments

Phishing also arrives as HTML attachments that draw a fake login page offline, and as executables renamed to `.pdf`. Both are found by their content.

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

[How the checks work](../../docs/how-it-works.md#phishing)
