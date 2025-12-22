# Forward Email Integration for SpamScanner

This document outlines the integration of Forward Email's spam detection patterns and reputation API into SpamScanner, providing enhanced spam detection capabilities including Microsoft Exchange spam classification, vendor-specific spam detection, and comprehensive attribute extraction.


## Overview

SpamScanner now includes several modules based on Forward Email's production spam filtering infrastructure:

1. **is-arbitrary.js** - Comprehensive spam pattern detection including Microsoft Exchange headers
2. **get-attributes.js** - Email attribute extraction for reputation checking
3. **reputation.js** - Forward Email reputation API client
4. **auth.js** - Email authentication (DKIM/SPF/ARC/DMARC/BIMI) via mailauth


## Microsoft Exchange Spam Detection

SpamScanner now detects spam that has been forwarded through Microsoft Exchange infrastructure by analyzing Microsoft-specific headers.

### Headers Analyzed

The `X-MS-Exchange-Authentication-Results` header is checked for authentication failures (SPF, DKIM, DMARC), while the `X-Forefront-Antispam-Report` header is analyzed for spam classification data.

### Spam Categories (CAT Values)

SpamScanner recognizes the following Microsoft spam categories:

| Category               | Description                        | Action |
| ---------------------- | ---------------------------------- | ------ |
| CAT:MALW               | Malware detected                   | Block  |
| CAT:HPHSH / CAT:HPHISH | High confidence phishing           | Block  |
| CAT:HSPM               | High confidence spam               | Block  |
| CAT:BIMP               | Brand impersonation                | Block  |
| CAT:DIMP               | Domain impersonation               | Block  |
| CAT:GIMP               | Mailbox intelligence impersonation | Block  |
| CAT:UIMP               | User impersonation                 | Block  |
| CAT:PHSH               | Phishing                           | Block  |
| CAT:SPOOF              | Spoofing                           | Block  |
| CAT:OSPM               | Outbound spam                      | Block  |
| CAT:SPM                | Spam                               | Block  |

### Spam Filtering Verdicts (SFV Values)

| Verdict  | Description                   | Action                                |
| -------- | ----------------------------- | ------------------------------------- |
| SFV:SPM  | Marked as spam                | Block                                 |
| SFV:SKB  | Blocked sender                | Block                                 |
| SFV:SKS  | Marked spam by mail flow rule | Block                                 |
| SFV:NSPM | NOT spam                      | Allow (used to avoid false positives) |

### Spam Confidence Level (SCL)

Messages with SCL >= 5 are blocked. The SCL range is -1 to 9, where higher values indicate higher spam confidence.


## Vendor-Specific Spam Detection

SpamScanner detects spam from specific vendors that are commonly abused:

| Vendor             | Detection Pattern                                                       | Category      |
| ------------------ | ----------------------------------------------------------------------- | ------------- |
| PayPal             | Invoice spam (X-Email-Type-Id: PPC001017, RT000238, RT000542, RT002947) | VENDOR_SPAM   |
| Authorize.net/VISA | Phishing scam combination                                               | PHISHING      |
| Amazon.co.jp       | Impersonation attacks                                                   | IMPERSONATION |
| pCloud             | Impersonation attacks                                                   | IMPERSONATION |
| Microsoft          | Bounce spam from `postmaster@outlook.com`                               | BOUNCE_SPAM   |
| 163.com            | Bounce spam                                                             | BOUNCE_SPAM   |
| DocuSign           | Microsoft scam combination                                              | PHISHING      |


## Attribute Extraction (get-attributes.js)

The `get-attributes.js` module extracts email attributes for reputation checking, following Forward Email's pattern. Extracted attributes include:

* Client hostname and root hostname (from Received headers)
* Remote IP address
* From header address, domain, and root domain
* Reply-To addresses, domains, and root domains
* MAIL FROM address, domain, and root domain (envelope sender)

### Aligned vs. Unaligned Attributes

By default, `onlyAligned` is set to `true`, meaning only attributes that have been verified through DKIM or SPF alignment are checked against the reputation API. This reduces false positives from spoofed headers. Set `--no-only-aligned` to check all attributes regardless of alignment.


## Enabling the Forward Email Reputation API

The Forward Email reputation API is disabled by default and can be enabled via configuration or CLI.

### Configuration

```javascript
const SpamScanner = require('spamscanner');

const scanner = new SpamScanner({
  enableReputation: true,
  reputationOptions: {
    apiUrl: 'https://api.forwardemail.net/v1/reputation',
    timeout: 10000,
    onlyAligned: true, // Set to false to check all attributes regardless of alignment
  },
});
```

### Command-Line Interface

```bash
# Enable reputation checking
spamscanner scan email.eml --enable-reputation

# Enable reputation checking with only aligned attributes
spamscanner scan email.eml --enable-reputation --only-aligned

# Full mail server integration
spamscanner scan email.eml \
  --enable-auth \
  --enable-reputation \
  --sender-ip 192.168.1.1 \
  --sender-hostname mail.example.com \
  --sender user@example.com \
  --add-headers \
  --add-auth-headers
```


## Configuration Options

### Reputation Options

| Option                          | Type      | Description                   | Default                                      |   |
| ------------------------------- | --------- | ----------------------------- | -------------------------------------------- | - |
| `enableReputation`              | `boolean` | Enable reputation checking    | `false`                                      |   |
| `reputationOptions.apiUrl`      | `string`  | Reputation API URL            | `https://api.forwardemail.net/v1/reputation` |   |
| `reputationOptions.timeout`     | `number`  | API timeout in ms             | `10000`                                      |   |
| `reputationOptions.onlyAligned` | `boolean` | Only check aligned attributes | `true`                                       |   |

### Authentication Options

| Option                 | Type      | Description                    | Default         |
| ---------------------- | --------- | ------------------------------ | --------------- |
| `enableAuthentication` | `boolean` | Enable DKIM/SPF/ARC/DMARC/BIMI | `false`         |
| `authOptions.ip`       | `string`  | Sender IP address              | -               |
| `authOptions.hostname` | `string`  | Sender hostname (from rDNS)    | -               |
| `authOptions.helo`     | `string`  | HELO/EHLO hostname             | -               |
| `authOptions.sender`   | `string`  | Envelope sender (MAIL FROM)    | -               |
| `authOptions.mta`      | `string`  | MTA hostname for headers       | `'spamscanner'` |
| `authOptions.timeout`  | `number`  | DNS lookup timeout in ms       | `10000`         |

### Arbitrary Detection Options

| Option                     | Type      | Description                     | Default |
| -------------------------- | --------- | ------------------------------- | ------- |
| `enableArbitraryDetection` | `boolean` | Enable arbitrary spam detection | `true`  |
| `arbitraryThreshold`       | `number`  | Score threshold for flagging    | `5`     |


## JSON Output

When reputation checking is enabled, the scan results include:

```json
{
  "results": {
    "reputation": {
      "isTruthSource": false,
      "truthSourceValue": null,
      "isAllowlisted": false,
      "allowlistValue": null,
      "isDenylisted": true,
      "denylistValue": "spam.example.com",
      "checkedValues": [
        "192.168.1.1",
        "mail.example.com",
        "example.com",
        "sender@example.com"
      ],
      "details": {
        "192.168.1.1": { "isDenylisted": false, ... },
        "mail.example.com": { "isDenylisted": true, ... }
      },
      "session": {
        "resolvedClientHostname": "mail.example.com",
        "originalFromAddress": "sender@example.com",
        ...
      }
    },
    "arbitrary": [
      {
        "type": "arbitrary",
        "subtype": "phishing",
        "description": "Arbitrary spam patterns detected (score: 12)",
        "score": 12,
        "reasons": ["MS_PHISHING_SPOOF: CAT:PHSH"],
        "category": "PHISHING"
      }
    ]
  }
}
```


## Spoofing Detection

SpamScanner detects spoofing attacks where the From address domain matches one of the recipient domains but lacks proper SPF/DKIM authentication. This is a common attack vector where spammers send emails appearing to be from the recipient's own domain.

Exceptions are made for legitimate automated emails such as WordPress notifications, PHP scripts, cron jobs, and system monitoring alerts.


## SRS (Sender Rewriting Scheme) Support

The attribute extraction module automatically detects and removes SRS encoding from email addresses, ensuring that forwarded emails are properly attributed to their original senders.


## Benefits

* **Microsoft Exchange Integration**: Leverage Microsoft's spam classification for emails forwarded through Exchange
* **Comprehensive Attribute Checking**: Check IPs, hostnames, domains, and email addresses against reputation databases
* **Vendor-Specific Detection**: Block known spam patterns from commonly abused services
* **Spoofing Protection**: Detect and block domain spoofing attacks
* **Alignment-Aware**: Option to only check authenticated/aligned attributes to reduce false positives


## References

* [Forward Email](https://forwardemail.net) - The 100% open-source and privacy-focused email service
* [Microsoft Message Headers](https://learn.microsoft.com/en-us/defender-office-365/message-headers-eop-mdo) - Microsoft Defender for Office 365 header documentation
* [mailauth](https://github.com/postalsys/mailauth) - Email authentication library for DKIM/SPF/ARC/DMARC/BIMI
