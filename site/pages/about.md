<!--
label: About
title: About Spam Scanner, its license and privacy
description: Who makes Spam Scanner, how to report a bug or a vulnerability, its license, and what this website collects: no cookies and no analytics.
keywords: about Spam Scanner, Forward Email, Spam Scanner license, BUSL-1.1, Spam Scanner contact, Spam Scanner privacy
-->

# About Spam Scanner

Spam Scanner is an email spam filter made by [Forward Email](https://forwardemail.net), the privacy-focused email service, which built it for its own mail servers. The source code, issues and releases are on [GitHub](https://github.com/spamscanner/spamscanner), and the package is on [npm](https://www.npmjs.com/package/spamscanner).


## Who makes it

The Forward Email team writes and maintains Spam Scanner. Forward Email keeps no logs of message content, so it could not send mail to an outside filtering service: the filter had to run on its own servers and explain each decision without a person reading the mail. [How Forward Email uses it](../../docs/forward-email.md)

Forward Email is open source as well, at [github.com/forwardemail/forwardemail.net](https://github.com/forwardemail/forwardemail.net). Its founder was one of the first employees at DuckDuckGo.


## Contact

* **Questions, bugs and feature requests:** open an issue on [GitHub](https://github.com/spamscanner/spamscanner/issues).
* **Security vulnerabilities:** report them privately through [GitHub's vulnerability reporting](https://github.com/spamscanner/spamscanner/security/advisories/new), not in public issues. The same address is in [security.txt](https://spamscanner.net/.well-known/security.txt).
* **Other licensing:** contact [Forward Email](https://forwardemail.net).


## License terms

Spam Scanner's [license](https://github.com/spamscanner/spamscanner/blob/master/LICENSE) is the Business Source License 1.1, with the Apache License 2.0 as its Change License. The Change Date named in the license has passed, and from that date the license grants you rights under the Apache License 2.0.


## Privacy

This website sets no cookies and loads no analytics, trackers, ads, fonts or scripts from other sites. Every file comes from spamscanner.net.

* The theme, the language you choose and the Mastodon server you share to are saved in your browser's local storage, and never sent anywhere.
* The video loads only when you play it.
* The share links are plain links, so nothing from those networks loads until you follow one.
* The site is hosted on GitHub Pages, and GitHub logs the IP address of each visitor for security purposes. See [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages) and the [GitHub General Privacy Statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).


## What the software sends

Spam Scanner sends no telemetry and checks for no updates. By default it looks up the host names of links in a message on Cloudflare's filtering DNS resolvers, and nothing else leaves the machine. Its other network checks are off until you turn them on. [Security and privacy](../../docs/security.md)


## Releases

The standalone binaries are built by GitHub Actions from the public repository. Each release lists their hashes in a `SHA256SUMS` file, which the install script checks, and each binary carries a signed build provenance attestation. Releases and their notes are on [GitHub](https://github.com/spamscanner/spamscanner/releases).
