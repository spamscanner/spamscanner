// Terms for the glossary page (/glossary/), besides the tooltip terms in
// build-site.js, and the page that explains each term. Used by build-site.js.

// Listed on the glossary page only, without tooltips.
export const MORE_TERMS = [
	['Content filter', 'A program a mail server hands each accepted message to, which passes it back with headers added. Postfix runs Spam Scanner this way with spamscanner filter.'],
	['Lookalike domain', 'A domain that imitates another with swapped characters or letters from another alphabet, such as paypa1.com, or pаypal.com with a Cyrillic а.'],
	['Spam score', 'The sum of the points of every test that fired. Spam Scanner marks a message as spam at 5 points and tells a mail server to refuse it at 15.'],
	['X-Spam headers', 'Headers such as X-Spam-Flag, X-Spam-Score and X-Spam-Status that a spam filter adds to a message, so mail programs and Sieve rules can sort it.'],
];

export const TERM_LINKS = {
	ham: '/docs/how-it-works/#the-classifier',
	milter: '/docs/postfix/#milter',
	SPF: '/docs/how-it-works/#authentication',
	DKIM: '/docs/how-it-works/#authentication',
	DMARC: '/docs/how-it-works/#authentication',
	ARC: '/docs/how-it-works/#authentication',
	DNSBL: '/docs/getting-started/#turn-on-more-checks',
	GTUBE: '/docs/postfix/#3-test-it',
	ClamAV: '/docs/how-it-works/#attachments',
	spamd: '/docs/mail-servers/#a-drop-in-for-spamassassins-spamd',
	Ollama: '/docs/llm/#quick-start-with-ollama',
	punycode: '/docs/how-it-works/#phishing',
	MTA: '/docs/mail-servers/',
	'Content filter': '/docs/postfix/#content-filter',
	'Lookalike domain': '/phishing-detection/',
	'Spam score': '/docs/scoring/',
	'X-Spam headers': '/docs/postfix/',
};

// Display names for tooltip terms written in lowercase.
export const TERM_NAMES = {ham: 'Ham', milter: 'Milter', punycode: 'Punycode'};
