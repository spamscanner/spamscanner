import {registrableDomain} from './tokenizer.js';

// The GTUBE test string: any message containing it must be treated as spam.
export const GTUBE = 'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X';

// Sextortion and account-takeover scams (as in Forward Email's MX rules).
const BLOCKED_SUBJECT = /cheecck y0ur acc0untt|recorded you|you've been hacked|account is hacked|personal data has leaked|private information has been stolen/i;

// Text addressed to an AI reading the message rather than to the recipient.
const PROMPT_INJECTION = /\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|rules)\b|\bclassify\s+(?:this|the)\s+(?:e-?mail|message)\s+as\s+(?:ham|safe|legitimate|not\s+spam|clean)\b|\b(?:system|developer)\s+prompt\s*:|\byou\s+are\s+(?:an?\s+)?(?:ai|llm|language model|spam filter|email classifier)\b.{0,80}\b(?:must|should)\b/is;

// PayPal sends from one domain per country.
const PAYPAL_DOMAIN = /^paypal\.(?:[a-z]{2,3}|com?\.[a-z]{2})$/i;

// PayPal notification templates used for invoice and money request spam.
const PAYPAL_SPAM_TYPE_IDS = new Set(['PPC001017', 'RT000238', 'RT000542', 'RT002947', 'RTI003384']);

// Invoice and money request subjects in PayPal's main languages.
const PAYPAL_INVOICE_SUBJECT = /\binvoice from\b|\bsent you an invoice\b|\b(?:money|payment) request\b|\brequest(?:ed)? (?:money|a payment|for (?:money|payment))\b|\brequested [$€£¥]|\brequested \d|\brechnung von\b|\bzahlungsaufforderung\b|\bgeldanforderung\b|\bfacture de\b|\bdemande d['’]argent\b|\bdemande de paiement\b|\bfactura de\b|\bsolicitud de (?:dinero|pago)\b|\bfattura da\b|\brichiesta di (?:denaro|pagamento)\b|\bfactuur van\b|\bbetaalverzoek\b|\bfatura de\b|\bpedido de (?:dinheiro|pagamento)\b/i;

// Microsoft's own spam verdicts, trusted only on mail relayed by Microsoft.
const MS_SPAM_VERDICT = /\bsfv:(?:spm|skb|sks)\b/i;
const MS_SPAM_CATEGORY = /\bcat:(?:ospm|spm|hspm|phsh|hphsh|hphish|malw|spoof)\b/i;

// Brands whose names appear in the display name of phishing mail.
const DISPLAY_BRANDS = ['paypal', 'apple', 'icloud', 'microsoft', 'outlook', 'office 365', 'amazon', 'netflix', 'docusign', 'dhl', 'fedex', 'ups', 'usps', 'coinbase', 'binance', 'metamask', 'wells fargo', 'chase', 'bank of america', 'american express', 'facebook', 'instagram', 'whatsapp', 'linkedin', 'dropbox', 'adobe', 'google', 'gmail', 'yahoo', 'norton', 'mcafee', 'geek squad', 'irs', 'hmrc', 'royal mail', 'la poste', 'sparkasse', 'santander', 'hsbc', 'barclays'];

function headerString(mail, name) {
	const value = mail.headers?.get?.(name);
	if (value === undefined || value === null) {
		return '';
	}

	if (typeof value === 'string') {
		return value;
	}

	if (Array.isArray(value)) {
		return value.map(entry => (typeof entry === 'string' ? entry : entry?.text ?? entry?.value ?? '')).join(' ');
	}

	return value.text ?? value.value ?? String(value);
}

function domainOf(address) {
	const value = String(address);
	const at = value.lastIndexOf('@');
	return at === -1 ? '' : value.slice(at + 1).toLowerCase();
}

/**
 * Session facts about the SMTP transaction that delivered a message. Only
 * what the receiving server observed is used: Received headers are written by
 * whoever sent the message and are never trusted.
 *
 * @param {object} mail - parsed message
 * @param {object} [session]
 * @param {string} [session.remoteAddress] - client IP address
 * @param {string} [session.resolvedClientHostname] - client hostname, verified by forward-confirmed reverse DNS
 * @param {string} [session.helo]
 * @param {{mailFrom?: {address: string}, rcptTo?: Array<{address: string}>}} [session.envelope]
 * @returns {object} the session plus originalFromAddress, originalFromAddressDomain and originalFromAddressRootDomain
 */
export function buildSessionInfo(mail = {}, session = {}) {
	const info = {...session};
	const from = mail.from?.value?.find(entry => entry.address)?.address || '';
	if (from && !info.originalFromAddress) {
		info.originalFromAddress = from.toLowerCase();
	}

	if (info.originalFromAddress) {
		info.originalFromAddressDomain ||= domainOf(info.originalFromAddress);
		info.originalFromAddressRootDomain ||= registrableDomain(info.originalFromAddressDomain);
	}

	if (info.resolvedClientHostname) {
		info.resolvedClientHostname = info.resolvedClientHostname.toLowerCase().replace(/\.$/, '');
		info.resolvedRootClientHostname ||= registrableDomain(info.resolvedClientHostname);
	}

	return info;
}

/**
 * Rules that recognise spam by structure rather than by words: the GTUBE test
 * string, sextortion subjects, text that tries to instruct an AI filter,
 * Microsoft's own spam verdict on mail it relayed, PayPal invoice and money
 * request spam, display names that claim another address or a brand, mail
 * that claims to come from the recipient's own domain without authenticating,
 * and missing or impossible dates.
 *
 * @param {object} mail - parsed message
 * @param {object} [options]
 * @param {number} [options.threshold] - total score at which isArbitrary is true
 * @param {object} [options.session] - see buildSessionInfo
 * @param {object} [options.authentication] - result of authenticate(), if run
 * @param {Date} [options.now]
 * @returns {{isArbitrary: boolean, score: number, reasons: string[], rules: Array<{name: string, score: number, message: string}>, category: string|null}}
 */
export function isArbitrary(mail = {}, options = {}) {
	const {threshold = 5, authentication = null, now = new Date()} = options;
	const session = buildSessionInfo(mail, options.session);
	const rules = [];
	let category = null;
	const hit = (name, score, message, kind = null) => {
		rules.push({name, score, message});
		category ||= kind;
	};

	const subject = typeof mail.subject === 'string' ? mail.subject : '';
	const text = typeof mail.text === 'string' ? mail.text : '';
	const html = typeof mail.html === 'string' ? mail.html : '';
	const rawHeaders = Array.isArray(mail.headerLines) ? mail.headerLines.map(line => line.line).join('\n') : '';

	if ([subject, text, html, rawHeaders].some(part => part.includes(GTUBE))) {
		hit('GTUBE', 1000, 'Contains the GTUBE spam test string', 'SPAM');
	}

	if (BLOCKED_SUBJECT.test(subject)) {
		hit('SEXTORTION_SUBJECT', 6, 'Subject used by sextortion and account takeover scams', 'SCAM');
	}

	if (PROMPT_INJECTION.test(`${subject}\n${text.slice(0, 50_000)}\n${html.slice(0, 100_000)}`)) {
		hit('PROMPT_INJECTION', 3, 'Contains instructions addressed to an AI filter', 'SPAM');
	}

	// Microsoft's verdict, only for mail its outbound servers relayed.
	if (session.resolvedClientHostname?.endsWith('.outbound.protection.outlook.com')) {
		const report = headerString(mail, 'x-forefront-antispam-report');
		const scl = Number.parseInt(report.match(/\bscl:(-?\d+)/i)?.[1] ?? '', 10);
		if (MS_SPAM_VERDICT.test(report) || MS_SPAM_CATEGORY.test(report)) {
			hit('MICROSOFT_SPAM_VERDICT', 5, 'Microsoft classified this message as spam before relaying it', 'SPAM');
		} else if (scl >= 5) {
			hit('MICROSOFT_HIGH_SCL', 3, `Microsoft gave this message a spam confidence level of ${scl}`, 'SPAM');
		}
	}

	// PayPal invoice and money request spam.
	if (PAYPAL_DOMAIN.test(session.originalFromAddressRootDomain || '')) {
		const typeId = headerString(mail, 'x-email-type-id').trim().toUpperCase();
		if (PAYPAL_SPAM_TYPE_IDS.has(typeId) || PAYPAL_INVOICE_SUBJECT.test(subject)) {
			hit('PAYPAL_INVOICE', 6, 'PayPal invoice or money request, a channel widely abused for scams', 'SCAM');
		}
	}

	const from = mail.from?.value?.find(entry => entry.address);
	if (from) {
		const fromRoot = session.originalFromAddressRootDomain;
		const name = typeof from.name === 'string' ? from.name.toLowerCase() : '';
		const claimed = name.match(/[\p{L}\p{N}._%+-]+@([\p{L}\p{N}-]+(?:\.[\p{L}\p{N}-]+)+)/u);
		if (claimed && registrableDomain(claimed[1]) !== fromRoot) {
			hit('FROM_NAME_OTHER_ADDRESS', 2.5, `Display name shows ${claimed[0]} but the message is from ${from.address}`, 'SPOOFING');
		}

		const brand = DISPLAY_BRANDS.find(word => new RegExp(`(?:^|[^\\p{L}])${word}(?:$|[^\\p{L}])`, 'u').test(name));
		if (brand && !fromRoot.replaceAll('-', '').startsWith(brand.replaceAll(' ', ''))) {
			hit('FROM_NAME_BRAND', 2, `Display name says "${brand}" but the message is from ${fromRoot}`, 'PHISHING');
		}

		// Claims to come from the recipient's own domain, without authenticating.
		if (authentication && session.envelope?.rcptTo?.length) {
			const recipients = new Set(session.envelope.rcptTo.map(rcpt => registrableDomain(domainOf(rcpt.address))));
			const aligned = authentication.dmarc?.status?.result === 'pass' || authentication.dkim?.aligned || (authentication.spf?.status?.result === 'pass' && registrableDomain(authentication.spf.domain || '') === fromRoot);
			if (recipients.has(fromRoot) && !aligned) {
				hit('SELF_SPOOF', 3, `Claims to be from the recipient's own domain (${fromRoot}) but does not authenticate`, 'SPOOFING');
			}
		}
	}

	if (mail.headers?.get) {
		if (!mail.date) {
			hit('MISSING_DATE', 0.5, 'No Date header');
		} else if (mail.date.getTime() - now.getTime() > 86_400_000) {
			hit('DATE_IN_FUTURE', 1, 'Date header is more than a day in the future');
		}

		if (!mail.messageId) {
			hit('MISSING_MESSAGE_ID', 0.5, 'No Message-ID header');
		}
	}

	const score = rules.reduce((sum, rule) => sum + rule.score, 0);
	return {
		isArbitrary: score >= threshold,
		score,
		reasons: rules.map(rule => rule.name),
		rules,
		category,
	};
}
