/**
 * Arbitrary Spam Detection Module
 * Based on Forward Email's is-arbitrary helper
 * Detects common spam patterns, Microsoft Exchange spam, and arbitrary spam indicators
 *
 * @see https://github.com/forwardemail/forwardemail.net/blob/master/helpers/is-arbitrary.js
 */

import {debuglog} from 'node:util';

const debug = debuglog('spamscanner:arbitrary');

/**
 * @typedef {Object} ArbitraryResult
 * @property {boolean} isArbitrary - Whether the message appears to be arbitrary spam
 * @property {string[]} reasons - List of reasons why the message was flagged
 * @property {number} score - Arbitrary spam score
 * @property {string|null} category - Spam category if detected (e.g., 'PHISHING', 'MALWARE', 'SPOOFING')
 */

/**
 * @typedef {Object} SessionInfo
 * @property {string} [resolvedClientHostname] - Resolved hostname of connecting client
 * @property {string} [resolvedRootClientHostname] - Root domain of resolved client hostname
 * @property {string} [remoteAddress] - IP address of connecting client
 * @property {string} [originalFromAddress] - Email address from From header
 * @property {string} [originalFromAddressDomain] - Domain from From header
 * @property {string} [originalFromAddressRootDomain] - Root domain from From header
 * @property {Object} [envelope] - SMTP envelope
 * @property {Object} [envelope.mailFrom] - MAIL FROM address
 * @property {Array} [envelope.rcptTo] - RCPT TO addresses
 * @property {boolean} [hadAlignedAndPassingDKIM] - Whether DKIM was aligned and passing
 * @property {Object} [spfFromHeader] - SPF result for From header
 * @property {boolean} [hasSameHostnameAsFrom] - Whether client hostname matches From domain
 * @property {boolean} [isAllowlisted] - Whether sender is allowlisted
 * @property {Set} [signingDomains] - Set of DKIM signing domains
 */

// Blocked phrases that indicate obvious spam
const BLOCKED_PHRASES_PATTERN
	= /cheecck y0ur acc0untt|recorded you|you've been hacked|account is hacked|personal data has leaked|private information has been stolen/im;

// Sysadmin subject patterns (legitimate automated emails)
const SYSADMIN_SUBJECT_PATTERN
	= /please moderate|mdadm monitoring|weekly report|wordfence|wordpress|wpforms|docker|graylog|digest|event notification|package update manager|event alert|system events|monit alert|ping|monitor|cron|yum|sendmail|exim|backup|logwatch|unattended-upgrades/im;

// Common spam patterns and indicators
const SPAM_PATTERNS = {
	// Subject line patterns
	subjectPatterns: [
		// Urgency patterns
		/\b(urgent|immediate|action required|act now|limited time|expires?|deadline)\b/i,
		// Money patterns
		/\b(free|winner|won|prize|lottery|million|billion|cash|money|investment|profit)\b/i,
		// Phishing patterns
		/\b(verify|confirm|update|suspend|locked|unusual activity|security alert)\b/i,
		// Adult content
		/\b(viagra|cialis|pharmacy|pills|medication|prescription)\b/i,
		// Crypto spam
		/\b(bitcoin|crypto|btc|eth|nft|blockchain|wallet)\b/i,
	],

	// Body patterns
	bodyPatterns: [
		// Nigerian prince / advance fee fraud
		/\b(nigerian?|prince|inheritance|beneficiary|next of kin|deceased|unclaimed)\b/i,
		// Lottery scams
		/\b(congratulations.*won|you have been selected|claim your prize)\b/i,
		// Phishing
		/\b(click here to verify|confirm your identity|update your account|suspended.*account)\b/i,
		// Urgency
		/\b(act now|limited time offer|expires in \d+|only \d+ left)\b/i,
		// Financial scams
		/\b(wire transfer|western union|moneygram|bank transfer|routing number)\b/i,
		// Adult/pharma spam
		/\b(enlarge|enhancement|erectile|dysfunction|weight loss|diet pills)\b/i,
	],

	// Suspicious sender patterns
	senderPatterns: [
		// Random numbers in email
		/^[a-z]+\d{4,}@/i,
		// Very long local parts
		/^.{30,}@/,
		// Suspicious domains
		/@.*(\.ru|\.cn|\.tk|\.ml|\.ga|\.cf|\.gq)$/i,
		// Numeric domains
		/@(?:\d+\.){3}\d+/,
	],
};

// Suspicious TLDs commonly used in spam
const SUSPICIOUS_TLDS = new Set([
	'tk',
	'ml',
	'ga',
	'cf',
	'gq', // Free TLDs often abused
	'xyz',
	'top',
	'wang',
	'win',
	'bid',
	'loan',
	'click',
	'link',
	'work',
	'date',
	'racing',
	'download',
	'stream',
	'trade',
]);

// Common spam keywords with weights
const SPAM_KEYWORDS = new Map([
	['free', 1],
	['winner', 2],
	['prize', 2],
	['lottery', 3],
	['urgent', 1],
	['act now', 2],
	['limited time', 1],
	['click here', 1],
	['unsubscribe', -1], // Legitimate emails often have this
	['verify your account', 2],
	['suspended', 2],
	['inheritance', 3],
	['million dollars', 3],
	['wire transfer', 3],
	['western union', 3],
	['nigerian', 3],
	['prince', 2],
	['beneficiary', 2],
	['congratulations', 1],
	['selected', 1],
	['viagra', 3],
	['cialis', 3],
	['pharmacy', 2],
	['bitcoin', 1],
	['crypto', 1],
	['investment opportunity', 2],
	['guaranteed', 1],
	['risk free', 2],
	['no obligation', 1],
	['dear friend', 2],
	['dear customer', 1],
	['dear user', 1],
]);

// PayPal spam email type IDs
const PAYPAL_SPAM_TYPE_IDS = new Set(['PPC001017', 'RT000238', 'RT000542', 'RT002947']);

/**
 * Microsoft Exchange Spam Categories (CAT values)
 * @see https://learn.microsoft.com/en-us/defender-office-365/how-policies-and-protections-are-combined
 */
const MS_SPAM_CATEGORIES = {
	// High-confidence threats (highest priority)
	highConfidence: ['cat:malw', 'cat:hphsh', 'cat:hphish', 'cat:hspm'],
	// Impersonation attempts
	impersonation: ['cat:bimp', 'cat:dimp', 'cat:gimp', 'cat:uimp'],
	// Phishing and spoofing
	phishingAndSpoofing: ['cat:phsh', 'cat:spoof'],
	// Spam classifications
	spam: ['cat:ospm', 'cat:spm'],
};

/**
 * Microsoft Spam Filtering Verdicts (SFV values)
 * @see https://learn.microsoft.com/en-us/defender-office-365/message-headers-eop-mdo
 */
const MS_SPAM_VERDICTS = ['sfv:spm', 'sfv:skb', 'sfv:sks'];

/**
 * Check if a message appears to be arbitrary spam
 * @param {Object} parsed - Parsed email message (from mailparser)
 * @param {Object} options - Detection options
 * @param {SessionInfo} [options.session] - Session information for advanced checks
 * @returns {ArbitraryResult}
 */
function isArbitrary(parsed, options = {}) {
	const {
		threshold = 5,
		checkSubject = true,
		checkBody = true,
		checkSender = true,
		checkHeaders = true,
		checkLinks = true,
		checkMicrosoftHeaders = true,
		checkVendorSpam = true,
		checkSpoofing = true,
		session = {},
	} = options;

	const reasons = [];
	let score = 0;
	let category = null;

	// Get headers helper
	const getHeader = name => {
		if (parsed.headers?.get) {
			return parsed.headers.get(name);
		}

		if (parsed.headerLines) {
			const header = parsed.headerLines.find(h => h.key.toLowerCase() === name.toLowerCase());
			return header?.line?.split(':').slice(1).join(':').trim();
		}

		return null;
	};

	const subject = parsed.subject || getHeader('subject') || '';
	const from = parsed.from?.value?.[0]?.address || parsed.from?.text || getHeader('from') || '';

	// Build session info from parsed email if not provided
	const sessionInfo = buildSessionInfo(parsed, session, getHeader);

	// Check for blocked phrases in subject
	if (subject && BLOCKED_PHRASES_PATTERN.test(subject)) {
		reasons.push('BLOCKED_PHRASE_IN_SUBJECT');
		score += 10;
		category = 'SPAM';
	}

	// Check Microsoft Exchange headers (only if from Microsoft infrastructure)
	if (checkMicrosoftHeaders) {
		const msResult = checkMicrosoftExchangeHeaders(getHeader, sessionInfo);
		if (msResult.blocked) {
			reasons.push(...msResult.reasons);
			score += msResult.score;
			category = msResult.category || category;
		}
	}

	// Check vendor-specific spam patterns
	if (checkVendorSpam) {
		const vendorResult = checkVendorSpam_(parsed, sessionInfo, getHeader, subject, from);
		if (vendorResult.blocked) {
			reasons.push(...vendorResult.reasons);
			score += vendorResult.score;
			category = vendorResult.category || category;
		}
	}

	// Check for spoofing attacks
	if (checkSpoofing) {
		const spoofResult = checkSpoofingAttacks(parsed, sessionInfo, getHeader, subject);
		if (spoofResult.blocked) {
			reasons.push(...spoofResult.reasons);
			score += spoofResult.score;
			category = spoofResult.category || category;
		}
	}

	// Check subject line
	if (checkSubject && subject) {
		const subjectResult = checkSubjectLine(subject);
		score += subjectResult.score;
		reasons.push(...subjectResult.reasons);
	}

	// Check body content
	if (checkBody) {
		const bodyText = parsed.text || '';
		const bodyHtml = parsed.html || '';
		const bodyResult = checkBodyContent(bodyText, bodyHtml);
		score += bodyResult.score;
		reasons.push(...bodyResult.reasons);
	}

	// Check sender
	if (checkSender) {
		const replyTo = parsed.replyTo?.value?.[0]?.address || parsed.replyTo?.text || '';
		const senderResult = checkSenderPatterns(from, replyTo);
		score += senderResult.score;
		reasons.push(...senderResult.reasons);
	}

	// Check headers
	if (checkHeaders) {
		const headerResult = checkHeaderAnomalies(parsed, getHeader);
		score += headerResult.score;
		reasons.push(...headerResult.reasons);
	}

	// Check links
	if (checkLinks) {
		const bodyHtml = parsed.html || parsed.text || '';
		const linkResult = checkSuspiciousLinks(bodyHtml);
		score += linkResult.score;
		reasons.push(...linkResult.reasons);
	}

	const isArbitrarySpam = score >= threshold;

	debug(
		'Arbitrary check result: score=%d, threshold=%d, isArbitrary=%s, category=%s, reasons=%o',
		score,
		threshold,
		isArbitrarySpam,
		category,
		reasons,
	);

	return {
		isArbitrary: isArbitrarySpam,
		reasons,
		score,
		category,
	};
}

/**
 * Build session info from parsed email and provided session
 * @param {Object} parsed - Parsed email
 * @param {SessionInfo} session - Provided session info
 * @param {Function} getHeader - Header getter function
 * @returns {SessionInfo}
 */
function buildSessionInfo(parsed, session, getHeader) {
	const info = {...session};

	// Extract from address info
	const from = parsed.from?.value?.[0]?.address || parsed.from?.text || getHeader('from') || '';
	if (from && !info.originalFromAddress) {
		info.originalFromAddress = from.toLowerCase();
		const atIndex = from.indexOf('@');
		if (atIndex > 0) {
			info.originalFromAddressDomain = from.slice(atIndex + 1).toLowerCase();
			info.originalFromAddressRootDomain = getRootDomain(info.originalFromAddressDomain);
		}
	}

	// Extract client hostname from Received headers
	if (!info.resolvedClientHostname) {
		info.resolvedClientHostname = extractClientHostname(parsed);
		if (info.resolvedClientHostname) {
			info.resolvedRootClientHostname = getRootDomain(info.resolvedClientHostname);
		}
	}

	// Extract remote IP
	info.remoteAddress ||= extractRemoteIp(parsed);

	// Only use envelope if provided from actual SMTP session
	// Don't create fake envelope from headers as it can cause false positives
	// in spoofing detection (To header != RCPT TO in SMTP)

	return info;
}

/**
 * Check Microsoft Exchange headers for spam classification
 * This detects spam forwarded through Microsoft Exchange infrastructure
 *
 * @see https://learn.microsoft.com/en-us/defender-office-365/message-headers-eop-mdo
 * @param {Function} getHeader - Header getter function
 * @param {SessionInfo} sessionInfo - Session information
 * @returns {{blocked: boolean, reasons: string[], score: number, category: string|null}}
 */
function checkMicrosoftExchangeHeaders(getHeader, sessionInfo) {
	const result = {
		blocked: false, reasons: [], score: 0, category: null,
	};

	// Only check if message came from Microsoft infrastructure
	const isFromMicrosoft
		= sessionInfo.resolvedClientHostname
			&& sessionInfo.resolvedClientHostname.endsWith('.outbound.protection.outlook.com');

	if (!isFromMicrosoft) {
		return result;
	}

	const msAuthHeader = getHeader('x-ms-exchange-authentication-results');
	const forefrontHeader = getHeader('x-forefront-antispam-report');

	// Check authentication failures first (if Microsoft didn't mark as non-spam)
	if (forefrontHeader) {
		const lowerForefront = forefrontHeader.toLowerCase();

		// Extract SCL (Spam Confidence Level)
		const sclMatch = lowerForefront.match(/scl:(\d+)/);
		const scl = sclMatch ? Number.parseInt(sclMatch[1], 10) : null;

		// Check if Microsoft says it's NOT spam
		const sfvNotSpam = lowerForefront.includes('sfv:nspm');
		const microsoftSaysNotSpam = sfvNotSpam || (scl !== null && scl <= 2);

		// Only check authentication if Microsoft didn't clear it
		if (!microsoftSaysNotSpam && msAuthHeader) {
			const lowerMsAuth = msAuthHeader.toLowerCase();

			// Check if any authentication passed
			const spfPass = lowerMsAuth.includes('spf=pass');
			const dkimPass = lowerMsAuth.includes('dkim=pass');
			const dmarcPass = lowerMsAuth.includes('dmarc=pass');

			// Only block if ALL authentication methods failed
			if (!spfPass && !dkimPass && !dmarcPass) {
				// Check for hard failures (not softfail)
				const spfFailed = lowerMsAuth.includes('spf=fail');
				const dkimFailed = lowerMsAuth.includes('dkim=fail');
				const dmarcFailed = lowerMsAuth.includes('dmarc=fail');

				if (spfFailed || dkimFailed || dmarcFailed) {
					result.blocked = true;
					result.reasons.push('MS_EXCHANGE_AUTH_FAILURE');
					result.score += 10;
					result.category = 'AUTHENTICATION_FAILURE';
					return result;
				}
			}
		}

		// Check for high-confidence threats
		for (const cat of MS_SPAM_CATEGORIES.highConfidence) {
			if (lowerForefront.includes(cat)) {
				result.blocked = true;
				result.reasons.push(`MS_HIGH_CONFIDENCE_THREAT: ${cat.toUpperCase()}`);
				result.score += 15;
				result.category = cat.includes('malw')
					? 'MALWARE'
					: (cat.includes('phish') || cat.includes('phsh')
						? 'PHISHING'
						: 'HIGH_CONFIDENCE_SPAM');
				return result;
			}
		}

		// Check for impersonation attempts
		for (const cat of MS_SPAM_CATEGORIES.impersonation) {
			if (lowerForefront.includes(cat)) {
				result.blocked = true;
				result.reasons.push(`MS_IMPERSONATION: ${cat.toUpperCase()}`);
				result.score += 12;
				result.category = 'IMPERSONATION';
				return result;
			}
		}

		// Check for phishing and spoofing
		for (const cat of MS_SPAM_CATEGORIES.phishingAndSpoofing) {
			if (lowerForefront.includes(cat)) {
				result.blocked = true;
				result.reasons.push(`MS_PHISHING_SPOOF: ${cat.toUpperCase()}`);
				result.score += 12;
				result.category = cat.includes('phsh') ? 'PHISHING' : 'SPOOFING';
				return result;
			}
		}

		// Check spam verdicts
		for (const verdict of MS_SPAM_VERDICTS) {
			if (lowerForefront.includes(verdict)) {
				result.blocked = true;
				result.reasons.push(`MS_SPAM_VERDICT: ${verdict.toUpperCase()}`);
				result.score += 10;
				result.category = 'SPAM';
				return result;
			}
		}

		// Check spam categories
		for (const cat of MS_SPAM_CATEGORIES.spam) {
			if (lowerForefront.includes(cat)) {
				result.blocked = true;
				result.reasons.push(`MS_SPAM_CATEGORY: ${cat.toUpperCase()}`);
				result.score += 10;
				result.category = 'SPAM';
				return result;
			}
		}

		// Check SCL threshold (5+ is spam)
		if (scl !== null && scl >= 5) {
			result.blocked = true;
			result.reasons.push(`MS_HIGH_SCL: ${scl}`);
			result.score += 8;
			result.category = 'SPAM';
			return result;
		}
	} else if (msAuthHeader) {
		// No forefront header, check authentication only
		const lowerMsAuth = msAuthHeader.toLowerCase();

		const spfPass = lowerMsAuth.includes('spf=pass');
		const dkimPass = lowerMsAuth.includes('dkim=pass');
		const dmarcPass = lowerMsAuth.includes('dmarc=pass');

		if (!spfPass && !dkimPass && !dmarcPass) {
			const spfFailed = lowerMsAuth.includes('spf=fail');
			const dkimFailed = lowerMsAuth.includes('dkim=fail');
			const dmarcFailed = lowerMsAuth.includes('dmarc=fail');

			if (spfFailed || dkimFailed || dmarcFailed) {
				result.blocked = true;
				result.reasons.push('MS_EXCHANGE_AUTH_FAILURE');
				result.score += 10;
				result.category = 'AUTHENTICATION_FAILURE';
			}
		}
	}

	return result;
}

/**
 * Check for vendor-specific spam patterns
 * @param {Object} parsed - Parsed email
 * @param {SessionInfo} sessionInfo - Session information
 * @param {Function} getHeader - Header getter function
 * @param {string} subject - Email subject
 * @param {string} from - From address
 * @returns {{blocked: boolean, reasons: string[], score: number, category: string|null}}
 */
function checkVendorSpam_(parsed, sessionInfo, getHeader, subject, from) {
	const result = {
		blocked: false, reasons: [], score: 0, category: null,
	};
	const fromLower = from.toLowerCase();

	// PayPal invoice spam
	if (
		sessionInfo.originalFromAddressRootDomain === 'paypal.com'
		&& getHeader('x-email-type-id')
	) {
		const typeId = getHeader('x-email-type-id');
		if (PAYPAL_SPAM_TYPE_IDS.has(typeId)) {
			result.blocked = true;
			result.reasons.push(`PAYPAL_INVOICE_SPAM: ${typeId}`);
			result.score += 15;
			result.category = 'VENDOR_SPAM';
			return result;
		}
	}

	// Authorize.net/VISA phishing scam
	if (
		sessionInfo.originalFromAddress === 'invoice@authorize.net'
		&& sessionInfo.resolvedRootClientHostname === 'visa.com'
	) {
		result.blocked = true;
		result.reasons.push('AUTHORIZE_VISA_PHISHING');
		result.score += 15;
		result.category = 'PHISHING';
		return result;
	}

	// Amazon.co.jp impersonation
	if (
		fromLower.includes('amazon.co.jp')
		&& (!sessionInfo.resolvedRootClientHostname
			|| !sessionInfo.resolvedRootClientHostname.startsWith('amazon.'))
	) {
		result.blocked = true;
		result.reasons.push('AMAZON_JP_IMPERSONATION');
		result.score += 12;
		result.category = 'IMPERSONATION';
		return result;
	}

	// PCloud impersonation
	if (
		subject
		&& subject.includes('pCloud')
		&& sessionInfo.originalFromAddressRootDomain !== 'pcloud.com'
		&& fromLower.includes('pcloud')
	) {
		result.blocked = true;
		result.reasons.push('PCLOUD_IMPERSONATION');
		result.score += 12;
		result.category = 'IMPERSONATION';
		return result;
	}

	// Microsoft postmaster bounce spam
	if (
		(sessionInfo.originalFromAddress === 'postmaster@outlook.com'
			|| (sessionInfo.resolvedClientHostname
				&& sessionInfo.resolvedClientHostname.endsWith('.outbound.protection.outlook.com'))
			|| (sessionInfo.originalFromAddress?.startsWith('postmaster@')
				&& sessionInfo.originalFromAddress?.endsWith('.onmicrosoft.com')))
			&& isAutoReply(getHeader)
			&& subject
			&& (subject.startsWith('Undeliverable: ') || subject.startsWith('No se puede entregar: '))
	) {
		result.blocked = true;
		result.reasons.push('MS_BOUNCE_SPAM');
		result.score += 10;
		result.category = 'BOUNCE_SPAM';
		return result;
	}

	// 163.com bounce spam
	if (
		sessionInfo.originalFromAddress === 'postmaster@163.com'
		&& subject
		&& subject.includes('系统退信')
	) {
		result.blocked = true;
		result.reasons.push('163_BOUNCE_SPAM');
		result.score += 10;
		result.category = 'BOUNCE_SPAM';
		return result;
	}

	// DocuSign + Microsoft scam
	if (
		sessionInfo.originalFromAddress === 'dse_na4@docusign.net'
		&& sessionInfo.spf?.domain
		&& (sessionInfo.spf.domain.endsWith('.onmicrosoft.com')
			|| sessionInfo.spf.domain === 'onmicrosoft.com')
	) {
		result.blocked = true;
		result.reasons.push('DOCUSIGN_MS_SCAM');
		result.score += 12;
		result.category = 'PHISHING';
		return result;
	}

	return result;
}

/**
 * Check for spoofing attacks
 * @param {Object} parsed - Parsed email
 * @param {SessionInfo} sessionInfo - Session information
 * @param {Function} getHeader - Header getter function
 * @param {string} subject - Email subject
 * @returns {{blocked: boolean, reasons: string[], score: number, category: string|null}}
 */
function checkSpoofingAttacks(parsed, sessionInfo, getHeader, subject) {
	const result = {
		blocked: false, reasons: [], score: 0, category: null,
	};

	// Skip if DKIM aligned and passing, or if allowlisted
	if (sessionInfo.hadAlignedAndPassingDKIM || sessionInfo.isAllowlisted) {
		return result;
	}

	// Skip if client hostname matches From domain
	if (sessionInfo.hasSameHostnameAsFrom) {
		return result;
	}

	// Check if any RCPT TO has same root domain as From header
	const rcptTo = sessionInfo.envelope?.rcptTo || [];
	const fromRootDomain = sessionInfo.originalFromAddressRootDomain;

	if (!fromRootDomain || rcptTo.length === 0) {
		return result;
	}

	const hasSameRcptToAsFrom = rcptTo.some(to => {
		if (!to.address) {
			return false;
		}

		const toRootDomain = getRootDomain(parseHostFromAddress(to.address));
		return toRootDomain === fromRootDomain;
	});

	if (!hasSameRcptToAsFrom) {
		return result;
	}

	// Check SPF result
	const spfResult = sessionInfo.spfFromHeader?.status?.result;
	if (spfResult === 'pass') {
		return result;
	}

	// Mark as potential phishing (for later notification)
	sessionInfo.isPotentialPhishing = true;

	// Allow sysadmin alerts through
	const xPhpScript = getHeader('x-php-script');
	const xMailer = getHeader('x-mailer');

	if (xPhpScript) {
		return result;
	}

	if (xMailer) {
		const mailerLower = xMailer.toLowerCase();
		if (mailerLower.includes('php') || mailerLower.includes('drupal')) {
			return result;
		}
	}

	if (subject && SYSADMIN_SUBJECT_PATTERN.test(subject)) {
		return result;
	}

	// This looks like a spoofing attack
	result.blocked = true;
	result.reasons.push('SPOOFING_ATTACK');
	result.score += 12;
	result.category = 'SPOOFING';

	return result;
}

/**
 * Check if message is an auto-reply or from a mailing list
 * @param {Function} getHeader - Header getter function
 * @returns {boolean}
 */
function isAutoReply(getHeader) {
	// Check Auto-Submitted header
	const autoSubmitted = getHeader('auto-submitted');
	if (autoSubmitted && autoSubmitted !== 'no') {
		return true;
	}

	// Check X-Auto-Response-Suppress
	const autoResponseSuppress = getHeader('x-auto-response-suppress');
	if (autoResponseSuppress) {
		return true;
	}

	// Check Precedence header
	const precedence = getHeader('precedence');
	if (precedence && ['bulk', 'junk', 'list', 'auto_reply'].includes(precedence.toLowerCase())) {
		return true;
	}

	// Check List-Unsubscribe (mailing list)
	if (getHeader('list-unsubscribe')) {
		return true;
	}

	return false;
}

/**
 * Check subject line for spam patterns
 * @param {string} subject
 * @returns {{score: number, reasons: string[]}}
 */
function checkSubjectLine(subject) {
	const reasons = [];
	let score = 0;

	// Check against patterns
	for (const pattern of SPAM_PATTERNS.subjectPatterns) {
		if (pattern.test(subject)) {
			const match = subject.match(pattern);
			reasons.push(`SUBJECT_SPAM_PATTERN: ${match[0]}`);
			score += 1;
		}
	}

	// Check for all caps
	const upperCount = (subject.match(/[A-Z]/g) || []).length;
	const letterCount = (subject.match(/[a-zA-Z]/g) || []).length;
	if (letterCount > 10 && upperCount / letterCount > 0.7) {
		reasons.push('SUBJECT_ALL_CAPS');
		score += 2;
	}

	// Check for excessive punctuation
	const punctCount = (subject.match(/[!?$]/g) || []).length;
	if (punctCount >= 3) {
		reasons.push('SUBJECT_EXCESSIVE_PUNCTUATION');
		score += 1;
	}

	// Check for RE:/FW: without proper threading
	if (/^(re|fw|fwd):/i.test(subject) && subject.length < 20) {
		reasons.push('SUBJECT_FAKE_REPLY');
		score += 1;
	}

	return {score, reasons};
}

/**
 * Check body content for spam patterns
 * @param {string} text - Plain text body
 * @param {string} html - HTML body
 * @returns {{score: number, reasons: string[]}}
 */
function checkBodyContent(text, html) {
	const reasons = [];
	let score = 0;

	const content = text || html || '';
	const contentLower = content.toLowerCase();

	// Check against body patterns
	for (const pattern of SPAM_PATTERNS.bodyPatterns) {
		if (pattern.test(content)) {
			const match = content.match(pattern);
			reasons.push(`BODY_SPAM_PATTERN: ${match[0].slice(0, 50)}`);
			score += 1;
		}
	}

	// Check for spam keywords
	for (const [keyword, weight] of SPAM_KEYWORDS) {
		if (contentLower.includes(keyword.toLowerCase())) {
			reasons.push(`SPAM_KEYWORD: ${keyword}`);
			score += weight;
		}
	}

	// Check for hidden text (white on white, tiny font, etc.)
	if (html) {
		if (/color:\s*#fff|color:\s*white|font-size:\s*[01]px/i.test(html)) {
			reasons.push('HIDDEN_TEXT');
			score += 3;
		}

		// Check for excessive images with few text
		const imgCount = (html.match(/<img/gi) || []).length;
		const textLength = (text || '').length;
		if (imgCount > 5 && textLength < 100) {
			reasons.push('IMAGE_HEAVY_LOW_TEXT');
			score += 2;
		}
	}

	// Check for base64 encoded content (often used to evade filters)
	if (/data:image\/[^;]+;base64,/i.test(html || '')) {
		reasons.push('BASE64_IMAGES');
		score += 1;
	}

	// Check for URL shorteners
	const shortenerPatterns
		= /\b(bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly|is\.gd|buff\.ly|adf\.ly|j\.mp)\b/i;
	if (shortenerPatterns.test(content)) {
		reasons.push('URL_SHORTENER');
		score += 2;
	}

	return {score, reasons};
}

/**
 * Check sender for suspicious patterns
 * @param {string} from - From address
 * @param {string} replyTo - Reply-To address
 * @returns {{score: number, reasons: string[]}}
 */
function checkSenderPatterns(from, replyTo) {
	const reasons = [];
	let score = 0;

	if (!from) {
		reasons.push('MISSING_FROM');
		score += 2;
		return {score, reasons};
	}

	// Check against sender patterns
	for (const pattern of SPAM_PATTERNS.senderPatterns) {
		if (pattern.test(from)) {
			reasons.push('SUSPICIOUS_SENDER_PATTERN');
			score += 2;
			break;
		}
	}

	// Check for suspicious TLD
	const tldMatch = from.match(/@[^.]+\.([a-z]+)$/i);
	if (tldMatch && SUSPICIOUS_TLDS.has(tldMatch[1].toLowerCase())) {
		reasons.push(`SUSPICIOUS_TLD: ${tldMatch[1]}`);
		score += 2;
	}

	// Check for From/Reply-To mismatch
	if (replyTo && from) {
		const fromDomain = from.split('@')[1]?.toLowerCase();
		const replyDomain = replyTo.split('@')[1]?.toLowerCase();
		if (fromDomain && replyDomain && fromDomain !== replyDomain) {
			reasons.push('FROM_REPLY_TO_MISMATCH');
			score += 2;
		}
	}

	// Check for display name spoofing
	// e.g., "PayPal <scammer@evil.com>"
	const spoofPatterns = /^(paypal|amazon|apple|microsoft|google|bank|security)/i;
	if (spoofPatterns.test(from) && !/@(paypal|amazon|apple|microsoft|google)\.com$/i.test(from)) {
		reasons.push('DISPLAY_NAME_SPOOFING');
		score += 3;
	}

	return {score, reasons};
}

/**
 * Check headers for anomalies
 * @param {Object} parsed - Parsed email
 * @param {Function} getHeader - Header getter function
 * @returns {{score: number, reasons: string[]}}
 */
function checkHeaderAnomalies(parsed, getHeader) {
	const reasons = [];
	let score = 0;

	// Check for missing Message-ID
	if (!parsed.messageId && !getHeader('message-id')) {
		reasons.push('MISSING_MESSAGE_ID');
		score += 1;
	}

	// Check for missing Date
	if (parsed.date) {
		// Check for future date
		const messageDate = new Date(parsed.date);
		const now = new Date();
		if (messageDate > now) {
			const hoursDiff = (messageDate - now) / (1000 * 60 * 60);
			if (hoursDiff > 24) {
				reasons.push('FUTURE_DATE');
				score += 2;
			}
		}

		// Check for very old date
		const daysDiff = (now - messageDate) / (1000 * 60 * 60 * 24);
		if (daysDiff > 365) {
			reasons.push('VERY_OLD_DATE');
			score += 1;
		}
	} else {
		reasons.push('MISSING_DATE');
		score += 1;
	}

	// Check for suspicious X-Mailer
	const xMailer = getHeader('x-mailer') || '';
	if (xMailer) {
		const suspiciousMailers = /mass mail|bulk mail|email blast/i;
		if (suspiciousMailers.test(xMailer)) {
			reasons.push('SUSPICIOUS_MAILER');
			score += 1;
		}
	}

	// Check for missing MIME-Version
	const mimeVersion = getHeader('mime-version');
	if (!mimeVersion && (parsed.html || parsed.attachments?.length > 0)) {
		reasons.push('MISSING_MIME_VERSION');
		score += 1;
	}

	// Check for excessive recipients
	const toCount = parsed.to?.value?.length || 0;
	const ccCount = parsed.cc?.value?.length || 0;
	if (toCount + ccCount > 50) {
		reasons.push('EXCESSIVE_RECIPIENTS');
		score += 2;
	}

	return {score, reasons};
}

/**
 * Check links in content for suspicious patterns
 * @param {string} content - Email content (HTML or text)
 * @returns {{score: number, reasons: string[]}}
 */
function checkSuspiciousLinks(content) {
	const reasons = [];
	let score = 0;

	// Extract URLs
	const urlPattern = /https?:\/\/[^\s<>"']+/gi;
	const urls = content.match(urlPattern) || [];

	if (urls.length === 0) {
		return {score, reasons};
	}

	// Check each URL
	const suspiciousUrls = new Set();
	for (const url of urls) {
		try {
			const parsed = new URL(url);
			const hostname = parsed.hostname.toLowerCase();

			// Check for IP address URLs
			if (/^(?:\d+\.){3}\d+$/.test(hostname)) {
				suspiciousUrls.add('IP_ADDRESS_URL');
			}

			// Check for suspicious TLD
			const tld = hostname.split('.').pop();
			if (SUSPICIOUS_TLDS.has(tld)) {
				suspiciousUrls.add(`SUSPICIOUS_URL_TLD: ${tld}`);
			}

			// Check for URL with port
			if (parsed.port && !['80', '443', ''].includes(parsed.port)) {
				suspiciousUrls.add('URL_WITH_PORT');
			}

			// Check for very long URLs (often used in phishing)
			if (url.length > 200) {
				suspiciousUrls.add('VERY_LONG_URL');
			}

			// Check for excessive subdomains
			const subdomainCount = hostname.split('.').length - 2;
			if (subdomainCount > 3) {
				suspiciousUrls.add('EXCESSIVE_SUBDOMAINS');
			}

			// Check for URL obfuscation (encoded characters)
			if (/%[\da-f]{2}/i.test(url) && /%[\da-f]{2}.*%[\da-f]{2}/i.test(url)) {
				suspiciousUrls.add('URL_OBFUSCATION');
			}
		} catch {
			// Invalid URL
			suspiciousUrls.add('INVALID_URL');
		}
	}

	// Add unique reasons
	for (const reason of suspiciousUrls) {
		reasons.push(reason);
		score += 1;
	}

	// Check for mismatched link text and URL (common in phishing)
	const linkPattern = /<a[^>]+href=["']([^"']+)["'][^>]*>([^<]+)<\/a>/gi;
	let match;
	while ((match = linkPattern.exec(content)) !== null) {
		const href = match[1];
		const text = match[2];

		// Check if link text looks like a URL but doesn't match href
		if (/^https?:\/\//i.test(text)) {
			try {
				const textUrl = new URL(text);
				const hrefUrl = new URL(href);
				if (textUrl.hostname.toLowerCase() !== hrefUrl.hostname.toLowerCase()) {
					reasons.push('LINK_TEXT_URL_MISMATCH');
					score += 3;
					break;
				}
			} catch {
				// Ignore parsing errors
			}
		}
	}

	return {score, reasons};
}

/**
 * Get root domain from a hostname
 * @param {string} hostname
 * @returns {string}
 */
function getRootDomain(hostname) {
	if (!hostname) {
		return '';
	}

	const parts = hostname.toLowerCase().split('.');
	if (parts.length <= 2) {
		return hostname.toLowerCase();
	}

	// Handle common multi-part TLDs
	const multiPartTlds = ['co.uk', 'com.au', 'co.nz', 'co.jp', 'com.br', 'co.in'];
	const lastTwo = parts.slice(-2).join('.');
	if (multiPartTlds.includes(lastTwo)) {
		return parts.slice(-3).join('.');
	}

	return parts.slice(-2).join('.');
}

/**
 * Parse host/domain from an email address
 * @param {string} address - Email address
 * @returns {string}
 */
function parseHostFromAddress(address) {
	if (!address) {
		return '';
	}

	const atIndex = address.indexOf('@');
	if (atIndex === -1) {
		return '';
	}

	return address.slice(atIndex + 1).toLowerCase();
}

/**
 * Extract client hostname from email headers
 * @param {Object} parsed - Parsed email
 * @returns {string|null}
 */
function extractClientHostname(parsed) {
	// Try to extract from Received headers
	let receivedHeaders = null;
	if (parsed.headers?.get) {
		receivedHeaders = parsed.headers.get('received');
	} else if (parsed.headerLines) {
		const headers = parsed.headerLines.filter(h => h.key.toLowerCase() === 'received');
		receivedHeaders = headers.map(h => h.line?.split(':').slice(1).join(':').trim());
	}

	if (!receivedHeaders) {
		return null;
	}

	const received = Array.isArray(receivedHeaders) ? receivedHeaders[0] : receivedHeaders;
	if (!received) {
		return null;
	}

	// Parse "from hostname" pattern
	const fromMatch = received.match(/from\s+([^\s(]+)/i);
	if (fromMatch) {
		return fromMatch[1].toLowerCase();
	}

	return null;
}

/**
 * Extract remote IP from email headers
 * @param {Object} parsed - Parsed email
 * @returns {string|null}
 */
function extractRemoteIp(parsed) {
	// Try to extract from Received headers
	let receivedHeaders = null;
	if (parsed.headers?.get) {
		receivedHeaders = parsed.headers.get('received');
	} else if (parsed.headerLines) {
		const headers = parsed.headerLines.filter(h => h.key.toLowerCase() === 'received');
		receivedHeaders = headers.map(h => h.line?.split(':').slice(1).join(':').trim());
	}

	if (!receivedHeaders) {
		return null;
	}

	const received = Array.isArray(receivedHeaders) ? receivedHeaders[0] : receivedHeaders;
	if (!received) {
		return null;
	}

	// Parse IP address patterns
	const ipv4Match = received.match(/\[((?:\d+\.){3}\d+)]/);
	if (ipv4Match) {
		return ipv4Match[1];
	}

	const ipv6Match = received.match(/\[([a-f\d:]+)]/i);
	if (ipv6Match) {
		return ipv6Match[1];
	}

	return null;
}

export {
	isArbitrary,
	checkSubjectLine,
	checkBodyContent,
	checkMicrosoftExchangeHeaders,
	checkVendorSpam_ as checkVendorSpam,
	checkSpoofingAttacks,
	checkSenderPatterns,
	checkHeaderAnomalies,
	checkSuspiciousLinks,
	getRootDomain,
	parseHostFromAddress,
	extractClientHostname,
	extractRemoteIp,
	buildSessionInfo,
	isAutoReply,
	SPAM_PATTERNS,
	SPAM_KEYWORDS,
	SUSPICIOUS_TLDS,
	MS_SPAM_CATEGORIES,
	MS_SPAM_VERDICTS,
	PAYPAL_SPAM_TYPE_IDS,
	BLOCKED_PHRASES_PATTERN,
	SYSADMIN_SUBJECT_PATTERN,
};
