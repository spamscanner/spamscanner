/**
 * Get Attributes Module
 * Based on Forward Email's get-attributes helper
 * Extracts email attributes for reputation checking
 *
 * This module extracts various attributes from an email message that can be
 * used for reputation checking against allowlists, denylists, and truth sources.
 *
 * Attributes extracted include:
 * - Client hostname and root hostname
 * - Remote IP address
 * - From header address, domain, and root domain
 * - Reply-To addresses, domains, and root domains
 * - MAIL FROM address, domain, and root domain
 *
 * @see https://github.com/forwardemail/forwardemail.net/blob/master/helpers/get-attributes.js
 */

import {debuglog} from 'node:util';

const debug = debuglog('spamscanner:attributes');

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
 * @property {Set} [signingDomains] - Set of DKIM signing domains
 */

/**
 * @typedef {Object} GetAttributesOptions
 * @property {boolean} [isAligned=false] - Only return attributes that are verified and aligned
 * @property {Object} [authResults] - Authentication results from mailauth
 */

/**
 * Check and remove SRS (Sender Rewriting Scheme) encoding from an address
 * @param {string} address - Email address
 * @returns {string} - Address with SRS removed
 */
function checkSRS(address) {
	if (!address) {
		return '';
	}

	// SRS0 format: SRS0=HHH=TT=domain=local@forwarder.com
	// SRS1 format: SRS1=HHH=forwarder.com==HHH=TT=domain=local@forwarder2.com
	const srs0Match = address.match(/^srs0=[^=]+=([^=]+)=([^=]+)=([^@]+)@/i);
	if (srs0Match) {
		return `${srs0Match[3]}@${srs0Match[2]}`;
	}

	const srs1Match = address.match(/^srs1=[^=]+=[^=]+==[^=]+=([^=]+)=([^=]+)=([^@]+)@/i);
	if (srs1Match) {
		return `${srs1Match[3]}@${srs1Match[2]}`;
	}

	return address;
}

/**
 * Parse host/domain from an email address or domain string
 * @param {string} addressOrDomain - Email address or domain
 * @returns {string} - Domain portion
 */
function parseHostFromDomainOrAddress(addressOrDomain) {
	if (!addressOrDomain) {
		return '';
	}

	// If it contains @, extract domain
	const atIndex = addressOrDomain.indexOf('@');
	if (atIndex !== -1) {
		return addressOrDomain.slice(atIndex + 1).toLowerCase();
	}

	// Otherwise return as-is (already a domain)
	return addressOrDomain.toLowerCase();
}

/**
 * Get root domain from a hostname
 * @param {string} hostname
 * @returns {string}
 */
function parseRootDomain(hostname) {
	if (!hostname) {
		return '';
	}

	const parts = hostname.toLowerCase().split('.');
	if (parts.length <= 2) {
		return hostname.toLowerCase();
	}

	// Handle common multi-part TLDs
	const multiPartTlds = new Set([
		'co.uk',
		'com.au',
		'co.nz',
		'co.jp',
		'com.br',
		'co.in',
		'org.uk',
		'net.au',
		'com.mx',
		'com.cn',
		'com.tw',
		'com.hk',
		'co.za',
		'com.sg',
	]);
	const lastTwo = parts.slice(-2).join('.');
	if (multiPartTlds.has(lastTwo)) {
		return parts.slice(-3).join('.');
	}

	return parts.slice(-2).join('.');
}

/**
 * Parse addresses from a header value
 * @param {string|Object|Array} headerValue - Header value (string or parsed object)
 * @returns {string[]} - Array of email addresses
 */
function parseAddresses(headerValue) {
	if (!headerValue) {
		return [];
	}

	// If it's already an array of address objects
	if (Array.isArray(headerValue)) {
		return headerValue
			.flatMap(item => {
				if (typeof item === 'string') {
					return item;
				}

				if (item.address) {
					return item.address;
				}

				if (item.value && Array.isArray(item.value)) {
					return item.value.map(v => v.address).filter(Boolean);
				}

				return null;
			})
			.filter(Boolean);
	}

	// If it's an object with value array (mailparser format)
	if (headerValue.value && Array.isArray(headerValue.value)) {
		return headerValue.value.map(v => v.address).filter(Boolean);
	}

	// If it's a string, try to parse it
	if (typeof headerValue === 'string') {
		// Simple regex to extract email addresses
		const emailPattern = /[\w.+-]+@[\w.-]+\.[a-z]{2,}/gi;
		return headerValue.match(emailPattern) || [];
	}

	return [];
}

/**
 * Get header value from parsed email
 * @param {Object} headers - Headers object
 * @param {string} name - Header name
 * @returns {string|null}
 */
function getHeaders(headers, name) {
	if (!headers) {
		return null;
	}

	// Mailparser format
	if (headers.get) {
		const value = headers.get(name);
		if (value) {
			if (typeof value === 'string') {
				return value;
			}

			if (value.text) {
				return value.text;
			}

			if (value.value && Array.isArray(value.value)) {
				return value.value.map(v => v.address || v.text || v).join(', ');
			}
		}

		return null;
	}

	// HeaderLines format
	if (headers.headerLines) {
		const header = headers.headerLines.find(h => h.key.toLowerCase() === name.toLowerCase());
		if (header) {
			return header.line?.split(':').slice(1).join(':').trim();
		}
	}

	// Plain object format
	if (typeof headers === 'object') {
		const key = Object.keys(headers).find(k => k.toLowerCase() === name.toLowerCase());
		if (key) {
			const value = headers[key];
			if (typeof value === 'string') {
				return value;
			}

			if (Array.isArray(value)) {
				return value[0];
			}
		}
	}

	return null;
}

/**
 * Get attributes from an email for reputation checking
 *
 * @param {Object} parsed - Parsed email message
 * @param {SessionInfo} session - Session information
 * @param {GetAttributesOptions} [options={}] - Options
 * @returns {Promise<string[]>} - Array of unique attributes to check
 */
async function getAttributes(parsed, session = {}, options = {}) {
	const {isAligned = false, authResults = null} = options;

	const headers = parsed.headers || parsed;

	// Get Reply-To addresses
	const replyToHeader = getHeaders(headers, 'reply-to');
	const replyToAddresses = parseAddresses(parsed.replyTo || (replyToHeader ? {value: [{address: replyToHeader}]} : null));

	// Base attributes: client hostname, root hostname, and IP
	// NOTE: we don't check HELO command input because it's arbitrary and can be spoofed
	const array = [
		session.resolvedClientHostname,
		session.resolvedRootClientHostname,
		session.remoteAddress,
	];

	// From header attributes
	const from = [
		session.originalFromAddress,
		session.originalFromAddressDomain,
		session.originalFromAddressRootDomain,
	];

	// Reply-To attributes
	const replyTo = [];
	for (const addr of replyToAddresses) {
		const checked = checkSRS(addr);
		replyTo.push(
			checked.toLowerCase(),
			parseHostFromDomainOrAddress(checked),
			parseRootDomain(parseHostFromDomainOrAddress(checked)),
		);
	}

	// MAIL FROM attributes
	const mailFrom = [];
	const mailFromAddress = session.envelope?.mailFrom?.address;
	if (mailFromAddress) {
		const checked = checkSRS(mailFromAddress);
		mailFrom.push(
			checked.toLowerCase(),
			parseHostFromDomainOrAddress(checked),
			parseRootDomain(parseHostFromDomainOrAddress(checked)),
		);
	}

	if (isAligned) {
		// Only include attributes that are verified and aligned
		const signingDomains = session.signingDomains || new Set();
		const spfResult = session.spfFromHeader?.status?.result;

		// Check if From header has SPF pass or DKIM alignment
		const fromHasSpfPass = spfResult === 'pass';
		const fromHasDkimAlignment
			= signingDomains.size > 0
				&& (signingDomains.has(session.originalFromAddressDomain)
					|| signingDomains.has(session.originalFromAddressRootDomain));

		if (fromHasSpfPass || fromHasDkimAlignment) {
			array.push(...from);
		}

		// Check Reply-To alignment
		let hasAlignedReplyTo = false;
		for (const addr of replyToAddresses) {
			const checked = checkSRS(addr);
			const domain = parseHostFromDomainOrAddress(checked);
			const rootDomain = parseRootDomain(domain);

			// Check DKIM alignment
			if (signingDomains.size > 0 && (signingDomains.has(domain) || signingDomains.has(rootDomain))) {
				hasAlignedReplyTo = true;
				break;
			}

			// Check SPF for Reply-To (if we have auth results)
			if (authResults?.spf) {
				const spfForReplyTo = authResults.spf.find(r => r.domain === domain || r.domain === rootDomain);
				if (spfForReplyTo?.result === 'pass') {
					hasAlignedReplyTo = true;
					break;
				}
			}
		}

		if (hasAlignedReplyTo) {
			array.push(...replyTo);
		}

		// Check MAIL FROM alignment
		if (mailFromAddress) {
			const checked = checkSRS(mailFromAddress);
			const domain = parseHostFromDomainOrAddress(checked);
			const rootDomain = parseRootDomain(domain);

			const mailFromHasDkimAlignment
				= signingDomains.size > 0 && (signingDomains.has(domain) || signingDomains.has(rootDomain));

			// Check SPF for MAIL FROM
			let mailFromHasSpfPass = false;
			if (authResults?.spf) {
				const spfForMailFrom = authResults.spf.find(r => r.domain === domain || r.domain === rootDomain);
				mailFromHasSpfPass = spfForMailFrom?.result === 'pass';
			}

			if (mailFromHasDkimAlignment || mailFromHasSpfPass) {
				array.push(...mailFrom);
			}
		}
	} else {
		// Include all attributes without alignment check
		array.push(...from, ...replyTo, ...mailFrom);
	}

	// Normalize and deduplicate
	const normalized = array
		.filter(string_ => typeof string_ === 'string' && string_.length > 0)
		.map(string_ => {
			try {
				// Convert to ASCII (punycode) and lowercase
				return string_.toLowerCase().trim();
			} catch {
				return string_.toLowerCase().trim();
			}
		});

	const unique = [...new Set(normalized)];

	debug('Extracted %d unique attributes (isAligned=%s): %o', unique.length, isAligned, unique);

	return unique;
}

/**
 * Build session info from parsed email
 * @param {Object} parsed - Parsed email
 * @param {Object} [existingSession={}] - Existing session info to merge
 * @returns {SessionInfo}
 */
function buildSessionFromParsed(parsed, existingSession = {}) {
	const session = {...existingSession};
	const headers = parsed.headers || parsed;

	// Extract From address info
	const fromHeader = getHeaders(headers, 'from');
	const fromAddresses = parseAddresses(parsed.from || fromHeader);
	const fromAddress = fromAddresses[0];

	if (fromAddress && !session.originalFromAddress) {
		session.originalFromAddress = checkSRS(fromAddress).toLowerCase();
		session.originalFromAddressDomain = parseHostFromDomainOrAddress(session.originalFromAddress);
		session.originalFromAddressRootDomain = parseRootDomain(session.originalFromAddressDomain);
	}

	// Extract client hostname from Received headers
	if (!session.resolvedClientHostname) {
		const receivedHeader = getHeaders(headers, 'received');
		if (receivedHeader) {
			const received = Array.isArray(receivedHeader) ? receivedHeader[0] : receivedHeader;
			const fromMatch = received?.match(/from\s+([^\s(]+)/i);
			if (fromMatch) {
				session.resolvedClientHostname = fromMatch[1].toLowerCase();
				session.resolvedRootClientHostname = parseRootDomain(session.resolvedClientHostname);
			}
		}
	}

	// Extract remote IP from Received headers
	if (!session.remoteAddress) {
		const receivedHeader = getHeaders(headers, 'received');
		if (receivedHeader) {
			const received = Array.isArray(receivedHeader) ? receivedHeader[0] : receivedHeader;
			const ipv4Match = received?.match(/\[((?:\d+\.){3}\d+)]/);
			if (ipv4Match) {
				session.remoteAddress = ipv4Match[1];
			} else {
				const ipv6Match = received?.match(/\[([a-f\d:]+)]/i);
				if (ipv6Match) {
					session.remoteAddress = ipv6Match[1];
				}
			}
		}
	}

	// Build envelope from headers if not provided
	if (!session.envelope) {
		session.envelope = {
			mailFrom: {address: session.originalFromAddress || ''},
			rcptTo: [],
		};

		// Get RCPT TO from To and Cc headers
		const toAddresses = parseAddresses(parsed.to || getHeaders(headers, 'to'));
		const ccAddresses = parseAddresses(parsed.cc || getHeaders(headers, 'cc'));

		for (const addr of [...toAddresses, ...ccAddresses]) {
			if (addr) {
				session.envelope.rcptTo.push({address: addr});
			}
		}
	}

	return session;
}

/**
 * Extract all checkable attributes from an email
 * This is a convenience function that combines building session and getting attributes
 *
 * @param {Object} parsed - Parsed email message
 * @param {Object} [options={}] - Options
 * @param {boolean} [options.isAligned=false] - Only return aligned attributes
 * @param {string} [options.senderIp] - Sender IP address
 * @param {string} [options.senderHostname] - Sender hostname
 * @param {Object} [options.authResults] - Authentication results
 * @returns {Promise<{attributes: string[], session: SessionInfo}>}
 */
async function extractAttributes(parsed, options = {}) {
	const {isAligned = false, senderIp, senderHostname, authResults} = options;

	// Build session from parsed email and options
	const session = buildSessionFromParsed(parsed, {
		remoteAddress: senderIp,
		resolvedClientHostname: senderHostname,
		resolvedRootClientHostname: senderHostname ? parseRootDomain(senderHostname) : undefined,
	});

	// Add DKIM signing domains from auth results
	if (authResults?.dkim) {
		session.signingDomains = new Set();
		for (const dkimResult of authResults.dkim) {
			if (dkimResult.result === 'pass' && dkimResult.domain) {
				session.signingDomains.add(dkimResult.domain);
				session.signingDomains.add(parseRootDomain(dkimResult.domain));
			}
		}

		// Check if DKIM was aligned with From
		session.hadAlignedAndPassingDKIM
			= session.signingDomains.has(session.originalFromAddressDomain)
				|| session.signingDomains.has(session.originalFromAddressRootDomain);
	}

	// Add SPF result from auth results
	if (authResults?.spf) {
		const spfForFrom = authResults.spf.find(r =>
			r.domain === session.originalFromAddressDomain
			|| r.domain === session.originalFromAddressRootDomain);
		if (spfForFrom) {
			session.spfFromHeader = {
				status: {result: spfForFrom.result},
			};
		}
	}

	// Get attributes
	const attributes = await getAttributes(parsed, session, {isAligned, authResults});

	return {attributes, session};
}

export {
	getAttributes,
	buildSessionFromParsed,
	extractAttributes,
	checkSRS,
	parseHostFromDomainOrAddress,
	parseRootDomain,
	parseAddresses,
	getHeaders,
};
