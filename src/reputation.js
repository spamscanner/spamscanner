import {isIP} from 'node:net';
import {domainToASCII} from 'node:url';
import {normalizeIp} from './dnsbl.js';
import {requestJson} from './http.js';
import {registrableDomain} from './tokenizer.js';

const EMPTY = Object.freeze({
	isTruthSource: false,
	truthSourceValue: null,
	isAllowlisted: false,
	allowlistValue: null,
	isDenylisted: false,
	denylistValue: null,
});

/**
 * A domain as a hostname in ASCII ("Bücher.example." is
 * "xn--bcher-kva.example"), or null when it is not one: only letters, digits,
 * hyphens and underscores in dot-separated labels of at most 63 characters,
 * 253 in all. (A URL such as "bank.com/x.attacker.example" is not a
 * hostname, though URL parsers read "bank.com" from it.)
 * @param {string} value
 * @returns {string|null}
 */
export function asciiHostname(value) {
	if (typeof value !== 'string') {
		return null;
	}

	// (checked after NFKC as well, as IDNA maps "／" to "/")
	const lower = value.normalize('NFKC').toLowerCase().replace(/\.$/, '');
	if (lower === '' || /[\0-,/:-^`{-\u007F]/.test(lower)) {
		return null;
	}

	const ascii = domainToASCII(lower);
	return ascii.length <= 253 && /^[\w-]{1,63}(?:\.[\w-]{1,63})*$/.test(ascii) ? ascii : null;
}

/**
 * Normalize an allowlist or denylist entry: an IP address (an IPv4 address
 * mapped into IPv6 as IPv4, without an IPv6 zone), a domain (which also
 * covers its subdomains), or an email address, with an international domain
 * in ASCII.
 * @param {string} value
 * @returns {string}
 */
function normalizeEntry(value) {
	const lower = normalizeIp(String(value).trim().toLowerCase().replace(/\.$/, ''));
	const at = lower.lastIndexOf('@');
	const ascii = isIP(lower) ? null : asciiHostname(lower.slice(at + 1));
	return ascii ? `${lower.slice(0, at + 1)}${ascii}` : lower;
}

/**
 * Whether a value (IP, hostname or email address) matches a list entry. A
 * domain entry matches the domain, its subdomains and addresses at either.
 *
 * With `hostnamesOnly` (for an allowlist, which must trust nothing it cannot
 * read), only a hostname matches a parent domain. Without it (for a
 * denylist, which anything should match) any name does, such as
 * "a_b!.evil.example" or one with a label of 64 characters, read from its
 * last 127 labels and 253 characters, so the work is bounded however long
 * the name.
 * @param {string} value
 * @param {Set<string>} list
 * @param {object} [options]
 * @param {boolean} [options.hostnamesOnly]
 * @returns {string|null} the entry that matched
 */
export function matchList(value, list, options = {}) {
	if (!value || list.size === 0) {
		return null;
	}

	const normalized = normalizeEntry(value);
	if (list.has(normalized)) {
		return normalized;
	}

	if (isIP(normalized)) {
		return null;
	}

	const host = normalized.slice(normalized.lastIndexOf('@') + 1);
	if (options.hostnamesOnly && asciiHostname(host) !== host) {
		return null;
	}

	// (parent domains from the shortest, of two labels or more, up to 127
	//  labels and 253 characters: the longest that matches is the entry)
	let found = null;
	let end = host.lastIndexOf('.');
	for (let labels = 2; labels <= 127 && end > 0; labels++) {
		const dot = host.lastIndexOf('.', end - 1);
		const candidate = host.slice(dot + 1);
		if (candidate.length > 253) {
			break;
		}

		// (in ASCII too, for an international name that is not a hostname)
		const ascii = asciiHostname(candidate);
		if (list.has(candidate) || (ascii !== null && list.has(ascii))) {
			found = list.has(candidate) ? candidate : ascii;
		}

		if (dot === -1) {
			break;
		}

		end = dot;
	}

	return found;
}

/**
 * Reputation lookups: local allowlists and denylists, and optionally an HTTP
 * reputation service.
 *
 * The service is any URL answering `GET <url>?q=<value>` with JSON
 * `{ "isTruthSource": bool, "isAllowlisted": bool, "isDenylisted": bool }`
 * (and optional `truthSourceValue`, `allowlistValue`, `denylistValue`).
 * Values looked up: the client IP and hostname, the From, envelope sender and
 * Reply-To addresses and their domains.
 *
 * Any of these values can put a message on the denylist. Only values that
 * cannot be forged can put it on the allowlist or make it a truth source
 * (see trustedReputationValues): anyone can write any address in From or
 * Reply-To.
 */
export class ReputationChecker {
	/**
	 * @param {object} [options]
	 * @param {string[]} [options.allowlist] - IPs, domains and addresses always accepted
	 * @param {string[]} [options.denylist] - IPs, domains and addresses always rejected
	 * @param {string} [options.apiUrl] - reputation service URL
	 * @param {Record<string, string>} [options.headers] - for the service, e.g. authorization
	 * @param {number} [options.timeout]
	 * @param {number} [options.concurrency] - parallel service requests
	 * @param {number} [options.cacheTtl] - milliseconds answers are kept
	 * @param {number} [options.cacheSize]
	 * @param {Map} [options.cache] - answers kept (shared with another checker
	 *   of the same service)
	 */
	constructor(options = {}) {
		this.allowlist = new Set((options.allowlist || []).map(entry => normalizeEntry(entry)));
		this.denylist = new Set((options.denylist || []).map(entry => normalizeEntry(entry)));
		this.apiUrl = options.apiUrl || null;
		this.headers = options.headers || {};
		this.timeout = options.timeout ?? 5000;
		this.concurrency = Math.max(1, options.concurrency ?? 8);
		this.cacheTtl = options.cacheTtl ?? 300_000;
		this.cacheSize = options.cacheSize ?? 10_000;
		this.cache = options.cache instanceof Map ? options.cache : new Map();
	}

	/**
	 * Ask the reputation service about one value. Failures count as unknown
	 * and are remembered for a minute, so an outage does not slow every scan.
	 * @param {string} value
	 * @returns {Promise<object>}
	 */
	async lookup(value) {
		const key = normalizeEntry(value);
		const hit = this.cache.get(key);
		if (hit && hit.expires > Date.now()) {
			return hit.result;
		}

		let result = EMPTY;
		let ttl = this.cacheTtl;
		try {
			const url = new URL(this.apiUrl);
			url.searchParams.set('q', key);
			const body = await requestJson('GET', url.href, null, {headers: this.headers, timeout: this.timeout, maxResponseBytes: 65_536});
			result = {
				isTruthSource: body?.isTruthSource === true,
				truthSourceValue: body?.isTruthSource === true ? (body.truthSourceValue || key) : null,
				isAllowlisted: body?.isAllowlisted === true,
				allowlistValue: body?.isAllowlisted === true ? (body.allowlistValue || key) : null,
				isDenylisted: body?.isDenylisted === true,
				denylistValue: body?.isDenylisted === true ? (body.denylistValue || key) : null,
			};
		} catch (error) {
			result = {...EMPTY, error: error.message};
			ttl = Math.min(ttl, 60_000);
		}

		this.cache.set(key, {result, expires: Date.now() + ttl});
		if (this.cache.size > this.cacheSize) {
			this.cache.delete(this.cache.keys().next().value);
		}

		return result;
	}

	/**
	 * Check a message's sender values against the lists and the service.
	 * @param {string[]} values - IPs, hostnames, addresses
	 * @param {object} [options]
	 * @param {string[]} [options.trusted] - the values that can allowlist the
	 *   message or make it a truth source (default: all of them); see
	 *   trustedReputationValues
	 * @returns {Promise<object>} isTruthSource, isAllowlisted, isDenylisted with
	 *   the matching values, plus checkedValues, per-value details, and
	 *   allowlisted (each value on the allowlist, with its entry)
	 */
	async check(values, options = {}) {
		const unique = [...new Set(values.filter(Boolean).map(value => normalizeEntry(value)))];
		const aggregated = {
			...EMPTY, checkedValues: unique, details: {}, allowlisted: {},
		};
		for (const value of unique) {
			const denied = matchList(value, this.denylist);
			if (denied && !aggregated.isDenylisted) {
				aggregated.isDenylisted = true;
				aggregated.denylistValue = denied;
			}

			const allowed = matchList(value, this.allowlist, {hostnamesOnly: true});
			if (allowed) {
				aggregated.allowlisted[value] = allowed;
			}
		}

		if (this.apiUrl) {
			const queue = [...unique];
			const worker = async () => {
				while (queue.length > 0) {
					const value = queue.shift();
					// eslint-disable-next-line no-await-in-loop
					const result = await this.lookup(value);
					aggregated.details[value] = result;
					if (result.isDenylisted && !aggregated.isDenylisted) {
						aggregated.isDenylisted = true;
						aggregated.denylistValue = result.denylistValue;
					}
				}
			};

			await Promise.all(Array.from({length: Math.min(this.concurrency, unique.length)}, () => worker()));
		}

		return trustReputation(aggregated, options.trusted ?? unique);
	}
}

// Whether an entry (a domain or an address) is vouched for by a passing
// signature or SPF check of `signer` in relaxed alignment, which must be of
// the same registrable domain: any such signer vouches for a registrable
// domain, and for a subdomain only the named domain, one under it, or a
// parent of it, which controls its DNS (evil.example.com does not vouch for
// trusted.example.com, example.com does). An empty signer (a DMARC pass
// without alignment details) vouches for registrable domains only.
function vouches(entry, signer) {
	const domain = entry.slice(entry.lastIndexOf('@') + 1);
	const registrable = registrableDomain(domain);
	if (signer === '') {
		return registrable === domain;
	}

	return registrableDomain(signer) === registrable
		&& (registrable === domain || signer === domain || signer.endsWith(`.${domain}`) || domain.endsWith(`.${signer}`));
}

/**
 * Set isAllowlisted and isTruthSource of a check() result from the trusted
 * values only (values that cannot be forged, see trustedReputationValues),
 * in the order checked.
 * @param {object} result - from ReputationChecker#check
 * @param {Array<string|{value: string, signers: string[]}>} trusted -
 *   values, or values trusted through relaxed alignment with `signers` only
 *   (the aligned DKIM or SPF domains), whose entries one of them must vouch
 *   for
 * @returns {object} a copy of the result
 */
export function trustReputation(result, trusted = []) {
	// (each value: null when trusted outright, else the domains that vouch
	//  for it)
	const allowed = new Map();
	for (const item of trusted.filter(Boolean)) {
		const value = normalizeEntry(typeof item === 'string' ? item : item.value);
		const signers = typeof item === 'string' ? null : item.signers;
		if (allowed.get(value) !== null) {
			allowed.set(value, signers && [...(allowed.get(value) || []), ...signers]);
		}
	}

	const out = {
		...result, isAllowlisted: false, allowlistValue: null, isTruthSource: false, truthSourceValue: null,
	};
	for (const value of result.checkedValues.filter(item => allowed.has(item))) {
		const signers = allowed.get(value);
		const counts = entry => Boolean(entry) && (signers === null || signers.some(signer => vouches(normalizeEntry(entry), signer)));
		const detail = result.details[value];
		const listed = result.allowlisted[value] || (detail?.isAllowlisted ? detail.allowlistValue : null);
		if (counts(listed) && !out.isAllowlisted) {
			out.isAllowlisted = true;
			out.allowlistValue = listed;
		}

		if (detail?.isTruthSource && counts(detail.truthSourceValue) && !out.isTruthSource) {
			out.isTruthSource = true;
			out.truthSourceValue = detail.truthSourceValue;
		}
	}

	return out;
}

/**
 * The values a message's reputation is checked by: the client IP address and
 * hostname, and the From, envelope sender and Reply-To addresses with their
 * domains and registrable domains.
 * @param {object} mail - parsed message
 * @param {object} [session] - remoteAddress, resolvedClientHostname, envelope
 * @returns {string[]}
 */
export function reputationValues(mail = {}, session = {}) {
	const values = [];
	const addAddress = address => {
		if (typeof address !== 'string' || !address.includes('@')) {
			return;
		}

		const lower = address.toLowerCase();
		const domain = lower.slice(lower.lastIndexOf('@') + 1);
		values.push(lower, domain, registrableDomain(domain));
	};

	if (session.remoteAddress) {
		values.push(session.remoteAddress);
	}

	if (session.resolvedClientHostname) {
		values.push(session.resolvedClientHostname, registrableDomain(session.resolvedClientHostname));
	}

	for (const entry of mail.from?.value || []) {
		addAddress(entry.address);
	}

	addAddress(session.envelope?.mailFrom?.address);
	for (const entry of mail.replyTo?.value || []) {
		addAddress(entry.address);
	}

	return [...new Set(values.filter(Boolean))];
}

const domainOf = address => (typeof address === 'string' && address.includes('@') ? asciiHostname(address.slice(address.lastIndexOf('@') + 1)) : null);
// (a result without the domain it is for, or with one that is not a
//  hostname, proves nothing: it fails closed)
const sameDomain = (a, b) => a !== null && a === asciiHostname(b);

/**
 * The reputation values that cannot be forged, which alone can allowlist a
 * message or make it a truth source: the client IP address and its verified
 * hostname (from the receiving server), a From address only when
 * authentication shows its domain sent it (DMARC passes for it, or a passing
 * DKIM signature is aligned with it), and the envelope sender only when SPF
 * passes for its domain. Never Reply-To. A result that does not name its
 * domain, or names one that is not a hostname, counts for none.
 *
 * Alignment is relaxed, as in DMARC (mailauth's DMARC domain is the From
 * domain's registrable domain), so From values are returned as
 * {value, signers}, with the aligned DKIM and SPF domains: an allowlist
 * entry naming a subdomain counts only for a signer that is it, under it or
 * a parent of it, of the same registrable domain. A DMARC pass for exactly
 * the From domain, without alignment details, trusts it outright; one for
 * its registrable domain only, registrable-domain entries. Under strict
 * alignment (adkim=s, aspf=s in the domain's DMARC record) only the From
 * domain itself vouches for it. A DKIM signature of part of the body (l=
 * shorter than the body, mailauth's underSized) vouches for nothing, nor
 * does a DMARC pass that rests on one alone, and no signature vouches for a
 * From address when DMARC fails, nor for one of a From field too long to read
 * whole (`mail.from.truncated`).
 * @param {object} mail - parsed message
 * @param {object} [session] - remoteAddress, resolvedClientHostname, envelope
 * @param {object|null} [authentication] - SPF, DKIM and DMARC results
 * @returns {Array<string|{value: string, signers: string[]}>}
 */
export function trustedReputationValues(mail = {}, session = {}, authentication = null) {
	const dmarc = authentication?.dmarc;
	const alignment = dmarc?.alignment;
	// (a signature with a body length, l=, shorter than the body signs only
	//  the start of it: anyone can append to a message its domain sent, so it
	//  vouches for nothing, nor does a DMARC pass that rests on it alone)
	const dkimAligned = alignment?.dkim?.underSized > 0 ? null : asciiHostname(alignment?.dkim?.result);
	const spfAligned = asciiHostname(alignment?.spf?.result);
	const onlyUnderSized = alignment?.dkim?.underSized > 0 && spfAligned === null;
	const dmarcDomain = dmarc?.status?.result === 'pass' && !onlyUnderSized ? asciiHostname(dmarc.domain) : null;
	const aligned = [dkimAligned, spfAligned].filter(Boolean);
	// (every passing signature of the whole body aligned with the From domain;
	//  none when DMARC fails, as it does for a checker that enforces strict
	//  alignment)
	const signers = dmarc?.status?.result === 'fail'
		? []
		: [...new Set([
			...(Array.isArray(authentication?.dkim?.results) ? authentication.dkim.results : []).filter(entry => entry?.status?.result === 'pass' && !(entry.status.underSized > 0)).map(entry => entry.status.aligned),
			authentication?.dkim?.aligned,
		].map(domain => asciiHostname(domain)).filter(Boolean))];
	// (the domains that vouch for a From domain: under strict alignment of the
	//  domain's DMARC record, adkim=s or aspf=s, which mailauth reports but
	//  does not enforce, only the From domain itself)
	const vouching = domain => [...new Set([
		...[dkimAligned, ...signers].filter(signer => signer !== null && (alignment?.dkim?.strict !== true || signer === domain)),
		...[spfAligned].filter(signer => signer !== null && (alignment?.spf?.strict !== true || signer === domain)),
	])];
	const fromValues = [];
	// (nor a From field cut, which was not read whole: see parseMessage)
	for (const {address} of mail.from?.truncated ? [] : mail.from?.value || []) {
		const domain = domainOf(address);
		const values = reputationValues({from: {value: [{address}]}});
		if (domain !== null && dmarcDomain !== null && (domain === dmarcDomain || registrableDomain(domain) === dmarcDomain)) {
			if (domain === dmarcDomain && aligned.length === 0) {
				fromValues.push(...values);
			} else if (aligned.length === 0 && signers.length === 0) {
				// (without alignment details, which domain aligned is not known)
				fromValues.push(...values.map(value => ({value, signers: ['']})));
			} else if (vouching(domain).length > 0) {
				fromValues.push(...values.map(value => ({value, signers: vouching(domain)})));
			}
		} else if (domain !== null && signers.some(signer => registrableDomain(signer) === registrableDomain(domain))) {
			fromValues.push(...values.map(value => ({value, signers})));
		}
	}

	const sender = session.envelope?.mailFrom?.address;
	const spf = authentication?.spf;
	const trustedSender = spf?.status?.result === 'pass' && sameDomain(domainOf(sender), spf.domain);
	return [...reputationValues({}, {
		remoteAddress: session.remoteAddress,
		resolvedClientHostname: session.resolvedClientHostname,
		envelope: trustedSender ? {mailFrom: {address: sender}} : undefined,
	}), ...fromValues];
}
