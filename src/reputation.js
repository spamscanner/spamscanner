import {isIP} from 'node:net';
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
 * Normalize an allowlist or denylist entry: an IP address, a domain (which
 * also covers its subdomains), or an email address.
 * @param {string} value
 * @returns {string}
 */
function normalizeEntry(value) {
	return String(value).trim().toLowerCase().replace(/\.$/, '');
}

/**
 * Whether a value (IP, hostname or email address) matches a list entry. A
 * domain entry matches the domain, its subdomains and addresses at either.
 * @param {string} value
 * @param {Set<string>} list
 * @returns {string|null} the entry that matched
 */
export function matchList(value, list) {
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

	const host = normalized.includes('@') ? normalized.slice(normalized.lastIndexOf('@') + 1) : normalized;
	const labels = host.split('.');
	for (let i = 0; i < labels.length - 1; i++) {
		const candidate = labels.slice(i).join('.');
		if (list.has(candidate)) {
			return candidate;
		}
	}

	return null;
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
		this.cache = new Map();
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
	 * @returns {Promise<object>} isTruthSource, isAllowlisted, isDenylisted with
	 *   the matching values, plus checkedValues and per-value details
	 */
	async check(values) {
		const unique = [...new Set(values.filter(Boolean).map(value => normalizeEntry(value)))];
		const aggregated = {...EMPTY, checkedValues: unique, details: {}};
		for (const value of unique) {
			const denied = matchList(value, this.denylist);
			if (denied && !aggregated.isDenylisted) {
				aggregated.isDenylisted = true;
				aggregated.denylistValue = denied;
			}

			const allowed = matchList(value, this.allowlist);
			if (allowed && !aggregated.isAllowlisted) {
				aggregated.isAllowlisted = true;
				aggregated.allowlistValue = allowed;
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
					for (const [flag, field] of [['isTruthSource', 'truthSourceValue'], ['isAllowlisted', 'allowlistValue'], ['isDenylisted', 'denylistValue']]) {
						if (result[flag] && !aggregated[flag]) {
							aggregated[flag] = true;
							aggregated[field] = result[field];
						}
					}
				}
			};

			await Promise.all(Array.from({length: Math.min(this.concurrency, unique.length)}, () => worker()));
		}

		return aggregated;
	}
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
