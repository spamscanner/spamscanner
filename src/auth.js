import {Buffer, File} from 'node:buffer';
import dns from 'node:dns';
import {debuglog} from 'node:util';

const debug = debuglog('spamscanner:auth');

let mailauth;
async function getMailauth() {
	// Undici, which mailauth loads, needs the File global of Node.js 20 and
	// later; Node.js 18 has the same class in node:buffer.
	globalThis.File ||= File;
	mailauth ||= await import('mailauth');
	return mailauth;
}

const RECORD_TYPES = new Set(['A', 'AAAA', 'MX', 'TXT', 'PTR', 'CNAME', 'NS', 'SOA', 'SRV']);

/**
 * A DNS resolver for mailauth: `resolver(name, type)` with the same results
 * as dns.promises.resolve (TXT records as arrays of strings, as mailauth
 * expects). Uses the system's name servers unless `servers` is given, and
 * gives up on a lookup after `timeout` milliseconds.
 * @param {number} [timeout]
 * @param {string[]} [servers]
 * @returns {(name: string, type: string) => Promise<any[]>}
 */
export function createResolver(timeout = 10_000, servers) {
	const resolver = new dns.promises.Resolver({timeout: Math.max(1, Math.floor(timeout / 2)), tries: 2});
	if (Array.isArray(servers) && servers.length > 0) {
		resolver.setServers(servers);
	}

	return async (name, type = 'A') => {
		const rrtype = String(type).toUpperCase();
		if (!RECORD_TYPES.has(rrtype)) {
			const error = new Error(`Unsupported DNS record type ${type}`);
			error.code = 'ENOTIMP';
			throw error;
		}

		let timer;
		try {
			return await Promise.race([
				resolver.resolve(name, rrtype),
				new Promise((_resolve, reject) => {
					timer = setTimeout(() => {
						const error = new Error(`DNS lookup of ${name} ${rrtype} timed out`);
						error.code = 'ETIMEOUT';
						reject(error);
					}, timeout);
				}),
			]);
		} finally {
			clearTimeout(timer);
		}
	};
}

function emptyResult() {
	return {
		dkim: {status: {result: 'none', comment: 'not checked'}, results: [], aligned: null},
		spf: {status: {result: 'none', comment: 'not checked'}, domain: null},
		dmarc: {
			status: {result: 'none', comment: 'not checked'}, policy: null, domain: null, p: null,
		},
		arc: {status: {result: 'none', comment: 'not checked'}},
		bimi: {status: {result: 'none', comment: 'not checked'}, location: null},
		receivedChain: [],
		headers: '',
		error: null,
	};
}

/**
 * Overall DKIM result from mailauth's per-signature results: "pass" when any
 * signature passes, "fail" when signatures exist and none passes, "none"
 * without signatures. `aligned` is the From domain a passing signature is
 * aligned with, if any.
 * @param {object} dkim
 * @returns {{status: {result: string, comment: string}, results: object[], aligned: string|null}}
 */
export function summarizeDkim(dkim) {
	// Mailauth reports an unsigned message as one result with status "none".
	const results = (Array.isArray(dkim?.results) ? dkim.results : []).filter(entry => entry?.status?.result !== 'none');
	const passing = results.filter(entry => entry?.status?.result === 'pass');
	if (passing.length > 0) {
		const aligned = passing.find(entry => entry.status.aligned)?.status.aligned || null;
		return {status: {result: 'pass', comment: passing.map(entry => entry.signingDomain).join(', ')}, results, aligned};
	}

	if (results.length === 0) {
		return {status: {result: 'none', comment: 'no signature'}, results, aligned: null};
	}

	const temporary = results.some(entry => entry?.status?.result === 'temperror');
	const neutral = results.every(entry => ['neutral', 'policy', 'none'].includes(entry?.status?.result));
	let result = 'fail';
	if (temporary) {
		result = 'temperror';
	} else if (neutral) {
		result = 'neutral';
	}

	return {status: {result, comment: results.map(entry => `${entry.signingDomain || '?'}: ${entry?.status?.comment || entry?.status?.result || 'invalid'}`).join('; ')}, results, aligned: null};
}

/**
 * Turn mailauth's output into this module's result shape, filling in "none"
 * for anything mailauth left out.
 * @param {object} output
 * @returns {object}
 */
export function normalizeAuthOutput(output = {}) {
	const empty = emptyResult();
	return {
		dkim: summarizeDkim(output.dkim),
		spf: {status: output.spf?.status || empty.spf.status, domain: output.spf?.domain || null},
		dmarc: {
			status: output.dmarc?.status || empty.dmarc.status, policy: output.dmarc?.policy || null, domain: output.dmarc?.domain || null, p: output.dmarc?.p || null,
		},
		arc: {status: output.arc?.status || empty.arc.status},
		bimi: {status: output.bimi?.status || empty.bimi.status, location: output.bimi?.location || null},
		receivedChain: output.receivedChain || [],
		headers: typeof output.headers === 'string' ? output.headers : '',
	};
}

/**
 * Check SPF, DKIM, DMARC, ARC and BIMI for a message, using mailauth.
 *
 * Needs the connecting client's IP address: without it nothing is checked and
 * every result is "none". DNS errors give "temperror" results, never a pass.
 *
 * @param {Buffer|string} message - the raw message
 * @param {object} options
 * @param {string} options.ip - IP address of the client that sent the message
 * @param {string} [options.helo] - hostname the client gave in HELO/EHLO
 * @param {string} [options.sender] - envelope sender (MAIL FROM)
 * @param {string} [options.mta] - this server's hostname, for the headers
 * @param {Function} [options.resolver] - custom DNS resolver (name, type)
 * @param {number} [options.timeout] - DNS timeout in milliseconds
 * @param {string[]} [options.dnsServers] - name servers to use
 * @returns {Promise<object>} dkim, spf, dmarc, arc, bimi, receivedChain and
 *   headers (Received-SPF and Authentication-Results, ready to prepend)
 */
export async function authenticate(message, options = {}) {
	const result = emptyResult();
	const {
		ip, helo, sender, mta = 'spamscanner', timeout = 10_000,
	} = options;
	if (!ip) {
		result.error = 'No client IP address given';
		return result;
	}

	try {
		const {authenticate: run} = await getMailauth();
		const resolver = options.resolver || createResolver(timeout, options.dnsServers);
		const raw = Buffer.isBuffer(message) ? message : Buffer.from(String(message));
		const output = await run(raw, {
			ip,
			helo: helo || undefined,
			sender: sender ?? undefined,
			mta,
			resolver,
		});
		Object.assign(result, normalizeAuthOutput(output));
	} catch (error) {
		debug('authentication failed: %s', error.message);
		result.error = error.message;
	}

	return result;
}

export const DEFAULT_AUTH_WEIGHTS = {
	dkimPass: -0.5,
	dkimFail: 1,
	spfPass: -0.5,
	spfFail: 2,
	spfSoftfail: 1,
	dmarcPass: -1.5,
	dmarcFail: 3.5,
	arcPass: -0.5,
	arcFail: 1,
};

/**
 * Score authentication results: failures add points, passes take some away.
 * @param {object} auth - from authenticate
 * @param {object} [weights] - overrides for DEFAULT_AUTH_WEIGHTS
 * @returns {{score: number, tests: Array<{name: string, score: number}>}}
 */
export function calculateAuthScore(auth, weights = {}) {
	const w = {...DEFAULT_AUTH_WEIGHTS, ...weights};
	const tests = [];
	const add = (name, score) => {
		if (score !== 0) {
			tests.push({name, score});
		}
	};

	const rules = [
		['DKIM', auth?.dkim?.status?.result, {pass: w.dkimPass, fail: w.dkimFail}],
		['SPF', auth?.spf?.status?.result, {pass: w.spfPass, fail: w.spfFail, softfail: w.spfSoftfail}],
		['DMARC', auth?.dmarc?.status?.result, {pass: w.dmarcPass, fail: w.dmarcFail}],
		['ARC', auth?.arc?.status?.result, {pass: w.arcPass, fail: w.arcFail}],
	];
	for (const [name, value, scores] of rules) {
		if (value && Object.hasOwn(scores, value)) {
			add(`${name}_${value.toUpperCase()}`, scores[value]);
		}
	}

	return {score: tests.reduce((sum, test) => sum + test.score, 0), tests};
}

/**
 * The Authentication-Results header (RFC 8601) for a result, without the
 * header name. mailauth's own headers are used when present.
 * @param {object} auth
 * @param {string} [hostname]
 * @returns {string}
 */
export function formatAuthResultsHeader(auth, hostname) {
	if (typeof auth?.headers === 'string') {
		const match = auth.headers.match(/^authentication-results:[ \t]*([\s\S]*?)(?=\r?\n\S|(?![\s\S]))/im);
		if (match) {
			const value = match[1].replaceAll(/\r?\n/g, '\r\n').trim();
			// The first word is the name of the server that checked the message.
			return hostname ? value.replace(/^[^;\s]+/, hostname) : value;
		}
	}

	const parts = [hostname || 'spamscanner'];
	const dkim = auth?.dkim?.status?.result || 'none';
	const signer = auth?.dkim?.results?.find(entry => entry?.status?.result === dkim)?.signingDomain;
	parts.push(`dkim=${dkim}${signer ? ` header.d=${signer}` : ''}`, `spf=${auth?.spf?.status?.result || 'none'}${auth?.spf?.domain ? ` smtp.mailfrom=${auth.spf.domain}` : ''}`, `dmarc=${auth?.dmarc?.status?.result || 'none'}${auth?.dmarc?.domain ? ` header.from=${auth.dmarc.domain}` : ''}`, `arc=${auth?.arc?.status?.result || 'none'}`);
	return parts.join(';\r\n\t');
}

/**
 * One line summarizing authentication results, for logs and LLM prompts.
 * @param {object} auth
 * @returns {string}
 */
export function summarizeAuth(auth) {
	return ['spf', 'dkim', 'dmarc', 'arc'].map(name => `${name}=${auth?.[name]?.status?.result || 'none'}`).join(' ');
}
