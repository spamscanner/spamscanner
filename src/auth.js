import {Buffer, File} from 'node:buffer';
import dns from 'node:dns';
import {debuglog} from 'node:util';
import {boundedForAuth} from './parse.js';
import {asciiHostname} from './reputation.js';
import {registrableDomain} from './tokenizer.js';

export {MAX_DKIM_SIGNATURES} from './parse.js';

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

/**
 * DNS lookups allowed for one message: room for SPF at the limits of RFC
 * 7208 (10 lookups, each MX mechanism with up to 10 hosts, A and AAAA, about
 * 220 in all, as mailauth counts them), MAX_DKIM_SIGNATURES keys (see
 * boundedForAuth), the
 * newest ARC seal, DMARC and BIMI.
 */
export const MAX_DNS_QUERIES = 300;

// The longest Authentication-Results value written (whole results only).
const MAX_AUTH_RESULTS_LENGTH = 8192;

function dnsTimeout(message) {
	const error = new Error(message);
	error.code = 'ETIMEOUT';
	return error;
}

/**
 * A resolver that answers through `resolver` at most `maxQueries` times and
 * until `deadline` (a time in milliseconds, as Date.now() gives it): any
 * lookup after either, or still unanswered at the deadline, fails at once
 * with ETIMEOUT, so a message's checks stop sending queries when its time is
 * up and never send more than `maxQueries`.
 * @param {(name: string, type: string) => Promise<any[]>} resolver
 * @param {{maxQueries?: number, deadline?: number}} [limits]
 * @returns {(name: string, type: string) => Promise<any[]>}
 */
export function limitResolver(resolver, {maxQueries = MAX_DNS_QUERIES, deadline = Number.POSITIVE_INFINITY} = {}) {
	let count = 0;
	return async (...args) => {
		count++;
		if (count > maxQueries) {
			throw dnsTimeout(`More than ${maxQueries} DNS lookups for one message`);
		}

		const left = deadline - Date.now();
		if (left <= 0) {
			throw dnsTimeout('Out of time for this message\'s DNS lookups');
		}

		let timer;
		try {
			return await Promise.race([
				resolver(...args),
				new Promise((_resolve, reject) => {
					timer = setTimeout(() => reject(dnsTimeout('Out of time for this message\'s DNS lookups')), Math.min(left, 2_147_483_647));
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
		arc: {status: {result: 'none', comment: 'not checked'}, sealer: null, trusted: false},
		bimi: {status: {result: 'none', comment: 'not checked'}, location: null},
		receivedChain: [],
		headers: '',
		error: null,
	};
}

/**
 * Overall DKIM result from mailauth's per-signature results: "pass" when any
 * signature passes, "fail" when signatures exist and none passes, "none"
 * without signatures. `aligned` is the signing domain of a passing signature
 * aligned with the From domain (relaxed: they share their registrable domain),
 * in ASCII, if any. A signature whose body length (l=) is shorter than the
 * body (mailauth's `status.underSized`) is aligned with nothing: it signs only
 * the start of the body, and anyone can append to it.
 * @param {object} dkim
 * @returns {{status: {result: string, comment: string}, results: object[], aligned: string|null}}
 */
export function summarizeDkim(dkim) {
	// Mailauth reports an unsigned message as one result with status "none".
	const results = (Array.isArray(dkim?.results) ? dkim.results : []).filter(entry => entry?.status?.result !== 'none');
	const passing = results.filter(entry => entry?.status?.result === 'pass');
	if (passing.length > 0) {
		// (a signing domain that is not a hostname, such as
		//  "bank.com/x.attacker.example", is aligned with nothing)
		const aligned = passing.filter(entry => !(entry.status.underSized > 0)).map(entry => asciiHostname(entry.status.aligned)).find(Boolean) || null;
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

// Whether a domain is one of the domains listed or under one of them.
function listedDomain(domain, list) {
	return domain !== null && (Array.isArray(list) ? list : []).map(entry => asciiHostname(entry)).some(entry => entry !== null && (domain === entry || domain.endsWith(`.${entry}`)));
}

// (a value of a parsed header tag, as mailauth gives it: a string or
//  {value})
const tagValue = value => (value && typeof value === 'object' ? value.value : value);

// A policy or tag value as RFC 7489 reads it: without spaces around it, in
// any case ("p= None" is none), or null.
const tagText = value => (typeof value === 'string' && value.trim() !== '' ? value.trim().toLowerCase() : null);

// The tags of a DMARC record ("v=DMARC1; p=reject; adkim=s"), names and
// values trimmed and lowercase, the first of each name.
function dmarcTags(record) {
	const tags = {};
	for (const part of String(record ?? '').split(';')) {
		const at = part.indexOf('=');
		const name = part.slice(0, at).trim().toLowerCase();
		if (at > 0 && !Object.hasOwn(tags, name)) {
			tags[name] = part.slice(at + 1).trim().toLowerCase();
		}
	}

	return tags;
}

// The registrable domain of an address or a domain, or null.
function organization(value) {
	const domain = asciiHostname(typeof value === 'string' ? value.slice(value.lastIndexOf('@') + 1) : null);
	return domain === null ? null : registrableDomain(domain);
}

// Whether the Authentication-Results a forwarder sealed (ARC-Authentication-
// Results) show the message passed when it got it, for the From domain: a
// DMARC pass for it, or a DKIM or SPF pass of a domain aligned with it
// (relaxed: the same registrable domain).
function arcVouches(results, fromDomain) {
	const from = organization(fromDomain);
	if (from === null || !results || typeof results !== 'object') {
		return false;
	}

	const passes = (entry, domain) => tagValue(entry?.result) === 'pass' && organization(tagValue(domain)) === from;
	return passes(results.dmarc, results.dmarc?.header?.from)
		|| (Array.isArray(results.dkim) ? results.dkim : []).some(entry => passes(entry, entry?.header?.d))
		|| passes(results.spf, results.spf?.smtp?.mailfrom);
}

// DMARC's alignment details, with the alignment modes of the record read as
// RFC 7489 reads them and strict alignment enforced (mailauth reports
// adkim=s, compared case and space sensitively, but aligns relaxed): under
// it only a signature, or an SPF pass, of the From domain itself aligns.
function enforcedAlignment(output, fromDomain) {
	const given = output.dmarc?.alignment;
	if (!given) {
		return null;
	}

	const tags = dmarcTags(output.dmarc.rr);
	const strict = {
		dkim: tags.adkim === undefined ? given.dkim?.strict === true : tags.adkim === 's',
		spf: tags.aspf === undefined ? given.spf?.strict === true : tags.aspf === 's',
	};
	const alignment = {dkim: {...given.dkim, strict: strict.dkim}, spf: {...given.spf, strict: strict.spf}};
	if (strict.dkim) {
		// (the signature of the whole body before one of part of it)
		const exact = (Array.isArray(output.dkim?.results) ? output.dkim.results : [])
			.filter(entry => entry?.status?.result === 'pass' && fromDomain !== null && asciiHostname(entry.signingDomain) === fromDomain)
			.sort((a, b) => (a.status.underSized || 0) - (b.status.underSized || 0))[0];
		alignment.dkim = {result: exact ? exact.signingDomain : false, strict: true, underSized: exact?.status?.underSized};
	}

	if (strict.spf && !(fromDomain !== null && asciiHostname(alignment.spf.result) === fromDomain)) {
		alignment.spf = {result: false, strict: true};
	}

	return alignment;
}

// The domain that sealed the newest ARC set (its ARC-Seal d=), when its
// ARC-Message-Signature is of the same domain, or null: a seal signed again
// by another domain over a forwarder's message signature is no forwarder's.
function arcSealer(arc) {
	const newest = Array.isArray(arc?.chain) ? arc.chain.at(-1) : null;
	const sealDomain = asciiHostname(tagValue(newest?.['arc-seal']?.parsed?.d));
	return sealDomain !== null && sealDomain === asciiHostname(arc.signature?.signingDomain) ? sealDomain : null;
}

/**
 * Turn mailauth's output into this module's result shape, filling in "none"
 * for anything mailauth left out, and checking what mailauth does not:
 *
 * - the policy (`p`, `sp`) and alignment modes (`adkim`, `aspf`) of the
 *   DMARC record are read without spaces and in any case, as RFC 7489 reads
 *   them ("p= None" is none, "adkim=S" strict), and strict alignment is
 *   enforced: under it only a signature or SPF pass of the From domain itself
 *   aligns, and DMARC fails without one;
 * - a message without exactly one From address, whose DMARC mailauth does
 *   not check, fails DMARC, as RFC 7489 (6.6.1) allows;
 * - `arc.sealer` is the domain of the newest ARC seal of a passing chain,
 *   when its ARC-Message-Signature is of the same domain, and `arc.trusted`
 *   whether it is one of `trustedArcSealers` (or under one) and the results
 *   it sealed show the message passed DMARC, or DKIM or SPF aligned with the
 *   From domain, when it got it.
 * @param {object} output
 * @param {object} [options]
 * @param {string[]} [options.trustedArcSealers] - forwarders whose ARC seal
 *   is believed
 * @returns {object}
 */
export function normalizeAuthOutput(output = {}, options = {}) {
	const empty = emptyResult();
	let dmarcStatus = output.dmarc?.status || empty.dmarc.status;
	const fromAddresses = Array.isArray(output.dkim?.headerFrom) ? output.dkim.headerFrom.filter(address => typeof address === 'string') : null;
	const fromDomain = asciiHostname(output.dmarc?.status?.header?.d) ?? (fromAddresses?.length === 1 ? asciiHostname(fromAddresses[0].slice(fromAddresses[0].lastIndexOf('@') + 1)) : null);
	if (!output.dmarc?.status && fromAddresses !== null && fromAddresses.length !== 1) {
		dmarcStatus = {result: 'fail', comment: `${fromAddresses.length} From addresses`};
	}

	const alignment = enforcedAlignment(output, fromDomain);
	if (dmarcStatus.result === 'pass' && alignment && !alignment.dkim.result && !alignment.spf.result) {
		dmarcStatus = {...dmarcStatus, result: 'fail', comment: 'strict alignment (adkim=s, aspf=s) not met'};
	}

	// (a pass by an aligned domain that is not a hostname, as mailauth gives
	//  for a signature of "bank.com/x.attacker.example", is a failure)
	const aligned = [alignment?.dkim?.result, alignment?.spf?.result].filter(domain => typeof domain === 'string');
	if (dmarcStatus.result === 'pass' && aligned.length > 0 && !aligned.some(domain => asciiHostname(domain))) {
		dmarcStatus = {...dmarcStatus, result: 'fail', comment: `aligned domain is not a hostname (${aligned.join(', ')})`};
	}

	const arcStatus = output.arc?.status || empty.arc.status;
	const sealer = arcStatus.result === 'pass' ? arcSealer(output.arc) : null;
	return {
		dkim: summarizeDkim(output.dkim),
		spf: {status: output.spf?.status || empty.spf.status, domain: output.spf?.domain || null},
		dmarc: {
			status: dmarcStatus, policy: tagText(output.dmarc?.policy), domain: output.dmarc?.domain || null, p: tagText(output.dmarc?.p), alignment,
		},
		arc: {status: arcStatus, sealer, trusted: listedDomain(sealer, options.trustedArcSealers) && arcVouches(output.arc?.authenticationResults, fromDomain)},
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
 * Only the first MAX_DKIM_SIGNATURES DKIM signatures are checked.
 *
 * @param {Buffer|string} message - the raw message
 * @param {object} options
 * @param {string} options.ip - IP address of the client that sent the message
 * @param {string} [options.helo] - hostname the client gave in HELO/EHLO
 * @param {string} [options.sender] - envelope sender (MAIL FROM)
 * @param {string} [options.mta] - this server's hostname, for the headers
 * @param {Function} [options.resolver] - custom DNS resolver (name, type)
 * @param {number} [options.timeout] - milliseconds for a DNS lookup, and for
 *   all of the message's: no lookup is sent, nor waited for, after this long
 *   (and 100 ms more)
 * @param {number} [options.maxDnsQueries] - DNS lookups allowed for the
 *   message (MAX_DNS_QUERIES); any more fail with a temporary error
 * @param {string[]} [options.dnsServers] - name servers to use
 * @param {string[]} [options.trustedArcSealers] - forwarders (such as a
 *   mailing list's domain) whose ARC seal is believed: a message they passed
 *   on, which passed when they got it, gets no points for failing SPF, DKIM
 *   and DMARC (see normalizeAuthOutput)
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
		const resolver = limitResolver(options.resolver || createResolver(timeout, options.dnsServers), {
			maxQueries: options.maxDnsQueries ?? MAX_DNS_QUERIES,
			// (a little after `timeout`, so a caller that waits that long for the
			//  result, as scan() does, has its answer first)
			deadline: Date.now() + timeout + 100,
		});
		// (with its address fields bounded, as the parser bounds them, only its
		//  first MAX_DKIM_SIGNATURES DKIM signatures, and a header that would
		//  take mailauth too long cut down)
		const bounded = boundedForAuth(Buffer.isBuffer(message) ? message : Buffer.from(String(message)));
		const output = await run(bounded.raw, {
			ip,
			helo: helo || undefined,
			sender: sender ?? undefined,
			mta,
			resolver,
		});
		Object.assign(result, normalizeAuthOutput(output, {trustedArcSealers: options.trustedArcSealers}));
		// (a From field cut, or left out of a header cut down, was not read
		//  whole: DMARC cannot pass for what mailauth did not read, and its
		//  headers would say what it read)
		if (bounded.fromCut) {
			result.dmarc = {...result.dmarc, status: {result: 'fail', comment: 'From field too long to read whole'}};
			result.headers = '';
		}
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
	// (for a domain whose policy is quarantine or reject)
	dmarcFail: 3.5,
	// (for a domain whose policy is none: it does not ask for its failures to
	//  be held back, and many such domains send through forwarders that break
	//  DMARC)
	dmarcFailNone: 1,
	arcPass: -0.5,
	arcFail: 1,
};

/**
 * Score authentication results: failures add points, passes take some away.
 *
 * A DMARC failure scores `dmarcFail` when the domain's policy is quarantine
 * or reject (or not known), and SPF failing as well adds nothing more: DMARC
 * already counts it. When the policy is none it scores `dmarcFailNone`, on
 * top of SPF's points, so a domain with policy none is never easier to
 * spoof than one without DMARC. A DKIM signature of only part of the body
 * (l=) earns no DKIM_PASS, nor a DMARC pass that rests on one alone
 * DMARC_PASS. An ARC seal counts only from a trusted forwarder (`arc.trusted`,
 * see authenticate's trustedArcSealers): its pass gets ARC_PASS, and no
 * points for failing SPF, DKIM or DMARC, as forwarding is what broke them.
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

	const forwarded = auth?.arc?.trusted === true && auth?.arc?.status?.result === 'pass';
	const policyNone = tagText(auth?.dmarc?.policy) === 'none';
	const spfCounted = !(auth?.dmarc?.status?.result === 'fail' && !policyNone);
	const failure = score => (forwarded ? 0 : score);
	const passing = (Array.isArray(auth?.dkim?.results) ? auth.dkim.results : []).filter(entry => entry?.status?.result === 'pass');
	const partOfBody = passing.length > 0 && passing.every(entry => entry.status.underSized > 0);
	const dmarcOnPart = auth?.dmarc?.alignment?.dkim?.underSized > 0 && !auth?.dmarc?.alignment?.spf?.result;
	const rules = [
		['DKIM', auth?.dkim?.status?.result, {pass: partOfBody ? 0 : w.dkimPass, fail: failure(w.dkimFail)}],
		['SPF', auth?.spf?.status?.result, {pass: w.spfPass, fail: spfCounted ? failure(w.spfFail) : 0, softfail: spfCounted ? failure(w.spfSoftfail) : 0}],
		['DMARC', auth?.dmarc?.status?.result, {pass: dmarcOnPart ? 0 : w.dmarcPass, fail: failure(policyNone ? w.dmarcFailNone : w.dmarcFail)}],
		['ARC', auth?.arc?.status?.result, {pass: forwarded ? w.arcPass : 0, fail: w.arcFail}],
	];
	for (const [name, value, scores] of rules) {
		if (value && Object.hasOwn(scores, value)) {
			add(`${name}_${value.toUpperCase()}`, scores[value]);
		}
	}

	return {score: tests.reduce((sum, test) => sum + test.score, 0), tests};
}

// An Authentication-Results value with as many of its results as fit in
// MAX_AUTH_RESULTS_LENGTH, whole (one longer than that alone is left out).
function limitResults(value) {
	if (value.length <= MAX_AUTH_RESULTS_LENGTH) {
		return value;
	}

	const [server, ...results] = value.split(/;(?=\s*(?:dkim|spf|dmarc|arc|bimi)=)/i);
	let kept = server;
	for (const result of results) {
		if (kept.length + 1 + result.length <= MAX_AUTH_RESULTS_LENGTH) {
			kept += `;${result}`;
		}
	}

	return kept;
}

/**
 * The Authentication-Results header (RFC 8601) for a result, without the
 * header name. mailauth's own headers are used when present, with as many
 * of their results as fit in 8 KiB.
 * @param {object} auth
 * @param {string} [hostname]
 * @returns {string}
 */
export function formatAuthResultsHeader(auth, hostname) {
	if (typeof auth?.headers === 'string') {
		const match = auth.headers.match(/^authentication-results:[ \t]*([\s\S]*?)(?=\r?\n\S|(?![\s\S]))/im);
		if (match) {
			const value = limitResults(match[1].replaceAll(/\r?\n/g, '\r\n').trim());
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
