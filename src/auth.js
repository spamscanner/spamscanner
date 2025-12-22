/**
 * Email Authentication Module
 * Integrates mailauth for DKIM, SPF, ARC, DMARC, BIMI checking
 */

import {Buffer} from 'node:buffer';
import {debuglog} from 'node:util';
import dns from 'node:dns';

const debug = debuglog('spamscanner:auth');

// Lazy load mailauth to avoid issues if not installed
let mailauth;
const getMailauth = async () => {
	mailauth ||= await import('mailauth');

	return mailauth;
};

/**
 * @typedef {Object} AuthResult
 * @property {Object} dkim - DKIM verification results
 * @property {Object} spf - SPF verification results
 * @property {Object} dmarc - DMARC verification results
 * @property {Object} arc - ARC verification results
 * @property {Object} bimi - BIMI verification results
 * @property {Array} receivedChain - Received header chain analysis
 * @property {Object} headers - Parsed authentication headers
 */

/**
 * @typedef {Object} AuthOptions
 * @property {string} ip - Remote IP address of the sender
 * @property {string} [helo] - HELO/EHLO hostname
 * @property {string} [mta] - MTA hostname (for ARC sealing)
 * @property {string} [sender] - Envelope sender (MAIL FROM)
 * @property {Function} [resolver] - Custom DNS resolver function
 * @property {number} [timeout] - DNS lookup timeout in ms
 */

/**
 * Default DNS resolver with timeout support
 */
const createResolver = (timeout = 10_000) => {
	const resolver = new dns.promises.Resolver();
	resolver.setServers(['8.8.8.8', '1.1.1.1']);

	return async (name, type) => {
		try {
			const controller = new AbortController();
			const timeoutId = setTimeout(() => controller.abort(), timeout);

			let result;
			switch (type) {
				case 'TXT': {
					result = await resolver.resolveTxt(name);
					// Flatten TXT records (they come as arrays of strings)
					result = result.map(r => (Array.isArray(r) ? r.join('') : r));
					break;
				}

				case 'MX': {
					result = await resolver.resolveMx(name);
					break;
				}

				case 'A': {
					result = await resolver.resolve4(name);
					break;
				}

				case 'AAAA': {
					result = await resolver.resolve6(name);
					break;
				}

				case 'PTR': {
					result = await resolver.resolvePtr(name);
					break;
				}

				case 'CNAME': {
					result = await resolver.resolveCname(name);
					break;
				}

				default: {
					result = await resolver.resolve(name, type);
				}
			}

			clearTimeout(timeoutId);
			return result;
		} catch (error) {
			debug('DNS lookup failed for %s %s: %s', type, name, error.message);
			throw error;
		}
	};
};

/**
 * Authenticate an email message
 * @param {Buffer|string} message - Raw email message
 * @param {AuthOptions} options - Authentication options
 * @returns {Promise<AuthResult>}
 */
async function authenticate(message, options = {}) {
	const {
		ip,
		helo,
		mta,
		sender,
		resolver = createResolver(options.timeout || 10_000),
	} = options;

	// Default result structure
	const defaultResult = {
		dkim: {
			results: [],
			status: {result: 'none', comment: 'No DKIM signature found'},
		},
		spf: {
			status: {result: 'none', comment: 'SPF check not performed'},
			domain: null,
		},
		dmarc: {
			status: {result: 'none', comment: 'DMARC check not performed'},
			policy: null,
			domain: null,
		},
		arc: {
			status: {result: 'none', comment: 'No ARC chain found'},
			chain: [],
		},
		bimi: {
			status: {result: 'none', comment: 'No BIMI record found'},
			location: null,
			authority: null,
		},
		receivedChain: [],
		headers: {},
	};

	if (!ip) {
		debug('No IP address provided, skipping authentication');
		return defaultResult;
	}

	try {
		const {authenticate: mailauthAuthenticate} = await getMailauth();

		// Convert string to Buffer if needed
		const messageBuffer = Buffer.isBuffer(message) ? message : Buffer.from(message);

		const authResult = await mailauthAuthenticate(messageBuffer, {
			ip,
			helo: helo || 'unknown',
			mta: mta || 'spamscanner',
			sender,
			resolver,
		});

		debug('Authentication result: %o', authResult);

		// Normalize the result
		return {
			dkim: normalizeResult(authResult.dkim, 'dkim'),
			spf: normalizeResult(authResult.spf, 'spf'),
			dmarc: normalizeResult(authResult.dmarc, 'dmarc'),
			arc: normalizeResult(authResult.arc, 'arc'),
			bimi: normalizeResult(authResult.bimi, 'bimi'),
			receivedChain: authResult.receivedChain || [],
			headers: authResult.headers || {},
		};
	} catch (error) {
		debug('Authentication failed: %s', error.message);
		return defaultResult;
	}
}

/**
 * Perform SPF check only
 * @param {string} ip - Remote IP address
 * @param {string} sender - Envelope sender (MAIL FROM)
 * @param {string} [helo] - HELO/EHLO hostname
 * @param {Object} [options] - Additional options
 * @returns {Promise<Object>}
 */
async function checkSpf(ip, sender, helo, options = {}) {
	const {
		resolver = createResolver(options.timeout || 10_000),
		mta = 'spamscanner',
	} = options;

	const defaultResult = {
		status: {result: 'none', comment: 'SPF check not performed'},
		domain: null,
	};

	if (!ip || !sender) {
		return defaultResult;
	}

	try {
		const {spf} = await getMailauth();

		const result = await spf({
			ip,
			sender,
			helo: helo || 'unknown',
			mta,
			resolver,
		});

		return normalizeResult(result, 'spf');
	} catch (error) {
		debug('SPF check failed: %s', error.message);
		return defaultResult;
	}
}

/**
 * Verify DKIM signature
 * @param {Buffer|string} message - Raw email message
 * @param {Object} [options] - Additional options
 * @returns {Promise<Object>}
 */
async function verifyDkim(message, options = {}) {
	const {
		resolver = createResolver(options.timeout || 10_000),
	} = options;

	const defaultResult = {
		results: [],
		status: {result: 'none', comment: 'No DKIM signature found'},
	};

	try {
		const {dkimVerify} = await getMailauth();

		const messageBuffer = Buffer.isBuffer(message) ? message : Buffer.from(message);

		const result = await dkimVerify(messageBuffer, {
			resolver,
		});

		return normalizeResult(result, 'dkim');
	} catch (error) {
		debug('DKIM verification failed: %s', error.message);
		return defaultResult;
	}
}

/**
 * Normalize authentication result to consistent structure
 * @param {Object} result - Raw result from mailauth
 * @param {string} type - Type of authentication (dkim, spf, dmarc, arc, bimi)
 * @returns {Object}
 */
function normalizeResult(result, type) {
	if (!result) {
		return {
			status: {result: 'none', comment: `No ${type.toUpperCase()} result`},
		};
	}

	switch (type) {
		case 'dkim': {
			return {
				results: result.results || [],
				status: result.status || {result: 'none', comment: 'No DKIM signature found'},
			};
		}

		case 'spf': {
			return {
				status: result.status || {result: 'none', comment: 'SPF check not performed'},
				domain: result.domain || null,
				explanation: result.explanation || null,
			};
		}

		case 'dmarc': {
			return {
				status: result.status || {result: 'none', comment: 'DMARC check not performed'},
				policy: result.policy || null,
				domain: result.domain || null,
				p: result.p || null,
				sp: result.sp || null,
				pct: result.pct || null,
			};
		}

		case 'arc': {
			return {
				status: result.status || {result: 'none', comment: 'No ARC chain found'},
				chain: result.chain || [],
				i: result.i || null,
			};
		}

		case 'bimi': {
			return {
				status: result.status || {result: 'none', comment: 'No BIMI record found'},
				location: result.location || null,
				authority: result.authority || null,
				selector: result.selector || null,
			};
		}

		default: {
			return result;
		}
	}
}

/**
 * Calculate authentication score based on results
 * @param {AuthResult} authResult - Authentication results
 * @param {Object} weights - Score weights for each check
 * @returns {Object} Score breakdown
 */
function calculateAuthScore(authResult, weights = {}) {
	const defaultWeights = {
		dkimPass: -2, // Reduce spam score if DKIM passes
		dkimFail: 3, // Increase spam score if DKIM fails
		spfPass: -1,
		spfFail: 2,
		spfSoftfail: 1,
		dmarcPass: -2,
		dmarcFail: 4,
		arcPass: -1,
		arcFail: 1,
		...weights,
	};

	let score = 0;
	const tests = [];

	// DKIM scoring
	const dkimResult = authResult.dkim?.status?.result;
	if (dkimResult === 'pass') {
		score += defaultWeights.dkimPass;
		tests.push(`DKIM_PASS(${defaultWeights.dkimPass})`);
	} else if (dkimResult === 'fail') {
		score += defaultWeights.dkimFail;
		tests.push(`DKIM_FAIL(${defaultWeights.dkimFail})`);
	}

	// SPF scoring
	const spfResult = authResult.spf?.status?.result;
	switch (spfResult) {
		case 'pass': {
			score += defaultWeights.spfPass;
			tests.push(`SPF_PASS(${defaultWeights.spfPass})`);

			break;
		}

		case 'fail': {
			score += defaultWeights.spfFail;
			tests.push(`SPF_FAIL(${defaultWeights.spfFail})`);

			break;
		}

		case 'softfail': {
			score += defaultWeights.spfSoftfail;
			tests.push(`SPF_SOFTFAIL(${defaultWeights.spfSoftfail})`);

			break;
		}
	// No default
	}

	// DMARC scoring
	const dmarcResult = authResult.dmarc?.status?.result;
	if (dmarcResult === 'pass') {
		score += defaultWeights.dmarcPass;
		tests.push(`DMARC_PASS(${defaultWeights.dmarcPass})`);
	} else if (dmarcResult === 'fail') {
		score += defaultWeights.dmarcFail;
		tests.push(`DMARC_FAIL(${defaultWeights.dmarcFail})`);
	}

	// ARC scoring
	const arcResult = authResult.arc?.status?.result;
	if (arcResult === 'pass') {
		score += defaultWeights.arcPass;
		tests.push(`ARC_PASS(${defaultWeights.arcPass})`);
	} else if (arcResult === 'fail') {
		score += defaultWeights.arcFail;
		tests.push(`ARC_FAIL(${defaultWeights.arcFail})`);
	}

	return {
		score,
		tests,
		details: {
			dkim: dkimResult || 'none',
			spf: spfResult || 'none',
			dmarc: dmarcResult || 'none',
			arc: arcResult || 'none',
		},
	};
}

/**
 * Format authentication results as Authentication-Results header
 * @param {AuthResult} authResult - Authentication results
 * @param {string} hostname - MTA hostname
 * @returns {string}
 */
function formatAuthResultsHeader(authResult, hostname = 'spamscanner') {
	const parts = [hostname];

	// DKIM
	if (authResult.dkim?.status?.result) {
		const dkimResult = authResult.dkim.status.result;
		let dkimPart = `dkim=${dkimResult}`;
		if (authResult.dkim.results?.[0]?.signingDomain) {
			dkimPart += ` header.d=${authResult.dkim.results[0].signingDomain}`;
		}

		parts.push(dkimPart);
	}

	// SPF
	if (authResult.spf?.status?.result) {
		let spfPart = `spf=${authResult.spf.status.result}`;
		if (authResult.spf.domain) {
			spfPart += ` smtp.mailfrom=${authResult.spf.domain}`;
		}

		parts.push(spfPart);
	}

	// DMARC
	if (authResult.dmarc?.status?.result) {
		let dmarcPart = `dmarc=${authResult.dmarc.status.result}`;
		if (authResult.dmarc.domain) {
			dmarcPart += ` header.from=${authResult.dmarc.domain}`;
		}

		parts.push(dmarcPart);
	}

	// ARC
	if (authResult.arc?.status?.result) {
		parts.push(`arc=${authResult.arc.status.result}`);
	}

	return parts.join(';\n\t');
}

export {
	authenticate,
	checkSpf,
	verifyDkim,
	calculateAuthScore,
	formatAuthResultsHeader,
	createResolver,
};
