/**
 * Forward Email Reputation API Client
 * Checks IP addresses, domains, and emails against Forward Email's reputation database
 */

import {debuglog} from 'node:util';

const debug = debuglog('spamscanner:reputation');

// Default Forward Email API URL
const DEFAULT_API_URL = 'https://api.forwardemail.net/v1/reputation';

// Cache for reputation results (TTL: 5 minutes)
const cache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

/**
 * @typedef {Object} ReputationResult
 * @property {boolean} isTruthSource - Whether the sender is a known truth source
 * @property {string|null} truthSourceValue - The truth source entry that matched
 * @property {boolean} isAllowlisted - Whether the sender is allowlisted
 * @property {string|null} allowlistValue - The allowlist entry that matched
 * @property {boolean} isDenylisted - Whether the sender is denylisted
 * @property {string|null} denylistValue - The denylist entry that matched
 */

/**
 * Check reputation for a single value (IP, domain, or email)
 * @param {string} value - The value to check
 * @param {Object} options - Options
 * @param {string} [options.apiUrl] - Custom API URL
 * @param {number} [options.timeout] - Request timeout in ms
 * @returns {Promise<ReputationResult>}
 */
async function checkReputation(value, options = {}) {
	const {
		apiUrl = DEFAULT_API_URL,
		timeout = 10_000,
	} = options;

	if (!value || typeof value !== 'string') {
		return {
			isTruthSource: false,
			truthSourceValue: null,
			isAllowlisted: false,
			allowlistValue: null,
			isDenylisted: false,
			denylistValue: null,
		};
	}

	// Check cache first
	const cacheKey = `${apiUrl}:${value}`;
	const cached = cache.get(cacheKey);
	if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
		debug('Cache hit for %s', value);
		return cached.result;
	}

	try {
		const url = new URL(apiUrl);
		url.searchParams.set('q', value);

		const controller = new AbortController();
		const timeoutId = setTimeout(() => controller.abort(), timeout);

		const response = await fetch(url.toString(), {
			method: 'GET',
			headers: {
				Accept: 'application/json',
				'User-Agent': 'SpamScanner/6.0',
			},
			signal: controller.signal,
		});

		clearTimeout(timeoutId);

		if (!response.ok) {
			debug('API returned status %d for %s', response.status, value);
			// Return default values on error
			return {
				isTruthSource: false,
				truthSourceValue: null,
				isAllowlisted: false,
				allowlistValue: null,
				isDenylisted: false,
				denylistValue: null,
			};
		}

		const result = await response.json();

		// Normalize the result
		const normalizedResult = {
			isTruthSource: Boolean(result.isTruthSource),
			truthSourceValue: result.truthSourceValue || null,
			isAllowlisted: Boolean(result.isAllowlisted),
			allowlistValue: result.allowlistValue || null,
			isDenylisted: Boolean(result.isDenylisted),
			denylistValue: result.denylistValue || null,
		};

		// Cache the result
		cache.set(cacheKey, {
			result: normalizedResult,
			timestamp: Date.now(),
		});

		debug('Reputation check for %s: %o', value, normalizedResult);
		return normalizedResult;
	} catch (error) {
		debug('Reputation check failed for %s: %s', value, error.message);
		// Return default values on error
		return {
			isTruthSource: false,
			truthSourceValue: null,
			isAllowlisted: false,
			allowlistValue: null,
			isDenylisted: false,
			denylistValue: null,
		};
	}
}

/**
 * Check reputation for multiple values in parallel
 * @param {string[]} values - Array of values to check (IPs, domains, emails)
 * @param {Object} options - Options
 * @returns {Promise<Map<string, ReputationResult>>}
 */
async function checkReputationBatch(values, options = {}) {
	const uniqueValues = [...new Set(values.filter(Boolean))];

	const results = await Promise.all(uniqueValues.map(async value => {
		const result = await checkReputation(value, options);
		return [value, result];
	}));

	return new Map(results);
}

/**
 * Aggregate reputation results from multiple checks
 * @param {ReputationResult[]} results - Array of reputation results
 * @returns {ReputationResult}
 */
function aggregateReputationResults(results) {
	const aggregated = {
		isTruthSource: false,
		truthSourceValue: null,
		isAllowlisted: false,
		allowlistValue: null,
		isDenylisted: false,
		denylistValue: null,
	};

	for (const result of results) {
		// Any truth source match is a truth source
		if (result.isTruthSource) {
			aggregated.isTruthSource = true;
			aggregated.truthSourceValue ||= result.truthSourceValue;
		}

		// Any allowlist match is allowlisted
		if (result.isAllowlisted) {
			aggregated.isAllowlisted = true;
			aggregated.allowlistValue ||= result.allowlistValue;
		}

		// Any denylist match is denylisted (takes precedence)
		if (result.isDenylisted) {
			aggregated.isDenylisted = true;
			aggregated.denylistValue ||= result.denylistValue;
		}
	}

	return aggregated;
}

/**
 * Clear the reputation cache
 */
function clearCache() {
	cache.clear();
}

export {
	checkReputation,
	checkReputationBatch,
	aggregateReputationResults,
	clearCache,
	DEFAULT_API_URL,
};
