/**
 * Forward Email Reputation API Client Type Definitions
 */

export interface ReputationResult {
	/** Whether the sender is a known truth source */
	isTruthSource: boolean;
	/** The truth source entry that matched, or null */
	truthSourceValue: string | null;
	/** Whether the sender is allowlisted */
	isAllowlisted: boolean;
	/** The allowlist entry that matched, or null */
	allowlistValue: string | null;
	/** Whether the sender is denylisted */
	isDenylisted: boolean;
	/** The denylist entry that matched, or null */
	denylistValue: string | null;
}

export interface ReputationOptions {
	/** Custom API URL (default: https://api.forwardemail.net/v1/reputation) */
	apiUrl?: string;
	/** Request timeout in milliseconds (default: 10000) */
	timeout?: number;
	/** Only check aligned/authenticated attributes (default: true) */
	onlyAligned?: boolean;
}

/**
 * Check reputation for a single value (IP, domain, or email)
 */
export function checkReputation(
	value: string,
	options?: ReputationOptions,
): Promise<ReputationResult>;

/**
 * Check reputation for multiple values in parallel
 */
export function checkReputationBatch(
	values: string[],
	options?: ReputationOptions,
): Promise<Map<string, ReputationResult>>;

/**
 * Aggregate reputation results from multiple checks
 */
export function aggregateReputationResults(
	results: ReputationResult[],
): ReputationResult;

/**
 * Clear the reputation cache
 */
export function clearCache(): void;

/**
 * Default Forward Email API URL
 */
export const DEFAULT_API_URL: string;
