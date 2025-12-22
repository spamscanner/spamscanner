/**
 * Arbitrary Spam Detection Module Type Definitions
 * Based on Forward Email's is-arbitrary helper
 */

import type {SessionInfo} from './get-attributes';

/**
 * Result from arbitrary spam detection
 */
export interface ArbitraryResult {
	/** Whether the message appears to be arbitrary spam */
	isArbitrary: boolean;
	/** List of reasons why the message was flagged */
	reasons: string[];
	/** Arbitrary spam score */
	score: number;
	/** Spam category if detected (e.g., 'PHISHING', 'MALWARE', 'SPOOFING') */
	category: string | null;
}

/**
 * Options for arbitrary spam detection
 */
export interface ArbitraryOptions {
	/** Score threshold for flagging as arbitrary spam (default: 5) */
	threshold?: number;
	/** Check subject line for spam patterns (default: true) */
	checkSubject?: boolean;
	/** Check body content for spam patterns (default: true) */
	checkBody?: boolean;
	/** Check sender for suspicious patterns (default: true) */
	checkSender?: boolean;
	/** Check headers for anomalies (default: true) */
	checkHeaders?: boolean;
	/** Check links for suspicious patterns (default: true) */
	checkLinks?: boolean;
	/** Check Microsoft Exchange headers for spam classification (default: true) */
	checkMicrosoftHeaders?: boolean;
	/** Check vendor-specific spam patterns (default: true) */
	checkVendorSpam?: boolean;
	/** Check for spoofing attacks (default: true) */
	checkSpoofing?: boolean;
	/** Session information for advanced checks */
	session?: SessionInfo;
}

/**
 * Result from pattern check functions
 */
export interface PatternCheckResult {
	score: number;
	reasons: string[];
}

/**
 * Result from Microsoft Exchange header check
 */
export interface MicrosoftCheckResult {
	blocked: boolean;
	reasons: string[];
	score: number;
	category: string | null;
}

/**
 * Result from vendor spam check
 */
export interface VendorSpamCheckResult {
	blocked: boolean;
	reasons: string[];
	score: number;
	category: string | null;
}

/**
 * Result from spoofing attack check
 */
export interface SpoofingCheckResult {
	blocked: boolean;
	reasons: string[];
	score: number;
	category: string | null;
}

/**
 * Check if a message appears to be arbitrary spam
 */
export function isArbitrary(
	parsed: Record<string, unknown>,
	options?: ArbitraryOptions,
): ArbitraryResult;

/**
 * Check subject line for spam patterns
 */
export function checkSubjectLine(subject: string): PatternCheckResult;

/**
 * Check body content for spam patterns
 */
export function checkBodyContent(text: string, html: string): PatternCheckResult;

/**
 * Check Microsoft Exchange headers for spam classification
 */
export function checkMicrosoftExchangeHeaders(
	getHeader: (name: string) => string | null,
	sessionInfo: SessionInfo,
): MicrosoftCheckResult;

/**
 * Check for vendor-specific spam patterns
 */
export function checkVendorSpam(
	parsed: Record<string, unknown>,
	sessionInfo: SessionInfo,
	getHeader: (name: string) => string | null,
	subject: string,
	from: string,
): VendorSpamCheckResult;

/**
 * Check for spoofing attacks
 */
export function checkSpoofingAttacks(
	parsed: Record<string, unknown>,
	sessionInfo: SessionInfo,
	getHeader: (name: string) => string | null,
	subject: string,
): SpoofingCheckResult;

/**
 * Check sender for suspicious patterns
 */
export function checkSenderPatterns(from: string, replyTo: string): PatternCheckResult;

/**
 * Check headers for anomalies
 */
export function checkHeaderAnomalies(
	parsed: Record<string, unknown>,
	getHeader: (name: string) => string | null,
): PatternCheckResult;

/**
 * Check links for suspicious patterns
 */
export function checkSuspiciousLinks(content: string): PatternCheckResult;

/**
 * Get root domain from a hostname
 */
export function getRootDomain(hostname: string): string;

/**
 * Parse host/domain from an email address
 */
export function parseHostFromAddress(address: string): string;

/**
 * Extract client hostname from email headers
 */
export function extractClientHostname(parsed: Record<string, unknown>): string | null;

/**
 * Extract remote IP from email headers
 */
export function extractRemoteIp(parsed: Record<string, unknown>): string | null;

/**
 * Build session info from parsed email
 */
export function buildSessionInfo(
	parsed: Record<string, unknown>,
	session?: Partial<SessionInfo>,
): SessionInfo;

/**
 * Check if message is an auto-reply or from a mailing list
 */
export function isAutoReply(getHeader: (name: string) => string | null): boolean;

/**
 * Spam patterns used for detection
 */
export const SPAM_PATTERNS: {
	subjectPatterns: RegExp[];
	bodyPatterns: RegExp[];
	senderPatterns: RegExp[];
};

/**
 * Spam keywords with their weights
 */
export const SPAM_KEYWORDS: Map<string, number>;

/**
 * Suspicious TLDs commonly used in spam
 */
export const SUSPICIOUS_TLDS: Set<string>;

/**
 * Microsoft Exchange spam categories (CAT values)
 */
export const MS_SPAM_CATEGORIES: {
	highConfidence: string[];
	impersonation: string[];
	phishingAndSpoofing: string[];
	spam: string[];
};

/**
 * Microsoft spam filtering verdicts (SFV values)
 */
export const MS_SPAM_VERDICTS: string[];

/**
 * PayPal spam email type IDs
 */
export const PAYPAL_SPAM_TYPE_IDS: Set<string>;

/**
 * Blocked phrases pattern for obvious spam
 */
export const BLOCKED_PHRASES_PATTERN: RegExp;

/**
 * Sysadmin subject patterns (legitimate automated emails)
 */
export const SYSADMIN_SUBJECT_PATTERN: RegExp;
