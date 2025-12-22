/**
 * Get Attributes Module Type Definitions
 * Based on Forward Email's get-attributes helper
 */

import type {AuthenticationResults} from './auth';

/**
 * Session information for attribute extraction
 */
export interface SessionInfo {
	/** Resolved hostname of connecting client */
	resolvedClientHostname?: string;
	/** Root domain of resolved client hostname */
	resolvedRootClientHostname?: string;
	/** IP address of connecting client */
	remoteAddress?: string;
	/** Email address from From header */
	originalFromAddress?: string;
	/** Domain from From header */
	originalFromAddressDomain?: string;
	/** Root domain from From header */
	originalFromAddressRootDomain?: string;
	/** SMTP envelope */
	envelope?: {
		mailFrom?: {address: string};
		rcptTo?: Array<{address: string}>;
	};
	/** Whether DKIM was aligned and passing */
	hadAlignedAndPassingDKIM?: boolean;
	/** SPF result for From header */
	spfFromHeader?: {
		status?: {result: string};
	};
	/** Whether client hostname matches From domain */
	hasSameHostnameAsFrom?: boolean;
	/** Whether sender is allowlisted */
	isAllowlisted?: boolean;
	/** Set of DKIM signing domains */
	signingDomains?: Set<string>;
	/** SPF domain */
	spf?: {
		domain?: string;
	};
	/** Whether message is potential phishing */
	isPotentialPhishing?: boolean;
}

/**
 * Options for attribute extraction
 */
export interface GetAttributesOptions {
	/** Only return attributes that are verified and aligned */
	isAligned?: boolean;
	/** Authentication results from mailauth */
	authResults?: AuthenticationResults | null;
}

/**
 * Options for extractAttributes convenience function
 */
export interface ExtractAttributesOptions extends GetAttributesOptions {
	/** Sender IP address */
	senderIp?: string;
	/** Sender hostname */
	senderHostname?: string;
}

/**
 * Result from extractAttributes
 */
export interface ExtractAttributesResult {
	/** Array of unique attributes to check */
	attributes: string[];
	/** Session information built from parsed email */
	session: SessionInfo;
}

/**
 * Get attributes from an email for reputation checking
 * @param parsed - Parsed email message
 * @param session - Session information
 * @param options - Options
 * @returns Array of unique attributes to check
 */
export function getAttributes(
	parsed: object,
	session?: SessionInfo,
	options?: GetAttributesOptions,
): Promise<string[]>;

/**
 * Build session info from parsed email
 * @param parsed - Parsed email
 * @param existingSession - Existing session info to merge
 * @returns Session information
 */
export function buildSessionFromParsed(
	parsed: object,
	existingSession?: Partial<SessionInfo>,
): SessionInfo;

/**
 * Extract all checkable attributes from an email
 * @param parsed - Parsed email message
 * @param options - Options
 * @returns Attributes and session info
 */
export function extractAttributes(
	parsed: object,
	options?: ExtractAttributesOptions,
): Promise<ExtractAttributesResult>;

/**
 * Check and remove SRS (Sender Rewriting Scheme) encoding from an address
 * @param address - Email address
 * @returns Address with SRS removed
 */
export function checkSRS(address: string): string;

/**
 * Parse host/domain from an email address or domain string
 * @param addressOrDomain - Email address or domain
 * @returns Domain portion
 */
export function parseHostFromDomainOrAddress(addressOrDomain: string): string;

/**
 * Get root domain from a hostname
 * @param hostname - Hostname
 * @returns Root domain
 */
export function parseRootDomain(hostname: string): string;

/**
 * Parse addresses from a header value
 * @param headerValue - Header value
 * @returns Array of email addresses
 */
export function parseAddresses(headerValue: string | object | unknown[]): string[];

/**
 * Get header value from parsed email
 * @param headers - Headers object
 * @param name - Header name
 * @returns Header value or null
 */
export function getHeaders(headers: object, name: string): string | null;
