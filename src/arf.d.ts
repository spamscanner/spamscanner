/**
 * ARF (Abuse Reporting Format) Parser Type Definitions
 *
 * @see https://www.rfc-editor.org/rfc/rfc5965.html
 */

/**
 * Valid feedback types as defined in RFC 5965 and extensions
 */
export declare const VALID_FEEDBACK_TYPES: Set<string>;

/**
 * Reporting MTA information
 */
export interface ReportingMta {
	/** MTA type (dns, smtp, etc.) */
	type: string;
	/** MTA hostname */
	name: string;
}

/**
 * Parsed ARF report result
 */
export interface ArfResult {
	/** Whether this is a valid ARF message */
	isArf: boolean;
	/** ARF version (usually "1") */
	version: string | null;
	/** Feedback type (abuse, fraud, virus, other, not-spam, auth-failure, dmarc) */
	feedbackType: string | null;
	/** Original feedback type if it was normalized to "other" */
	feedbackTypeOriginal?: string;
	/** User agent that generated the report */
	userAgent: string | null;
	/** Arrival date of the original message */
	arrivalDate: Date | null;
	/** Source IP address of the original message */
	sourceIp: string | null;
	/** Original MAIL FROM address */
	originalMailFrom: string | null;
	/** Original RCPT TO addresses */
	originalRcptTo: string[] | null;
	/** Reporting MTA information */
	reportingMta: ReportingMta | null;
	/** Original envelope ID */
	originalEnvelopeId: string | null;
	/** Authentication results */
	authenticationResults: string[] | null;
	/** Reported domains */
	reportedDomain: string[] | null;
	/** Reported URIs */
	reportedUri: string[] | null;
	/** Number of incidents */
	incidents: number;
	/** Human-readable description */
	humanReadable: string | null;
	/** Original message content */
	originalMessage: string | null;
	/** Parsed headers from original message */
	originalHeaders: Record<string, unknown> | null;
	/** Raw feedback report content */
	rawFeedbackReport: string | null;
}

/**
 * Options for creating an ARF report
 */
export interface ArfCreateOptions {
	/** Feedback type (abuse, fraud, virus, other) */
	feedbackType: string;
	/** User agent string */
	userAgent: string;
	/** From address for the report */
	from: string;
	/** To address for the report */
	to: string;
	/** Original message content */
	originalMessage: string;
	/** Human-readable description */
	humanReadable?: string;
	/** Source IP of original message */
	sourceIp?: string;
	/** Original MAIL FROM address */
	originalMailFrom?: string;
	/** Original RCPT TO addresses */
	originalRcptTo?: string[];
	/** Arrival date of original message */
	arrivalDate?: Date;
	/** Reporting MTA name */
	reportingMta?: string;
}

/**
 * ARF Parser class for parsing and creating ARF (Abuse Reporting Format) messages
 */
export declare class ArfParser {
	/**
	 * Check if a parsed email message is an ARF report
	 * @param parsed - Parsed email message from mailparser
	 * @returns True if message is ARF
	 */
	static isArfMessage(parsed: unknown): boolean;

	/**
	 * Parse an ARF message
	 * @param source - Raw email message as Buffer or string
	 * @returns Parsed ARF report
	 * @throws Error if not a valid ARF message
	 */
	static parse(source: Buffer | string): Promise<ArfResult>;

	/**
	 * Try to parse a message as ARF, return null if not ARF
	 * @param source - Raw email message as Buffer or string
	 * @returns Parsed ARF report or null if not ARF
	 */
	static tryParse(source: Buffer | string): Promise<ArfResult | null>;

	/**
	 * Create an ARF report message
	 * @param options - Report options
	 * @returns ARF message as string
	 * @throws Error if missing required fields
	 */
	static create(options: ArfCreateOptions): string;
}

export default ArfParser;
