/**
 * ARF (Abuse Reporting Format) Parser
 *
 * Parses email feedback reports according to RFC 5965.
 * ARF messages are multipart/report MIME messages with report-type=feedback-report.
 *
 * Structure of an ARF message:
 * 1. First part: Human-readable description (text/plain)
 * 2. Second part: Machine-readable report (message/feedback-report)
 * 3. Third part: Original message (message/rfc822 or text/rfc822-headers)
 *
 * @see https://www.rfc-editor.org/rfc/rfc5965.html
 */

import {simpleParser} from 'mailparser';
import {checkReputation} from './reputation.js';

/**
 * Valid feedback types as defined in RFC 5965 and extensions
 */
const VALID_FEEDBACK_TYPES = new Set([
	'abuse',
	'fraud',
	'virus',
	'other',
	'not-spam',
	'auth-failure', // RFC 6591
	'dmarc', // RFC 7489
]);

/**
 * Extract boundary from Content-Type header
 * @param {string} contentType - Content-Type header value
 * @returns {string|null} Boundary string
 */
function extractBoundary(contentType) {
	const match = /boundary=["']?([^"';\s]+)["']?/i.exec(contentType);
	return match ? match[1] : null;
}

/**
 * Parse MIME parts from raw email content
 * @param {string} content - Raw email content
 * @param {string} boundary - MIME boundary
 * @returns {object[]} Array of parsed parts
 */
function parseMimeParts(content, boundary) {
	const parts = [];
	const boundaryRegex = new RegExp(`--${boundary.replaceAll(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`)}(?:--)?`, 'g');

	// Split by boundary
	const segments = content.split(boundaryRegex);

	// Skip first segment (preamble) and last if it's empty or just whitespace
	for (let index = 1; index < segments.length; index++) {
		const segment = segments[index].trim();
		if (!segment || segment === '--') {
			continue;
		}

		// Split headers from body
		const headerBodySplit = segment.indexOf('\r\n\r\n');
		const headerBodySplitAlt = segment.indexOf('\n\n');

		let headerEnd;
		let bodyStart;

		if (headerBodySplit !== -1 && (headerBodySplitAlt === -1 || headerBodySplit < headerBodySplitAlt)) {
			headerEnd = headerBodySplit;
			bodyStart = headerBodySplit + 4;
		} else if (headerBodySplitAlt === -1) {
			continue;
		} else {
			headerEnd = headerBodySplitAlt;
			bodyStart = headerBodySplitAlt + 2;
		}

		const headerSection = segment.slice(0, headerEnd);
		const body = segment.slice(bodyStart);

		// Parse headers
		const headers = {};
		const headerLines = headerSection.split(/\r?\n/);
		let currentHeader = null;
		let currentValue = '';

		for (const line of headerLines) {
			if (/^\s+/.test(line) && currentHeader) {
				currentValue += ' ' + line.trim();
			} else {
				if (currentHeader) {
					headers[currentHeader.toLowerCase()] = currentValue;
				}

				const colonIndex = line.indexOf(':');
				if (colonIndex !== -1) {
					currentHeader = line.slice(0, colonIndex).trim();
					currentValue = line.slice(colonIndex + 1).trim();
				}
			}
		}

		if (currentHeader) {
			headers[currentHeader.toLowerCase()] = currentValue;
		}

		parts.push({headers, body});
	}

	return parts;
}

/**
 * Parse ARF header fields from the machine-readable part
 * @param {string} content - Raw content of message/feedback-report part
 * @returns {object} Parsed header fields
 */
function parseArfHeaders(content) {
	const headers = {};
	const lines = content.split(/\r?\n/);
	let currentField = null;
	let currentValue = '';

	for (const line of lines) {
		// Check for continuation (line starts with whitespace)
		if (/^\s+/.test(line) && currentField) {
			currentValue += ' ' + line.trim();
			continue;
		}

		// Save previous field if exists
		if (currentField) {
			const fieldName = currentField.toLowerCase().replaceAll('-', '_');
			if (headers[fieldName]) {
				// Handle multiple occurrences
				if (Array.isArray(headers[fieldName])) {
					headers[fieldName].push(currentValue);
				} else {
					headers[fieldName] = [headers[fieldName], currentValue];
				}
			} else {
				headers[fieldName] = currentValue;
			}
		}

		// Parse new field
		const match = /^([^:]+):\s*(.*)$/.exec(line);
		if (match) {
			currentField = match[1];
			currentValue = match[2];
		} else {
			currentField = null;
			currentValue = '';
		}
	}

	// Save last field
	if (currentField) {
		const fieldName = currentField.toLowerCase().replaceAll('-', '_');
		if (headers[fieldName]) {
			if (Array.isArray(headers[fieldName])) {
				headers[fieldName].push(currentValue);
			} else {
				headers[fieldName] = [headers[fieldName], currentValue];
			}
		} else {
			headers[fieldName] = currentValue;
		}
	}

	return headers;
}

/**
 * Extract email address from various formats
 * @param {string} value - Email field value
 * @returns {string|null} Extracted email address
 */
function extractEmail(value) {
	if (!value) {
		return null;
	}

	// Handle <email@example.com> format
	const angleMatch = /<([^>]+)>/.exec(value);
	if (angleMatch) {
		return angleMatch[1];
	}

	// Handle plain email
	const emailMatch = /[\w.+-]+@[\w.-]+\.\w+/.exec(value);
	if (emailMatch) {
		return emailMatch[0];
	}

	return value.trim();
}

/**
 * Parse IP address from Source-IP field
 * @param {string} value - Source-IP field value
 * @returns {string|null} Parsed IP address
 */
function parseSourceIp(value) {
	if (!value) {
		return null;
	}

	// Handle IPv4
	const ipv4Match = /((?:\d{1,3}\.){3}\d{1,3})/.exec(value);
	if (ipv4Match) {
		return ipv4Match[1];
	}

	// Handle IPv6
	const ipv6Match = /([a-fA-F\d:]+:+[a-fA-F\d:]+)/.exec(value);
	if (ipv6Match) {
		return ipv6Match[1];
	}

	return value.trim();
}

/**
 * Parse date from various formats
 * @param {string} value - Date field value
 * @returns {Date|null} Parsed date
 */
function parseDate(value) {
	if (!value) {
		return null;
	}

	try {
		const date = new Date(value);
		if (Number.isNaN(date.getTime())) {
			return null;
		}

		return date;
	} catch {
		return null;
	}
}

/**
 * Parse Reporting-MTA field
 * @param {string} value - Reporting-MTA field value
 * @returns {object} Parsed MTA info
 */
function parseReportingMta(value) {
	if (!value) {
		return null;
	}

	// Format: dns; hostname or smtp; hostname
	const match = /^(\w+);\s*(.+)$/.exec(value.trim());
	if (match) {
		return {
			type: match[1].toLowerCase(),
			name: match[2].trim(),
		};
	}

	return {
		type: 'unknown',
		name: value.trim(),
	};
}

/**
 * Process feedback report part
 * @param {string} content - Feedback report content
 * @param {object} result - Result object to populate
 */
function processFeedbackReport(content, result) {
	result.rawFeedbackReport = content;

	const headers = parseArfHeaders(content);

	// Required fields
	result.feedbackType = headers.feedback_type?.toLowerCase() || null;
	result.userAgent = headers.user_agent || null;
	result.version = headers.version || '1';

	// Optional fields (single occurrence)
	result.arrivalDate = parseDate(headers.arrival_date || headers.received_date);
	result.sourceIp = parseSourceIp(headers.source_ip);
	result.originalMailFrom = extractEmail(headers.original_mail_from);
	result.originalEnvelopeId = headers.original_envelope_id || null;
	result.reportingMta = parseReportingMta(headers.reporting_mta);
	result.incidents = headers.incidents ? Number.parseInt(headers.incidents, 10) : 1;

	// Optional fields (multiple occurrences)
	if (headers.original_rcpt_to) {
		const rcptTo = Array.isArray(headers.original_rcpt_to)
			? headers.original_rcpt_to
			: [headers.original_rcpt_to];
		result.originalRcptTo = rcptTo.map(r => extractEmail(r)).filter(Boolean);
	}

	if (headers.authentication_results) {
		result.authenticationResults = Array.isArray(headers.authentication_results)
			? headers.authentication_results
			: [headers.authentication_results];
	}

	if (headers.reported_domain) {
		result.reportedDomain = Array.isArray(headers.reported_domain)
			? headers.reported_domain
			: [headers.reported_domain];
	}

	if (headers.reported_uri) {
		result.reportedUri = Array.isArray(headers.reported_uri)
			? headers.reported_uri
			: [headers.reported_uri];
	}
}

/**
 * Process original message part
 * @param {string} content - Original message content
 * @param {object} result - Result object to populate
 * @returns {Promise<void>}
 */
async function processOriginalMessage(content, result) {
	result.originalMessage = content;

	// Also parse the original message headers
	try {
		const originalParsed = await simpleParser(content, {
			skipHtmlToText: true,
			skipTextToHtml: true,
			skipImageLinks: true,
		});
		result.originalHeaders = {};
		for (const [key, value] of originalParsed.headers) {
			result.originalHeaders[key] = value;
		}
	} catch {
		// Ignore parsing errors for original message
	}
}

/**
 * ARF Parser class
 */
const ArfParser = {
	/**
	 * Check if a message is an ARF report
	 * @param {object} parsed - Parsed email message from mailparser
	 * @returns {boolean} True if message is ARF
	 */
	isArfMessage(parsed) {
		const contentType = parsed.headers?.get('content-type');
		if (!contentType) {
			return false;
		}

		// Check for multipart/report with report-type=feedback-report
		const value = typeof contentType === 'object' ? contentType.value : contentType;
		const parameters = typeof contentType === 'object' ? contentType.params : {};

		if (!value?.toLowerCase().includes('multipart/report')) {
			return false;
		}

		const reportType = parameters?.['report-type'] || '';
		return reportType.toLowerCase() === 'feedback-report';
	},

	/**
	 * Parse an ARF message
	 * @param {Buffer|string} source - Raw email message
	 * @returns {Promise<object>} Parsed ARF report
	 */
	async parse(source) {
		const rawContent = typeof source === 'string' ? source : source.toString('utf8');

		// Parse the email message for headers and basic validation
		const parsed = await simpleParser(source, {
			skipHtmlToText: true,
			skipTextToHtml: true,
			skipImageLinks: true,
		});

		// Validate it's an ARF message
		if (!ArfParser.isArfMessage(parsed)) {
			throw new Error('Not a valid ARF message: missing multipart/report with report-type=feedback-report');
		}

		// Get the boundary from the Content-Type header
		const contentType = parsed.headers.get('content-type');
		const boundary = typeof contentType === 'object'
			? contentType.params?.boundary
			: extractBoundary(contentType);

		if (!boundary) {
			throw new Error('Not a valid ARF message: missing MIME boundary');
		}

		const result = {
			isArf: true,
			version: null,
			feedbackType: null,
			userAgent: null,
			arrivalDate: null,
			sourceIp: null,
			originalMailFrom: null,
			originalRcptTo: null,
			reportingMta: null,
			originalEnvelopeId: null,
			authenticationResults: null,
			reportedDomain: null,
			reportedUri: null,
			incidents: 1,
			humanReadable: null,
			originalMessage: null,
			originalHeaders: null,
			rawFeedbackReport: null,
			// Reputation fields (populated if sourceIp is available)
			isTruthSource: false,
			isAllowlisted: false,
			isDenylisted: false,
			allowlistValue: null,
			denylistValue: null,
		};

		// Parse MIME parts manually to get message/rfc822 content
		const parts = parseMimeParts(rawContent, boundary);

		// Find and categorize parts
		let rfc822Part = null;

		for (const part of parts) {
			const partContentType = part.headers['content-type']?.toLowerCase() || '';

			if (partContentType.includes('text/plain')) {
				result.humanReadable = part.body.trim();
			} else if (partContentType.includes('message/feedback-report')) {
				processFeedbackReport(part.body, result);
			} else if (partContentType.includes('message/rfc822')) {
				rfc822Part = part;
			} else if (partContentType.includes('text/rfc822-headers')) {
				result.originalHeaders = part.body.trim();
			}
		}

		// Process original message outside the loop to avoid await-in-loop
		if (rfc822Part) {
			await processOriginalMessage(rfc822Part.body, result);
		}

		// Validate required fields
		if (!result.feedbackType) {
			throw new Error('Invalid ARF message: missing required Feedback-Type field');
		}

		if (!result.userAgent) {
			throw new Error('Invalid ARF message: missing required User-Agent field');
		}

		// Validate feedback type
		if (!VALID_FEEDBACK_TYPES.has(result.feedbackType)) {
			// Allow unknown types but mark as other
			result.feedbackTypeOriginal = result.feedbackType;
			result.feedbackType = 'other';
		}

		// Check reputation if sourceIp is available
		if (result.sourceIp) {
			try {
				const reputation = await checkReputation(result.sourceIp);
				result.isTruthSource = reputation.isTruthSource;
				result.isAllowlisted = reputation.isAllowlisted;
				result.isDenylisted = reputation.isDenylisted;
				result.allowlistValue = reputation.allowlistValue;
				result.denylistValue = reputation.denylistValue;
			} catch {
				// Ignore reputation check errors
			}
		}

		return result;
	},

	/**
	 * Try to parse a message as ARF, return null if not ARF
	 * @param {Buffer|string} source - Raw email message
	 * @returns {Promise<object|null>} Parsed ARF report or null
	 */
	async tryParse(source) {
		try {
			return await ArfParser.parse(source);
		} catch {
			return null;
		}
	},

	/**
	 * Create an ARF report message
	 * @param {object} options - Report options
	 * @param {string} options.feedbackType - Type of feedback (abuse, fraud, virus, other)
	 * @param {string} options.userAgent - User agent string
	 * @param {string} options.from - From address for the report
	 * @param {string} options.to - To address for the report
	 * @param {string} options.originalMessage - Original message content
	 * @param {string} [options.humanReadable] - Human-readable description
	 * @param {string} [options.sourceIp] - Source IP of original message
	 * @param {string} [options.originalMailFrom] - Original MAIL FROM
	 * @param {string[]} [options.originalRcptTo] - Original RCPT TO addresses
	 * @param {Date} [options.arrivalDate] - Arrival date of original message
	 * @param {string} [options.reportingMta] - Reporting MTA name
	 * @returns {string} ARF message as string
	 */
	create(options) {
		const {
			feedbackType,
			userAgent,
			from,
			to,
			originalMessage,
			humanReadable = 'This is an abuse report.',
			sourceIp,
			originalMailFrom,
			originalRcptTo,
			arrivalDate,
			reportingMta,
		} = options;

		if (!feedbackType || !userAgent || !from || !to || !originalMessage) {
			throw new Error('Missing required fields for ARF report');
		}

		const boundary = `arf_boundary_${Date.now()}_${Math.random().toString(36).slice(2)}`;
		const date = new Date().toUTCString();

		// Build feedback report part
		let feedbackReport = `Feedback-Type: ${feedbackType}\r\n`;
		feedbackReport += `User-Agent: ${userAgent}\r\n`;
		feedbackReport += 'Version: 1\r\n';

		if (sourceIp) {
			feedbackReport += `Source-IP: ${sourceIp}\r\n`;
		}

		if (originalMailFrom) {
			feedbackReport += `Original-Mail-From: <${originalMailFrom}>\r\n`;
		}

		if (originalRcptTo && originalRcptTo.length > 0) {
			for (const rcpt of originalRcptTo) {
				feedbackReport += `Original-Rcpt-To: <${rcpt}>\r\n`;
			}
		}

		if (arrivalDate) {
			feedbackReport += `Arrival-Date: ${arrivalDate.toUTCString()}\r\n`;
		}

		if (reportingMta) {
			feedbackReport += `Reporting-MTA: dns; ${reportingMta}\r\n`;
		}

		// Build the full message
		let message = `From: ${from}\r\n`;
		message += `To: ${to}\r\n`;
		message += `Date: ${date}\r\n`;
		message += 'Subject: Abuse Report\r\n';
		message += 'MIME-Version: 1.0\r\n';
		message += `Content-Type: multipart/report; report-type=feedback-report; boundary="${boundary}"\r\n`;
		message += '\r\n';

		// Part 1: Human-readable
		message += `--${boundary}\r\n`;
		message += 'Content-Type: text/plain; charset="utf-8"\r\n';
		message += 'Content-Transfer-Encoding: 7bit\r\n';
		message += '\r\n';
		message += humanReadable + '\r\n';
		message += '\r\n';

		// Part 2: Machine-readable
		message += `--${boundary}\r\n`;
		message += 'Content-Type: message/feedback-report\r\n';
		message += '\r\n';
		message += feedbackReport;
		message += '\r\n';

		// Part 3: Original message
		message += `--${boundary}\r\n`;
		message += 'Content-Type: message/rfc822\r\n';
		message += 'Content-Disposition: inline\r\n';
		message += '\r\n';
		message += originalMessage;
		message += '\r\n';

		message += `--${boundary}--\r\n`;

		return message;
	},
};

export default ArfParser;
export {ArfParser, VALID_FEEDBACK_TYPES};
