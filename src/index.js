import {Buffer} from 'node:buffer';
import {readFile} from 'node:fs/promises';
import {debuglog} from 'node:util';
import {inspectAttachments, sniff} from './attachments.js';
import {
	authenticate, calculateAuthScore, normalizeAuthOutput, summarizeAuth,
} from './auth.js';
import {scanBuffer} from './clamav.js';
import {Classifier} from './classifier.js';
import {DnsChecker} from './dnsbl.js';
import {visibleText} from './html.js';
import HomographDetector from './homograph.js';
import {isArbitrary} from './is-arbitrary.js';
import {normalizeLanguageCode} from './language.js';
import {LLMClassifier} from './llm.js';
import {loadDefaultModel, loadModel, saveModel} from './model.js';
import {expandAttachments, parseWithin} from './parse.js';
import {
	ReputationChecker, reputationValues, trustReputation, trustedReputationValues,
} from './reputation.js';
import {scoreResults} from './score.js';
import {
	extractLinks, getFeatures, isDeceptiveLink, obfuscationOf, registrableDomain, segmentWords, unwrapLink,
} from './tokenizer.js';
import {VERSION} from './version.js';

const debug = debuglog('spamscanner');

/**
 * A detection result with a readable message. Converting one to a string
 * gives its message, so `results.phishing.join(' ')` reads naturally.
 * @param {object} fields
 * @returns {object}
 */
function finding(fields) {
	Object.defineProperty(fields, 'toString', {
		value() {
			return this.message;
		},
		enumerable: false,
	});
	return fields;
}

async function withTimeout(promise, ms, fallback) {
	let timer;
	try {
		return await Promise.race([
			promise,
			new Promise(resolve => {
				timer = setTimeout(() => resolve(fallback), ms);
			}),
		]);
	} finally {
		clearTimeout(timer);
	}
}

async function toBuffer(source) {
	if (Buffer.isBuffer(source)) {
		return source;
	}

	if (typeof source === 'string') {
		return Buffer.from(source, 'utf8');
	}

	if (source instanceof Uint8Array) {
		return Buffer.from(source);
	}

	if (source && typeof source[Symbol.asyncIterator] === 'function') {
		const chunks = [];
		for await (const chunk of source) {
			chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
		}

		return Buffer.concat(chunks);
	}

	throw new TypeError('A message must be a Buffer, a string, a Uint8Array or a readable stream');
}

/**
 * Settings and their defaults. Every key can be passed to the constructor and
 * most can be overridden for one message in scan()'s options.
 */
export const DEFAULTS = {
	// Score at which a message is spam, and at which servers should reject it.
	threshold: 5,
	rejectThreshold: 15,
	// Points per test (see DEFAULT_SCORES in score.js).
	scores: {},
	// The classifier: a Classifier, a model object or file path, or false to
	// turn it off. The default is the model shipped with the package.
	classifier: undefined,
	classifierOptions: {},
	// Language codes accepted (ISO 639-1). Mail confidently detected in another
	// language gets LANGUAGE_NOT_ALLOWED. Empty: every language.
	allowedLanguages: [],
	phishing: {
		// Ask Cloudflare's malware (1.1.1.2) and family (1.1.1.3) resolvers about link hosts.
		cloudflare: true,
		adult: true,
		maxHosts: 25,
		// Characters of text read for links (twice as many of HTML): more than
		// for the classifier (maxLength), as a link anywhere in a message may be
		// followed; a longer message sets results.linksTruncated.
		maxLength: 1_000_000,
		// Options for the lookalike domain detector: brands, extraBrands, allowlist, strictMode.
		homograph: {},
	},
	// DNS blocklists: { ip: ['zen.spamhaus.org'], domain: ['dbl.spamhaus.org'] }.
	dnsbl: {ip: [], domain: []},
	// Name servers for DNS checks (default: the system's) and their timeout.
	dns: {servers: null, timeout: 3000},
	attachments: true,
	arbitrary: true,
	// SPF, DKIM, DMARC and ARC (needs the client IP: scan(raw, {session: {remoteAddress}})).
	authentication: false,
	// { allowlist, denylist, apiUrl, headers, timeout } or false.
	reputation: false,
	// ClamAV: true to use clamd's default socket, or { socket } or { host, port }.
	clamav: false,
	// A second opinion from a language model (see llm.js), or null.
	llm: null,
	// Optional models you load yourself (see the docs): { model, threshold }.
	// toxicity.model.classify([text]) returns @tensorflow-models/toxicity predictions;
	// nsfw.model.classify(imageBuffer) returns nsfwjs predictions.
	toxicity: false,
	nsfw: false,
	// Characters of body text read; longer bodies are cut.
	maxLength: 100_000,
	// Milliseconds allowed for each network check.
	timeout: 10_000,
	// SMTP session defaults (remoteAddress, resolvedClientHostname, helo, envelope).
	session: {},
};

// An object without its undefined values, so that an option passed as
// undefined keeps its default.
function defined(object) {
	return object && typeof object === 'object' ? Object.fromEntries(Object.entries(object).filter(([, value]) => value !== undefined)) : object;
}

// The nested settings merged key by key with their defaults.
const NESTED = ['phishing', 'dnsbl', 'dns', 'session'];

/**
 * @typedef {object} SmtpSession
 * @property {string} [remoteAddress] - the client's IP address
 * @property {string} [resolvedClientHostname] - its verified reverse DNS name
 * @property {string} [helo] - the name it gave in HELO or EHLO
 * @property {{mailFrom?: {address?: string}, rcptTo?: Array<{address?: string}>}} [envelope]
 */

/**
 * @typedef {object} ReputationOptions
 * @property {string[]} [allowlist] - IPs, domains and addresses always accepted
 * @property {string[]} [denylist] - IPs, domains and addresses always rejected
 * @property {string} [apiUrl] - reputation service URL
 * @property {Record<string, string>} [headers] - for the service, e.g. authorization
 * @property {number} [timeout]
 * @property {number} [concurrency] - parallel service requests
 * @property {number} [cacheTtl] - milliseconds answers are kept
 * @property {number} [cacheSize]
 */

/**
 * @typedef {import('./legacy.js').LegacyOptions} LegacyOptions
 */

/**
 * @typedef {ScannerSettings & LegacyOptions} SpamScannerOptions - the settings,
 *   and the options of earlier versions they are read from
 */

/**
 * @typedef {object} ScannerSettings
 * @property {number} [threshold] - score at which a message is spam (5)
 * @property {number} [rejectThreshold] - score at which servers reject it (15)
 * @property {Record<string, number>} [scores] - points per test (see DEFAULT_SCORES)
 * @property {Classifier|object|string|false} [classifier] - a classifier, a model object or file, or false
 * @property {object} [classifierOptions]
 * @property {string[]|null} [allowedLanguages] - ISO 639-1 codes; empty for every language
 * @property {{cloudflare?: boolean, adult?: boolean, maxHosts?: number, maxLength?: number, homograph?: object}} [phishing]
 * @property {{ip?: string[], domain?: string[]}} [dnsbl] - DNS blocklist zones
 * @property {{servers?: string[]|null, timeout?: number, resolve4?: (name: string, servers?: string[]|null) => Promise<string[]>}} [dns]
 * @property {boolean} [attachments]
 * @property {boolean} [macros] - flag macros, active PDFs and RTF objects
 * @property {boolean} [arbitrary]
 * @property {boolean|object} [authentication] - SPF, DKIM, DMARC and ARC (see authenticate())
 * @property {false|ReputationOptions} [reputation]
 * @property {string[]} [allowlist] - IPs and hostnames of clients, and authenticated sender domains and addresses, always accepted
 * @property {string[]} [denylist] - IPs, domains and addresses always rejected
 * @property {boolean|{socket?: string, host?: string, port?: number, timeout?: number}} [clamav] - timeout: milliseconds for all of a message's attachments (60000)
 * @property {object|null} [llm] - see LLMClassifier
 * @property {false|{model: {classify: Function}, threshold?: number}} [toxicity]
 * @property {false|{model: {classify: Function}, threshold?: number}} [nsfw]
 * @property {number} [maxLength] - characters of body text read (100000)
 * @property {number} [timeout] - milliseconds allowed for each network check (10000)
 * @property {SmtpSession} [session]
 */

/**
 * @typedef {SpamScannerOptions & {authenticationResults?: object}} ScanOptions
 */

/**
 * @typedef {object} ScanTest
 * @property {string} name
 * @property {number} score
 * @property {string} description
 */

/**
 * @typedef {object} ScanFinding - a detection; converts to its message
 * @property {string} type
 * @property {string} message
 */

/**
 * @typedef {object} ReputationAnswer - a reputation service's answer for one value
 * @property {boolean} isTruthSource
 * @property {string|null} truthSourceValue
 * @property {boolean} isAllowlisted
 * @property {string|null} allowlistValue
 * @property {boolean} isDenylisted
 * @property {string|null} denylistValue
 * @property {string} [error] - why the service could not be asked
 */

/**
 * @typedef {object} ReputationResult
 * @property {boolean} isTruthSource
 * @property {string|null} truthSourceValue
 * @property {boolean} isAllowlisted
 * @property {string|null} allowlistValue
 * @property {boolean} isDenylisted
 * @property {string|null} denylistValue
 * @property {string[]} checkedValues - the values looked up
 * @property {Record<string, ReputationAnswer>} details - the service's answer per value
 * @property {Record<string, string>} allowlisted - each value on the allowlist, with its entry
 */

/**
 * @typedef {object} ScanDetails
 * @property {{category: string, probability: number, spam: number, ham: number, clues: Array<{feature: string, probability: number}>, coverage?: {feature: string|null, spam: number, ham: number, confidence: number}}} classification - coverage: how well the training data covers the message's language (absent when the classifier is off)
 * @property {string|null} parseError - the MIME parser's limit (more than 1000 parts, or a part's header over 1 MB) the message or a message attached to it exceeds, so that it was not read whole, or why an attached message could not be read (MIME_TOO_COMPLEX), or null
 * @property {ScanFinding[]} phishing
 * @property {ScanFinding[]} attachments
 * @property {ScanFinding[]} viruses
 * @property {ScanFinding[]} arbitrary - rules that decide on their own
 * @property {{invisible: number, mixed: number, styled: boolean}} obfuscation
 * @property {object|null} authentication - SPF, DKIM, DMARC and ARC results
 * @property {ReputationResult|null} reputation
 * @property {Array<{zone: string, value: string, answers: string[]}>} dnsbl
 * @property {{language: string|null, script: string|null, notAllowed: boolean}} language
 * @property {ScanFinding[]} toxicity
 * @property {ScanFinding[]} nsfw
 * @property {object|null} llm - the language model's verdict
 * @property {ScanFinding[]} executables
 * @property {ScanFinding[]} macros
 * @property {number} uncheckedHosts - link hosts beyond phishing.maxHosts, not looked up
 * @property {number} timedOutHosts - link hosts looked up but not answered
 * @property {Array<{filename: string, error: string}>} virusScanErrors - attachments clamd could not scan
 * @property {Array<{filename: string, reason: string}>} virusScanSkipped - attachments larger than clamd accepts (StreamMaxLength), not scanned
 * @property {boolean} linksTruncated - whether text beyond phishing.maxLength was not read for links
 * @property {{detected: boolean, domains: ScanFinding[], riskScore: number}} idnHomographAttack
 */

/**
 * @typedef {object} ScanResult
 * @property {boolean} isSpam
 * @property {number} score
 * @property {number} threshold
 * @property {number} rejectThreshold
 * @property {'accept'|'tag'|'reject'} action
 * @property {string} message
 * @property {ScanTest[]} tests
 * @property {ScanDetails} results
 * @property {string[]} links
 * @property {string|null} language
 * @property {string[]} tokens
 * @property {object} mail - the message parsed by mailparser
 * @property {string} version
 * @property {{totalTime: number}} metrics
 */

function mergeLegacyOptions(input) {
	const options = defined(input);
	for (const key of NESTED) {
		if (options[key] !== undefined) {
			options[key] = defined(options[key]);
		}
	}

	const config = {...options};
	// Options of earlier versions.
	if (options.enableAuthentication !== undefined && config.authentication === undefined) {
		// (without the client's details, which go to the session: there a
		//  scan's own session replaces them)
		const {ip, helo, sender, hostname, ...authOptions} = options.authOptions || {};
		config.authentication = options.enableAuthentication ? authOptions : false;
	}

	if (options.authOptions) {
		const {ip, helo, sender, hostname} = options.authOptions;
		config.session = {
			...(ip ? {remoteAddress: ip} : {}),
			...(helo ? {helo} : {}),
			...(hostname ? {resolvedClientHostname: hostname} : {}),
			...(sender ? {envelope: {mailFrom: {address: sender}, rcptTo: []}} : {}),
			...options.session,
		};
	}

	if (options.enableReputation && options.reputationOptions?.apiUrl && config.reputation === undefined) {
		config.reputation = {apiUrl: options.reputationOptions.apiUrl, timeout: options.reputationOptions.timeout};
	}

	if (options.enableMacroDetection === false || options.enableArbitraryDetection === false) {
		if (options.enableArbitraryDetection === false) {
			config.arbitrary = false;
		}

		if (options.enableMacroDetection === false) {
			config.macros = false;
		}
	}

	if (options.strictIDNDetection) {
		config.phishing = {...options.phishing, homograph: {...options.phishing?.homograph, strictMode: true}};
	}

	if (options.clamscan !== undefined && config.clamav === undefined) {
		const {clamscan} = options;
		// (the clamscan package's options: clamdscan {socket, host, port}, or
		//  the same at the top)
		const daemon = {...clamscan, ...clamscan?.clamdscan};
		config.clamav = typeof clamscan === 'object' && clamscan ? {socket: daemon.socket, host: daemon.host, port: daemon.port} : Boolean(clamscan);
	}

	if (options.allowlist || options.denylist) {
		config.reputation = {
			...(typeof config.reputation === 'object' ? config.reputation : {}), ...(options.allowlist ? {allowlist: options.allowlist} : {}), ...(options.denylist ? {denylist: options.denylist} : {}),
		};
	}

	return config;
}

// The most hosts of a message checked for lookalikes (links first).
const MAX_LOOKALIKE_HOSTS = 1000;
// At most this many deceptive links are reported for a message (one is enough
// to score it)
const MAX_DECEPTIVE_LINKS = 50;
// Attachments sent to clamd at the same time, and milliseconds for all of a
// message's attachments (clamav.timeout).
const CLAMAV_CONCURRENCY = 4;
const CLAMAV_TIMEOUT = 60_000;
// The reply of clamd for a file larger than it accepts (StreamMaxLength),
// which it gives on every try, as clamav-milter skips a file over its
// MaxFileSize. Others, its scan limits too (MaxScanSize, MaxFiles,
// MaxRecursion, MaxScanTime, which an archive bomb reaches), are failures.
const CLAMAV_LIMITS = /size limit exceeded/i;
// Images classified by the NSFW model, at most.
const MAX_NSFW_IMAGES = 10;

// Reputation services whose answers a scanner keeps (the most recently used).
const MAX_REPUTATION_CACHES = 100;

/**
 * A reputation checker sharing the scanner's answers from the same service
 * (URL and headers). The size of the shared cache is the one it was made
 * with, so a cacheSize given for one message does not shrink it.
 * @param {SpamScanner} scanner
 * @param {object} settings - ReputationChecker options
 * @returns {ReputationChecker}
 */
function sharedReputationChecker(scanner, settings) {
	const key = JSON.stringify([settings.apiUrl, settings.headers]);
	const shared = scanner.reputationCaches.get(key) || {cache: new Map(), cacheSize: settings.cacheSize};
	// (most recently used last; the least recently used goes first)
	scanner.reputationCaches.delete(key);
	scanner.reputationCaches.set(key, shared);
	if (scanner.reputationCaches.size > MAX_REPUTATION_CACHES) {
		scanner.reputationCaches.delete(scanner.reputationCaches.keys().next().value);
	}

	return new ReputationChecker({...settings, cache: shared.cache, cacheSize: shared.cacheSize});
}

// The domain of a message's (first) From address, or "" for none.
function fromDomain(mail) {
	const address = mail.from?.value?.[0]?.address;
	const at = typeof address === 'string' ? address.lastIndexOf('@') : -1;
	return at === -1 ? '' : address.slice(at + 1).toLowerCase();
}

// A message to parse from raw input: text whose first line is not a header
// field ("Name: value", or an mbox "From " line) as the body of a message
// with no header, so its text is the input, as parse(), learn() and scan()
// all read it.
function withHeader(raw) {
	const first = raw.subarray(0, 1000).toString('latin1');
	const headerless = raw.length > 0 && !/^(?:[!-9;-~]+[ \t]*:|From |[\r\n])/.test(first);
	return headerless ? Buffer.concat([Buffer.from('\r\n'), raw]) : raw;
}

/**
 * Spam Scanner: scores a message for spam, phishing, scams and malware.
 *
 * @example
 * const scanner = new SpamScanner();
 * const result = await scanner.scan(rawMessage, {session: {remoteAddress: '192.0.2.1'}});
 * if (result.isSpam) console.log(result.score, result.tests);
 */
export class SpamScanner {
	/**
	 * @param {SpamScannerOptions} [options] - see DEFAULTS
	 */
	constructor(options = {}) {
		const merged = mergeLegacyOptions(options);
		this.config = {
			...DEFAULTS,
			...merged,
			phishing: {...DEFAULTS.phishing, ...merged.phishing},
			dnsbl: {...DEFAULTS.dnsbl, ...merged.dnsbl},
			dns: {...DEFAULTS.dns, ...merged.dns},
		};
		this.classifier = null;
		// (a model file or object is read now, so a missing or damaged model
		//  stops the scanner from starting rather than failing every scan)
		if (typeof this.config.classifier === 'string' || (this.config.classifier && typeof this.config.classifier === 'object')) {
			this.getClassifier();
		}

		this.homograph = new HomographDetector(this.config.phishing.homograph);
		this.dns = new DnsChecker({servers: this.config.dns.servers, timeout: this.config.dns.timeout, resolve4: this.config.dns.resolve4});
		// (the answers of each reputation service, failures too, kept for every
		//  checker of it: lists given for one message keep what is known)
		this.reputationCaches = new Map();
		this.reputation = this.config.reputation ? sharedReputationChecker(this, this.config.reputation) : null;
		this.llm = this.config.llm ? new LLMClassifier(this.config.llm) : null;
		this.llms = new WeakMap();
		this.metrics = {totalScans: 0, averageTime: 0, lastScanTime: 0};
		for (const name of ['toxicity', 'nsfw']) {
			const setting = this.config[name];
			if (setting && typeof setting.model?.classify !== 'function') {
				throw new TypeError(`The ${name} check needs { model } with a classify() method; see https://spamscanner.net/docs/api/#${name}`);
			}
		}
	}

	/**
	 * The classifier, loaded on first use.
	 * @returns {Classifier|null}
	 */
	getClassifier() {
		if (this.classifier || this.config.classifier === false) {
			return this.classifier;
		}

		const setting = this.config.classifier;
		if (setting instanceof Classifier) {
			this.classifier = setting;
		} else if (typeof setting === 'string') {
			this.classifier = loadModel(setting, this.config.classifierOptions);
		} else if (setting && typeof setting === 'object') {
			this.classifier = Classifier.fromJSON(setting, this.config.classifierOptions);
		} else {
			this.classifier = loadDefaultModel(this.config.classifierOptions);
		}

		return this.classifier;
	}

	/**
	 * Parse a raw message with mailparser, as scan() does: a message beyond
	 * the parser's limits (more than 1000 MIME parts, a part's header over
	 * 1 MB) is read for what can be read of it. Text whose first line is not
	 * a header field ("Name: value", or an mbox "From " line) is read as the
	 * body of a message with no header, so its text is the input; other
	 * input mailparser cannot read gives a message with no text. Other errors
	 * are thrown.
	 * @param {Buffer|string|Uint8Array|AsyncIterable} source
	 * @returns {Promise<{raw: Buffer, mail: object}>}
	 */
	async parse(source) {
		const raw = await toBuffer(source);
		const {mail} = await parseWithin(withHeader(raw));
		return {raw, mail};
	}

	/**
	 * Classifier features of a parsed message.
	 * @param {object} mail
	 * @returns {ReturnType<typeof getFeatures>}
	 */
	getFeatures(mail) {
		return getFeatures(mail, {maxLength: this.config.maxLength});
	}

	/**
	 * Words of a text in any language, normalized (see segmentWords). Useful
	 * for search indexes.
	 * @param {string} text
	 * @param {string} [locale]
	 * @returns {string[]}
	 */
	getTokens(text, locale) {
		return segmentWords(text, {locale, maxLength: this.config.maxLength}).words;
	}

	/**
	 * Parse a message and return its words and parsed form, as earlier
	 * versions did.
	 * @param {Buffer|string} source
	 * @returns {Promise<{tokens: string[], features: string[], mail: object}>}
	 */
	async getTokensAndMailFromSource(source) {
		const {mail} = await this.parse(source);
		const {words, features} = this.getFeatures(mail);
		return {tokens: words, features, mail};
	}

	/**
	 * Classify features with the classifier.
	 * @param {string[]} features
	 * @returns {object} probability, category (spam, ham, unsure or disabled) and the strongest clues
	 */
	getClassification(features) {
		const classifier = this.getClassifier();
		if (!classifier) {
			return {
				category: 'disabled', probability: 0.5, spam: 0.5, ham: 0.5, clues: [],
			};
		}

		return classifier.classify(features);
	}

	/**
	 * Teach the classifier one message.
	 * @param {Buffer|string} source
	 * @param {'spam'|'ham'} category
	 * @returns {Promise<void>}
	 */
	async learn(source, category) {
		const {mail} = await this.parse(source);
		if (!this.getClassifier()) {
			// The classifier was turned off: learning starts a new one.
			this.classifier = new Classifier(this.config.classifierOptions);
		}

		this.classifier.learn(this.getFeatures(mail).features, category);
	}

	/**
	 * Undo learn() for a message.
	 * @param {Buffer|string} source
	 * @param {'spam'|'ham'} category
	 * @returns {Promise<void>}
	 */
	async unlearn(source, category) {
		const {mail} = await this.parse(source);
		const classifier = this.getClassifier();
		if (classifier) {
			classifier.unlearn(this.getFeatures(mail).features, category);
		}
	}

	/**
	 * Save the classifier, with everything it learned, to a file.
	 * @param {string} file
	 * @param {object} [options] - see Classifier#toJSON
	 */
	saveModel(file, options) {
		const classifier = this.getClassifier() || new Classifier(this.config.classifierOptions);
		saveModel(classifier, file, options);
	}

	/**
	 * Scan a message file.
	 * @param {string} file
	 * @param {ScanOptions} [options] - as for scan()
	 * @returns {Promise<ScanResult>}
	 */
	async scanFile(file, options) {
		return this.scan(await readFile(file), options);
	}

	async checkLinks(links, config, hosts = [], from = '') {
		const phishing = [];
		const homographs = [];
		const seenHosts = new Set();
		const analysed = new Set();
		const lookalike = (host, extra) => {
			// (at most MAX_LOOKALIKE_HOSTS hosts a message: each takes up to
			// about a millisecond)
			if (analysed.has(host) || analysed.size >= MAX_LOOKALIKE_HOSTS) {
				return;
			}

			analysed.add(host);
			const analysis = this.homograph.detectHomographAttack(host);
			// (a host only named in the text counts when it is plainly an
			// imitation of a brand of five letters or more: a reply or a
			// signature may name any site, a brand's other domains, or a
			// company whose short name reads like a brand with a digit for a
			// letter, such as "lrs.com" for irs)
			const counts = extra.source === 'text'
				? analysis.riskScore >= 0.95 || (analysis.riskScore >= 0.85 && analysis.brand.length >= 5)
				: analysis.riskScore >= 0.5;
			if (counts) {
				const item = finding({
					type: 'homograph',
					...extra,
					domain: analysis.domain,
					unicode: analysis.unicode,
					brand: analysis.brand,
					riskScore: analysis.riskScore,
					riskFactors: analysis.riskFactors,
					mixedScripts: analysis.riskFactors.some(factor => factor.includes(' mixes ')),
					message: analysis.riskFactors.at(-1),
				});
				phishing.push(item);
				homographs.push(item);
			}
		};

		// (a link through a security gateway, Safe Links or Proofpoint, by the
		//  address it goes on to,
		//  written as link hosts are: without a final dot or IPv6 brackets)
		const destination = link => unwrapLink(link.url)?.hostname.toLowerCase().replace(/\.$/, '').replace(/^\[(.*)]$/, '$1') || link.host;
		let deceptive = 0;
		for (const link of links) {
			// (a link through click tracking counts by who sent it: see isDeceptiveLink)
			if (deceptive < MAX_DECEPTIVE_LINKS && isDeceptiveLink(link, {from})) {
				deceptive++;
				phishing.push(finding({
					type: 'deceptive_link', url: link.url, text: link.text, message: `A link shows "${link.text}" but goes to ${link.host}`,
				}));
			}

			// (by the host looked up: a gateway's own host is not)
			seenHosts.add(destination(link));
		}

		// (links before hosts in the text, and links that show an address
		// first: a message cannot put a link out of reach with text, or the
		// hosts it shows with other links)
		for (const link of [...links.filter(link => link.text), ...links.filter(link => !link.text)]) {
			lookalike(destination(link), {url: link.url});
		}

		// Host names in the text that are not links (written without
		// "http://", or in an email address) are checked for lookalikes only:
		// a quoted reply or a signature may name any site, so they are not
		// looked up.
		for (const host of hosts) {
			lookalike(host, {source: 'text'});
		}

		// The hosts looked up, in the order of the lookalike pass, the first
		// host of each registrable domain before the others: a message cannot
		// put a link out of reach with links to other hosts of one domain.
		const ordered = [...new Set([...links.filter(link => link.text), ...links.filter(link => !link.text)].map(link => destination(link)))];
		const firsts = new Map();
		for (const host of ordered) {
			const domain = registrableDomain(host);
			if (!firsts.has(domain)) {
				firsts.set(domain, host);
			}
		}

		const checked = [...new Set([...firsts.values(), ...ordered])].slice(0, config.phishing.maxHosts);
		const domains = [...new Set(checked.map(host => registrableDomain(host)))];
		// Each host is looked up on its own, and what was found by the time
		// limit is kept (a slow answer for one host does not lose the others);
		// the hosts without an answer by then (or whose lookup failed) are
		// counted.
		const blocked = [];
		let answered = 0;
		const cloudflare = async () => {
			await withTimeout(Promise.all(checked.map(async host => {
				const found = await this.dns.checkCloudflare([host], {adult: config.phishing.adult});
				blocked.push(...found);
				if (!found.unanswered?.length) {
					answered++;
				}
			})), config.timeout, null);
			// (copies taken at once: an answer that comes later is not added
			//  after the fact)
			return {found: [...blocked], unanswered: checked.length - answered};
		};

		const [cloudflareResult, listed] = await Promise.all([
			config.phishing.cloudflare && checked.length > 0 ? cloudflare() : {found: [], unanswered: 0},
			config.dnsbl.domain?.length > 0 && domains.length > 0 ? withTimeout(this.dns.checkDomains(domains, config.dnsbl.domain), config.timeout, []) : [],
		]);
		for (const {host, category} of cloudflareResult.found) {
			phishing.push(finding(category === 'malware'
				? {type: 'malicious_domain', domain: host, message: `Link hostname ${host} is blocked by Cloudflare's malware filtering as phishing or malware`}
				: {type: 'adult_domain', domain: host, message: `Link hostname ${host} was detected by Cloudflare's family filtering to contain adult-related content`}));
		}

		for (const {zone, value} of listed) {
			phishing.push(finding({
				type: 'uribl', domain: value, zone, message: `Link domain ${value} is listed in ${zone}`,
			}));
		}

		return {
			phishing, homographs, uncheckedHosts: seenHosts.size - checked.length, timedOutHosts: cloudflareResult.unanswered,
		};
	}

	/**
	 * Scan attachments with clamd, a few at a time, all within clamav.timeout
	 * (60 seconds). A connection refused or a busy clamd (EAGAIN) is tried
	 * once more.
	 * @param {Array<object>} attachments
	 * @param {object} config
	 * @returns {Promise<{viruses: object[], errors: Array<{filename: string, error: string}>, skipped: Array<{filename: string, reason: string}>}>}
	 */
	async scanViruses(attachments, config) {
		const settings = config.clamav === true ? {} : config.clamav;
		// (ClamAV has its own time limit for all of a message's attachments,
		//  not the network checks': a slow clamd would otherwise defer the
		//  message on every try)
		const budget = settings.timeout ?? CLAMAV_TIMEOUT;
		const deadline = Date.now() + budget;
		const viruses = [];
		const errors = [];
		const skipped = [];
		const carriers = new Map();
		const queue = [...attachments];
		const scan = async (attachment, retry) => {
			try {
				return await scanBuffer(attachment.content, {...settings, timeout: Math.max(1, deadline - Date.now())});
			} catch (error) {
				if (retry && ['EAGAIN', 'ECONNREFUSED'].includes(error.code) && deadline > Date.now()) {
					return scan(attachment, false);
				}

				throw error;
			}
		};

		const worker = async () => {
			while (queue.length > 0) {
				const attachment = queue.shift();
				const filename = attachment.filename || 'unnamed attachment';
				if (deadline <= Date.now()) {
					errors.push({filename, error: `not scanned within ${budget} ms`});
					continue;
				}

				try {
					// eslint-disable-next-line no-await-in-loop
					const result = await scan(attachment, true);
					if (result.infected) {
						const found = finding({
							type: 'virus', filename, virus: result.viruses, message: `Attachment "${filename}" contains ${result.viruses.join(', ')}`,
						});
						viruses.push(found);
						// (an attached message: its attachments are named after it,
						//  as expandAttachments names them)
						if (attachment.contentType === 'message/rfc822' || /\.eml$/i.test(attachment.filename || '')) {
							carriers.set(found, attachment.filename || 'attached message');
						}
					}
				} catch (error) {
					debug('virus scan failed: %s', error.message);
					// (an attachment larger than clamd accepts is not scanned, as
					//  clamav-milter skips one over its MaxFileSize: the same on
					//  every try, it is not a failure to try again)
					if (CLAMAV_LIMITS.test(error.message)) {
						skipped.push({filename, reason: error.message.replace(/^clamd: (?:stream: )?/, '')});
					} else {
						errors.push({filename, error: error.message});
					}
				}
			}
		};

		await Promise.all(Array.from({length: Math.min(CLAMAV_CONCURRENCY, attachments.length)}, () => worker()));
		// (clamd finds a virus in an attached message, which it reads, and
		//  again in the attachment of it that carries the virus: only that one
		//  is reported)
		const reported = viruses.filter(item => {
			const prefix = carriers.get(item);
			if (prefix === undefined) {
				return true;
			}

			const inner = new Set(viruses.filter(other => other.filename.startsWith(`${prefix}/`)).flatMap(other => other.virus));
			return !item.virus.every(name => inner.has(name));
		});
		return {viruses: reported, errors, skipped};
	}

	async scanToxicity(mail, config, shown = mail.text) {
		const {model, threshold = 0.7} = config.toxicity;
		const text = [mail.subject, shown].filter(Boolean).join('\n').slice(0, 5000);
		if (text.trim().length < 10) {
			return [];
		}

		try {
			const predictions = await withTimeout(Promise.resolve(model.classify([text])), config.timeout, []);
			return predictions
				.map(prediction => ({label: prediction.label, probability: prediction.results?.[0]?.probabilities?.[1] ?? 0}))
				.filter(prediction => prediction.probability >= threshold)
				.map(prediction => finding({
					type: 'toxicity', category: prediction.label, probability: prediction.probability, message: `Toxic content: ${prediction.label} (${(prediction.probability * 100).toFixed(1)}%)`,
				}));
		} catch (error) {
			debug('toxicity check failed: %s', error.message);
			return [];
		}
	}

	async scanNsfw(attachments, config) {
		const {model, threshold = 0.6} = config.nsfw;
		// (the first images only, all within one time limit)
		const images = attachments.filter(attachment => ['png', 'jpg', 'gif', 'webp'].includes(sniff(attachment.content)?.type)).slice(0, MAX_NSFW_IMAGES);
		const deadline = Date.now() + config.timeout;
		const results = [];
		for (const image of images) {
			const left = deadline - Date.now();
			if (left <= 0) {
				break;
			}

			try {
				// eslint-disable-next-line no-await-in-loop
				const predictions = await withTimeout(Promise.resolve(model.classify(image.content)), left, []);
				const hit = predictions.find(prediction => ['Porn', 'Hentai', 'Sexy'].includes(prediction.className) && prediction.probability >= threshold);
				if (hit) {
					results.push(finding({
						type: 'nsfw', filename: image.filename || 'unnamed image', category: hit.className, probability: hit.probability, message: `Image "${image.filename || 'unnamed image'}" looks like ${hit.className.toLowerCase()} content (${(hit.probability * 100).toFixed(1)}%)`,
					}));
				}
			} catch (error) {
				debug('NSFW check failed: %s', error.message);
			}
		}

		return results;
	}

	/**
	 * Scan a message.
	 *
	 * @param {Buffer|string|Uint8Array|AsyncIterable} source - the raw message
	 * @param {ScanOptions} [options] - settings for this message only (see DEFAULTS), plus:
	 * @param {object} [options.session] - what the receiving server knows:
	 *   remoteAddress (client IP), resolvedClientHostname (verified reverse
	 *   DNS), helo, and envelope { mailFrom: {address}, rcptTo: [{address}] }
	 * @param {object} [options.authenticationResults] - SPF, DKIM, DMARC and
	 *   ARC results the receiving server already has, as mailauth's
	 *   authenticate() gives them ({spf, dkim: {results}, dmarc, arc}): scored
	 *   as if checked here, without checking again
	 * @returns {Promise<ScanResult>} isSpam, score, threshold, action
	 *   ("accept", "tag" or "reject"), message, tests, results (per detector),
	 *   links, language, tokens, mail and metrics
	 */
	async scan(source, options = {}) {
		const started = Date.now();
		const extra = mergeLegacyOptions(options);
		const config = {
			...this.config,
			...extra,
			phishing: {...this.config.phishing, ...extra.phishing},
			dnsbl: {...this.config.dnsbl, ...extra.dnsbl},
			session: {...this.config.session, ...extra.session},
		};
		const {session} = config;
		// (lists or a service given for this message: a checker for it, with
		//  the scanner's settings for what is not given)
		const reputationChecker = Object.hasOwn(extra, 'reputation')
			? (extra.reputation ? sharedReputationChecker(this, {...this.config.reputation, ...extra.reputation}) : null)
			: this.reputation;
		const raw = await toBuffer(source);
		// (a message beyond the parser's limits is read for its first parts,
		//  and gets MIME_TOO_COMPLEX)
		const parsed = await parseWithin(withHeader(raw));
		const {mail} = parsed;
		const parseErrors = parsed.error ? [parsed.error] : [];
		const extracted = getFeatures(mail, {maxLength: config.maxLength});
		const classification = this.getClassification(extracted.features);
		// (the links checked: those of the whole message, up to
		//  phishing.maxLength, not only of what the classifier reads)
		const linkLength = Number.isFinite(config.phishing.maxLength) && config.phishing.maxLength > 0 ? config.phishing.maxLength : 1_000_000;
		const text = typeof mail.text === 'string' ? mail.text : '';
		const html = typeof mail.html === 'string' ? mail.html : '';
		const checkedLinks = extractLinks(text.slice(0, linkLength), html.slice(0, linkLength * 2), {maxLength: linkLength * 2});
		const linksTruncated = text.length > linkLength || html.length > linkLength * 2;

		// Obfuscation seen by the tokenizer.
		// (of the text the HTML shows and of the plain text, the more of each:
		//  the HTML part always counts, and an alternative part, the same text
		//  again, is not counted twice)
		const plainObfuscation = obfuscationOf(`${mail.subject || ''}\n${typeof mail.text === 'string' ? mail.text : ''}`, {maxLength: config.maxLength});
		const shownObfuscation = obfuscationOf(`${mail.subject || ''}\n${visibleText(html.slice(0, config.maxLength * 2)).text}`, {maxLength: config.maxLength});
		const obfuscation = {
			invisible: Math.max(plainObfuscation.invisible, shownObfuscation.invisible),
			mixed: Math.max(plainObfuscation.mixed, shownObfuscation.mixed),
			styled: plainObfuscation.styled || shownObfuscation.styled,
		};

		// (with the attachments of attached messages)
		const attached = await expandAttachments(mail.attachments, parseErrors);
		const attachments = config.attachments === false ? [] : inspectAttachments(attached).filter(item => config.macros !== false || !['macro', 'pdf_active', 'rtf_object'].includes(item.type)).map(item => finding(item));

		const [links, authentication, checkedReputation, dnsbl, virusScan, toxicity, nsfw] = await Promise.all([
			this.checkLinks(checkedLinks, config, extracted.hosts, fromDomain(mail)),
			config.authenticationResults && typeof config.authenticationResults === 'object'
				? normalizeAuthOutput(config.authenticationResults)
				: (config.authentication && session.remoteAddress
					// (the client is always the scan's: settings never name it)
					? withTimeout(authenticate(raw, {
						timeout: config.timeout, ...(typeof config.authentication === 'object' ? config.authentication : {}), ip: session.remoteAddress, helo: session.helo, sender: session.envelope?.mailFrom?.address,
					}), config.timeout, null)
					: null),
			reputationChecker ? withTimeout(reputationChecker.check(reputationValues(mail, session)), config.timeout, null) : null,
			session.remoteAddress && config.dnsbl.ip?.length > 0 ? withTimeout(this.dns.checkIp(session.remoteAddress, config.dnsbl.ip), config.timeout, []) : [],
			// (clamd reads a message it cannot be given in parts whole)
			config.clamav ? this.scanViruses(parsed.error ? [{filename: 'message.eml', contentType: 'message/rfc822', content: raw}] : attached, config) : {viruses: [], errors: [], skipped: []},
			// (the text a mail client shows, of the HTML too)
			config.toxicity ? this.scanToxicity(mail, config, extracted.text) : [],
			config.nsfw ? this.scanNsfw(attached, config) : [],
		]);
		const {viruses} = virusScan;
		// (only what cannot be forged allowlists a message: the client, and
		//  sender addresses that authentication shows are genuine)
		const reputation = checkedReputation && trustReputation(checkedReputation, trustedReputationValues(mail, session, authentication));

		if (authentication) {
			authentication.score = calculateAuthScore(authentication, typeof config.authentication === 'object' ? config.authentication.weights : undefined);
		}

		const arbitrary = config.arbitrary === false ? {rules: [], score: 0, reasons: []} : isArbitrary(mail, {session, authentication});
		// ("en-US" and "eng" are English too)
		const allowed = (config.allowedLanguages || []).map(code => normalizeLanguageCode(code)).filter(Boolean);
		const language = {
			language: extracted.language,
			script: extracted.script,
			notAllowed: Boolean(allowed.length > 0 && extracted.language && !allowed.includes(extracted.language)),
		};

		const results = {
			// Limits of the MIME parser the message or a message attached to it
			// exceeds, or why an attached message could not be read (it was not
			// read whole), or null.
			parseError: parseErrors.length > 0 ? [...new Set(parseErrors)].join('; ') : null,
			classification,
			phishing: links.phishing,
			attachments,
			viruses,
			arbitrary,
			obfuscation,
			authentication,
			reputation,
			dnsbl,
			language,
			toxicity,
			nsfw,
			llm: null,
		};
		const scoring = {scores: config.scores, threshold: config.threshold, rejectThreshold: config.rejectThreshold};
		let scored = scoreResults(results, scoring);

		// Ask the language model when the decision is close or the classifier unsure.
		// (`llm: false` or `null` for a scan asks no model; other settings than
		//  the scanner's get their own client, kept for the next scan with them)
		let {llm} = this;
		if (config.llm === false || config.llm === null) {
			llm = null;
		} else if (config.llm && config.llm !== this.config.llm) {
			if (!this.llms.has(config.llm)) {
				this.llms.set(config.llm, new LLMClassifier(config.llm));
			}

			llm = this.llms.get(config.llm);
		}

		if (llm) {
			const settings = config.llm;
			const mode = String(settings.mode || 'auto').toLowerCase();
			const low = settings.minScore ?? config.threshold - 4;
			const high = settings.maxScore ?? config.rejectThreshold;
			const close = scored.score >= low && scored.score < high;
			if (mode === 'always' || (mode === 'auto' && (close || classification.category === 'unsure' || classification.category === 'disabled'))) {
				try {
					results.llm = await llm.classify(mail, {
						links: extracted.links, text: extracted.text, hidden: extracted.hidden, authentication: authentication ? summarizeAuth(authentication) : null,
					});
				} catch (error) {
					debug('LLM check failed: %s', error.message);
					results.llm = {
						verdict: null, error: error.message, provider: llm.config.provider, model: llm.config.model,
					};
				}

				scored = scoreResults(results, scoring);
			}
		}

		const reasons = scored.tests.filter(test => test.score > 0).sort((a, b) => b.score - a.score).map(test => test.name);
		const time = Date.now() - started;
		this.metrics.totalScans++;
		this.metrics.lastScanTime = time;
		this.metrics.averageTime += (time - this.metrics.averageTime) / this.metrics.totalScans;

		return {
			isSpam: scored.isSpam,
			score: scored.score,
			threshold: scored.threshold,
			rejectThreshold: scored.rejectThreshold,
			action: scored.action,
			message: scored.isSpam ? `Spam (${reasons.slice(0, 5).join(', ')})` : 'Ham',
			tests: scored.tests,
			results: {
				...results,
				// Rules that decide on their own (GTUBE, sextortion, PayPal invoice spam,
				// Microsoft's verdict); the others count only toward the score.
				arbitrary: arbitrary.rules.filter(rule => rule.score >= config.threshold).map(rule => finding({type: 'arbitrary', ...rule})),
				// Grouped as in earlier versions.
				executables: attachments.filter(item => ['executable', 'disguised_executable', 'double_extension', 'rtl_override', 'executable_in_archive', 'script_in_archive'].includes(item.type)),
				macros: attachments.filter(item => ['macro', 'pdf_active', 'rtf_object'].includes(item.type)),
				// Link hosts beyond phishing.maxHosts, which were not looked up.
				uncheckedHosts: links.uncheckedHosts,
				// Link hosts looked up but not answered: no answer within the time
				// limit, or the lookup failed.
				timedOutHosts: links.timedOutHosts,
				// Attachments clamd could not scan (it was unreachable, busy, or
				// refused the file, or the time limit was reached), as
				// {filename, error}: a message with any may hold a virus.
				virusScanErrors: virusScan.errors,
				// Attachments larger than clamd accepts (StreamMaxLength), not
				// scanned, as {filename, reason}: the same on every try, so not a
				// failure.
				virusScanSkipped: virusScan.skipped,
				// Whether the message has more text than phishing.maxLength, whose
				// links were not read.
				linksTruncated,
				idnHomographAttack: {
					detected: links.homographs.length > 0,
					domains: links.homographs,
					riskScore: Math.max(0, ...links.homographs.map(item => item.riskScore)),
				},
			},
			links: checkedLinks.map(link => link.url),
			language: extracted.language,
			tokens: extracted.words,
			mail,
			version: VERSION,
			metrics: {totalTime: time},
		};
	}
}

export default SpamScanner;
export {Classifier} from './classifier.js';
export {getFeatures, segmentWords} from './tokenizer.js';
export {detectLanguage} from './language.js';
export {LLMClassifier, PROVIDERS} from './llm.js';
export {DEFAULT_SCORES, scoreResults} from './score.js';
export {spamHeaders, rewriteMessage} from './headers.js';
export {
	loadModel, saveModel, defaultModelPath, loadDefaultModel,
} from './model.js';
export {train, evaluate, readExamples} from './train.js';
export {MilterServer} from './milter.js';
export {createHttpServer, createTcpServer} from './server.js';
export {createSpamdServer} from './spamd.js';
export {RECOMMENDED_MODELS, CLASSIFIER_MODELS, DECISION_MODELS} from './models.js';
export {VERSION} from './version.js';
