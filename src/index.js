import {Buffer} from 'node:buffer';
import {readFile} from 'node:fs/promises';
import {debuglog} from 'node:util';
import {simpleParser} from 'mailparser';
import {inspectAttachments, sniff} from './attachments.js';
import {authenticate, calculateAuthScore, summarizeAuth} from './auth.js';
import {scanBuffer} from './clamav.js';
import {Classifier} from './classifier.js';
import {DnsChecker} from './dnsbl.js';
import HomographDetector from './homograph.js';
import {isArbitrary} from './is-arbitrary.js';
import {LLMClassifier} from './llm.js';
import {loadDefaultModel, loadModel, saveModel} from './model.js';
import {ReputationChecker, reputationValues} from './reputation.js';
import {scoreResults} from './score.js';
import {
	getFeatures, isDeceptiveLink, registrableDomain, segmentWords,
} from './tokenizer.js';
import {VERSION} from './version.js';

const debug = debuglog('spamscanner');

const PARSER_OPTIONS = {skipImageLinks: true, skipTextToHtml: true, skipTextLinks: true};

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

function mergeLegacyOptions(options) {
	const config = {...options};
	// Options of earlier versions.
	if (options.enableAuthentication !== undefined && config.authentication === undefined) {
		config.authentication = options.enableAuthentication ? {...options.authOptions} : false;
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
		config.clamav = typeof clamscan === 'object' && clamscan ? {socket: clamscan.clamdscan?.socket || clamscan.socket, host: clamscan.clamdscan?.host, port: clamscan.clamdscan?.port} : Boolean(clamscan);
	}

	if (options.allowlist || options.denylist) {
		config.reputation = {...(typeof config.reputation === 'object' ? config.reputation : {}), allowlist: options.allowlist, denylist: options.denylist};
	}

	return config;
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
	 * @param {object} [options] - see DEFAULTS
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
		this.homograph = new HomographDetector(this.config.phishing.homograph);
		this.dns = new DnsChecker({servers: this.config.dns.servers, timeout: this.config.dns.timeout, resolve4: this.config.dns.resolve4});
		this.reputation = this.config.reputation ? new ReputationChecker(this.config.reputation) : null;
		this.llm = this.config.llm ? new LLMClassifier(this.config.llm) : null;
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
	 * Parse a raw message with mailparser. Unparseable input becomes a message
	 * whose text is the input.
	 * @param {Buffer|string|Uint8Array|AsyncIterable} source
	 * @returns {Promise<{raw: Buffer, mail: object}>}
	 */
	async parse(source) {
		const raw = await toBuffer(source);
		const mail = await simpleParser(raw, PARSER_OPTIONS);
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
	 * @param {object} [options] - as for scan()
	 * @returns {ReturnType<SpamScanner['scan']>}
	 */
	async scanFile(file, options) {
		return this.scan(await readFile(file), options);
	}

	async checkLinks(links, config) {
		const phishing = [];
		const homographs = [];
		const seenHosts = new Set();
		for (const link of links) {
			if (isDeceptiveLink(link)) {
				phishing.push(finding({
					type: 'deceptive_link', url: link.url, text: link.text, message: `A link shows "${link.text}" but goes to ${link.host}`,
				}));
			}

			if (seenHosts.has(link.host)) {
				continue;
			}

			seenHosts.add(link.host);
			const analysis = this.homograph.detectHomographAttack(link.host);
			if (analysis.riskScore >= 0.5) {
				const item = finding({
					type: 'homograph',
					url: link.url,
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
		}

		const hosts = [...seenHosts].slice(0, config.phishing.maxHosts);
		const domains = [...new Set(hosts.map(host => registrableDomain(host)))];
		const [blocked, listed] = await Promise.all([
			config.phishing.cloudflare && hosts.length > 0 ? withTimeout(this.dns.checkCloudflare(hosts, {adult: config.phishing.adult}), config.timeout, []) : [],
			config.dnsbl.domain?.length > 0 && domains.length > 0 ? withTimeout(this.dns.checkDomains(domains, config.dnsbl.domain), config.timeout, []) : [],
		]);
		for (const {host, category} of blocked) {
			phishing.push(finding(category === 'malware'
				? {type: 'malicious_domain', domain: host, message: `Link hostname ${host} is blocked by Cloudflare's malware filtering as phishing or malware`}
				: {type: 'adult_domain', domain: host, message: `Link hostname ${host} was detected by Cloudflare's family filtering to contain adult-related content`}));
		}

		for (const {zone, value} of listed) {
			phishing.push(finding({
				type: 'uribl', domain: value, zone, message: `Link domain ${value} is listed in ${zone}`,
			}));
		}

		return {phishing, homographs};
	}

	async scanViruses(mail, config) {
		const settings = config.clamav === true ? {} : config.clamav;
		const viruses = [];
		await Promise.all(mail.attachments.map(async attachment => {
			try {
				const result = await scanBuffer(attachment.content, {timeout: config.timeout, ...settings});
				if (result.infected) {
					viruses.push(finding({
						type: 'virus', filename: attachment.filename || 'unnamed attachment', virus: result.viruses, message: `Attachment "${attachment.filename || 'unnamed attachment'}" contains ${result.viruses.join(', ')}`,
					}));
				}
			} catch (error) {
				debug('virus scan failed: %s', error.message);
			}
		}));
		return viruses;
	}

	async scanToxicity(mail, config) {
		const {model, threshold = 0.7} = config.toxicity;
		const text = [mail.subject, mail.text].filter(Boolean).join('\n').slice(0, 5000);
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

	async scanNsfw(mail, config) {
		const {model, threshold = 0.6} = config.nsfw;
		const images = mail.attachments.filter(attachment => ['png', 'jpg', 'gif', 'webp'].includes(sniff(attachment.content)?.type));
		const results = [];
		for (const image of images) {
			try {
				// eslint-disable-next-line no-await-in-loop
				const predictions = await withTimeout(Promise.resolve(model.classify(image.content)), config.timeout, []);
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
	 * @param {object} [options] - settings for this message only (see DEFAULTS), plus:
	 * @param {object} [options.session] - what the receiving server knows:
	 *   remoteAddress (client IP), resolvedClientHostname (verified reverse
	 *   DNS), helo, and envelope { mailFrom: {address}, rcptTo: [{address}] }
	 * @returns {Promise<object>} isSpam, score, threshold, action ("accept",
	 *   "tag" or "reject"), message, tests, results (per detector), links,
	 *   language, tokens, mail and metrics
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
		const {raw, mail} = await this.parse(source);
		const extracted = this.getFeatures(mail);
		const classification = this.getClassification(extracted.features);

		// Obfuscation seen by the tokenizer.
		const body = segmentWords(`${mail.subject || ''}\n${typeof mail.text === 'string' ? mail.text : ''}`, {maxLength: config.maxLength});
		const obfuscation = {invisible: body.invisible, mixed: body.mixed, styled: body.styled};

		const attachments = config.attachments === false ? [] : inspectAttachments(mail.attachments).filter(item => config.macros !== false || !['macro', 'pdf_active', 'rtf_object'].includes(item.type)).map(item => finding(item));

		const [links, authentication, reputation, dnsbl, viruses, toxicity, nsfw] = await Promise.all([
			this.checkLinks(extracted.links, config),
			config.authentication && session.remoteAddress
				? authenticate(raw, {
					ip: session.remoteAddress, helo: session.helo, sender: session.envelope?.mailFrom?.address, timeout: config.timeout, ...(typeof config.authentication === 'object' ? config.authentication : {}),
				})
				: null,
			this.reputation ? withTimeout(this.reputation.check(reputationValues(mail, session)), config.timeout, null) : null,
			session.remoteAddress && config.dnsbl.ip?.length > 0 ? withTimeout(this.dns.checkIp(session.remoteAddress, config.dnsbl.ip), config.timeout, []) : [],
			config.clamav ? this.scanViruses(mail, config) : [],
			config.toxicity ? this.scanToxicity(mail, config) : [],
			config.nsfw ? this.scanNsfw(mail, config) : [],
		]);

		if (authentication) {
			authentication.score = calculateAuthScore(authentication, typeof config.authentication === 'object' ? config.authentication.weights : undefined);
		}

		const arbitrary = config.arbitrary === false ? {rules: [], score: 0, reasons: []} : isArbitrary(mail, {session, authentication});
		const allowed = (config.allowedLanguages || []).map(code => code.toLowerCase());
		const language = {
			language: extracted.language,
			script: extracted.script,
			notAllowed: Boolean(allowed.length > 0 && extracted.language && !allowed.includes(extracted.language)),
		};

		const results = {
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
		const llm = config.llm && config.llm !== this.config.llm ? new LLMClassifier(config.llm) : this.llm;
		if (llm) {
			const settings = config.llm;
			const mode = settings.mode || 'auto';
			const low = settings.minScore ?? config.threshold - 4;
			const high = settings.maxScore ?? config.rejectThreshold;
			const close = scored.score >= low && scored.score < high;
			if (mode === 'always' || (mode === 'auto' && (close || classification.category === 'unsure' || classification.category === 'disabled'))) {
				try {
					results.llm = await llm.classify(mail, {links: extracted.links, authentication: authentication ? summarizeAuth(authentication) : null});
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
				executables: attachments.filter(item => ['executable', 'disguised_executable', 'double_extension', 'rtl_override', 'executable_in_archive'].includes(item.type)),
				macros: attachments.filter(item => ['macro', 'pdf_active', 'rtf_object'].includes(item.type)),
				idnHomographAttack: {
					detected: links.homographs.length > 0,
					domains: links.homographs,
					riskScore: Math.max(0, ...links.homographs.map(item => item.riskScore)),
				},
			},
			links: extracted.links.map(link => link.url),
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
