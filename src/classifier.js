import {Buffer} from 'node:buffer';

// Model format version written by toJSON.
export const MODEL_VERSION = 2;

/**
 * 32-bit FNV-1a hash of a string's UTF-8 bytes. Models store hashes, not
 * words, so a model never contains text from the messages it learned from.
 * @param {string} value
 * @returns {number}
 */
export function hashFeature(value) {
	let hash = 0x81_1C_9D_C5;
	const bytes = Buffer.from(value, 'utf8');
	for (const byte of bytes) {
		hash ^= byte;
		hash = Math.imul(hash, 0x01_00_01_93);
	}

	return hash >>> 0;
}

/**
 * Upper tail of the chi-squared distribution with an even number of degrees
 * of freedom: the probability of a value at least `x2`.
 * @param {number} x2
 * @param {number} degrees
 * @returns {number}
 */
export function chi2Q(x2, degrees) {
	const m = x2 / 2;
	let term = Math.exp(-m);
	let sum = term;
	for (let i = 1; i < degrees / 2; i++) {
		term *= m / i;
		sum += term;
	}

	return Math.min(sum, 1);
}

const DEFAULTS = {
	// Robinson's s and x: how much an unseen or rare feature is pulled to 0.5.
	strength: 0.45,
	unknown: 0.5,
	// Features whose probability is closer to 0.5 than this are ignored.
	minDistance: 0.1,
	// Most features to combine per message (the strongest clues).
	maxClues: 150,
	// Results at or below hamCutoff are ham, at or above spamCutoff spam,
	// and anything between is unsure.
	hamCutoff: 0.2,
	spamCutoff: 0.99,
	// A language the classifier has seen little ham or spam in gets a result
	// pulled toward unsure. Full confidence needs this many ham messages in the
	// language and a fifth as many spam messages, or languageShare of the
	// smaller class if that is fewer (so small personal classifiers are not
	// held back). Ham counts most: too little of it is what flags ordinary mail.
	minLanguageExamples: 1000,
	languageShare: 0.02,
	// Weigh words against the spam and ham counts of the message's own
	// language rather than of all languages, so a language seen mostly in spam
	// does not make its everyday words look like spam.
	languagePrior: true,
};

// What each option of a model may be: any number earlier releases computed
// with (Infinity too where it means "no limit" or "never").
const OPTION_CHECKS = {
	strength: value => value >= 0 && Number.isFinite(value),
	unknown: value => Number.isFinite(value),
	minDistance: value => !Number.isNaN(value),
	maxClues: value => !Number.isNaN(value),
	hamCutoff: value => !Number.isNaN(value),
	spamCutoff: value => !Number.isNaN(value),
	minLanguageExamples: value => !Number.isNaN(value),
	languageShare: value => Number.isFinite(value),
	languagePrior: value => typeof value === 'boolean',
};

// (JSON writes Infinity as null, as 7.0.3 saved it: read back as the
//  infinity each option can mean, "no limit" or "never ham" and "never
//  spam", and as the default for the others, where it meant nothing)
const NULL_MEANS = {
	minDistance: Infinity, maxClues: Infinity, minLanguageExamples: Infinity, hamCutoff: -Infinity, spamCutoff: Infinity,
};

// The options stored in a model, checked; others are ignored.
function modelOptions(options, corrupt) {
	if (options === undefined) {
		return {};
	}

	if (!options || typeof options !== 'object' || Array.isArray(options)) {
		throw corrupt('options is not an object');
	}

	const checked = {};
	for (const [name, valid] of Object.entries(OPTION_CHECKS)) {
		const value = options[name] === null ? NULL_MEANS[name] : options[name];
		if (value !== undefined) {
			if ((name !== 'languagePrior' && typeof value !== 'number') || !valid(value)) {
				throw corrupt(`option ${name} is out of range`);
			}

			checked[name] = value;
		}
	}

	return checked;
}

// Words, word pairs and subject words belong to one language; features with
// another prefix (url:, pat:, html:, ...) do not.
const isWord = feature => !feature.includes(':') || feature.startsWith('s:');

// Which language or script a message is in describes the training data
// rather than the message, so these features never count as clues.
const IDENTITY = /^(?:lang|script):(?!mixed$)/;

/**
 * A spam classifier that learns from examples.
 *
 * It counts in how many spam and ham messages each feature appears. To score a
 * message it estimates each feature's spam probability with Robinson's method,
 * keeps the strongest clues and combines them with Fisher's chi-squared
 * method, as SpamBayes and bogofilter do. The result runs from 0 (ham) to 1
 * (spam), with "unsure" in between: classes of very different sizes and words
 * never seen before do not push it either way.
 */
export class Classifier {
	/**
	 * @param {object} [options] - strength, unknown, minDistance, maxClues, hamCutoff, spamCutoff
	 */
	constructor(options = {}) {
		this.options = {...DEFAULTS, ...options};
		this.nspam = 0;
		this.nham = 0;
		// Learned counts, updated by learn(): hash -> [spam, ham]
		this.counts = new Map();
		// Frozen counts from a loaded model, searched by binary search.
		this.frozen = null;
	}

	/**
	 * Learn from one message.
	 * @param {string[]} features
	 * @param {'spam'|'ham'} category
	 * @param {number} [weight] - 1 to learn, -1 to unlearn
	 */
	learn(features, category, weight = 1) {
		if (category !== 'spam' && category !== 'ham') {
			throw new TypeError('category must be "spam" or "ham"');
		}

		const index = category === 'spam' ? 0 : 1;
		if (index === 0) {
			this.nspam = Math.max(0, this.nspam + weight);
		} else {
			this.nham = Math.max(0, this.nham + weight);
		}

		for (const hash of new Set(features.map(feature => hashFeature(feature)))) {
			let pair = this.counts.get(hash);
			if (!pair) {
				pair = this.frozenCounts(hash);
				this.counts.set(hash, pair);
			}

			pair[index] = Math.max(0, pair[index] + weight);
		}
	}

	/**
	 * Undo learn() for a message learned earlier, for example one reported as
	 * misclassified before learning it again in the other category.
	 * @param {string[]} features
	 * @param {'spam'|'ham'} category
	 */
	unlearn(features, category) {
		this.learn(features, category, -1);
	}

	frozenCounts(hash) {
		if (!this.frozen) {
			return [0, 0];
		}

		const {keys, spam, ham} = this.frozen;
		let low = 0;
		let high = keys.length - 1;
		while (low <= high) {
			const mid = (low + high) >>> 1;
			const key = keys[mid];
			if (key === hash) {
				return [spam[mid], ham[mid]];
			}

			if (key < hash) {
				low = mid + 1;
			} else {
				high = mid - 1;
			}
		}

		return [0, 0];
	}

	countsFor(hash) {
		return this.counts.get(hash) || this.frozenCounts(hash);
	}

	/**
	 * Spam probability of one feature: Robinson's f(w).
	 * @param {string} feature
	 * @returns {number}
	 */
	probability(feature) {
		return this.probabilityOf(this.countsFor(hashFeature(feature)));
	}

	probabilityOf([spamCount, hamCount], [spamTotal, hamTotal] = [this.nspam, this.nham]) {
		const {strength, unknown} = this.options;
		const n = spamCount + hamCount;
		if (n === 0) {
			return unknown;
		}

		const spamRatio = spamCount / Math.max(spamTotal, 1);
		const hamRatio = hamCount / Math.max(hamTotal, 1);
		const p = spamRatio / (spamRatio + hamRatio);
		return ((strength * unknown) + (n * p)) / (strength + n);
	}

	/**
	 * Score a message.
	 * @param {string[]} features
	 * @returns {{probability: number, category: 'spam'|'ham'|'unsure', spam: number, ham: number, clues: Array<{feature: string, probability: number}>, coverage: {feature: string|null, spam: number, ham: number, confidence: number}}}
	 */
	classify(features) {
		const {minDistance, maxClues, hamCutoff, spamCutoff} = this.options;
		const unique = [...new Set(features)];
		const coverage = this.coverage(unique.filter(feature => IDENTITY.test(feature)));
		const totals = this.options.languagePrior && coverage.spam > 0 && coverage.ham > 0 ? [coverage.spam, coverage.ham] : undefined;
		const candidates = [];
		for (const feature of unique) {
			if (IDENTITY.test(feature)) {
				continue;
			}

			const p = this.probabilityOf(this.countsFor(hashFeature(feature)), isWord(feature) ? totals : undefined);
			const distance = Math.abs(p - 0.5);
			if (distance >= minDistance) {
				candidates.push({feature, probability: p, distance});
			}
		}

		candidates.sort((a, b) => b.distance - a.distance || (a.feature < b.feature ? -1 : 1));
		const clues = candidates.slice(0, maxClues);
		if (clues.length === 0 || this.nspam === 0 || this.nham === 0) {
			return {
				probability: 0.5, category: 'unsure', spam: 0.5, ham: 0.5, clues: [], coverage,
			};
		}

		let spamLog = 0;
		let hamLog = 0;
		for (const {probability} of clues) {
			const p = Math.min(Math.max(probability, 1e-6), 1 - 1e-6);
			spamLog += Math.log(1 - p);
			hamLog += Math.log(p);
		}

		const degrees = 2 * clues.length;
		const spam = 1 - chi2Q(-2 * spamLog, degrees);
		const ham = 1 - chi2Q(-2 * hamLog, degrees);
		const probability = 0.5 + ((((1 + spam - ham) / 2) - 0.5) * coverage.confidence);
		let category = 'unsure';
		if (probability >= spamCutoff) {
			category = 'spam';
		} else if (probability <= hamCutoff) {
			category = 'ham';
		}

		return {
			probability,
			category,
			spam,
			ham,
			clues: clues.slice(0, 15).map(({feature, probability}) => ({feature, probability})),
			coverage,
		};
	}

	/**
	 * How well the training data covers the language of a message, from the
	 * spam and ham counts of its lang: feature (or script: feature when the
	 * language is unknown).
	 * @param {string[]} identity - the message's lang: and script: features
	 * @returns {{feature: string|null, spam: number, ham: number, confidence: number}}
	 */
	coverage(identity) {
		const feature = identity.find(item => item.startsWith('lang:')) || identity[0];
		if (!feature) {
			return {
				feature: null, spam: 0, ham: 0, confidence: 1,
			};
		}

		const [spam, ham] = this.countsFor(hashFeature(feature));
		const {minLanguageExamples, languageShare} = this.options;
		const needed = Math.max(Math.min(minLanguageExamples, languageShare * Math.min(this.nspam, this.nham)), 1);
		return {
			feature, spam, ham, confidence: Math.min(ham / needed, spam / (needed / 5), 1),
		};
	}

	/**
	 * Number of distinct features the classifier knows.
	 * @returns {number}
	 */
	get size() {
		if (!this.frozen) {
			return this.counts.size;
		}

		let extra = 0;
		for (const hash of this.counts.keys()) {
			const [spam, ham] = this.frozenCounts(hash);
			if (spam === 0 && ham === 0) {
				extra++;
			}
		}

		return this.frozen.keys.length + extra;
	}

	/**
	 * Add another classifier's counts to this one, for example a model trained
	 * on one mailbox to the default model.
	 * @param {Classifier} other
	 * @returns {this}
	 */
	merge(other) {
		this.nspam += other.nspam;
		this.nham += other.nham;
		// (merging a classifier into itself reads its rows before changing
		//  them, as its rows read later would otherwise include the change)
		for (const [hash, [spam, ham]] of other === this ? [...other.entries()] : other.entries()) {
			const pair = this.counts.get(hash) || this.frozenCounts(hash);
			this.counts.set(hash, [pair[0] + spam, pair[1] + ham]);
		}

		return this;
	}

	/**
	 * Every feature hash with its counts.
	 * @returns {IterableIterator<[number, number[]]>}
	 */
	* entries() {
		if (this.frozen) {
			const {keys, spam, ham} = this.frozen;
			for (const [i, key] of keys.entries()) {
				if (!this.counts.has(key)) {
					yield [key, [spam[i], ham[i]]];
				}
			}
		}

		yield * this.counts.entries();
	}

	/**
	 * Serialize the model. Features seen in fewer than `minCount` messages can
	 * be dropped, and at most `maxFeatures` of the most frequent kept.
	 * @param {object} [options]
	 * @param {number} [options.minCount]
	 * @param {number} [options.maxFeatures]
	 * @param {object} [options.metadata] - stored as is, e.g. training sources
	 * @returns {object}
	 */
	toJSON(options = {}) {
		const {minCount = 1, maxFeatures = Infinity, metadata} = options;
		let rows = [...this.entries()].filter(([, [spam, ham]]) => spam + ham >= minCount && spam + ham > 0);
		if (rows.length > maxFeatures) {
			rows.sort((a, b) => (b[1][0] + b[1][1]) - (a[1][0] + a[1][1]) || a[0] - b[0]);
			rows = rows.slice(0, maxFeatures);
		}

		rows.sort((a, b) => a[0] - b[0]);
		const keys = new Uint32Array(rows.length);
		const spam = new Uint32Array(rows.length);
		const ham = new Uint32Array(rows.length);
		for (const [i, [hash, [s, h]]] of rows.entries()) {
			keys[i] = hash;
			spam[i] = s;
			ham[i] = h;
		}

		const encode = array => Buffer.from(array.buffer, array.byteOffset, array.byteLength).toString('base64');
		return {
			type: 'spamscanner-classifier',
			version: MODEL_VERSION,
			hash: 'fnv1a32',
			nspam: this.nspam,
			nham: this.nham,
			features: rows.length,
			options: {
				strength: this.options.strength,
				unknown: this.options.unknown,
				minDistance: this.options.minDistance,
				maxClues: this.options.maxClues,
				// (a probability is from 0 to 1: a cutoff beyond, infinite too,
				//  is saved as -1 or 2, which JSON can hold)
				hamCutoff: Math.min(Math.max(this.options.hamCutoff, -1), 2),
				spamCutoff: Math.min(Math.max(this.options.spamCutoff, -1), 2),
				minLanguageExamples: this.options.minLanguageExamples,
				languageShare: this.options.languageShare,
				languagePrior: this.options.languagePrior,
			},
			...(metadata ? {metadata} : {}),
			keys: encode(keys),
			spam: encode(spam),
			ham: encode(ham),
		};
	}

	/**
	 * Load a model written by toJSON. Options passed here override the model's.
	 * A model is data that may come from anywhere, so everything in it is
	 * checked: a damaged one throws a TypeError starting "Corrupt classifier
	 * model".
	 * @param {object|string} json
	 * @param {object} [options]
	 * @returns {Classifier}
	 */
	static fromJSON(json, options = {}) {
		const corrupt = reason => new TypeError(`Corrupt classifier model: ${reason}`);
		let data;
		try {
			data = typeof json === 'string' ? JSON.parse(json) : json;
		} catch (error) {
			throw corrupt(error.message);
		}

		if (!data || data.type !== 'spamscanner-classifier') {
			throw new TypeError('Not a Spam Scanner classifier model (expected type "spamscanner-classifier")');
		}

		if (data.version !== MODEL_VERSION) {
			throw new TypeError(`Unsupported classifier model version ${data.version}; this release reads version ${MODEL_VERSION}`);
		}

		const decode = (value, name) => {
			const buffer = typeof value === 'string' ? Buffer.from(value, 'base64') : null;
			if (!buffer || buffer.byteLength % 4 !== 0) {
				throw corrupt(`${name} is not a list of 32-bit numbers`);
			}

			const copy = new Uint8Array(buffer.byteLength);
			copy.set(buffer);
			return new Uint32Array(copy.buffer);
		};

		for (const name of ['nspam', 'nham']) {
			if (!Number.isSafeInteger(data[name]) || data[name] < 0) {
				throw corrupt(`${name} is not a count`);
			}
		}

		const keys = decode(data.keys, 'keys');
		const spam = decode(data.spam, 'spam');
		const ham = decode(data.ham, 'ham');
		if (keys.length !== spam.length || keys.length !== ham.length) {
			throw corrupt('feature arrays differ in length');
		}

		// (looked up by binary search: in increasing order, each once)
		for (let i = 1; i < keys.length; i++) {
			if (keys[i] <= keys[i - 1]) {
				throw corrupt('feature hashes are not in increasing order');
			}
		}

		const classifier = new Classifier({...modelOptions(data.options, corrupt), ...options});
		classifier.nspam = data.nspam;
		classifier.nham = data.nham;
		classifier.frozen = {keys, spam, ham};
		classifier.metadata = data.metadata || null;
		return classifier;
	}
}
