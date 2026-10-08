import {createHash} from 'node:crypto';
import path from 'node:path';
import {simpleParser} from 'mailparser';
import {Classifier} from './classifier.js';
import {getFeatures} from './tokenizer.js';
import {readCsv, readJsonl, readMessages} from './sources.js';

/**
 * Classifier features of a raw message (Buffer or string).
 * @param {Buffer|string} raw
 * @param {object} [options] - passed to getFeatures
 * @returns {Promise<string[]>}
 */
export async function featuresFromMessage(raw, options = {}) {
	const mail = await simpleParser(raw, {skipImageLinks: true, skipTextToHtml: true, skipTextLinks: true});
	return getFeatures(mail, options).features;
}

/**
 * Classifier features of a dataset row that holds text, not a whole message.
 * @param {{text: string, subject?: string}} row
 * @param {object} [options]
 * @returns {string[]}
 */
export function featuresFromText(row, options = {}) {
	return getFeatures({text: row.text, subject: row.subject || ''}, options).features;
}

/**
 * Read labelled examples from the sources given.
 *
 * - spam / ham: paths to messages (.eml files, mbox files, Maildirs or
 *   directories of messages); every message gets that label.
 * - datasets: CSV or JSON Lines files with a text column and a label column,
 *   as { file, textColumn, labelColumn, subjectColumn } or a path.
 *
 * Each example is { label, features, id }, where id is a hash of the content
 * used to drop duplicates.
 *
 * @param {object} sources
 * @param {string[]} [sources.spam]
 * @param {string[]} [sources.ham]
 * @param {Array<string|object>} [sources.datasets]
 * @param {object} [options]
 * @param {(count: number) => void} [options.onProgress]
 * @param {number} [options.limit] - most examples to read per source
 * @returns {AsyncGenerator<{label: 'spam'|'ham', features: string[], id: string}>}
 */
export async function * readExamples(sources, options = {}) {
	const {onProgress, limit = Infinity} = options;
	const seen = new Set();
	let count = 0;
	const emit = (label, features, content) => {
		const id = createHash('sha1').update(content).digest('hex');
		if (seen.has(id)) {
			return null;
		}

		seen.add(id);
		count++;
		if (onProgress && count % 1000 === 0) {
			onProgress(count);
		}

		return {label, features, id};
	};

	for (const label of ['spam', 'ham']) {
		for (const source of sources[label] || []) {
			let taken = 0;
			for await (const raw of readMessages(source)) {
				if (taken++ >= limit) {
					break;
				}

				const example = emit(label, await featuresFromMessage(raw), raw);
				if (example) {
					yield example;
				}
			}
		}
	}

	for (const dataset of sources.datasets || []) {
		const spec = typeof dataset === 'string' ? {file: dataset} : dataset;
		const extension = path.extname(spec.file.replace(/\.gz$/, '')).toLowerCase();
		const rows = extension === '.csv' ? readCsv(spec.file, spec) : readJsonl(spec.file, spec);
		let taken = 0;
		for await (const row of rows) {
			if (taken++ >= limit) {
				break;
			}

			const example = emit(row.label, featuresFromText(row), `${row.subject}\n${row.text}`);
			if (example) {
				yield example;
			}
		}
	}
}

/**
 * Train a classifier.
 * @param {object} sources - see readExamples
 * @param {object} [options]
 * @param {Classifier} [options.classifier] - classifier to keep training (default: a new one)
 * @param {(example: object) => boolean} [options.include] - return false to skip an example, e.g. a held-out test set
 * @param {(count: number) => void} [options.onProgress]
 * @param {number} [options.limit]
 * @returns {Promise<{classifier: Classifier, spam: number, ham: number}>}
 */
export async function train(sources, options = {}) {
	const classifier = options.classifier || new Classifier();
	let spam = 0;
	let ham = 0;
	for await (const example of readExamples(sources, options)) {
		if (options.include && !options.include(example)) {
			continue;
		}

		classifier.learn(example.features, example.label);
		if (example.label === 'spam') {
			spam++;
		} else {
			ham++;
		}
	}

	return {classifier, spam, ham};
}

/**
 * Measure a classifier on labelled examples.
 *
 * "unsure" results count as neither spam nor ham caught; they are reported
 * separately, as they would go to a second opinion (an LLM) or be delivered.
 *
 * @param {Classifier} classifier
 * @param {AsyncIterable<{label: string, features: string[]}>|Iterable<{label: string, features: string[]}>} examples
 * @returns {Promise<object>} counts and rates
 */
export async function evaluate(classifier, examples) {
	const counts = {
		truePositive: 0, falsePositive: 0, trueNegative: 0, falseNegative: 0, unsureSpam: 0, unsureHam: 0,
	};
	for await (const {label, features} of examples) {
		const {category} = classifier.classify(features);
		if (category === 'unsure') {
			counts[label === 'spam' ? 'unsureSpam' : 'unsureHam']++;
		} else if (label === 'spam') {
			counts[category === 'spam' ? 'truePositive' : 'falseNegative']++;
		} else {
			counts[category === 'ham' ? 'trueNegative' : 'falsePositive']++;
		}
	}

	const spam = counts.truePositive + counts.falseNegative + counts.unsureSpam;
	const ham = counts.trueNegative + counts.falsePositive + counts.unsureHam;
	const ratio = (a, b) => (b === 0 ? 0 : a / b);
	const precision = ratio(counts.truePositive, counts.truePositive + counts.falsePositive);
	const recall = ratio(counts.truePositive, spam);
	return {
		...counts,
		spam,
		ham,
		precision,
		recall,
		f1: ratio(2 * precision * recall, precision + recall),
		falsePositiveRate: ratio(counts.falsePositive, ham),
		falseNegativeRate: ratio(counts.falseNegative, spam),
		unsureRate: ratio(counts.unsureSpam + counts.unsureHam, spam + ham),
		accuracy: ratio(counts.truePositive + counts.trueNegative, spam + ham),
	};
}
