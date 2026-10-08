#!/usr/bin/env node
// Builds the default classifier model shipped in model/classifier.json.
//
// Downloads public, openly licensed datasets from Hugging Face into data/
// (skipped when the files are already there), holds out every tenth message
// for testing, trains on the rest, prints precision and recall overall and per
// language, then trains on everything and writes the model with its metrics.
//
//   node scripts/train-model.js [--out model/classifier.json] [--data data]
//     [--no-download] [--with multilingual-sms]
//
// --with adds an optional dataset that the default model leaves out because of
// its license or quality; see OPTIONAL below.

import {
	createReadStream, createWriteStream, existsSync, mkdirSync, writeFileSync,
} from 'node:fs';
import {createInterface} from 'node:readline';
import path from 'node:path';
import process from 'node:process';
import {pipeline} from 'node:stream/promises';
import {Readable} from 'node:stream';
import {parseArgs} from 'node:util';
import {Classifier} from '../src/classifier.js';
import {parseCsvLine} from '../src/sources.js';
import {evaluate, readExamples} from '../src/train.js';

const DATASETS = [
	{
		name: 'all-scam-spam',
		description: 'Messages and emails in 43 languages, labelled spam or ham',
		url: 'https://huggingface.co/datasets/FredZhang7/all-scam-spam/resolve/main/junkmail_dataset.csv',
		page: 'https://huggingface.co/datasets/FredZhang7/all-scam-spam',
		license: 'Apache-2.0',
		file: 'all-scam-spam.csv',
		textColumn: 'text',
		labelColumn: 'is_spam',
	},
	{
		name: 'enron-spam',
		description: 'The Enron-Spam corpus (Metsis, Androutsopoulos and Paliouras, 2006)',
		url: 'https://huggingface.co/datasets/SetFit/enron_spam/resolve/main/train.jsonl',
		page: 'https://huggingface.co/datasets/SetFit/enron_spam',
		license: 'Public research corpus',
		file: 'enron-train.jsonl',
		textColumn: 'message',
		labelColumn: 'label_text',
	},
	{
		name: 'telegram-spam-ru',
		description: 'Russian messages from Telegram chats, labelled spam or not',
		url: 'https://huggingface.co/datasets/alt-gnome/telegram-spam/resolve/main/data/train-00000-of-00001.parquet',
		page: 'https://huggingface.co/datasets/alt-gnome/telegram-spam',
		license: 'CC0-1.0',
		file: 'telegram-spam-ru.parquet',
		textColumn: 'text',
		labelColumn: 'label',
	},
	...['german', 'italian', 'spanish'].map(language => ({
		name: `synthetic-spam-${language}`,
		description: `Synthetic ${language[0].toUpperCase()}${language.slice(1)} messages, labelled spam or not`,
		url: `https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-${language}/resolve/main/data/data.csv`,
		page: `https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-${language}`,
		license: 'MIT',
		file: `synthetic-spam-${language}.csv`,
		textColumn: 'text',
		labelColumn: 'labels',
	})),
	{
		name: 'enron-spam-test',
		description: 'The Enron-Spam corpus, test split',
		url: 'https://huggingface.co/datasets/SetFit/enron_spam/resolve/main/test.jsonl',
		page: 'https://huggingface.co/datasets/SetFit/enron_spam',
		license: 'Public research corpus',
		file: 'enron-test.jsonl',
		textColumn: 'message',
		labelColumn: 'label_text',
	},
];

// Optional datasets, added with --with <name>.
const OPTIONAL = [
	{
		name: 'multilingual-sms',
		description: 'The SMS Spam Collection machine-translated into 21 languages (wide CSV, one column per language)',
		url: 'https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset/resolve/main/data-augmented.csv',
		page: 'https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset',
		license: 'GPL (per the dataset card); check it suits how the model is shared',
		file: 'multilingual-sms.csv',
		wide: true,
		textColumn: 'text',
		labelColumn: 'label',
	},
];

const {values} = parseArgs({
	options: {
		out: {type: 'string', default: 'model/classifier.json'},
		data: {type: 'string', default: 'data'},
		'no-download': {type: 'boolean', default: false},
		with: {type: 'string', multiple: true, default: []},
		'max-features': {type: 'string', default: '400000'},
		'min-count': {type: 'string', default: '2'},
	},
});

for (const name of values.with) {
	if (!OPTIONAL.some(dataset => dataset.name === name)) {
		throw new Error(`Unknown dataset "${name}"; optional datasets: ${OPTIONAL.map(dataset => dataset.name).join(', ')}`);
	}
}

const selected = [...DATASETS, ...OPTIONAL.filter(dataset => values.with.includes(dataset.name))];

async function download(dataset, directory) {
	const target = path.join(directory, dataset.file);
	if (existsSync(target)) {
		return target;
	}

	if (values['no-download']) {
		throw new Error(`${target} is missing`);
	}

	console.error(`Downloading ${dataset.url}`);
	const response = await fetch(dataset.url);
	if (!response.ok) {
		throw new Error(`${dataset.url}: HTTP ${response.status}`);
	}

	await pipeline(Readable.fromWeb(response.body), createWriteStream(target));
	return target;
}

// Parquet files are converted to JSON Lines once, next to the download.
async function toJsonl(file) {
	if (!file.endsWith('.parquet')) {
		return file;
	}

	const target = file.replace(/\.parquet$/, '.jsonl');
	if (!existsSync(target)) {
		const {asyncBufferFromFile, parquetReadObjects} = await import('hyparquet');
		const rows = await parquetReadObjects({file: await asyncBufferFromFile(file)});
		writeFileSync(target, rows.map(row => JSON.stringify(row, (key, value) => (typeof value === 'bigint' ? Number(value) : value))).join('\n') + '\n');
	}

	return target;
}

// A wide CSV (labels, text, text_hi, text_de, ...) becomes one row per
// message and language.
async function unwiden(file) {
	const target = file.replace(/\.csv$/, '.wide.jsonl');
	if (existsSync(target)) {
		return target;
	}

	const out = createWriteStream(target);
	let header;
	let pending = '';
	for await (const line of createInterface({input: createReadStream(file), crlfDelay: Number.POSITIVE_INFINITY})) {
		pending = pending ? `${pending}\n${line}` : line;
		const cells = parseCsvLine(pending);
		if (!cells) {
			continue;
		}

		pending = '';
		if (!header) {
			header = cells;
			continue;
		}

		const label = cells[header.indexOf('labels')];
		for (const [index, column] of header.entries()) {
			if (column.startsWith('text') && cells[index]) {
				out.write(JSON.stringify({text: cells[index], label}) + '\n');
			}
		}
	}

	await new Promise(resolve => {
		out.end(resolve);
	});
	return target;
}

function isHeldOut(example) {
	return Number.parseInt(example.id.slice(0, 8), 16) % 10 === 0;
}

function languageOf(features) {
	const tag = features.find(feature => feature.startsWith('lang:'));
	return tag ? tag.slice(5) : 'unknown';
}

function round(n) {
	return Math.round(n * 10_000) / 10_000;
}

function summary(result, messages) {
	return {
		messages,
		precision: round(result.precision),
		recall: round(result.recall),
		falsePositiveRate: round(result.falsePositiveRate),
		unsureRate: round(result.unsureRate),
	};
}

async function grouped(classifier, test, key) {
	const groups = new Map();
	for (const example of test) {
		const name = key(example);
		if (!groups.has(name)) {
			groups.set(name, []);
		}

		groups.get(name).push(example);
	}

	const out = {};
	for (const [name, group] of [...groups].sort((a, b) => b[1].length - a[1].length)) {
		if (group.length >= 20) {
			out[name] = summary(await evaluate(classifier, group), group.length);
		}
	}

	return out;
}

mkdirSync(values.data, {recursive: true});
console.error('Reading and tokenizing examples');
const examples = [];
const seen = new Set();
for (const dataset of selected) {
	let file = await toJsonl(await download(dataset, values.data));
	if (dataset.wide) {
		file = await unwiden(file);
	}

	const sources = {datasets: [{file, textColumn: dataset.textColumn, labelColumn: dataset.labelColumn}]};
	for await (const example of readExamples(sources, {onProgress: n => process.stderr.write(`\r${dataset.name}: ${n} examples`)})) {
		if (!seen.has(example.id)) {
			seen.add(example.id);
			examples.push({...example, source: dataset.name});
		}
	}

	process.stderr.write('\n');
}

const holdout = new Classifier();
const test = [];
for (const example of examples) {
	if (isHeldOut(example)) {
		test.push(example);
	} else {
		holdout.learn(example.features, example.label);
	}
}

const overall = await evaluate(holdout, test);
const metrics = {
	test: 'Every tenth message (by content hash) held out; trained on the rest',
	messages: test.length,
	precision: round(overall.precision),
	recall: round(overall.recall),
	f1: round(overall.f1),
	accuracy: round(overall.accuracy),
	falsePositiveRate: round(overall.falsePositiveRate),
	falseNegativeRate: round(overall.falseNegativeRate),
	unsureRate: round(overall.unsureRate),
	bySource: await grouped(holdout, test, example => example.source),
	byLanguage: await grouped(holdout, test, example => languageOf(example.features)),
};
console.error(JSON.stringify(metrics, null, 2));

const classifier = new Classifier();
let spam = 0;
let ham = 0;
for (const example of examples) {
	classifier.learn(example.features, example.label);
	if (example.label === 'spam') {
		spam++;
	} else {
		ham++;
	}
}

const json = classifier.toJSON({
	minCount: Number(values['min-count']),
	maxFeatures: Number(values['max-features']),
	metadata: {
		trainedOn: selected.map(({name, page, license, description}) => ({
			name, page, license, description,
		})),
		spam,
		ham,
		metrics,
	},
});
mkdirSync(path.dirname(values.out), {recursive: true});
writeFileSync(values.out, `${JSON.stringify(json)}\n`);
console.error(`Wrote ${values.out}: ${json.features} features from ${spam} spam and ${ham} ham messages`);
