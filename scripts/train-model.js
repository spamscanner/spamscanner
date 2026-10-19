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
//
// Each download is pinned to a dataset revision and checked against its
// SHA-256, files already in data/ are checked against it too, and every file
// is written under a .part name and renamed when complete, so an interrupted
// run leaves no truncated file behind to be reused (scripts/download.js).

import {
	createReadStream, createWriteStream, existsSync, mkdirSync, writeFileSync,
} from 'node:fs';
import {createInterface} from 'node:readline';
import path from 'node:path';
import process from 'node:process';
import {parseArgs} from 'node:util';
import {Classifier} from '../src/classifier.js';
import {parseCsvLine} from '../src/sources.js';
import {evaluate, readExamples} from '../src/train.js';
import {download as downloadPinned, writeAtomically} from './download.js';

const DATASETS = [
	{
		name: 'all-scam-spam',
		description: 'Messages and emails in 43 languages, labelled spam or ham',
		url: 'https://huggingface.co/datasets/FredZhang7/all-scam-spam/resolve/802cef358a0a0a9f7582fb96ff262b57a398ee17/junkmail_dataset.csv',
		sha256: 'cf1bcb8c8e5a0299c3aeb950505aedd3f842c46c45790e42b6b638828a2f2510',
		page: 'https://huggingface.co/datasets/FredZhang7/all-scam-spam',
		license: 'Apache-2.0',
		file: 'all-scam-spam.csv',
		textColumn: 'text',
		labelColumn: 'is_spam',
	},
	{
		name: 'enron-spam',
		description: 'The Enron-Spam corpus (Metsis, Androutsopoulos and Paliouras, 2006)',
		url: 'https://huggingface.co/datasets/SetFit/enron_spam/resolve/1916f66c89d52221ae33eb57d44498b4f3a5df22/train.jsonl',
		sha256: 'b846cf15bcad7676c37ea3535622e39e6bff5c9c004f634513e4f9c2951e5f02',
		page: 'https://huggingface.co/datasets/SetFit/enron_spam',
		license: 'Public research corpus',
		file: 'enron-train.jsonl',
		textColumn: 'message',
		labelColumn: 'label_text',
	},
	{
		name: 'telegram-spam-ru',
		description: 'Russian messages from Telegram chats, labelled spam or not',
		url: 'https://huggingface.co/datasets/alt-gnome/telegram-spam/resolve/af298cd351ce1d257ae789571f649d4d94d2cdd6/data/train-00000-of-00001.parquet',
		sha256: 'b496e7fdc413bed25a510e7d019f35056fa30629cf76f3df45266ff8c5a22238',
		page: 'https://huggingface.co/datasets/alt-gnome/telegram-spam',
		license: 'CC0-1.0',
		file: 'telegram-spam-ru.parquet',
		textColumn: 'text',
		labelColumn: 'label',
	},
	...[
		['german', 'bd4f0adfd2ec1d72b76cfc94d048b31248de3e50', '6da8ba8db100f100fd213ec5a2bb1ae5699451601ff27b1ef7bd5008db0d343c'],
		['italian', '492e11c6882cd0b6a89835b28521041f27c5ac3a', '7ed74f6843eb098968f281a0018d34c387e8b8f152f829ead72280bd6fbd6928'],
		['spanish', '1bf0a602a61be1dd8d20d7b79c69bddf8f184f03', '1d455d3a28bbd58e310591be4bee236cf6d2244b5406af76ce1052f7301158ac'],
	].map(([language, revision, sha256]) => ({
		name: `synthetic-spam-${language}`,
		description: `Synthetic ${language[0].toUpperCase()}${language.slice(1)} messages, labelled spam or not`,
		url: `https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-${language}/resolve/${revision}/data/data.csv`,
		sha256,
		page: `https://huggingface.co/datasets/tanaos/synthetic-spam-detection-dataset-${language}`,
		license: 'MIT',
		file: `synthetic-spam-${language}.csv`,
		textColumn: 'text',
		labelColumn: 'labels',
	})),
	{
		name: 'enron-spam-test',
		description: 'The Enron-Spam corpus, test split',
		url: 'https://huggingface.co/datasets/SetFit/enron_spam/resolve/1916f66c89d52221ae33eb57d44498b4f3a5df22/test.jsonl',
		sha256: 'f07a4cca7bfc1d845d4ff59650e69a0ad31d9b5c0409ddad088219f7fc32bb52',
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
		url: 'https://huggingface.co/datasets/dbarbedillo/SMS_Spam_Multilingual_Collection_Dataset/resolve/4b5332a8771b3f6388f8ecc51c2b8ade4be31c73/data-augmented.csv',
		sha256: 'f90ca26ca52ca65acdb71c1d73bf1d1c3806bb12f9489ae3f0b6e4e64a76920f',
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

// (a file already there is reused only if it is the pinned one; if not, it
//  and the files made from it are downloaded and made again)
async function download(dataset, directory) {
	const target = path.join(directory, dataset.file);
	return downloadPinned(dataset, directory, {
		offline: values['no-download'],
		derived: [target.replace(/\.parquet$/, '.jsonl'), target.replace(/\.csv$/, '.wide.jsonl')],
	});
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
		await writeAtomically(target, async part => writeFileSync(part, rows.map(row => JSON.stringify(row, (key, value) => (typeof value === 'bigint' ? Number(value) : value))).join('\n') + '\n'));
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

	await writeAtomically(target, async part => writeWide(file, part));
	return target;
}

async function writeWide(file, target) {
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

	await new Promise((resolve, reject) => {
		out.on('error', reject);
		out.end(resolve);
	});
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
