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
// A dataset may name the column of its subjects (subjectColumn), and one whose
// labels are not "spam" and "ham", or whose text is spread over fields, gives
// a row function: what one of its rows is as {text, subject, label}, or null
// to leave it out. A dataset of ordinary mail only (invoices, notifications,
// newsletters, a company's correspondence) is all ham.
//
// Each download is pinned to a dataset revision and checked against its
// SHA-256, files already in data/ are checked against it too, and every file
// is written under a .part name and renamed when complete, so an interrupted
// run leaves no truncated file behind to be reused (scripts/download.js).

import {
	createReadStream, createWriteStream, existsSync, mkdirSync, readFileSync, writeFileSync,
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
	...[
		['spamassassin', 'SpamAssasin.csv', '3bfe8f8abff89f69a98456be50413c2fcb20a476141116dd84ee1507b980c00e', 'The SpamAssassin public corpus: mailing lists, newsletters and spam'],
		['nazario-phishing', 'Nazario.csv', 'b8fbc4158fbdfaff1ed98584c43d72e283c6352d7ade4d457d34c1d79488d184', 'The Nazario phishing corpus'],
		['nigerian-fraud', 'Nigerian_Fraud.csv', 'f5d6930763cae6feeae6484131c79655a7440abbb97d6f51eab757aea4e6ab4b', 'Advance-fee fraud emails'],
	].map(([name, source, sha256, description]) => ({
		name,
		description: `${description} (Phishing Email Curated Datasets, Zenodo 8339691)`,
		url: `https://huggingface.co/datasets/kudzaiprichard/aura-phishing-email-corpus/resolve/539567cee21d03c83bd2fb1b142c18a80904eb72/${source}`,
		sha256,
		page: 'https://huggingface.co/datasets/kudzaiprichard/aura-phishing-email-corpus',
		license: 'CC-BY-4.0',
		file: `${name}.csv`,
		textColumn: 'body',
		labelColumn: 'label',
		subjectColumn: 'subject',
	})),
	{
		name: 'scam-ham-india',
		description: 'Messages in 14 languages of India, labelled scam or not',
		url: 'https://huggingface.co/datasets/anmolshrivastav/scam_ham_india_14_languages/resolve/34e2c413aefd2e8f2a6e93177a155f29733290a5/data/train-00000-of-00001.parquet',
		sha256: 'ed39a6957580d03de350516f3ddbba2a13bce9d5fb00e00f1ba8bce9cafc695f',
		page: 'https://huggingface.co/datasets/anmolshrivastav/scam_ham_india_14_languages',
		license: 'MIT',
		file: 'scam-ham-india.parquet',
		textColumn: 'text',
		labelColumn: 'label',
	},
	{
		name: 'email-categories-id',
		description: 'Indonesian emails in six categories: promotions, updates, social media, forums, verification codes and spam',
		url: 'https://huggingface.co/datasets/chairulridjal/high-accuracy-email-classifier-indonesian/resolve/928e9eee71429154cbb1cbbfb2ddff975d203ae0/full_dataset.csv',
		sha256: 'ad889170effedd7070f096071af70ff7adaeb1b42139ae28516dc7bd73a810f1',
		page: 'https://huggingface.co/datasets/chairulridjal/high-accuracy-email-classifier-indonesian',
		license: 'Apache-2.0',
		file: 'email-categories-id.csv',
		row: row => ({subject: row.subject, text: row.body, label: row.category === 'spam' ? 'spam' : 'ham'}),
	},
	{
		name: 'email-categories-en',
		description: 'English emails by kind: business, bills, bookings, newsletters, promotions and others, none of them spam',
		url: 'https://huggingface.co/datasets/imnim/multiclass-email-classification/resolve/e95090f0bb6dae0b05c9cd6db314dcae1d40db3f/email_dataset.json',
		sha256: '1093f1a3191e52b715ae728609b2e15bac71ba2573814a968856c43b009a0b30',
		page: 'https://huggingface.co/datasets/imnim/multiclass-email-classification',
		license: 'MIT',
		file: 'email-categories-en.json',
		row: row => ({subject: row.subject, text: row.body, label: 'ham'}),
	},
	{
		name: 'business-mail-es',
		description: 'A Spanish-speaking company\'s mail by kind: invoices, payment notices, suppliers, verification codes, subscriptions and others, none of them spam',
		url: 'https://huggingface.co/datasets/JeisonJimenez/emails_2025/resolve/8738410773b8e840f598e909c2b77ec51f593961/dataset.csv',
		sha256: 'e644337f36f986798767b3919af512aaaa3fdd27cc5e3347502dbfb16d57f913',
		page: 'https://huggingface.co/datasets/JeisonJimenez/emails_2025',
		license: 'Apache-2.0',
		file: 'business-mail-es.csv',
		// (line ends of the spreadsheet it was exported from)
		row: row => ({text: row.text.replaceAll('_x000d_', ''), label: 'ham'}),
	},
	{
		name: 'email-triage',
		description: 'English emails to a support desk: finance, travel, meetings, personal, support and phishing',
		url: 'https://huggingface.co/datasets/weijianzhg/email-triage-action-seed/resolve/8c98baa8b10a1dddd676c860d9e1b86c89141c38/data/train.parquet',
		sha256: '9ea7c656d016012f7e800a9612d399114ca081bfcbdce4101d1999cb6c293854',
		page: 'https://huggingface.co/datasets/weijianzhg/email-triage-action-seed',
		license: 'Apache-2.0',
		file: 'email-triage.parquet',
		row: row => ({subject: row.subject, text: row.body, label: row.category === 'phishing' ? 'spam' : 'ham'}),
	},
	{
		name: 'job-application-mail',
		description: 'English mail about job applications and ordinary mail beside it, none of it spam',
		url: 'https://huggingface.co/datasets/dedsec995/Email_Classification_Text/resolve/a19b7be7f683b04daa12e7ecb9564b4f574e1cc5/clean_data.csv',
		sha256: 'bd35b39dcc3727c693a50574ec4c8b6c6af15e657aa4cfc0e167e502a4429639',
		page: 'https://huggingface.co/datasets/dedsec995/Email_Classification_Text',
		license: 'MIT',
		file: 'job-application-mail.csv',
		row: row => ({text: row.plain_text, label: 'ham'}),
	},
	{
		name: 'system-email-templates',
		description: 'The account, security and billing emails services send their users',
		url: 'https://huggingface.co/datasets/vpakarinen/open-wiki-email-templates/resolve/edd87b63f0e0825e49ee49ace6315ee278d86179/data.json',
		sha256: 'ded26ca5654b1d5ab6a83b32bad4400abdfa6088ac7b9130388895e78ceb4e48',
		page: 'https://huggingface.co/datasets/vpakarinen/open-wiki-email-templates',
		license: 'Apache-2.0',
		file: 'system-email-templates.json',
		row(row) {
			const match = /^Subject: (.*)\n(?:From: .*\n)?\n?(?:Body:\n)?([\s\S]*)$/.exec(row.output);
			return {subject: match ? match[1] : '', text: match ? match[2] : row.output, label: 'ham'};
		},
	},
	{
		name: 'abandoned-cart-emails',
		description: 'A shop\'s reminders of a cart left behind, in English and French',
		url: 'https://huggingface.co/datasets/neurocheckout-ai/synthetic-abandoned-cart-email-examples/resolve/57e62fa4da4e85fdb1d2ded2dcce16adae45a933/data/train.jsonl',
		sha256: '7d62ed2ea4dc089c4b4a31efcdd2ae22547614247338271fe6d36e53fa97acc7',
		page: 'https://huggingface.co/datasets/neurocheckout-ai/synthetic-abandoned-cart-email-examples',
		license: 'CC-BY-4.0',
		file: 'abandoned-cart-emails.jsonl',
		// (not its examples of what a reminder should not be)
		row: row => (row.draft_variant === 'high_risk' ? null : {subject: row.subject, text: `${row.preview_text}\n${row.body}\n${row.cta}`, label: 'ham'}),
	},
	{
		name: 'marketing-emails',
		description: 'Marketing emails written for products',
		url: 'https://huggingface.co/datasets/dhnanjay/MarketMail-AI-Dataset/resolve/24be2b64f28824d60290bfb32553c392608ab99c/data/train-00000-of-00001-4b63ab942856b171.parquet',
		sha256: '0c82ce13ec424b8033e42e828e7357c11d7dae5ef6cb000381fd2f84dbfbad09',
		page: 'https://huggingface.co/datasets/dhnanjay/MarketMail-AI-Dataset',
		license: 'MIT',
		file: 'marketing-emails.parquet',
		row(row) {
			const match = /^subject(?: line)?: (.*)\n+([\s\S]*)$/i.exec(row.marketing_email);
			return {subject: match ? match[1] : '', text: match ? match[2] : row.marketing_email, label: 'ham'};
		},
	},
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
		derived: [target.replace(/\.parquet$/, '.jsonl'), target.replace(/\.csv$/, '.wide.jsonl'), rowsFile(target.replace(/\.parquet$/, '.jsonl'))],
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

// The rows of a file as objects: a CSV by its header (a quoted field may span
// lines), a JSON array, or JSON Lines.
async function * recordsOf(file) {
	if (file.endsWith('.json')) {
		yield * JSON.parse(readFileSync(file, 'utf8'));
		return;
	}

	const csv = file.endsWith('.csv');
	let header;
	let pending = '';
	for await (const line of createInterface({input: createReadStream(file), crlfDelay: Number.POSITIVE_INFINITY})) {
		if (!csv) {
			if (line.trim()) {
				yield JSON.parse(line);
			}

			continue;
		}

		pending = pending ? `${pending}\n${line}` : line;
		const cells = parseCsvLine(pending);
		if (!cells) {
			continue;
		}

		pending = '';
		if (header) {
			yield Object.fromEntries(header.map((name, index) => [name, cells[index] ?? '']));
		} else {
			header = cells;
		}
	}
}

function rowsFile(file) {
	return `${file}.rows.jsonl`;
}

// A dataset read by its row function is written once as JSON Lines of
// {text, subject, label}, next to the download.
async function labelled(dataset, file) {
	const target = rowsFile(file);
	if (existsSync(target)) {
		return target;
	}

	await writeAtomically(target, async part => {
		const out = createWriteStream(part);
		for await (const record of recordsOf(file)) {
			const row = dataset.row(record);
			if (row && typeof row.text === 'string' && row.text.trim() !== '') {
				out.write(JSON.stringify({text: row.text, subject: row.subject || '', label: row.label}) + '\n');
			}
		}

		await new Promise((resolve, reject) => {
			out.on('error', reject);
			out.end(resolve);
		});
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

	if (dataset.row) {
		file = await labelled(dataset, file);
	}

	const sources = {
		datasets: [dataset.row
			? {
				file, textColumn: 'text', labelColumn: 'label', subjectColumn: 'subject',
			}
			: {
				file, textColumn: dataset.textColumn, labelColumn: dataset.labelColumn, subjectColumn: dataset.subjectColumn,
			}],
	};
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
