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
// newsletters, a company's correspondence) is all ham. A dataset may name the
// columns read of a large Parquet file (columns), or be made here instead of
// downloaded (make: its rows).
//
// The languages the public datasets have little ordinary mail of get three
// more: what people say every day (the utterances of MASSIVE, twenty to a
// message), a company's correspondence in French, and the mail and spam
// written for this project (scripts/everyday-mail.js). Without them a
// language known mostly by its spam takes every ordinary word for spam.
//
// Each download is pinned to a dataset revision and checked against its
// SHA-256, files already in data/ are checked against it too, and every file
// is written under a .part name and renamed when complete, so an interrupted
// run leaves no truncated file behind to be reused (scripts/download.js).

import {
	createReadStream, createWriteStream, existsSync, mkdirSync, readFileSync, writeFileSync,
} from 'node:fs';
import {createInterface} from 'node:readline';
import zlib from 'node:zlib';
import path from 'node:path';
import process from 'node:process';
import {parseArgs} from 'node:util';
import {Classifier} from '../src/classifier.js';
import {parseCsvLine} from '../src/sources.js';
import {evaluate, readExamples} from '../src/train.js';
import {download as downloadPinned, writeAtomically} from './download.js';
import {everydayMail} from './everyday-mail.js';

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
	// (twenty utterances to a message, which is then as long as a mail: a
	//  word is counted by the messages it is in, so in shorter ones every
	//  word would be rarer than in the spam, and so a sign of spam)
	...[
		['ar', '00248b42a1b0d80eff39ed80363f54021bbb13dd6ac3212fcdda2b8e2c11f43b'],
		['da', 'adc01b3bb986d54134abbdf0003ee00be8a2c70a6ffaf0080c4da662d15b033e'],
		['el', 'b4b789777234e2d6f15ca870ab0f9d7a9c7b9a34e47f8e57f7bfaf8ae6f59a42'],
		['fi', 'd1e10c8c5b9b2d24d960eea60cb14d1a3b9c6961a4d250d9dc20354bbba64e43'],
		['fr', '358225d1825d0c0477922bae317994efe3a173059c26aa4dd3aa5ff8e4d3a646'],
		['he', '68ba726d46a6935db7af0ba5527d6b37aeb4eceeeb5c1cf78e668ab7c3515e3e'],
		['hi', '12fc80cca23c13b9b950af39db31b00b7f067d9d0f2e351432e59b6bac430dbd'],
		['hu', '8253765228081a4ad3e20faf459c6ae0aa052fb7bf50874ff84ccd1c65f9aa81'],
		['ja', '13a28465d617bf74f7e3146e907f7de85b955bf11758bb42a8f4f70aeab7dccb'],
		['ko', '12f2c0b57f1e1c6fa8bda5b2c4ffc4b28dbcfde8b9bfb3df3f20c103a3829151'],
		['nb', 'f5aa67d82d4cf8356b8f0c0345867974b4f5f90a8b3ba0de1cfa7f3a07b5db09'],
		['nl', '292f0feb3af88ffe6ff6e6991e56a37fd0e5b09a939d6719e44dc755252e2cf1'],
		['pl', '74a794de72f560ec26b96d45b13c70bc091c078ba17848c8ee17bd2737e4e291'],
		['pt', '36589d77185b98e1d497a560c47a761fcee8a99bd8a2a1004d1a4ff244aaeb67'],
		['ro', 'd4ad48100a094d26beb2d3fb474250b20a575fb64ad9bdb7ad534cc0f999ecc8'],
		['sv', '6103e260ea03278be0583ade5304598cb08926df44b07bfb73662e55dc9f7007'],
		['th', '395e4570efbe08fc3f9f8a3f97e01692a53af5fd1330f15444529263acc25482'],
		['tr', '6922a0a63cf7fe2d1af8355e612ba355e572d4f58807bc06c7f4134b5bd9233b'],
		['vi', 'afbc319eb5ebef51e86cee0b0b2e47a653670d86d62329f9b84af98fa8ddccd1'],
		['zh-CN', '8339f3f6c65fbdb6471642cf1854972aa6f084251e0151cbd3403ebe85a4a0dc'],
		['zh-TW', 'bdfe6da9ff6c64b7c8efdf99711dde797f75730044a525e7d2853f86221d53d7'],
	].map(([language, sha256]) => {
		let said = [];
		return {
			name: `everyday-speech-${language}`,
			description: `What people ask and tell an assistant, in ${language} (MASSIVE)`,
			url: `https://huggingface.co/datasets/mteb/amazon_massive_intent/resolve/940fd47a81eaa7f2cc7b129674d945d618ac38c2/train/${language}.json.gz`,
			sha256,
			page: 'https://huggingface.co/datasets/AmazonScience/massive',
			license: 'CC-BY-4.0',
			file: `everyday-speech-${language}.json.gz`,
			row(row) {
				said.push(row.text);
				if (said.length < 20) {
					return null;
				}

				const text = said.join('. ');
				said = [];
				return {text, label: 'ham'};
			},
		};
	}),
	(() => {
		let french = 0;
		return {
			name: 'business-mail-fr',
			description: 'The mail of a made-up company, written by language models: every sixth of its French messages',
			url: 'https://huggingface.co/datasets/sinabis-group/sinabis-100k-synthetic-emails/resolve/c2bfc90f30da0ea99491a07938830882e07c31fe/data/train-00000-of-00001.parquet',
			sha256: 'c94b685510d725776080b276e5fc91bd9f6cefc574d0ff03c8ab3a981d7a1654',
			page: 'https://huggingface.co/datasets/sinabis-group/sinabis-100k-synthetic-emails',
			license: 'CC-BY-4.0',
			file: 'business-mail-fr.parquet',
			columns: ['lang', 'subject', 'body'],
			row: row => (row.lang === 'fr' && french++ % 6 === 0 ? {subject: row.subject, text: row.body, label: 'ham'} : null),
		};
	})(),
	{
		name: 'everyday-mail',
		description: 'Everyday mail and spam in 23 languages, written for this project (scripts/everyday-mail.js)',
		page: 'https://github.com/spamscanner/spamscanner/tree/master/scripts/everyday-mail',
		license: 'BUSL-1.1, with this project',
		file: 'everyday-mail.jsonl',
		// (no spam where the language has no other ordinary text to weigh
		//  its words against)
		* make() {
			for (const message of everydayMail()) {
				if (message.label === 'ham' || !['bg', 'cs', 'uk'].includes(message.language)) {
					yield message;
				}
			}
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
		derived: [target.replace(/\.parquet$|\.json\.gz$/, '.jsonl'), target.replace(/\.csv$/, '.wide.jsonl'), rowsFile(target.replace(/\.parquet$|\.json\.gz$/, '.jsonl'))],
	});
}

// Parquet files and gzipped JSON Lines are converted to JSON Lines once, next
// to the download: a Parquet file in parts, of the columns named, so a large
// one is not held whole.
async function toJsonl(file, {columns} = {}) {
	if (file.endsWith('.json.gz')) {
		const target = file.replace(/\.json\.gz$/, '.jsonl');
		if (!existsSync(target)) {
			await writeAtomically(target, async part => writeFileSync(part, zlib.gunzipSync(readFileSync(file))));
		}

		return target;
	}

	if (!file.endsWith('.parquet')) {
		return file;
	}

	const target = file.replace(/\.parquet$/, '.jsonl');
	if (!existsSync(target)) {
		const {asyncBufferFromFile, parquetMetadataAsync, parquetReadObjects} = await import('hyparquet');
		const buffer = await asyncBufferFromFile(file);
		const metadata = await parquetMetadataAsync(buffer);
		const rows = Number(metadata.num_rows);
		// (Zstandard, with Node.js 22.15 or later)
		const compressors = zlib.zstdDecompressSync ? {ZSTD: input => new Uint8Array(zlib.zstdDecompressSync(input))} : undefined;
		await writeAtomically(target, async part => {
			const out = createWriteStream(part);
			for (let start = 0; start < rows; start += 5000) {
				const read = await parquetReadObjects({
					file: buffer, rowStart: start, rowEnd: Math.min(start + 5000, rows), columns, compressors,
				});
				out.write(read.map(row => JSON.stringify(row, (key, value) => (typeof value === 'bigint' ? Number(value) : value))).join('\n') + '\n');
			}

			await new Promise((resolve, reject) => {
				out.on('error', reject);
				out.end(resolve);
			});
		});
	}

	return target;
}

// The rows a dataset makes itself, written as JSON Lines of {text, subject,
// label} each time.
async function made(dataset, directory) {
	const target = path.join(directory, dataset.file);
	await writeAtomically(target, async part => writeFileSync(part, [...dataset.make()].map(row => JSON.stringify({text: row.text, subject: row.subject || '', label: row.label})).join('\n') + '\n'));
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

// A mail server's bounce is its standard text, the same for any message it
// returns, and says nothing of spam. The corpora have bounces only among their
// spam (those of spam sent in the mailbox's name), which taught the model
// that the words of every bounce are spam: an ordinary bounce that returned
// only the header of its message scored 99%. They are left out, by words
// each mail server has together: qmail and those that write like it,
// sendmail, Exim, Postfix, Domino, iPlanet, and a delivery status
// notification by its name.
const BOUNCE_WORDS = [
	['qmail send', 'send program'],
	['deliver your', 'following addresses'],
	['addresses had', 'session follows'],
	['created automatically', 'delivery software'],
	['problem report', 'own text'],
	['delivery failure', 'domino directory'],
	['delivery has', 'report relates'],
	['delivery status', 'status notification'],
	['s:delivery', 's:status', 's:notification'],
];

function isBounce(features) {
	const words = new Set(features);
	return BOUNCE_WORDS.some(group => group.every(word => words.has(word)));
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
const bounces = {spam: 0, ham: 0};
for (const dataset of selected) {
	let file = dataset.make ? await made(dataset, values.data) : await toJsonl(await download(dataset, values.data), dataset);
	if (dataset.wide) {
		file = await unwiden(file);
	}

	if (dataset.row) {
		file = await labelled(dataset, file);
	}

	const sources = {
		datasets: [dataset.row || dataset.make
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
			if (isBounce(example.features)) {
				bounces[example.label]++;
			} else {
				examples.push({...example, source: dataset.name});
			}
		}
	}

	process.stderr.write('\n');
}

console.error(`Left out ${bounces.spam} bounces labelled spam and ${bounces.ham} labelled ham`);
// (in a function, so the classifier measured with is let go before the one
//  kept is trained: the two do not fit in memory together)
async function measured() {
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
	return {
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
}

const metrics = await measured();
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
