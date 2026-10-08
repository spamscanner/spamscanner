#!/usr/bin/env node
// Measures a language model on public, labelled email: how many messages it
// gets right with each method ("decision": the probability of each verdict
// from one forward pass; "generate": a written JSON verdict) and how long
// each takes, with the hardware it ran on.
//
// The sample is fixed: from each of three datasets, the first spam and ham
// messages in the order of a SHA-256 hash of their text.
//
// - Enron-Spam, test split (https://huggingface.co/datasets/SetFit/enron_spam)
// - all-scam-spam, 43 languages (https://huggingface.co/datasets/FredZhang7/all-scam-spam, Apache-2.0)
// - phishing-dataset, texts (https://huggingface.co/datasets/ealvaradob/phishing-dataset, Apache-2.0)
//
//   node scripts/llm-benchmark.js --model qwen3.5:4b [--methods decision,generate]
//     [--llm ollama] [--url http://127.0.0.1:11434] [--per-group 12]
//     [--max-chars 2500] [--data data] [--results file.jsonl] [--no-download]
//
// Results are appended to --results, so an interrupted run continues where it
// stopped. The datasets download into --data the first time.
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {
	appendFileSync, createWriteStream, existsSync, mkdirSync, readFileSync, writeFileSync,
} from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {Readable} from 'node:stream';
import {pipeline} from 'node:stream/promises';
import {fileURLToPath} from 'node:url';
import {parseArgs} from 'node:util';
import {LLMClassifier, describeHardware, describeMessage} from '../src/llm.js';
import {getFeatures} from '../src/tokenizer.js';

const DATASETS = {
	enron: {url: 'https://huggingface.co/datasets/SetFit/enron_spam/resolve/main/test.jsonl', file: 'enron-test.jsonl'},
	scam: {url: 'https://huggingface.co/datasets/FredZhang7/all-scam-spam/resolve/main/junkmail_dataset.csv', file: 'all-scam-spam.csv'},
	phish: {url: 'https://huggingface.co/datasets/ealvaradob/phishing-dataset/resolve/main/texts.json', file: 'phishing-texts.json'},
};
const STORED = 20;

const {values} = parseArgs({
	options: {
		model: {type: 'string'},
		methods: {type: 'string', default: 'decision,generate'},
		llm: {type: 'string', default: 'ollama'},
		url: {type: 'string'},
		'per-group': {type: 'string', default: '12'},
		'max-chars': {type: 'string', default: '2500'},
		data: {type: 'string', default: 'data'},
		results: {type: 'string'},
		'no-download': {type: 'boolean', default: false},
		prepare: {type: 'boolean', default: false},
	},
});

const sampleFile = path.join(values.data, 'llm-benchmark-sample.json');
const sha256 = text => createHash('sha256').update(text).digest('hex');

// A whole CSV file, quoted fields with commas and line breaks included.
function csvRows(text) {
	const rows = [];
	let field = '';
	let row = [];
	let quoted = false;
	for (let i = 0; i < text.length; i++) {
		const char = text[i];
		if (quoted) {
			if (char === '"' && text[i + 1] === '"') {
				field += '"';
				i++;
			} else if (char === '"') {
				quoted = false;
			} else {
				field += char;
			}
		} else {
			switch (char) {
				case '"': {
					quoted = true;
					break;
				}

				case ',': {
					row.push(field);
					field = '';
					break;
				}

				case '\n': {
					row.push(field);
					rows.push(row);
					row = [];
					field = '';
					break;
				}

				case '\r': {
					break;
				}

				default: {
					field += char;
				}
			}
		}
	}

	return rows;
}

async function download({url, file}) {
	const target = path.join(values.data, file);
	if (!existsSync(target)) {
		if (values['no-download']) {
			throw new Error(`${target} is missing`);
		}

		console.error(`Downloading ${url}`);
		const response = await fetch(url);
		if (!response.ok) {
			throw new Error(`${url}: HTTP ${response.status}`);
		}

		mkdirSync(values.data, {recursive: true});
		await pipeline(Readable.fromWeb(response.body), createWriteStream(target));
	}

	return readFileSync(target, 'utf8');
}

// The first `count` messages with a label, in hash order.
function pick(rows, label, count, seed) {
	return rows.filter(row => row.label === label && row.text.trim().length > 40)
		.map(row => ({row, hash: sha256(seed + row.text)}))
		.sort((a, b) => a.hash.localeCompare(b.hash))
		.slice(0, count)
		.map(({row}) => ({...row, text: row.text.slice(0, 20_000)}));
}

async function prepare() {
	const enronText = await download(DATASETS.enron);
	const enron = enronText.trim().split('\n').map(line => JSON.parse(line))
		.map(row => ({
			source: 'enron', subject: row.subject || '', text: row.message || row.text, label: row.label_text === 'spam' ? 'spam' : 'ham',
		}));
	const [header, ...rows] = csvRows(await download(DATASETS.scam));
	// The text starts with the subject line.
	const scam = rows.filter(row => row.length === header.length).map(([text, isSpam]) => {
		const [first, ...rest] = text.split('\n');
		return {
			source: 'all-scam-spam', subject: first.slice(0, 200), text: rest.join('\n').trim() || text, label: isSpam === '1' ? 'spam' : 'ham',
		};
	});
	// Bare links are left out: this measures messages.
	const phish = JSON.parse(await download(DATASETS.phish))
		.filter(row => !/^https?:\/\/\S+$/.test(row.text.trim()))
		.map(row => ({
			source: 'phishing', subject: '', text: row.text, label: row.label === 1 ? 'spam' : 'ham',
		}));
	const sample = [];
	for (const [seed, list] of [['enron', enron], ['scam', scam], ['phish', phish]]) {
		sample.push(...pick(list, 'spam', STORED, seed), ...pick(list, 'ham', STORED, seed));
	}

	writeFileSync(sampleFile, JSON.stringify(sample));
}

if (values.prepare) {
	await prepare();
	process.exit(0);
}

if (!values.model) {
	console.error('Usage: node scripts/llm-benchmark.js --model <name> [--methods decision,generate] [--llm ollama] [--url <url>]');
	process.exit(2);
}

// The datasets are large; reading them in another process keeps this one small
// next to the model.
if (!existsSync(sampleFile)) {
	const child = spawnSync(process.execPath, [fileURLToPath(import.meta.url), '--prepare', '--data', values.data, ...(values['no-download'] ? ['--no-download'] : [])], {stdio: 'inherit'});
	if (child.status !== 0) {
		process.exit(child.status ?? 1);
	}
}

const perGroup = Number(values['per-group']);
const maxChars = Number(values['max-chars']);
const methods = values.methods.split(',');
const counts = {};
const sample = JSON.parse(readFileSync(sampleFile, 'utf8')).filter(row => {
	const key = `${row.source}:${row.label}`;
	counts[key] = (counts[key] || 0) + 1;
	return counts[key] <= perGroup;
});

const resultsFile = values.results || path.join(values.data, `llm-benchmark-${values.model.replaceAll(/\W/g, '_')}.jsonl`);
const done = new Map();
if (existsSync(resultsFile)) {
	for (const line of readFileSync(resultsFile, 'utf8').split('\n').filter(Boolean)) {
		const row = JSON.parse(line);
		done.set(`${row.method}:${row.id}`, row);
	}
}

const classifiers = Object.fromEntries(methods.map(method => [method, new LLMClassifier({
	provider: values.llm, model: values.model, ...(values.url ? {baseUrl: values.url} : {}), method, maxInputChars: maxChars, timeout: 600_000, cacheSize: 0,
})]));

// The first request loads the model; it is not timed. A model server that
// is still starting or restarting gets a few tries.
for (const classifier of Object.values(classifiers)) {
	for (let attempt = 1; ; attempt++) {
		try {
			await classifier.classifyText('Warm up.');
			break;
		} catch (error) {
			if (attempt === 3) {
				throw error;
			}

			console.error(`Warm-up failed (${error.message}); trying again`);
			await new Promise(resolve => {
				setTimeout(resolve, 10_000);
			});
		}
	}
}

let index = 0;
for (const row of sample) {
	index++;
	const mail = {subject: row.subject, text: row.text, attachments: []};
	const text = describeMessage(mail, {links: getFeatures(mail).links}, {maxInputChars: maxChars});
	const id = sha256(row.source + row.text).slice(0, 12);
	for (const method of methods) {
		if (done.has(`${method}:${id}`)) {
			continue;
		}

		let result;
		try {
			const answer = await classifiers[method].classifyText(text);
			result = {
				id, method, used: answer.method, model: values.model, source: row.source, label: row.label, verdict: answer.verdict, unwanted: answer.verdict === 'ham' ? 1 - answer.confidence : answer.confidence, time: answer.time,
			};
		} catch (error) {
			console.error(`${index} ${method}: ${error.message}`);
			continue;
		}

		done.set(`${method}:${id}`, result);
		appendFileSync(resultsFile, `${JSON.stringify(result)}\n`);
		console.error(`${index}/${sample.length} ${method} ${row.source} ${row.label} ${result.verdict} ${result.time} ms`);
	}
}

const median = list => list.length > 0 ? list[Math.floor((list.length - 1) / 2)] : Number.NaN;
const lines = ['| Model | Method | Correct | Spam caught | Ham marked as spam | Median | 90th percentile |', '| --- | --- | --- | --- | --- | --- | --- |'];
const ids = new Set(sample.map(row => sha256(row.source + row.text).slice(0, 12)));
for (const method of methods) {
	const rows = [...done.values()].filter(row => row.method === method && ids.has(row.id));
	const spam = rows.filter(row => row.label === 'spam');
	const ham = rows.filter(row => row.label === 'ham');
	const caught = spam.filter(row => row.unwanted >= 0.5).length;
	const flagged = ham.filter(row => row.unwanted >= 0.5).length;
	const times = rows.map(row => row.time).sort((a, b) => a - b);
	const seconds = ms => `${(ms / 1000).toFixed(1)} s`;
	lines.push(`| \`${values.model}\` | \`${method}\` | ${caught + ham.length - flagged} of ${rows.length} | ${caught} of ${spam.length} | ${flagged} of ${ham.length} | ${seconds(median(times))} | ${seconds(times[Math.ceil(times.length * 0.9) - 1])} |`);
}

let server = '';
if (values.llm === 'ollama') {
	try {
		const response = await fetch(`${values.url || 'http://127.0.0.1:11434'}/api/version`);
		const {version} = await response.json();
		server = `, Ollama ${version}`;
	} catch {}
}

console.log(lines.join('\n'));
console.log(`\n${sample.length} messages, cut to ${maxChars} characters. Hardware: ${describeHardware()}${server}.`);
