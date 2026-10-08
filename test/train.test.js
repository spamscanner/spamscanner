import assert from 'node:assert/strict';
import {mkdirSync, symlinkSync, writeFileSync} from 'node:fs';
import path from 'node:path';
import {describe, it} from 'node:test';
import {gzipSync} from 'node:zlib';
import {Classifier} from '../src/classifier.js';
import {
	normalizeLabel, parseCsvLine, readCsv, readJsonl, readMbox, readMessages,
} from '../src/sources.js';
import {
	evaluate, featuresFromMessage, featuresFromText, readExamples, train,
} from '../src/train.js';
import {
	HAM, SPAM, message, temporaryDirectory,
} from './helpers/index.js';

async function collect(iterable) {
	const out = [];
	for await (const item of iterable) {
		out.push(item);
	}

	return out;
}

function mailbox(messages) {
	return messages.map((raw, i) => `From sender${i}@example.org Mon Oct  5 09:30:00 2026\n${raw.replaceAll('\r\n', '\n')}`).join('\n');
}

describe('reading sources', () => {
	it('reads mbox files, plain and gzipped, unescaping mboxrd lines', async () => {
		const dir = temporaryDirectory();
		const raw = message({subject: 'One', text: 'First'});
		const content = `preamble that is not a message\n${mailbox([raw, 'Subject: Two\n\n>From the start of a line\n'])}\n`;
		writeFileSync(path.join(dir, 'box.mbox'), content);
		writeFileSync(path.join(dir, 'box.mbox.gz'), gzipSync(content));
		for (const file of ['box.mbox', 'box.mbox.gz']) {
			const messages = await collect(readMbox(path.join(dir, file)));
			assert.equal(messages.length, 2);
			assert.match(messages[1], /^From the start of a line$/m);
		}

		writeFileSync(path.join(dir, 'empty.mbox'), 'no separators here\n');
		assert.deepEqual(await collect(readMbox(path.join(dir, 'empty.mbox'))), []);
		writeFileSync(path.join(dir, 'trailing.mbox'), 'From a@b Mon Oct  5 09:30:00 2026\nFrom b@c Mon Oct  5 09:30:00 2026\n');
		assert.deepEqual(await collect(readMbox(path.join(dir, 'trailing.mbox'))), []);
	});

	it('reads directories of messages: Maildirs, .eml files and mbox files, skipping what is not mail', async () => {
		const dir = temporaryDirectory();
		for (const sub of ['Maildir/cur', 'Maildir/new', 'Maildir/tmp', 'eml', '.hidden']) {
			mkdirSync(path.join(dir, sub), {recursive: true});
		}

		writeFileSync(path.join(dir, 'Maildir/cur/1:2,S'), message({subject: 'cur'}));
		writeFileSync(path.join(dir, 'Maildir/new/2'), message({subject: 'new'}));
		writeFileSync(path.join(dir, 'Maildir/tmp/3'), message({subject: 'tmp'}));
		writeFileSync(path.join(dir, 'Maildir/dovecot-uidlist'), 'not mail');
		writeFileSync(path.join(dir, '.hidden/4'), message({subject: 'hidden'}));
		writeFileSync(path.join(dir, 'eml/a.eml'), message({subject: 'eml'}));
		writeFileSync(path.join(dir, 'eml/archive.gz'), gzipSync('not an mbox'));
		symlinkSync(path.join(dir, 'eml/a.eml'), path.join(dir, 'eml/link.eml'));
		writeFileSync(path.join(dir, 'eml/inbox'), mailbox([message({subject: 'mbox one'}), message({subject: 'mbox two'})]));
		const subjects = (await collect(readMessages(dir))).map(raw => /Subject: (.+)/.exec(raw.toString())[1].trim());
		assert.deepEqual(subjects.sort(), ['cur', 'eml', 'mbox one', 'mbox two', 'new']);
		assert.equal((await collect(readMessages(path.join(dir, 'eml/a.eml')))).length, 1);
	});

	it('parses CSV lines with quotes', () => {
		assert.deepEqual(parseCsvLine('a,"b, c","say ""hi"""'), ['a', 'b, c', 'say "hi"']);
		assert.equal(parseCsvLine('"open'), null);
		assert.deepEqual(parseCsvLine(''), ['']);
		assert.deepEqual(parseCsvLine('x"y,z'), ['x"y', 'z']);
	});

	it('reads labelled CSV, including fields over several lines and custom column names', async () => {
		const dir = temporaryDirectory();
		const file = path.join(dir, 'data.csv');
		writeFileSync(file, 'Email Text,Email Type,subject\n"Win money\nnow",Phishing Email,Prize\nHello friend,Safe Email,\nUnclear,maybe,\n,spam,\n');
		const rows = await collect(readCsv(file));
		assert.deepEqual(rows, [{text: 'Win money\nnow', subject: 'Prize', label: 'spam'}, {text: 'Hello friend', subject: '', label: 'ham'}]);
		const custom = path.join(dir, 'custom.csv');
		writeFileSync(custom, 'body,verdict\nhello,ham\n');
		assert.deepEqual(await collect(readCsv(custom, {textColumn: 'body', labelColumn: 'verdict'})), [{text: 'hello', subject: '', label: 'ham'}]);
		await assert.rejects(collect(readCsv(custom)), /could not find the text and label columns/);
	});

	it('reads labelled JSON Lines', async () => {
		const dir = temporaryDirectory();
		const file = path.join(dir, 'data.jsonl');
		writeFileSync(file, `${[
			JSON.stringify({text: 'win now', label_text: 'spam', subject: 'Prize'}),
			'',
			'not json',
			JSON.stringify({message: 'see you', label: 0}),
			JSON.stringify({body: 'x', category: 'unknown'}),
			JSON.stringify({content: '  ', labels: 'spam'}),
			JSON.stringify({mytext: 'custom', mylabel: 'junk', title: 'T'}),
		].join('\n')}\n`);
		assert.deepEqual(await collect(readJsonl(file)), [{text: 'win now', subject: 'Prize', label: 'spam'}, {text: 'see you', subject: '', label: 'ham'}]);
		assert.deepEqual(await collect(readJsonl(file, {textColumn: 'mytext', labelColumn: 'mylabel', subjectColumn: 'title'})), [{text: 'custom', subject: 'T', label: 'spam'}]);
	});

	it('normalizes labels', () => {
		for (const value of ['spam', 'SPAM', 1, '1', 'Phishing Email', 'junk', true]) {
			assert.equal(normalizeLabel(value), 'spam', String(value));
		}

		for (const value of ['ham', 0, 'Safe Email', 'not_spam', 'legitimate', false]) {
			assert.equal(normalizeLabel(value), 'ham', String(value));
		}

		assert.equal(normalizeLabel('perhaps'), null);
		assert.equal(normalizeLabel(undefined), null);
	});
});

describe('training', () => {
	function writeCorpus() {
		const dir = temporaryDirectory();
		mkdirSync(path.join(dir, 'spam'));
		mkdirSync(path.join(dir, 'ham'));
		for (const [i, [, subject, text]] of SPAM.entries()) {
			writeFileSync(path.join(dir, 'spam', `${i}.eml`), message({subject, text}));
		}

		for (const [i, [, subject, text]] of HAM.entries()) {
			writeFileSync(path.join(dir, 'ham', `${i}.eml`), message({subject, text}));
		}

		// A duplicate is read once.
		writeFileSync(path.join(dir, 'spam', 'copy.eml'), '');
		writeFileSync(path.join(dir, 'spam', 'copy2.eml'), '');
		const rows = path.join(dir, 'rows.jsonl');
		writeFileSync(rows, `${[...SPAM.map(([, subject, text]) => ({subject, text: `${text} extra`, label: 'spam'})), ...HAM.map(([, subject, text]) => ({subject, text: `${text} extra`, label: 'ham'}))].map(row => JSON.stringify(row)).join('\n')}\n`);
		const csv = path.join(dir, 'rows.csv');
		writeFileSync(csv, 'text,label\n"Exclusive casino bonus, claim free spins now",spam\n"The invoice for March is attached, thanks",ham\n');
		return {dir, rows, csv};
	}

	it('learns from messages and datasets, in every language', async () => {
		const {dir, rows, csv} = writeCorpus();
		const progress = [];
		const {classifier, spam, ham} = await train({spam: [path.join(dir, 'spam')], ham: [path.join(dir, 'ham')], datasets: [rows, {file: csv}]}, {onProgress: n => progress.push(n)});
		assert.equal(spam, (SPAM.length * 2) + 2);
		assert.equal(ham, (HAM.length * 2) + 1);
		for (const [language, subject, text] of SPAM) {
			assert.equal(classifier.classify(featuresFromText({subject, text})).category, 'spam', language);
		}

		const features = await featuresFromMessage(message({subject: 'Treffen am Montag', text: 'Hallo Anna, wir treffen uns am Montag im Büro, um den Projektplan zu besprechen. Viele Grüße'}));
		assert.notEqual(classifier.classify(features).category, 'spam');
		assert.deepEqual(progress, []);
	});

	it('keeps training an existing classifier, skips excluded examples and honours limits', async () => {
		const {dir} = writeCorpus();
		const classifier = new Classifier();
		classifier.learn(['seed'], 'ham');
		const result = await train({spam: [path.join(dir, 'spam')], ham: [path.join(dir, 'ham')]}, {classifier, include: example => example.label === 'spam', limit: 3});
		assert.equal(result.classifier, classifier);
		assert.equal(result.spam, 3);
		assert.equal(result.ham, 0);
		assert.equal(classifier.nham, 1);
	});

	it('reports progress every thousand examples', async () => {
		const dir = temporaryDirectory();
		const file = path.join(dir, 'many.jsonl');
		writeFileSync(file, `${Array.from({length: 1001}, (_, i) => JSON.stringify({text: `message number ${i}`, label: i % 2 ? 'spam' : 'ham'})).join('\n')}\n`);
		const progress = [];
		const examples = await collect(readExamples({datasets: [file]}, {onProgress: n => progress.push(n)}));
		assert.equal(examples.length, 1001);
		assert.deepEqual(progress, [1000]);
		assert.equal((await collect(readExamples({datasets: [file]}, {limit: 5}))).length, 5);
	});

	it('measures precision, recall and false positives, counting unsure results apart', async () => {
		const classifier = new Classifier();
		for (let i = 0; i < 100; i++) {
			classifier.learn(['bad'], 'spam');
			classifier.learn(['good'], 'ham');
		}

		const metrics = await evaluate(classifier, [
			{label: 'spam', features: ['bad']},
			{label: 'spam', features: ['good']},
			{label: 'spam', features: ['unknown']},
			{label: 'ham', features: ['good']},
			{label: 'ham', features: ['bad']},
			{label: 'ham', features: ['unknown']},
		]);
		assert.deepEqual({
			tp: metrics.truePositive, fn: metrics.falseNegative, fp: metrics.falsePositive, tn: metrics.trueNegative, us: metrics.unsureSpam, uh: metrics.unsureHam,
		}, {
			tp: 1, fn: 1, fp: 1, tn: 1, us: 1, uh: 1,
		});
		assert.equal(metrics.precision, 0.5);
		assert.equal(metrics.recall, 1 / 3);
		assert.equal(metrics.falsePositiveRate, 1 / 3);
		assert.equal(metrics.unsureRate, 2 / 6);
		const empty = await evaluate(classifier, []);
		assert.equal(empty.precision, 0);
		assert.equal(empty.f1, 0);
	});
});
