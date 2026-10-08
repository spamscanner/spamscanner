import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {describe, it} from 'node:test';
import {
	foldHeader, rewriteMessage, spamHeaders, splitMessage,
} from '../src/headers.js';
import {DEFAULT_SCORES, bayesTestName, scoreResults} from '../src/score.js';

const names = result => result.tests.map(test => test.name);

describe('scoreResults', () => {
	it('scores the classifier on a sliding scale, named like SpamAssassin', () => {
		assert.deepEqual(scoreResults({classification: {probability: 1, category: 'spam'}}).tests, [{name: 'BAYES_999', score: DEFAULT_SCORES.bayesSpam, description: 'Classifier spam probability 100.0%'}]);
		assert.equal(scoreResults({classification: {probability: 0}}).score, -DEFAULT_SCORES.bayesHam);
		assert.deepEqual(names(scoreResults({classification: {probability: 0.5}})), ['BAYES_50']);
		assert.equal(scoreResults({classification: {probability: 0.5}}).tests[0].score, 0);
		// On the log-odds scale, 99% is exactly the spam threshold and 90% is not near it.
		assert.equal(scoreResults({classification: {probability: 0.99}}).score, 5);
		assert.equal(scoreResults({classification: {probability: 0.9}}).score, 2.39);
		assert.equal(scoreResults({classification: {probability: 0.01}}).score, -2);
		assert.deepEqual(names(scoreResults({classification: {probability: 0.7, category: 'disabled'}})), []);
		assert.deepEqual(names(scoreResults({classification: {}})), []);
		assert.deepEqual([0.9995, 0.995, 0.96, 0.85, 0.65, 0.45, 0.3, 0.1, 0.03, 0].map(p => bayesTestName(p)), ['BAYES_999', 'BAYES_99', 'BAYES_95', 'BAYES_80', 'BAYES_60', 'BAYES_50', 'BAYES_40', 'BAYES_20', 'BAYES_05', 'BAYES_00']);
	});

	it('scores links', () => {
		const result = scoreResults({
			phishing: [
				{type: 'homograph', riskScore: 0.95, message: 'a'},
				{
					type: 'homograph', riskScore: 0.6, mixedScripts: true, message: 'b',
				},
				{type: 'homograph', riskScore: 0.6, message: 'c'},
				{type: 'homograph', riskScore: 0.5, message: 'd'},
				{type: 'deceptive_link', message: 'e'},
				{type: 'malicious_domain', message: 'f'},
				{type: 'adult_domain', message: 'g'},
				{type: 'uribl', zone: 'dbl.spamhaus.org', message: 'h'},
				{type: 'something_new', message: 'i'},
			],
		});
		assert.deepEqual(names(result), ['PHISHING_LOOKALIKE_DOMAIN', 'MIXED_SCRIPT_DOMAIN', 'BRAND_IN_DOMAIN', 'TYPO_DOMAIN', 'DECEPTIVE_LINK', 'MALICIOUS_DOMAIN', 'ADULT_DOMAIN', 'URIBL_DBL']);
	});

	it('scores attachments, viruses, rules, obfuscation, authentication, reputation, blocklists and language', () => {
		const result = scoreResults({
			attachments: [{type: 'executable', message: 'x'}, {type: 'html_attachment', active: true, message: 'y'}, {type: 'macro', message: 'z'}, {type: 'unknown_kind'}],
			viruses: [{message: 'Eicar'}],
			arbitrary: {rules: [{name: 'GTUBE', score: 1000, message: 'gtube'}]},
			obfuscation: {invisible: 3, mixed: 2, styled: true},
			authentication: {score: {tests: [{name: 'DMARC_FAIL', score: 3.5}]}},
			reputation: {isDenylisted: true, denylistValue: 'bad.example'},
			dnsbl: [{zone: 'zen.spamhaus.org', value: '192.0.2.1'}],
			language: {notAllowed: true, language: 'ru'},
			toxicity: [{message: 'insult'}],
			nsfw: [{message: 'image'}],
		});
		assert.deepEqual(names(result), ['EXECUTABLE_ATTACHMENT', 'HTML_ATTACHMENT', 'MACRO_ATTACHMENT', 'VIRUS', 'GTUBE', 'INVISIBLE_CHARACTERS', 'MIXED_SCRIPT_WORDS', 'STYLED_LETTERS', 'DMARC_FAIL', 'DENYLISTED', 'RBL_ZEN', 'LANGUAGE_NOT_ALLOWED', 'TOXIC_CONTENT', 'NSFW_IMAGE']);
		assert.equal(result.tests[1].score, DEFAULT_SCORES.activeHtmlAttachment);
		assert.equal(result.action, 'reject');
	});

	it('takes points off for allowlisted and truth-source senders', () => {
		assert.deepEqual(names(scoreResults({reputation: {isAllowlisted: true, allowlistValue: 'x'}})), ['ALLOWLISTED']);
		assert.deepEqual(names(scoreResults({reputation: {isTruthSource: true, truthSourceValue: 'x'}})), ['TRUTH_SOURCE']);
		assert.deepEqual(names(scoreResults({reputation: {}})), []);
		assert.deepEqual(names(scoreResults({obfuscation: {invisible: 2, mixed: 1}})), []);
	});

	it('adds or removes points for the language model\'s verdict, scaled by confidence', () => {
		const spam = scoreResults({
			llm: {
				verdict: 'phishing', confidence: 0.5, model: 'qwen', reasons: ['urgent'],
			},
		});
		assert.deepEqual(spam.tests, [{name: 'LLM_PHISHING', score: DEFAULT_SCORES.llmSpam / 2, description: 'qwen says phishing (50%): urgent'}]);
		const ham = scoreResults({
			llm: {
				verdict: 'ham', confidence: 1, provider: 'ollama', reasons: [],
			},
		});
		assert.equal(ham.tests[0].score, -DEFAULT_SCORES.llmHam);
		assert.match(ham.tests[0].description, /^ollama says ham/);
		assert.equal(scoreResults({llm: {verdict: 'spam', confidence: 1, provider: 'x'}}).tests[0].description, 'x says spam (100%)');
		assert.deepEqual(names(scoreResults({llm: {verdict: null, error: 'down'}})), []);
		// A message that instructs AI filters gets no ham credit from the model, only the rule's points.
		const injection = {arbitrary: {rules: [{name: 'PROMPT_INJECTION', score: 3, message: 'm'}]}};
		assert.deepEqual(names(scoreResults({...injection, llm: {verdict: 'ham', confidence: 0.9, provider: 'x'}})), ['PROMPT_INJECTION']);
		assert.deepEqual(names(scoreResults({...injection, llm: {verdict: 'phishing', confidence: 0.9, provider: 'x'}})), ['PROMPT_INJECTION', 'LLM_PHISHING']);
	});

	it('decides accept, tag or reject with custom scores and thresholds', () => {
		const results = {attachments: [{type: 'macro', message: 'm'}]};
		assert.equal(scoreResults(results).action, 'accept');
		assert.equal(scoreResults(results, {threshold: 4}).action, 'tag');
		assert.equal(scoreResults(results, {scores: {macro: 20}}).action, 'reject');
		// A test name sets that test's points, including rules with fixed scores.
		assert.equal(scoreResults(results, {scores: {MACRO_ATTACHMENT: 0.5}}).score, 0.5);
		assert.equal(scoreResults({arbitrary: {rules: [{name: 'FROM_NAME_BRAND', score: 2, message: 'm'}]}}, {scores: {FROM_NAME_BRAND: 7}}).action, 'tag');
		assert.equal(scoreResults(results, {threshold: 1, rejectThreshold: 3}).action, 'reject');
		assert.equal(scoreResults().score, 0);
	});

	it('counts each test once and ignores non-numeric scores', () => {
		const result = scoreResults({arbitrary: {rules: [{name: 'X', score: 1}, {name: 'X', score: 1}, {name: 'Y', score: Number.NaN}]}});
		assert.deepEqual(names(result), ['X']);
	});
});

describe('headers', () => {
	const result = {
		score: 7.25, threshold: 5, isSpam: true, action: 'tag', tests: [{name: 'BAYES_99'}, {name: 'DECEPTIVE_LINK'}],
	};

	it('makes SpamAssassin-style headers', () => {
		const headers = Object.fromEntries(spamHeaders(result, {version: '7.0.0'}));
		assert.deepEqual(headers, {
			'X-Spam-Flag': 'YES',
			'X-Spam-Score': '7.3',
			'X-Spam-Level': '*******',
			'X-Spam-Status': 'Yes, score=7.3 required=5.0 tests=BAYES_99,DECEPTIVE_LINK version=7.0.0',
			'X-Spam-Action': 'tag',
		});
		const ham = Object.fromEntries(spamHeaders({
			score: -2, threshold: 5, isSpam: false, action: 'accept', tests: [],
		}));
		assert.equal(ham['X-Spam-Level'], '');
		assert.equal(ham['X-Spam-Status'], 'No, score=-2.0 required=5.0 tests=none');
	});

	it('folds long header values', () => {
		const folded = foldHeader('X-Spam-Status', `Yes, ${'TEST_NAME,'.repeat(30)}`);
		assert.ok(folded.split('\r\n').every(line => line.length <= 80));
		assert.ok(folded.split('\r\n').slice(1).every(line => line.startsWith('\t')));
		assert.equal(foldHeader('X', 'short', '\n'), 'X: short');
		assert.equal(foldHeader('X', 'a'.repeat(100)), `X: ${'a'.repeat(100)}`);
	});

	it('adds headers, removes forged ones and tags the subject, keeping the body byte for byte', () => {
		const body = Buffer.from([0xC3, 0xA9, 0x0D, 0x0A, 0xFF]);
		const raw = Buffer.concat([Buffer.from('X-Spam-Flag: NO\r\nX-Spam-Status: No,\r\n forged\r\nSubject: Hello\r\n there\r\nFrom: a@example.org\r\n\r\n'), body]);
		const out = rewriteMessage(raw, [['X-Spam-Flag', 'YES'], ['X-Note', 'café']], {subjectTag: '[SPAM]'});
		const text = out.toString('latin1');
		assert.equal((text.match(/X-Spam-Flag/g) || []).length, 1);
		assert.ok(!text.includes('forged'));
		assert.ok(text.includes('Subject: [SPAM] Hello\r\n there'));
		assert.equal(out.subarray(out.length - body.length).compare(body), 0);
		assert.ok(out.toString('utf8').includes('X-Note: café'));
		const twice = rewriteMessage(out, [], {subjectTag: '[SPAM]'}).toString();
		assert.equal((twice.match(/\[SPAM]/g) || []).length, 1);
	});

	it('handles LF line endings, missing subjects, header-only messages and strings', () => {
		const lf = rewriteMessage('From: a@example.org\n\nbody\n', [['X-Spam-Flag', 'NO']], {subjectTag: '[SPAM]'}).toString();
		assert.equal(lf, 'X-Spam-Flag: NO\nFrom: a@example.org\nSubject: [SPAM]\n\nbody\n');
		assert.equal(rewriteMessage('From: a@example.org', [['X-A', '1']]).toString(), 'X-A: 1\r\nFrom: a@example.org\r\n\r\n');
		assert.equal(rewriteMessage('From: a@example.org\r\n', [], {remove: /^from$/i}).toString(), '\r\n\r\n');
		assert.equal(rewriteMessage('', [['X-A', '1']]).toString(), 'X-A: 1\r\n\r\n');
		assert.equal(rewriteMessage('From: a@example.org\n', [['X-A', '1']]).toString(), 'X-A: 1\nFrom: a@example.org\n\n');
		assert.deepEqual(splitMessage(Buffer.from('A: b\r\n')), {header: 'A: b', body: Buffer.alloc(0), newline: '\r\n'});
	});
});
