import assert from 'node:assert/strict';
import path from 'node:path';
import {writeFileSync} from 'node:fs';
import {describe, it} from 'node:test';
import SpamScanner from '../src/index.js';
import {readJsonl} from '../src/sources.js';
import {temporaryDirectory} from './helpers/index.js';

const offline = {phishing: {cloudflare: false}};

async function collect(iterable) {
	const out = [];
	for await (const item of iterable) {
		out.push(item);
	}

	return out;
}

describe('languages allowed by other codes', () => {
	it('allows Norwegian as "no" and Filipino as "fil"', async () => {
		const scanner = new SpamScanner({...offline, classifier: false});
		const norwegian = 'Hei Kari,\n\nTakk for møtet i går. Jeg har sendt deg referatet fra styremøtet, og vi må bestemme datoen for neste samling før fredag. Kan du se gjennom budsjettet og gi meg beskjed om det er noe som mangler? Vi snakkes i morgen.\n\nMed vennlig hilsen\nOla';
		const filipino = 'Magandang umaga po! Salamat sa inyong mensahe kahapon. Ipapadala ko po ang mga dokumento bukas ng hapon pagkatapos ng aming pulong sa opisina. Sana ay maayos ang lahat sa inyong pamilya.';
		for (const [text, allowed, detected] of [[norwegian, ['no'], 'nb'], [filipino, ['fil'], 'tl']]) {
			const result = await scanner.scan(`From: a@sender.example\r\nTo: b@recipient.example\r\nSubject: hei\r\n\r\n${text}\r\n`, {allowedLanguages: allowed});
			assert.equal(result.results.language.language, detected);
			assert.equal(result.results.language.notAllowed, false, allowed[0]);
		}
	});
});

describe('link hosts counted once', () => {
	it('counts a link through a security gateway, or with a final dot, by the host looked up', async () => {
		const scanner = new SpamScanner({...offline, classifier: false});
		const safe = url => `https://nam12.safelinks.protection.outlook.com/?url=${encodeURIComponent(url)}&amp;data=05`;
		for (const html of [
			`<a href="${safe('https://a.example.com/')}">A</a> <a href="${safe('https://b.example.org/')}">B</a>`,
			'<a href="https://www.example.com./x">x</a>',
			'<a href="https://[2001:db8::1]/x">x</a>',
		]) {
			const result = await scanner.scan(`From: a@sender.example\r\nTo: b@recipient.example\r\nSubject: hi\r\nContent-Type: text/html\r\n\r\n${html}\r\n`);
			assert.equal(result.results.uncheckedHosts, 0, html);
		}
	});
});

describe('text without a header', () => {
	it('scans text whose first line is not a header field as the message\'s text, as parse() and learn() read it', async () => {
		const scanner = new SpamScanner({...offline, classifier: false});
		for (const text of ['Hello there, how are you?\nSecond line', 'Dear user:\nyour account is ready']) {
			const result = await scanner.scan(text);
			assert.equal(result.mail.text, text);
			assert.equal(result.mail.text, (await scanner.parse(text)).mail.text);
		}

		const headed = await scanner.scan('Subject: hi\n\nbody');
		assert.deepEqual([headed.mail.subject, headed.mail.text], ['hi', 'body']);
	});
});

describe('JSON Lines fields that hold nothing', () => {
	it('takes the next name when a field is empty or not a label, and the content before an address', async () => {
		const file = path.join(temporaryDirectory(), 'fields.jsonl');
		writeFileSync(file, `${[
			JSON.stringify({text: 'win a prize', label_text: '', label: 1}),
			JSON.stringify({text: 'see you', label_text: 'unknown', label: 'ham'}),
			JSON.stringify({email: 'sender@example.com', content: 'the quarterly report', label: 'ham'}),
			JSON.stringify({text: '', body: 'free money', label: 'spam'}),
			JSON.stringify({email: 'only an address field', label: 'nothing'}),
		].join('\n')}\n`);
		assert.deepEqual(await collect(readJsonl(file)), [
			{text: 'win a prize', subject: '', label: 'spam'},
			{text: 'see you', subject: '', label: 'ham'},
			{text: 'the quarterly report', subject: '', label: 'ham'},
			{text: 'free money', subject: '', label: 'spam'},
		]);
	});
});
