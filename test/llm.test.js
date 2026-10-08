import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {describe, it} from 'node:test';
import {requestJson} from '../src/http.js';
import {
	DEFAULT_SYSTEM_PROMPT, LLMClassifier, PROVIDERS, VERDICTS, authHeaders, buildRequest, describeMessage, parseClassifierOutput, parseVerdict, redact, replyText, resolveConfig,
} from '../src/llm.js';
import {ReputationChecker, matchList, reputationValues} from '../src/reputation.js';
import {httpServer} from './helpers/index.js';

const verdict = (value, extra = {}) => JSON.stringify({
	verdict: value, confidence: 0.9, language: 'en', reasons: ['test reason'], ...extra,
});

const mail = {
	from: {value: [{name: 'Shop', address: 'deals@shop.example'}]},
	replyTo: {value: [{address: 'reply@other.example'}]},
	to: [{value: [{address: 'bob@example.net'}]}],
	subject: 'Deal',
	text: 'Buy now at https://shop.example/buy?token=secret123 or call +1 555 010 0199, card 4111 1111 1111 1111, mail bob@example.net, SSN 123-45-6789.',
	attachments: [{filename: 'a.pdf', contentType: 'application/pdf'}, {}],
};

describe('LLM configuration', () => {
	it('defaults to a local Ollama server, and to an OpenAI-compatible server when given a URL', () => {
		const ollama = resolveConfig({}, {});
		assert.equal(ollama.provider, 'ollama');
		assert.equal(ollama.baseUrl, 'http://127.0.0.1:11434');
		assert.equal(ollama.model, 'qwen3.5:4b');
		assert.equal(ollama.local, true);
		assert.equal(ollama.redact, false);
		const custom = resolveConfig({baseUrl: 'https://llm.example/v1/', model: 'm'}, {});
		assert.equal(custom.provider, 'openai-compatible');
		assert.equal(custom.baseUrl, 'https://llm.example/v1');
		assert.equal(custom.redact, true);
		assert.equal(resolveConfig({url: 'http://10.0.0.5:8000/v1', model: 'm'}, {}).provider, 'openai-compatible');
		assert.equal(resolveConfig({host: 'gpu.example', model: 'm'}, {}).baseUrl, 'http://gpu.example');
	});

	it('replaces parts of a preset URL: protocol, host, port and path', () => {
		const config = resolveConfig({
			provider: 'ollama', host: '10.0.0.5', port: 8434, protocol: 'https', path: '/ollama',
		}, {});
		assert.equal(config.baseUrl, 'https://10.0.0.5:8434/ollama');
		assert.equal(config.local, true);
		assert.equal(resolveConfig({provider: 'vllm', port: 9000, model: 'x'}, {}).baseUrl, 'http://127.0.0.1:9000/v1');
		assert.equal(resolveConfig({provider: 'openai', protocol: 'http:', model: 'x'}, {}).baseUrl, 'http://api.openai.com/v1');
	});

	it('reads API keys from options, SPAMSCANNER_LLM_API_KEY or the provider\'s own variable', () => {
		assert.equal(resolveConfig({provider: 'anthropic'}, {ANTHROPIC_API_KEY: 'a'}).apiKey, 'a');
		assert.equal(resolveConfig({provider: 'anthropic'}, {ANTHROPIC_API_KEY: 'a', SPAMSCANNER_LLM_API_KEY: 'b'}).apiKey, 'b');
		assert.equal(resolveConfig({provider: 'anthropic', apiKey: 'c'}, {SPAMSCANNER_LLM_API_KEY: 'b'}).apiKey, 'c');
		assert.equal(resolveConfig({provider: 'ollama'}, {}).apiKey, null);
		assert.equal(resolveConfig({
			provider: 'openai-compatible', baseUrl: 'http://x', model: 'm', apiKey: 'k',
		}, {}).auth, 'bearer');
	});

	it('rejects unknown providers, missing URLs and missing models', () => {
		assert.throws(() => resolveConfig({provider: 'nope'}), /Unknown LLM provider "nope"/);
		assert.throws(() => resolveConfig({provider: 'azure', model: 'x'}), /needs a base URL/);
		assert.throws(() => resolveConfig({provider: 'openrouter'}, {}), /needs a model name/);
		assert.equal(resolveConfig({provider: 'tei'}, {}).model, undefined);
	});

	it('has presets for the major providers and local servers', () => {
		for (const name of ['ollama', 'lmstudio', 'llamacpp', 'vllm', 'openai', 'anthropic', 'gemini', 'mistral', 'groq', 'openrouter', 'deepseek', 'huggingface', 'azure', 'openai-compatible', 'tei']) {
			assert.ok(PROVIDERS[name], name);
		}

		assert.deepEqual(VERDICTS, ['spam', 'phishing', 'scam', 'malware', 'ham']);
		assert.match(DEFAULT_SYSTEM_PROMPT, /untrusted data/);
	});

	it('builds every kind of authentication header', () => {
		assert.deepEqual(authHeaders({auth: 'none'}), {});
		assert.deepEqual(authHeaders({auth: 'bearer', apiKey: 'k'}), {authorization: 'Bearer k'});
		assert.deepEqual(authHeaders({auth: 'bearer', apiKey: 'k', authPrefix: 'Token '}), {authorization: 'Token k'});
		assert.deepEqual(authHeaders({auth: 'bearer'}), {});
		assert.deepEqual(authHeaders({auth: 'x-api-key', apiKey: 'k'}), {'x-api-key': 'k'});
		assert.deepEqual(authHeaders({auth: 'x-api-key'}), {});
		assert.deepEqual(authHeaders({auth: 'api-key', apiKey: 'k'}), {'api-key': 'k'});
		assert.deepEqual(authHeaders({auth: 'api-key'}), {});
		assert.deepEqual(authHeaders({auth: 'basic', username: 'u', password: 'p'}), {authorization: `Basic ${Buffer.from('u:p').toString('base64')}`});
		assert.deepEqual(authHeaders({auth: 'basic', apiKey: 'k'}), {authorization: `Basic ${Buffer.from(':k').toString('base64')}`});
		assert.deepEqual(authHeaders({auth: 'basic'}), {authorization: `Basic ${Buffer.from(':').toString('base64')}`});
		assert.deepEqual(authHeaders({auth: 'header', authHeader: 'X-Key', apiKey: 'k'}), {'x-key': 'k'});
		assert.deepEqual(authHeaders({
			auth: 'header', authHeader: 'X-Key', authPrefix: 'Key ', apiKey: 'k',
		}), {'x-key': 'Key k'});
		assert.deepEqual(authHeaders({auth: 'header', authHeader: 'X-Key'}), {});
		assert.throws(() => authHeaders({auth: 'header'}), /needs authHeader/);
		assert.throws(() => authHeaders({auth: 'magic'}), /Unknown auth "magic"/);
	});
});

describe('message description and verdict parsing', () => {
	it('describes headers, links and attachments, and redacts personal data for remote services', () => {
		const text = describeMessage(mail, {authentication: 'spf=pass dkim=none', links: [{url: 'https://shop.example/buy', text: 'https://shop.example'}, {url: 'https://x.example/', text: null}]}, {redact: false});
		assert.match(text, /^From: "Shop" <deals@shop\.example>/);
		assert.match(text, /Reply-To: <reply@other\.example>/);
		assert.match(text, /To: <bob@example\.net>/);
		assert.match(text, /Authentication: spf=pass/);
		assert.match(text, /shown as "https:\/\/shop\.example", goes to https:\/\/shop\.example\/buy/);
		assert.match(text, /Attachments: a\.pdf \(application\/pdf\), unnamed \(unknown type\)/);
		const hidden = describeMessage(mail, {}, {redact: true});
		assert.ok(!hidden.includes('secret123'));
		assert.ok(!hidden.includes('4111'));
		assert.ok(!hidden.includes('555 010'));
		assert.ok(!hidden.includes('123-45-6789'));
		assert.ok(hidden.includes('[email]@example.net'));
		assert.equal(redact('no data'), 'no data');
	});

	it('shortens long messages and reads HTML when there is no text', () => {
		const short = describeMessage({subject: 's', text: 'word '.repeat(5000)}, {}, {maxInputChars: 100});
		assert.ok(short.endsWith('[message shortened]'));
		const html = describeMessage({from: {value: [{address: 'a@b.example'}]}, html: '<style>x{}</style><p>Hello <b>there</b></p><script>bad()</script>', to: {value: [{}]}});
		assert.match(html, /Hello there/);
		assert.ok(!html.includes('bad()'));
		assert.match(html, /To: <>/);
		assert.match(describeMessage({}), /^From: \nSubject: \n\n$/);
		assert.match(describeMessage({from: {value: [{name: 'Only Name'}]}}), /^From: "Only Name" <>/);
		assert.match(describeMessage({text: '  ', html: false}), /^From: /);
	});

	it('finds the verdict in JSON, prose, code fences and reasoning output', () => {
		assert.deepEqual(parseVerdict(verdict('phishing')), {
			verdict: 'phishing', confidence: 0.9, language: 'en', reasons: ['test reason'],
		});
		assert.equal(parseVerdict(`Sure! \`\`\`json\n${verdict('scam')}\n\`\`\``).verdict, 'scam');
		assert.equal(parseVerdict(`<think>maybe {"verdict": "ham"}</think>${verdict('spam')}`).verdict, 'spam');
		assert.equal(parseVerdict(String.raw`{"note": "a \"quoted\" {brace}"} {"label": "Not Spam", "score": 85}`).verdict, 'ham');
		assert.equal(parseVerdict('{"label": "Not Spam", "score": 85}').confidence, 0.85);
		assert.equal(parseVerdict('{"classification": "malware", "probability": "high"}').confidence, 0.6);
		assert.equal(parseVerdict('{"category": "spam", "confidence": 7}').confidence, 0.07);
		assert.equal(parseVerdict('{"category": "spam", "confidence": 700}').confidence, 1);
		assert.equal(parseVerdict('{"verdict": "spam", "confidence": -1}').confidence, 0);
		assert.deepEqual(parseVerdict('{"verdict": "ham", "reason": "friendly", "language": "toolonglanguage"}').reasons, ['friendly']);
		assert.equal(parseVerdict('{"verdict": "ham", "language": "toolonglanguage"}').language, null);
		assert.equal(parseVerdict('{"verdict": "unknown"} and later the word legitimate').verdict, 'ham');
		assert.equal(parseVerdict('{"broken": json} This looks like PHISHING to me').verdict, 'phishing');
		assert.equal(parseVerdict('{"open": "never closed'), null);
		assert.equal(parseVerdict('[1, 2] no verdict here'), null);
		assert.equal(parseVerdict('{"verdict": null}'), null);
		assert.equal(parseVerdict(null), null);
		assert.equal(parseVerdict('{"verdict": ["spam"]}').verdict, 'spam');
		assert.equal(parseVerdict('{"details": {"nested": true}, "verdict": "malware"}').verdict, 'malware');
		assert.equal(parseVerdict('{"verdict": 7} nothing'), null);
	});

	it('reads text classification model output', () => {
		assert.deepEqual(parseClassifierOutput([[{label: 'LABEL_1', score: 0.97}, {label: 'LABEL_0', score: 0.03}]]), {
			verdict: 'spam', confidence: 0.97, language: null, reasons: ['classifier: LABEL_1 0.970, LABEL_0 0.030'],
		});
		assert.equal(parseClassifierOutput([{label: 'Safe Email', score: 0.8}, {label: 'Phishing Email', score: 0.2}]).verdict, 'ham');
		assert.equal(parseClassifierOutput([{label: 'bad', score: 0.9}, {label: 'good', score: 'x'}], {bad: 'spam', good: 'ham'}).verdict, 'spam');
		assert.equal(parseClassifierOutput([{label: 'x', score: 'y'}]).confidence, 0);
		assert.equal(parseClassifierOutput([{label: 'spam', score: 'n/a'}]).confidence, 0);
		assert.equal(parseClassifierOutput([{label: 'Phishing', score: 0.7}, {label: 'ok', score: 0.3}], {ok: 'ham'}).verdict, 'spam');
		assert.equal(parseClassifierOutput([]), null);
		assert.equal(parseClassifierOutput({error: 'x'}), null);
	});

	it('reads replies of each API style', () => {
		assert.equal(replyText('anthropic', {content: [{type: 'thinking', thinking: 'x'}, {type: 'text', text: 'a'}, {type: 'text', text: 'b'}]}), 'ab');
		assert.equal(replyText('anthropic', {content: []}), null);
		assert.equal(replyText('anthropic', {}), null);
		assert.equal(replyText('ollama', {message: {content: 'x'}}), 'x');
		assert.equal(replyText('ollama', {response: 'y'}), 'y');
		assert.equal(replyText('ollama', {}), null);
		assert.equal(replyText('openai', {choices: [{message: {content: 'z'}}]}), 'z');
		assert.equal(replyText('openai', {choices: [{message: {content: null, reasoning_content: 'r'}}]}), 'r');
		assert.equal(replyText('openai', {}), null);
	});

	it('builds requests for each API style', () => {
		const anthropic = buildRequest(resolveConfig({
			provider: 'anthropic', apiKey: 'k', temperature: 0, policy: 'We never send invoices.',
		}, {}), 'text');
		assert.equal(anthropic.url, 'https://api.anthropic.com/v1/messages');
		assert.equal(anthropic.headers['x-api-key'], 'k');
		assert.equal(anthropic.headers['anthropic-version'], '2023-06-01');
		assert.equal(anthropic.body.temperature, 0);
		assert.match(anthropic.body.system, /We never send invoices/);
		assert.match(anthropic.body.messages[0].content, /<<<EMAIL [\da-f]{12}>>>\ntext\n<<<END EMAIL [\da-f]{12}>>>/);
		const ollama = buildRequest(resolveConfig({keepAlive: '10m', json: false}, {}), 't');
		assert.equal(ollama.body.keep_alive, '10m');
		assert.equal(ollama.body.format, undefined);
		assert.equal(ollama.body.think, false);
		assert.equal(buildRequest(resolveConfig({provider: 'groq', apiKey: 'k', temperature: 0.2}, {}), 't').body.temperature, 0.2);
		assert.equal(buildRequest(resolveConfig({provider: 'lmstudio', model: 'm'}, {}), 't').body.response_format, undefined);
		const openai = buildRequest(resolveConfig({provider: 'openai', apiKey: 'k'}, {}), 't');
		assert.equal(openai.body.max_completion_tokens, 400);
		assert.deepEqual(openai.body.response_format, {type: 'json_object'});
		assert.equal(openai.body.temperature, undefined);
		const azure = buildRequest(resolveConfig({
			provider: 'azure', baseUrl: 'https://x.openai.azure.com/openai/deployments/d', query: {'api-version': '2025-01-01'}, apiKey: 'k', model: 'd',
		}, {}), 't');
		assert.equal(azure.url, 'https://x.openai.azure.com/openai/deployments/d/chat/completions?api-version=2025-01-01');
		assert.equal(azure.headers['api-key'], 'k');
		const hf = buildRequest(resolveConfig({provider: 'huggingface-classifier', apiKey: 'k'}, {}), 't');
		assert.equal(hf.url, 'https://router.huggingface.co/hf-inference/models/cybersectony/phishing-email-detection-distilbert_v2.4.1');
		assert.deepEqual(hf.body, {inputs: 't', truncate: true});
		assert.throws(() => buildRequest({...resolveConfig({}, {}), api: 'soap'}, 't'), /Unknown LLM API "soap"/);
	});
});

describe('LLM classification against servers', () => {
	it('talks to Ollama, OpenAI-compatible, Anthropic and classifier APIs', async () => {
		const server = await httpServer(request => {
			switch (request.url) {
				case '/api/chat': {
					return {message: {content: verdict('spam')}};
				}

				case '/v1/chat/completions': {
					return {choices: [{message: {content: verdict('ham')}}]};
				}

				case '/v1/messages': {
					return {content: [{type: 'text', text: verdict('scam')}]};
				}

				case '/predict': {
					return [{label: 'spam', score: 0.88}, {label: 'ham', score: 0.12}];
				}

				default: {
					return {status: 404, body: 'no'};
				}
			}
		});
		try {
			const ollama = new LLMClassifier({provider: 'ollama', baseUrl: server.url, model: 'test'}, {});
			assert.equal((await ollama.classify(mail)).verdict, 'spam');
			const openai = new LLMClassifier({
				provider: 'vllm', baseUrl: `${server.url}/v1`, model: 'test', apiKey: 'secret',
			}, {});
			const ham = await openai.classify(mail);
			assert.equal(ham.verdict, 'ham');
			assert.equal(ham.provider, 'vllm');
			const anthropic = new LLMClassifier({
				provider: 'anthropic', baseUrl: `${server.url}/v1`, apiKey: 'k', redact: true,
			}, {});
			assert.equal((await anthropic.classify(mail)).verdict, 'scam');
			const tei = new LLMClassifier({provider: 'tei', baseUrl: `${server.url}/predict`}, {});
			const classified = await tei.classify(mail);
			assert.equal(classified.verdict, 'spam');
			assert.equal(classified.model, null);
			const requests = server.requests.map(request => [request.url, request.headers.authorization || request.headers['x-api-key'] || null]);
			assert.deepEqual(requests, [['/api/chat', null], ['/v1/chat/completions', 'Bearer secret'], ['/v1/messages', 'k'], ['/predict', null]]);
			// Redaction is on for remote services (asked for here), off for local ones.
			assert.ok(server.requests[2].body.messages[0].content.includes('[redacted]'));
			assert.ok(server.requests[0].body.messages[1].content.includes('secret123'));
		} finally {
			await server.close();
		}
	});

	it('caches verdicts by message, with a size limit', async () => {
		const server = await httpServer(() => ({message: {content: verdict('spam')}}));
		try {
			const classifier = new LLMClassifier({baseUrl: server.url, provider: 'ollama', cacheSize: 1}, {});
			assert.equal((await classifier.classifyText('one')).cached, false);
			assert.equal((await classifier.classifyText('one')).cached, true);
			await classifier.classifyText('two');
			assert.equal((await classifier.classifyText('one')).cached, false);
			assert.equal(server.requests.length, 3);
			const uncached = new LLMClassifier({baseUrl: server.url, provider: 'ollama', cacheSize: 0}, {});
			await uncached.classifyText('one');
			assert.equal((await uncached.classifyText('one')).cached, false);
		} finally {
			await server.close();
		}
	});

	it('limits concurrent requests', async () => {
		let active = 0;
		let peak = 0;
		const server = await httpServer(async () => {
			active++;
			peak = Math.max(peak, active);
			await new Promise(resolve => {
				setTimeout(resolve, 30);
			});
			active--;
			return {message: {content: verdict('ham')}};
		});
		try {
			const classifier = new LLMClassifier({baseUrl: server.url, provider: 'ollama', concurrency: 2}, {});
			await Promise.all(['a', 'b', 'c', 'd', 'e'].map(text => classifier.classifyText(text)));
			assert.equal(peak, 2);
		} finally {
			await server.close();
		}
	});

	it('reports HTTP errors, bad JSON, missing verdicts, timeouts and huge replies', async () => {
		const server = await httpServer(request => {
			switch (request.url) {
				case '/error/api/chat': {
					return {status: 500, body: 'model not loaded'};
				}

				case '/text/api/chat': {
					return {status: 200, headers: {'content-type': 'text/plain'}, body: 'not json'};
				}

				case '/empty/api/chat': {
					return {message: {content: 'I cannot help with that.'}};
				}

				case '/huge/api/chat': {
					return {message: {content: 'x'.repeat(5000)}};
				}

				default: {
					return 'hang';
				}
			}
		});
		const make = (path, extra = {}) => new LLMClassifier({
			provider: 'ollama', baseUrl: `${server.url}${path}`, timeout: 300, ...extra,
		}, {});
		try {
			await assert.rejects(make('/error').classifyText('x'), /HTTP 500 .*model not loaded/);
			await assert.rejects(make('/text').classifyText('x'), /Invalid JSON/);
			await assert.rejects(make('/empty').classifyText('x'), /Ollama returned no verdict/);
			await assert.rejects(make('/huge', {maxResponseBytes: 100}).classifyText('x'), /larger than 100 bytes/);
			await assert.rejects(make('/hang').classifyText('x'), /timed out after 300 ms/);
			await assert.rejects(make('', {baseUrl: 'http://127.0.0.1:1'}).classifyText('x'), /ECONNREFUSED/);
		} finally {
			await server.close();
		}
	});

	it('speaks HTTPS with a custom certificate authority option and sends GET requests', async () => {
		const server = await httpServer(request => ({method: request.method}));
		try {
			assert.deepEqual(await requestJson('GET', `${server.url}/x`, null, {}), {method: 'GET'});
			await assert.rejects(requestJson('GET', 'https://127.0.0.1:1/', null, {ca: 'not a certificate', timeout: 500}), /econnrefused|certificate|pem/i);
		} finally {
			await server.close();
		}
	});
});

describe('reputation', () => {
	it('matches IPs, domains, subdomains and addresses in lists', () => {
		const list = new Set(['192.0.2.1', 'example.com', 'person@example.org']);
		assert.equal(matchList('192.0.2.1', list), '192.0.2.1');
		assert.equal(matchList('192.0.2.2', list), null);
		assert.equal(matchList('mail.example.com', list), 'example.com');
		assert.equal(matchList('anyone@example.com', list), 'example.com');
		assert.equal(matchList('Person@Example.org', list), 'person@example.org');
		assert.equal(matchList('other@example.org', list), null);
		assert.equal(matchList('', list), null);
		assert.equal(matchList('x', new Set()), null);
	});

	it('collects the values to check from the message and session', () => {
		const values = reputationValues({from: {value: [{address: 'A@Mail.Example.com'}, {name: 'no address'}]}, replyTo: {value: [{address: 'r@reply.example'}]}}, {remoteAddress: '192.0.2.1', resolvedClientHostname: 'mx.sender.example', envelope: {mailFrom: {address: 'bounce@sender.example'}}});
		assert.deepEqual(values, ['192.0.2.1', 'mx.sender.example', 'sender.example', 'a@mail.example.com', 'mail.example.com', 'example.com', 'bounce@sender.example', 'r@reply.example', 'reply.example']);
		assert.deepEqual(reputationValues(), []);
	});

	it('checks local lists and a reputation service, caching answers and failures', async () => {
		const server = await httpServer(request => {
			const q = new URL(request.url, 'http://x').searchParams.get('q');
			if (q === 'truth.example') {
				return {isTruthSource: true};
			}

			if (q === 'listed.example') {
				return {isDenylisted: true, denylistValue: 'listed.example'};
			}

			if (q === 'friend.example') {
				return {isAllowlisted: true};
			}

			if (q === 'listed2.example') {
				return {isDenylisted: true};
			}

			if (q === 'null.example') {
				return null;
			}

			if (q === 'broken.example') {
				return {status: 503, body: 'down'};
			}

			return {};
		});
		try {
			const checker = new ReputationChecker({
				allowlist: ['good.example'], denylist: ['bad.example', '203.0.113.9'], apiUrl: `${server.url}/v1/reputation`, headers: {authorization: 'Bearer t'}, concurrency: 2,
			});
			const result = await checker.check(['203.0.113.9', 'x@good.example', 'truth.example', 'listed.example', 'friend.example', 'broken.example', null]);
			assert.equal(result.isDenylisted, true);
			assert.equal(result.denylistValue, '203.0.113.9');
			assert.equal(result.isAllowlisted, true);
			assert.equal(result.allowlistValue, 'good.example');
			assert.equal(result.isTruthSource, true);
			assert.equal(result.truthSourceValue, 'truth.example');
			assert.match(result.details['broken.example'].error, /HTTP 503/);
			assert.equal(server.requests[0].headers.authorization, 'Bearer t');
			const before = server.requests.length;
			await checker.check(['broken.example', 'truth.example']);
			assert.equal(server.requests.length, before);
			const second = await checker.check(['listed2.example', 'null.example']);
			assert.equal(second.denylistValue, 'listed2.example');
			assert.equal(second.details['null.example'].isDenylisted, false);
			const local = await new ReputationChecker({denylist: ['bad.example']}).check(['bad.example']);
			assert.deepEqual([local.isDenylisted, local.details], [true, {}]);
			const small = new ReputationChecker({apiUrl: server.url, cacheSize: 1});
			await small.check(['a.example', 'b.example']);
			assert.equal(small.cache.size, 1);
		} finally {
			await server.close();
		}
	});
});
