import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {execFile} from 'node:child_process';
import {once} from 'node:events';
import {
	chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync,
} from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import process from 'node:process';
import {Readable} from 'node:stream';
import {describe, it} from 'node:test';
import {promisify} from 'node:util';
import {
	HELP, buildConfig, buildSession, deliver, main, parseCli,
} from '../src/cli.js';
import {GTUBE} from '../src/is-arbitrary.js';
import {VERSION} from '../src/version.js';
import {
	HAM, SPAM, httpServer, message, milterClient, sink, temporaryDirectory,
} from './helpers/index.js';

const run = promisify(execFile);
const offline = ['--no-cloudflare'];
const ham = message({subject: 'Lunch', text: 'Hi Bob, are we still on for lunch on Thursday at noon? Alice'});
const spam = message({subject: 'Test', text: GTUBE});

// Run the CLI in this process with fake standard streams.
async function cli(argv, {stdin = '', env = {}, onListening} = {}) {
	const stdout = sink();
	const stderr = sink();
	const code = await main(argv, {
		stdin: Readable.from([Buffer.from(stdin)]), stdout, stderr, env, onListening,
	});
	return {code, stdout: stdout.text(), stderr: stderr.text()};
}

// Start a server command; resolves once it listens, with the promise of its
// exit.
function serve(argv, env = {}) {
	return new Promise(resolve => {
		const done = cli(argv, {
			env,
			onListening(server) {
				resolve({server, done});
			},
		});
	});
}

// A sendmail stand-in that records its arguments and input.
function fakeSendmail(exitCode = 0) {
	const directory = temporaryDirectory();
	const file = path.join(directory, 'sendmail');
	writeFileSync(file, `#!/bin/sh\nprintf '%s\\n' "$@" > "${directory}/args"\ncat > "${directory}/message"\nexit ${exitCode}\n`);
	chmodSync(file, 0o755);
	return {
		file,
		args: () => readFileSync(path.join(directory, 'args'), 'utf8').trim().split('\n'),
		message: () => readFileSync(path.join(directory, 'message'), 'utf8'),
		delivered: () => existsSync(path.join(directory, 'message')),
	};
}

describe('command-line parsing', () => {
	it('parses commands, options and the optional --clamav value', () => {
		assert.deepEqual(parseCli(['scan', 'a.eml', '--json']).positionals, ['a.eml']);
		assert.equal(parseCli(['nonsense']).command, null);
		assert.equal(parseCli(['scan', '--clamav']).values.clamav, '');
		assert.equal(parseCli(['scan', '--clamav', '--json']).values.clamav, '');
		assert.equal(parseCli(['scan', '--clamav', '/run/clamd.sock']).values.clamav, '/run/clamd.sock');
		assert.throws(() => parseCli(['scan', '--bogus']), /Unknown option/);
	});

	it('builds scanner settings from options, on top of a config file', () => {
		const file = path.join(temporaryDirectory(), 'config.json');
		writeFileSync(file, JSON.stringify({
			threshold: 3, dnsbl: {ip: ['a.example']}, authentication: {timeout: 100}, llm: {provider: 'ollama', headers: {'x-a': '1'}}, reputation: {apiUrl: 'https://r.example'},
		}));
		const config = buildConfig(parseCli([
			'scan',
			'--config',
			file,
			'--reject-threshold',
			'20',
			'--model',
			'm.json',
			'--allow-language',
			'en, de,',
			'--auth',
			'--uribl',
			'dbl.example',
			'--dns-server',
			'127.0.0.1',
			'--no-cloudflare',
			'--clamav',
			'/run/clamd.sock',
			'--allowlist',
			'good.example',
			'--denylist',
			'bad.example',
			'--llm-model',
			'qwen3.5:4b',
			'--llm-url',
			'http://10.0.0.5:11434',
			'--llm-host',
			'h',
			'--llm-path',
			'/p',
			'--llm-protocol',
			'https',
			'--llm-api-key',
			'k',
			'--llm-auth',
			'header',
			'--llm-auth-header',
			'x-key',
			'--llm-username',
			'u',
			'--llm-password',
			'p',
			'--llm-mode',
			'always',
			'--llm-policy',
			'No invoices',
			'--llm-port',
			'8080',
			'--llm-timeout',
			'5000',
			'--llm-header',
			'X-B: two: parts',
			'--llm-redact',
			'--llm-method',
			'decision',
			'--llm-account',
			'acc',
		]).values, {});
		assert.equal(config.threshold, 3);
		assert.equal(config.rejectThreshold, 20);
		assert.equal(config.classifier, 'm.json');
		assert.deepEqual(config.allowedLanguages, ['en', 'de']);
		assert.deepEqual(config.authentication, {timeout: 100});
		assert.deepEqual(config.dnsbl, {ip: ['a.example'], domain: ['dbl.example']});
		assert.deepEqual(config.dns, {servers: ['127.0.0.1']});
		assert.equal(config.phishing.cloudflare, false);
		assert.deepEqual(config.clamav, {socket: '/run/clamd.sock'});
		assert.deepEqual(config.reputation, {apiUrl: 'https://r.example', allowlist: ['good.example'], denylist: ['bad.example']});
		assert.deepEqual(config.llm, {
			provider: 'ollama', headers: {'x-a': '1', 'x-b': 'two: parts'}, model: 'qwen3.5:4b', baseUrl: 'http://10.0.0.5:11434', host: 'h', path: '/p', protocol: 'https', apiKey: 'k', auth: 'header', authHeader: 'x-key', username: 'u', password: 'p', mode: 'always', policy: 'No invoices', method: 'decision', account: 'acc', port: 8080, timeout: 5000, redact: true,
		});

		const environment = buildConfig(parseCli(['scan', '--threshold', '7', '--no-classifier', '--enable-auth', '--dnsbl', 'zen.example', '--clamav', '--allowlist', 'a.example', '--llm', 'openai', '--no-llm-redact']).values, {SPAMSCANNER_CONFIG: file});
		assert.equal(environment.threshold, 7);
		assert.equal(environment.classifier, false);
		assert.deepEqual(environment.dnsbl, {ip: ['zen.example']});
		assert.equal(environment.clamav, true);
		assert.deepEqual(environment.reputation.allowlist, ['a.example']);
		assert.equal(environment.reputation.denylist, undefined);
		assert.equal(environment.llm.provider, 'openai');
		assert.equal(environment.llm.redact, false);
		assert.deepEqual(buildConfig(parseCli(['scan', '--auth', '--denylist', 'b.example']).values, {}), {authentication: true, reputation: {denylist: ['b.example']}});
		assert.throws(() => buildConfig(parseCli(['scan', '--threshold', 'lots']).values, {}), /--threshold must be a number/);
		assert.throws(() => buildConfig(parseCli(['scan', '--llm-header', 'novalue']).values, {}), /--llm-header must look like/);
	});

	it('builds the SMTP session from options', () => {
		assert.deepEqual(buildSession(parseCli(['scan', '--ip', '192.0.2.1', '--hostname', 'mx.example.org', '--helo', 'mx', '--from', 'a@example.org', '--to', 'b@example.com', '--to', 'c@example.com']).values), {
			remoteAddress: '192.0.2.1', resolvedClientHostname: 'mx.example.org', helo: 'mx', envelope: {mailFrom: {address: 'a@example.org'}, rcptTo: [{address: 'b@example.com'}, {address: 'c@example.com'}]},
		});
		assert.deepEqual(buildSession(parseCli(['scan', '--sender-ip', '192.0.2.2', '--sender-hostname', 'h.example', '--sender', '']).values), {
			remoteAddress: '192.0.2.2', resolvedClientHostname: 'h.example', envelope: {mailFrom: {address: ''}, rcptTo: []},
		});
		assert.deepEqual(buildSession(parseCli(['scan', '--to', 'b@example.com']).values).envelope.mailFrom, {address: ''});
		assert.deepEqual(buildSession({}), {});
	});
});

describe('spamscanner version and help', () => {
	it('prints the version and usage, and explains mistakes', async () => {
		assert.deepEqual(await cli(['version']), {code: 0, stdout: `spamscanner ${VERSION}\n`, stderr: ''});
		assert.equal((await cli(['--version'])).stdout, `spamscanner ${VERSION}\n`);
		assert.equal((await cli(['help'])).stdout, HELP);
		assert.equal((await cli(['scan', '--help'])).stdout, HELP);
		const nothing = await cli([]);
		assert.equal(nothing.code, 2);
		assert.equal(nothing.stderr, HELP);
		assert.equal((await cli(['frobnicate'])).code, 2);
		const bad = await cli(['scan', '--bogus']);
		assert.equal(bad.code, 2);
		assert.match(bad.stderr, /Unknown option '--bogus'[\s\S]*spamscanner help/);
	});
});

describe('spamscanner scan', () => {
	it('scans a file or standard input and exits 1 for spam', async () => {
		const file = path.join(temporaryDirectory(), 'ham.eml');
		writeFileSync(file, ham);
		const clean = await cli(['scan', file, ...offline]);
		assert.equal(clean.code, 0);
		assert.match(clean.stdout, /^HAM {2}score -?\d+\.\d \(spam at 5\.0, reject at 15\.0\) {2}action: accept {2}language: en\n/);
		const bad = await cli(['scan', '-', ...offline], {stdin: spam});
		assert.equal(bad.code, 1);
		assert.match(bad.stdout, /^SPAM[\s\S]*\+1000\.0 {2}GTUBE/m);
		const nothing = await cli(['scan', ...offline, '--no-classifier'], {stdin: message({text: '12345'})});
		assert.doesNotMatch(nothing.stdout, /language:/);
	});

	it('prints JSON, the message with headers, or every test and clue', async () => {
		const json = JSON.parse((await cli(['scan', '--json', ...offline], {stdin: spam})).stdout);
		assert.equal(json.isSpam, true);
		assert.equal(json.mail, undefined);
		const verboseJson = JSON.parse((await cli(['scan', '--json', '--verbose', ...offline], {stdin: ham})).stdout);
		assert.ok(verboseJson.tokens.includes('lunch'));
		const headers = await cli(['scan', '--headers', ...offline], {stdin: ham});
		assert.match(headers.stdout, /^X-Spam-Flag: NO\r\n[\s\S]*Subject: Lunch\r\n/);
		assert.match((await cli(['scan', '--add-headers', ...offline], {stdin: ham})).stdout, /^X-Spam-Flag: NO/);
		assert.match((await cli(['scan', '--subject-tag', '***SPAM***', ...offline], {stdin: spam})).stdout, /^Subject: \*{3}SPAM\*{3} Test\r\n/m);
		assert.match((await cli(['scan', '--prepend-subject', ...offline], {stdin: spam})).stdout, /^Subject: \[SPAM] Test\r\n/m);
		assert.match((await cli(['scan', '--prepend-subject', ...offline], {stdin: ham})).stdout, /^Subject: Lunch\r\n/m);
		const verbose = await cli(['scan', '--verbose', ...offline], {stdin: message({subject: SPAM[0][1], text: SPAM[0][2]})});
		assert.match(verbose.stdout, /Strongest clues:\n {4}\d\.\d{3} {2}\S+/);
		const unclued = await cli(['scan', '--verbose', '--no-classifier', ...offline], {stdin: ham});
		assert.doesNotMatch(unclued.stdout, /Strongest clues/);
		assert.match(unclued.stdout, / {3}0\.0 {2}MISSING|BAYES|^HAM/m);
	});

	it('reports a language model that fails, and errors with exit code 2', async () => {
		const failed = await cli(['scan', '--no-classifier', ...offline, '--llm', 'ollama', '--llm-url', 'http://127.0.0.1:1', '--llm-mode', 'always', '--llm-timeout', '2000'], {stdin: ham});
		assert.match(failed.stdout, /Language model failed: .*ECONNREFUSED/);
		const missing = await cli(['scan', path.join(temporaryDirectory(), 'missing.eml')]);
		assert.equal(missing.code, 2);
		assert.match(missing.stderr, /^spamscanner: ENOENT/);
		assert.doesNotMatch(missing.stderr, /\n {4}at /);
		const debug = await cli(['scan', '--threshold', 'x', '--debug']);
		assert.match(debug.stderr, /--threshold must be a number[\s\S]*\n {4}at /);
	});
});

describe('spamscanner filter', () => {
	it('adds headers and passes mail on to sendmail', async () => {
		const sendmail = fakeSendmail();
		const result = await cli(['filter', '--sendmail', sendmail.file, '--no-classifier', ...offline, '-f', 'alice@example.org', '--', 'bob@example.com', 'carol@example.com'], {stdin: ham});
		assert.equal(result.code, 0);
		assert.deepEqual(sendmail.args(), ['-G', '-i', '-f', 'alice@example.org', '--', 'bob@example.com', 'carol@example.com']);
		assert.match(sendmail.message(), /^X-Spam-Flag: NO\r\n/);
		assert.ok(sendmail.message().endsWith(ham.slice(ham.indexOf('\r\n\r\n'))));
		const tagged = fakeSendmail();
		await cli(['filter', '--sendmail', tagged.file, '--no-classifier', ...offline, '--subject-tag', '[SPAM]', '--sender', 'x@example.org', '--', 'bob@example.com'], {stdin: spam});
		assert.match(tagged.message(), /^X-Spam-Flag: YES[\s\S]*^Subject: \[SPAM] Test/m);
		assert.equal(tagged.args()[3], 'x@example.org');
		const untagged = fakeSendmail();
		await cli(['filter', '--sendmail', untagged.file, '--no-classifier', ...offline, '--', 'bob@example.com'], {stdin: spam});
		assert.match(untagged.message(), /^Subject: Test/m);
		assert.equal(untagged.args()[3], '');
	});

	it('rejects or discards mail at the reject threshold', async () => {
		const sendmail = fakeSendmail();
		const rejected = await cli(['filter', '--sendmail', sendmail.file, '--no-classifier', ...offline, '--reject', '--', 'bob@example.com'], {stdin: spam});
		assert.equal(rejected.code, 69);
		assert.match(rejected.stderr, /^5\.7\.1 Message rejected as spam \(score \d+/);
		const discarded = await cli(['filter', '--sendmail', sendmail.file, '--no-classifier', ...offline, '--discard', '--', 'bob@example.com'], {stdin: spam});
		assert.equal(discarded.code, 0);
		assert.equal(sendmail.delivered(), false);
	});

	it('defers when it cannot scan or deliver, and needs recipients', async () => {
		assert.equal((await cli(['filter', '--no-classifier'], {stdin: ham})).code, 64);
		const failing = fakeSendmail(1);
		const deferred = await cli(['filter', '--sendmail', failing.file, '--no-classifier', ...offline, '--', 'bob@example.com'], {stdin: ham});
		assert.equal(deferred.code, 75);
		assert.match(deferred.stderr, /sendmail exited with 1, deferring/);
		const missing = await cli(['filter', '--sendmail', path.join(temporaryDirectory(), 'none'), '--no-classifier', ...offline, '--', 'bob@example.com'], {stdin: ham});
		assert.equal(missing.code, 75);
		const broken = path.join(temporaryDirectory(), 'broken.json');
		writeFileSync(broken, '{"type":"nope"}');
		const unscanned = await cli(['filter', '--model', broken, '--', 'bob@example.com'], {stdin: ham});
		assert.equal(unscanned.code, 75);
		assert.match(unscanned.stderr, /scan failed, deferring/);
		assert.equal((await cli(['filter', '--threshold', 'x', '--', 'bob@example.com'], {stdin: ham})).code, 75);
	});

	it('reports sendmail being killed', async () => {
		const file = path.join(temporaryDirectory(), 'sendmail');
		writeFileSync(file, '#!/bin/sh\ncat > /dev/null\nkill -9 $$\n');
		chmodSync(file, 0o755);
		assert.equal(await deliver(file, [], Buffer.from(ham)), 'a signal');
	});
});

describe('spamscanner servers', () => {
	it('runs the milter until it is closed', async () => {
		const {server, done: stopped} = await serve(['milter', '--port', '0', '--no-classifier', ...offline, '--reject', '--reject-code', '550', '--quarantine', '--subject-tag', '[SPAM]', '--name', 'mx.example.com', '--verbose']);

		const client = await milterClient(server.address().port);
		client.send('M', '<alice@example.org>\0');
		await client.read();
		client.send('B', GTUBE);
		await client.read();
		client.send('E');
		const answers = await client.readUntilFinal();
		assert.match(answers.at(-1).data.toString(), /^550 5\.7\.1/);
		// An invalid packet is logged as an error.
		const bytes = Buffer.alloc(5);
		client.socket.write(bytes);
		await once(client.socket, 'close');
		server.close();
		const result = await stopped;
		assert.equal(result.code, 0);
		assert.match(result.stderr, /^Listening on 127\.0\.0\.1:\d+\n/);
		assert.match(result.stderr, /^- alice@example\.org \d+\.\d reject GTUBE/m);
		assert.match(result.stderr, /^milter: Invalid milter packet length 0$/m);
	});

	it('runs the milter with its defaults', async () => {
		const {server, done: stopped} = await serve(['milter', '--port', '0', '--no-classifier', ...offline, '--verbose']);

		const client = await milterClient(server.address().port);
		const connect = Buffer.concat([Buffer.from('mail.example.org\u00004'), Buffer.from([0, 25]), Buffer.from('192.0.2.1\0')]);
		client.send('C', connect);
		await client.read();
		client.send('B', GTUBE);
		await client.read();
		client.send('E');
		const answers = await client.readUntilFinal();
		assert.equal(answers.at(-1).command, 'c');
		assert.ok(!answers.some(item => item.command === 'm'));
		client.close();
		server.close();
		assert.match((await stopped).stderr, /^192\.0\.2\.1 <> \d+\.\d reject GTUBE/m);
	});

	it('runs the HTTP and TCP servers, on ports or Unix sockets', async () => {
		const start = argv => serve(argv, {SPAMSCANNER_TOKEN: 'from-env'});
		const http = await start(['http', '--port', '0', '--host', '127.0.0.1', '--no-classifier', ...offline]);
		const {port} = http.server.address();
		assert.equal((await fetch(`http://127.0.0.1:${port}/scan`, {method: 'POST', body: ham})).status, 401);
		const scanned = await fetch(`http://127.0.0.1:${port}/scan`, {method: 'POST', body: spam, headers: {authorization: 'Bearer from-env'}});
		assert.equal((await scanned.json()).isSpam, true);
		http.server.close();
		assert.equal((await http.done).code, 0);

		const modelPath = path.join(temporaryDirectory(), 'learned.json');
		const learning = await start(['http', '--port', '0', '--token', 'flag', '--out', modelPath, '--no-classifier', ...offline]);
		const learned = await fetch(`http://127.0.0.1:${learning.server.address().port}/learn/spam`, {method: 'POST', body: spam, headers: {authorization: 'Bearer flag'}});
		assert.equal(learned.status, 200);
		assert.ok(existsSync(modelPath));
		learning.server.close();
		await learning.done;

		const socket = path.join(temporaryDirectory(), 'tcp.sock');
		const text = await start(['server', '--socket', socket, '--verbose', '--no-classifier', ...offline]);
		const connection = net.createConnection(socket);
		const chunks = [];
		connection.on('data', chunk => chunks.push(chunk));
		connection.end(spam);
		await once(connection, 'close');
		assert.match(Buffer.concat(chunks).toString(), /^SPAM /);
		text.server.close();
		const stopped = await text.done;
		assert.match(stopped.stderr, new RegExp(`^Listening on ${socket.replaceAll(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`)}\\n`));

		// The default port and address.
		const json = await start(['server', '--no-classifier', ...offline]);
		assert.deepEqual(json.server.address(), {address: '127.0.0.1', family: 'IPv4', port: 7830});
		json.server.close();
		await json.done;
	});

	it('runs the spamd server', async () => {
		const {server, done} = await serve(['spamd', '--port', '0', '--no-classifier', ...offline, '--subject-tag', '[SPAM]']);
		const socket = net.createConnection(server.address().port, '127.0.0.1');
		const chunks = [];
		socket.on('data', chunk => chunks.push(chunk));
		socket.end(`CHECK SPAMC/1.5\r\nContent-length: ${Buffer.byteLength(spam)}\r\n\r\n${spam}`);
		await once(socket, 'close');
		assert.match(Buffer.concat(chunks).toString(), /^SPAMD\/1\.5 0 EX_OK\r\nSpam: True ; /);
		server.close();
		assert.equal((await done).code, 0);
		const learning = await serve(['spamd', '--port', '0', '--allow-tell', '--out', path.join(temporaryDirectory(), 'told.json'), '--no-classifier', ...offline]);
		learning.server.close();
		await learning.done;
	});

	it('exits 2 when it cannot listen', async () => {
		const blocker = net.createServer();
		blocker.listen(0, '127.0.0.1');
		await once(blocker, 'listening');
		try {
			const result = await cli(['http', '--port', String(blocker.address().port), '--no-classifier', ...offline]);
			assert.equal(result.code, 2);
			assert.match(result.stderr, /EADDRINUSE/);
		} finally {
			blocker.close();
		}
	});
});

describe('spamscanner train, eval and learn', () => {
	function corpus() {
		const directory = temporaryDirectory();
		const mbox = path.join(directory, 'spam.mbox');
		writeFileSync(mbox, SPAM.map(([, subject, text]) => `From spammer@example.biz Mon Oct  5 09:30:00 2026\n${message({subject, text}).replaceAll('\r\n', '\n')}\n`).join(''));
		const hamDirectory = path.join(directory, 'ham');
		mkdirSync(hamDirectory);
		for (const [index, [, subject, text]] of HAM.entries()) {
			writeFileSync(path.join(hamDirectory, `${index}.eml`), message({subject, text}));
		}

		const csv = path.join(directory, 'rows.csv');
		writeFileSync(csv, 'body,kind\n"Win a free cruise now, click here",spam\n"Minutes from the budget meeting attached",ham\n');
		// Enough rows for a progress report.
		const large = path.join(directory, 'large.csv');
		writeFileSync(large, 'text,label\n' + Array.from({length: 1000}, (_, index) => `"Weekly report number ${index} for the team",ham\n`).join(''));
		return {
			directory, mbox, hamDirectory, csv, large,
		};
	}

	it('trains a model from mbox files, folders and datasets, and measures it', async () => {
		const {directory, mbox, hamDirectory, csv} = corpus();
		const out = path.join(directory, 'model.json');
		const trained = await cli(['train', '--spam', mbox, '--ham', hamDirectory, '--dataset', csv, '--text-column', 'body', '--label-column', 'kind', '--out', out]);
		assert.equal(trained.code, 0);
		assert.match(trained.stdout, new RegExp(`^Learned ${SPAM.length + 1} spam and ${HAM.length + 1} ham messages; wrote .*model\\.json \\(\\d+ features\\)\\n$`));
		const model = JSON.parse(readFileSync(out, 'utf8'));
		assert.equal(model.metadata.trainedWith, `spamscanner ${VERSION}`);
		assert.equal(model.metadata.merged, false);

		const evaluated = await cli(['eval', '--model', out, '--spam', mbox, '--ham', hamDirectory]);
		assert.match(evaluated.stdout, new RegExp(`^Messages: ${SPAM.length} spam, ${HAM.length} ham\\nPrecision: \\d+\\.\\d\\d% {3}Recall: `));
		const json = JSON.parse((await cli(['eval', '--json', '--model', out, '--spam', mbox])).stdout);
		assert.equal(json.spam, SPAM.length);

		const merged = path.join(directory, 'merged.json');
		await cli(['train', '--merge', '--model', out, '--spam', mbox, '--out', merged]);
		assert.equal(JSON.parse(readFileSync(merged, 'utf8')).nspam, (SPAM.length * 2) + 1);
		assert.equal(JSON.parse(readFileSync(merged, 'utf8')).metadata.merged, true);
	});

	it('merges with the bundled model and measures it by default', async () => {
		const {directory, mbox} = corpus();
		const previous = process.cwd();
		process.chdir(directory);
		try {
			const trained = await cli(['train', '--merge', '--spam', mbox]);
			assert.match(trained.stdout, /wrote spamscanner-model\.json/);
			assert.ok(JSON.parse(readFileSync('spamscanner-model.json', 'utf8')).nspam > 1000);
		} finally {
			process.chdir(previous);
		}

		const evaluated = JSON.parse((await cli(['eval', '--json', '--spam', mbox])).stdout);
		assert.equal(evaluated.spam, SPAM.length);
	});

	it('reports progress while training', async () => {
		const {directory, large} = corpus();
		const result = await cli(['train', '--dataset', large, '--out', path.join(directory, 'large.json')]);
		assert.match(result.stderr, /\r1000 messages/);
		assert.match(result.stdout, /^Learned 0 spam and 1000 ham messages/);
	});

	it('needs something to train on', async () => {
		const result = await cli(['train']);
		assert.equal(result.code, 2);
		assert.match(result.stderr, /give --spam, --ham or --dataset/);
	});

	it('learns one message into a model file, starting from the bundled model', async () => {
		const file = path.join(temporaryDirectory(), 'mine.json');
		const first = await cli(['learn', 'spam', '-', '--model', file], {stdin: spam});
		assert.equal(first.code, 0);
		assert.match(first.stdout, /^Learned one spam message; saved /);
		const bundled = JSON.parse(readFileSync(file, 'utf8')).nspam;
		assert.ok(bundled > 1000);
		const source = path.join(temporaryDirectory(), 'ham.eml');
		writeFileSync(source, ham);
		await cli(['learn', 'ham', source, '--out', file]);
		await cli(['learn', 'spam', '--model', file], {stdin: spam});
		const updated = JSON.parse(readFileSync(file, 'utf8'));
		assert.equal(updated.nspam, bundled + 1);
		assert.equal((await cli(['learn', 'maybe', '--model', file])).code, 2);
		const noModel = await cli(['learn', 'spam']);
		assert.equal(noModel.code, 2);
		assert.match(noModel.stderr, /give --model/);
	});
});

describe('spamscanner llm-test and models', () => {
	it('checks the language model with sample messages', async () => {
		const expected = text => (/Lunch on Thursday/.test(text) ? 'ham' : (/Congratulazioni/.test(text) ? 'scam' : 'phishing'));
		// A server without token probabilities: Spam Scanner asks for a written verdict.
		const llm = await httpServer((request, body) => {
			const verdict = expected(JSON.stringify(body));
			return {message: {content: JSON.stringify({verdict, confidence: 0.9, reasons: verdict === 'ham' ? [] : ['asks for credentials']})}};
		});
		// A server with them: the verdict is read from one forward pass.
		const decision = await httpServer((request, body) => {
			const verdict = expected(JSON.stringify(body));
			const top = verdict === 'ham' ? [{token: 'ham', logprob: Math.log(0.9)}, {token: 'spam', logprob: Math.log(0.1)}] : [{token: verdict, logprob: Math.log(0.95)}, {token: 'ham', logprob: Math.log(0.05)}];
			return {message: {content: verdict}, logprobs: [{token: verdict, top_logprobs: top}]};
		});
		const wrong = await httpServer(() => ({message: {content: '{"verdict":"ham","confidence":0.6,"reasons":[]}'}}));
		try {
			const passed = await cli(['llm-test', '--llm', 'ollama', '--llm-url', llm.url, '--llm-model', 'test']);
			assert.equal(passed.code, 0);
			assert.match(passed.stdout, /^ok {3}expected ham {2}got ham \(90%, \d+ ms\)\n/);
			assert.match(passed.stdout, /^ok {3}expected spam got phishing \(90%, \d+ ms\): asks for credentials$/m);
			assert.match(passed.stdout, /3 of 3 correct with Ollama test at http:\/\/127\.0\.0\.1:\d+ \(method: generate\)$/m);
			assert.match(passed.stdout, /^Hardware \(model on this machine\): .+ CPU threads, [\d.]+ GB RAM, /m);
			const decided = await cli(['llm-test', '--llm', 'ollama', '--llm-url', decision.url, '--llm-model', 'test']);
			assert.equal(decided.code, 0);
			assert.match(decided.stdout, /^ok {3}expected ham {2}got ham \(90%, \d+ ms\): ham 90%, spam 10%$/m);
			assert.match(decided.stdout, /^ok {3}expected spam got scam \(95%, \d+ ms\): scam 95%, ham 5%$/m);
			assert.match(decided.stdout, /\(method: decision\)$/m);
			const failed = await cli(['llm-test', '--llm', 'ollama', '--llm-url', wrong.url]);
			assert.equal(failed.code, 1);
			assert.match(failed.stdout, /^MISS expected spam got ham/m);
			assert.match(failed.stdout, /1 of 3 correct with Ollama qwen3\.5:4b/);
		} finally {
			await llm.close();
			await decision.close();
			await wrong.close();
		}

		const down = await cli(['llm-test', '--llm', 'ollama', '--llm-url', 'http://127.0.0.1:1']);
		assert.equal(down.code, 1);
		assert.match(down.stdout, /^FAIL .*ECONNREFUSED/m);
		const remote = await cli(['llm-test', '--llm', 'clef-flash', '--llm-account', 'acc', '--llm-api-key', 'k', '--llm-url', 'http://192.0.2.1:9/v1', '--llm-timeout', '200']);
		assert.equal(remote.code, 1);
		assert.match(remote.stdout, /^FAIL /m);
		assert.match(remote.stdout, /0 of 3 correct with Cloudflare Clef Flash clef-flash at http:\/\/192\.0\.2\.1:9\/v1 \(method: decision\)$/m);
		assert.match(remote.stdout, /^Times include the round trip to 192\.0\.2\.1:9$/m);
		const unnamed = await cli(['llm-test', '--llm', 'lmstudio', '--llm-url', 'http://127.0.0.1:1/v1']);
		assert.equal(unnamed.code, 2);
		assert.match(unnamed.stderr, /"lmstudio" needs a model name/);
		const none = await cli(['llm-test']);
		assert.equal(none.code, 2);
		assert.match(none.stderr, /choose a provider with --llm/);
	});

	it('lists recommended models', async () => {
		const {code, stdout} = await cli(['models']);
		assert.equal(code, 0);
		assert.match(stdout, /^ {2}qwen3\.5:4b +small +Apache-2\.0 +3\.3 GB +hf\.co\/Qwen\/Qwen3\.5-4B$/m);
		assert.match(stdout, /cybersectony\/phishing-email-detection-distilbert_v2\.4\.1 {2}\(Apache-2\.0\)/);
		assert.match(stdout, /^ {2}--llm clef-flash +Cloudflare Clef Flash +Apache-2\.0 +hf\.co\/Cloudflare\/clef-flash$/m);
		assert.match(stdout, /^ {2}--llm jev +TypeSafe Jev +proprietary closed weights$/m);
	});
});

describe('spamscanner executable', () => {
	it('runs from the command line and sets the exit code', async () => {
		const {stdout} = await run(process.execPath, ['src/bin.js', 'version']);
		assert.equal(stdout, `spamscanner ${VERSION}\n`);
		await assert.rejects(run(process.execPath, ['src/bin.js']), error => error.code === 2 && error.stderr.startsWith('Spam Scanner'));
	});
});
