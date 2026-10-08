import {Buffer} from 'node:buffer';
import {spawn} from 'node:child_process';
import {existsSync, readFileSync} from 'node:fs';
import process from 'node:process';
import {parseArgs} from 'node:util';
import {Classifier} from './classifier.js';
import {rewriteMessage, spamHeaders} from './headers.js';
import {PROVIDERS} from './llm.js';
import {MilterServer} from './milter.js';
import {loadDefaultModel, loadModel, saveModel} from './model.js';
import {CLASSIFIER_MODELS, RECOMMENDED_MODELS} from './models.js';
import {createHttpServer, createTcpServer, serializeResult} from './server.js';
import {createSpamdServer} from './spamd.js';
import {evaluate, readExamples, train} from './train.js';
import {VERSION} from './version.js';
import {SpamScanner} from './index.js';

export const HELP = `Spam Scanner ${VERSION}

Usage: spamscanner <command> [options]

Commands:
  scan [file|-]        Scan a message (a file, or standard input with "-")
  filter -f <sender> -- <recipients...>
                       Postfix content filter: scan standard input, add headers,
                       and pass the message on to sendmail
  milter               Run a milter for Postfix or Sendmail (port 7831)
  http                 Run an HTTP API (port 7832)
  server               Run a plain TCP server (port 7830)
  spamd                Run a SpamAssassin-compatible spamd server (port 783),
                       for spamc, Exim's spam condition and Haraka
  train                Train a classifier model from your mail
  eval                 Measure a model on labelled mail
  learn spam|ham [file|-] --model <file>
                       Teach a model one message (for "report spam" buttons)
  llm-test             Check the language model settings with sample messages
  models               List recommended open models
  version, help

Scanning:
  --json               Print the full result as JSON
  --headers            Print the message with X-Spam headers added
  --subject-tag <tag>  Prefix the subject of spam, e.g. "[SPAM]"
  --verbose            Show every test and the classifier's strongest clues
  --threshold <n>      Score at which mail is spam (default 5)
  --reject-threshold <n>  Score at which mail is rejected (default 15)
  --model <file>       Classifier model (default: the bundled model)
  --no-classifier      Do not use the classifier
  --config <file>      JSON file with scanner settings (see the API docs)
  --allow-language <codes>  Accepted languages, e.g. en,de,fr

SMTP session (improves accuracy):
  --ip <address>       IP address of the client that sent the message
  --hostname <name>    Its verified reverse DNS name
  --helo <name>        The name it gave in HELO/EHLO
  --from <address>     Envelope sender (MAIL FROM)
  --to <address>       Envelope recipient (repeatable)

Checks:
  --auth               Check SPF, DKIM, DMARC and ARC (needs --ip)
  --dnsbl <zone>       IP blocklist, e.g. zen.spamhaus.org (repeatable)
  --uribl <zone>       Domain blocklist for links, e.g. dbl.spamhaus.org (repeatable)
  --dns-server <ip>    Name server for DNS checks (repeatable)
  --no-cloudflare      Do not ask Cloudflare's filtering resolvers about links
  --clamav [socket]    Scan attachments with clamd (default socket if none given)
  --allowlist <value>  Always accept this IP, domain or address (repeatable)
  --denylist <value>   Always reject this IP, domain or address (repeatable)

Language model (a second opinion; see "spamscanner models"):
  --llm <provider>     ${Object.keys(PROVIDERS).join(', ')}
  --llm-model <name>   Model name, e.g. qwen3.5:4b or claude-haiku-4-5
  --llm-url <url>      Base URL, e.g. http://10.0.0.5:11434 or https://host/v1
  --llm-host <host>  --llm-port <port>  --llm-path <path>  --llm-protocol <http|https>
                       Change parts of the provider's URL
  --llm-api-key <key>  API key (or SPAMSCANNER_LLM_API_KEY, or the provider's
                       variable: OPENAI_API_KEY, ANTHROPIC_API_KEY, ...)
  --llm-auth <type>    bearer, x-api-key, api-key, basic, header or none
  --llm-auth-header <name>  Header that carries the key, with --llm-auth header
  --llm-username <u>  --llm-password <p>  For --llm-auth basic
  --llm-header "Name: value"  Extra request header (repeatable)
  --llm-mode <mode>    auto (when the score is close; default) or always
  --llm-timeout <ms>   Default 30000
  --llm-policy <text>  Extra rules for the model, e.g. "We never send invoices"
  --llm-redact / --no-llm-redact  Remove personal data first (default: on for remote providers)

Filter (Postfix pipe):
  --sendmail <path>    Default /usr/sbin/sendmail
  --reject             Bounce mail at the reject threshold instead of passing it on
  --discard            Drop mail at the reject threshold instead of passing it on

Servers:
  --port <n>  --host <ip>  --socket <path>
  --reject             Milter: refuse mail at the reject threshold
  --reject-code <n>    Milter: 451 (try later; default) or 550
  --name <hostname>    Milter: this server's name in Authentication-Results
  --quarantine         Milter: hold spam in the mail server's quarantine
  --token <secret>     HTTP: require "Authorization: Bearer <secret>"
  --allow-tell         spamd: accept TELL (learning) requests; saves to --out

Training:
  --spam <path>        Spam: an mbox file, a Maildir or a folder of .eml files (repeatable)
  --ham <path>         Ham, likewise (repeatable)
  --dataset <file>     A CSV or JSON Lines file with text and label columns (repeatable)
  --text-column <name>  --label-column <name>  Column names in datasets
  --out <file>         Where to write the model (train, learn)
  --merge              Start from the bundled model instead of an empty one

Exit codes for scan: 0 ham, 1 spam, 2 error.
Documentation: https://spamscanner.net
`;

const OPTIONS = {
	help: {type: 'boolean', short: 'h'},
	version: {type: 'boolean', short: 'v'},
	json: {type: 'boolean', short: 'j'},
	headers: {type: 'boolean'},
	'add-headers': {type: 'boolean'},
	'subject-tag': {type: 'string'},
	'prepend-subject': {type: 'boolean'},
	verbose: {type: 'boolean'},
	debug: {type: 'boolean'},
	threshold: {type: 'string'},
	'reject-threshold': {type: 'string'},
	model: {type: 'string'},
	'no-classifier': {type: 'boolean'},
	config: {type: 'string'},
	'allow-language': {type: 'string'},
	ip: {type: 'string'},
	'sender-ip': {type: 'string'},
	hostname: {type: 'string'},
	'sender-hostname': {type: 'string'},
	helo: {type: 'string'},
	from: {type: 'string', short: 'f'},
	sender: {type: 'string'},
	to: {type: 'string', multiple: true},
	auth: {type: 'boolean'},
	'enable-auth': {type: 'boolean'},
	dnsbl: {type: 'string', multiple: true},
	uribl: {type: 'string', multiple: true},
	'dns-server': {type: 'string', multiple: true},
	'no-cloudflare': {type: 'boolean'},
	clamav: {type: 'string'},
	allowlist: {type: 'string', multiple: true},
	denylist: {type: 'string', multiple: true},
	llm: {type: 'string'},
	'llm-model': {type: 'string'},
	'llm-url': {type: 'string'},
	'llm-host': {type: 'string'},
	'llm-port': {type: 'string'},
	'llm-path': {type: 'string'},
	'llm-protocol': {type: 'string'},
	'llm-api-key': {type: 'string'},
	'llm-auth': {type: 'string'},
	'llm-auth-header': {type: 'string'},
	'llm-username': {type: 'string'},
	'llm-password': {type: 'string'},
	'llm-header': {type: 'string', multiple: true},
	'llm-mode': {type: 'string'},
	'llm-timeout': {type: 'string'},
	'llm-policy': {type: 'string'},
	'llm-redact': {type: 'boolean'},
	'no-llm-redact': {type: 'boolean'},
	sendmail: {type: 'string', default: '/usr/sbin/sendmail'},
	reject: {type: 'boolean'},
	discard: {type: 'boolean'},
	port: {type: 'string'},
	host: {type: 'string'},
	socket: {type: 'string'},
	'reject-code': {type: 'string'},
	name: {type: 'string'},
	quarantine: {type: 'boolean'},
	token: {type: 'string'},
	'allow-tell': {type: 'boolean'},
	spam: {type: 'string', multiple: true},
	ham: {type: 'string', multiple: true},
	dataset: {type: 'string', multiple: true},
	'text-column': {type: 'string'},
	'label-column': {type: 'string'},
	out: {type: 'string'},
	merge: {type: 'boolean'},
};

const COMMANDS = new Set(['scan', 'filter', 'milter', 'http', 'server', 'spamd', 'train', 'eval', 'learn', 'llm-test', 'models', 'version', 'help']);

function number(value, name) {
	const parsed = Number(value);
	if (!Number.isFinite(parsed)) {
		throw new TypeError(`${name} must be a number, not "${value}"`);
	}

	return parsed;
}

/**
 * The --clamav option is optional-valued: "--clamav" alone uses the default
 * socket. parseArgs needs a value, so a bare flag is given an empty one first.
 * @param {string[]} argv
 * @returns {string[]}
 */
function normalizeArgv(argv) {
	const out = [];
	for (let i = 0; i < argv.length; i++) {
		out.push(argv[i]);
		if (argv[i] === '--clamav' && (i + 1 >= argv.length || argv[i + 1].startsWith('-'))) {
			out.push('');
		}
	}

	return out;
}

/**
 * Parse command-line arguments.
 * @param {string[]} argv
 * @returns {{command: string|null, positionals: string[], values: object}}
 */
export function parseCli(argv) {
	const {values, positionals} = parseArgs({
		args: normalizeArgv(argv), options: OPTIONS, allowPositionals: true, strict: true,
	});
	const command = positionals.length > 0 && COMMANDS.has(positionals[0]) ? positionals[0] : null;
	return {command, positionals: command ? positionals.slice(1) : positionals, values};
}

/**
 * Scanner settings from command-line values, on top of a --config file.
 * @param {object} values
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {object}
 */
export function buildConfig(values, env = process.env) {
	const file = values.config || env.SPAMSCANNER_CONFIG;
	const config = file ? JSON.parse(readFileSync(file, 'utf8')) : {};
	if (values.threshold !== undefined) {
		config.threshold = number(values.threshold, '--threshold');
	}

	if (values['reject-threshold'] !== undefined) {
		config.rejectThreshold = number(values['reject-threshold'], '--reject-threshold');
	}

	if (values.model) {
		config.classifier = values.model;
	}

	if (values['no-classifier']) {
		config.classifier = false;
	}

	if (values['allow-language']) {
		config.allowedLanguages = values['allow-language'].split(',').map(code => code.trim()).filter(Boolean);
	}

	if (values.auth || values['enable-auth']) {
		config.authentication ||= true;
	}

	if (values.dnsbl || values.uribl) {
		config.dnsbl = {...config.dnsbl, ...(values.dnsbl ? {ip: values.dnsbl} : {}), ...(values.uribl ? {domain: values.uribl} : {})};
	}

	if (values['dns-server']) {
		config.dns = {...config.dns, servers: values['dns-server']};
	}

	if (values['no-cloudflare']) {
		config.phishing = {...config.phishing, cloudflare: false};
	}

	if (values.clamav !== undefined) {
		config.clamav = values.clamav ? {socket: values.clamav} : true;
	}

	if (values.allowlist || values.denylist) {
		config.reputation = {
			...config.reputation, ...(values.allowlist ? {allowlist: values.allowlist} : {}), ...(values.denylist ? {denylist: values.denylist} : {}),
		};
	}

	const llm = {...config.llm};
	const map = {
		llm: 'provider', 'llm-model': 'model', 'llm-url': 'baseUrl', 'llm-host': 'host', 'llm-path': 'path', 'llm-protocol': 'protocol', 'llm-api-key': 'apiKey', 'llm-auth': 'auth', 'llm-auth-header': 'authHeader', 'llm-username': 'username', 'llm-password': 'password', 'llm-mode': 'mode', 'llm-policy': 'policy',
	};
	for (const [flag, key] of Object.entries(map)) {
		if (values[flag] !== undefined) {
			llm[key] = values[flag];
		}
	}

	if (values['llm-port'] !== undefined) {
		llm.port = number(values['llm-port'], '--llm-port');
	}

	if (values['llm-timeout'] !== undefined) {
		llm.timeout = number(values['llm-timeout'], '--llm-timeout');
	}

	if (values['llm-header']) {
		llm.headers = {...llm.headers};
		for (const header of values['llm-header']) {
			const colon = header.indexOf(':');
			if (colon < 1) {
				throw new TypeError(`--llm-header must look like "Name: value", not "${header}"`);
			}

			llm.headers[header.slice(0, colon).trim().toLowerCase()] = header.slice(colon + 1).trim();
		}
	}

	if (values['llm-redact']) {
		llm.redact = true;
	}

	if (values['no-llm-redact']) {
		llm.redact = false;
	}

	if (Object.keys(llm).length > 0) {
		config.llm = llm;
	}

	return config;
}

/**
 * SMTP session details from command-line values.
 * @param {object} values
 * @returns {object}
 */
export function buildSession(values) {
	const session = {};
	const ip = values.ip || values['sender-ip'];
	if (ip) {
		session.remoteAddress = ip;
	}

	const hostname = values.hostname || values['sender-hostname'];
	if (hostname) {
		session.resolvedClientHostname = hostname;
	}

	if (values.helo) {
		session.helo = values.helo;
	}

	const from = values.from ?? values.sender;
	if (from !== undefined || values.to) {
		session.envelope = {mailFrom: {address: from || ''}, rcptTo: (values.to || []).map(address => ({address}))};
	}

	return session;
}

async function readInput(file, stdin) {
	if (!file || file === '-') {
		const chunks = [];
		for await (const chunk of stdin) {
			chunks.push(Buffer.from(chunk));
		}

		return Buffer.concat(chunks);
	}

	return readFileSync(file);
}

function formatResult(result, verbose) {
	const lines = [`${result.isSpam ? 'SPAM' : 'HAM'}  score ${result.score.toFixed(1)} (spam at ${result.threshold.toFixed(1)}, reject at ${result.rejectThreshold.toFixed(1)})  action: ${result.action}${result.language ? `  language: ${result.language}` : ''}`];
	const tests = verbose ? result.tests : result.tests.filter(test => test.score !== 0);
	for (const test of [...tests].sort((a, b) => Math.abs(b.score) - Math.abs(a.score))) {
		lines.push(`  ${`${test.score > 0 ? '+' : ''}${test.score.toFixed(1)}`.padStart(7)}  ${test.name.padEnd(28)} ${test.description}`);
	}

	if (verbose && result.results.classification.clues?.length > 0) {
		lines.push('  Strongest clues:', ...result.results.classification.clues.slice(0, 10).map(clue => `    ${clue.probability.toFixed(3)}  ${clue.feature}`));
	}

	if (result.results.llm?.error) {
		lines.push(`  Language model failed: ${result.results.llm.error}`);
	}

	return lines.join('\n');
}

function listen(server, values, defaultPort, io) {
	return new Promise((resolve, reject) => {
		server.once('error', reject);
		const ready = () => {
			const address = server.address();
			io.stderr.write(`Listening on ${typeof address === 'string' ? address : `${address.address}:${address.port}`}\n`);
			resolve(server);
		};

		if (values.socket) {
			server.listen(values.socket, ready);
		} else {
			server.listen(Number(values.port ?? defaultPort), values.host || '127.0.0.1', ready);
		}
	});
}

/**
 * Pipe a message to sendmail and wait for it to exit.
 * @param {string} sendmail
 * @param {string[]} args
 * @param {Buffer} message
 * @returns {Promise<number|string>} sendmail's exit code, or "a signal" if it was killed
 */
export function deliver(sendmail, args, message) {
	return new Promise((resolve, reject) => {
		const child = spawn(sendmail, args, {stdio: ['pipe', 'ignore', 'inherit']});
		child.on('error', reject);
		child.on('close', code => resolve(code ?? 'a signal'));
		child.stdin.on('error', () => {});
		child.stdin.end(message);
	});
}

const SAMPLES = [
	['ham', 'From: Alice <alice@example.org>\r\nTo: bob@example.net\r\nSubject: Lunch on Thursday?\r\n\r\nHi Bob, are we still on for lunch on Thursday at noon? I can book the usual place. Alice\r\n'],
	['spam', 'From: "Account Security" <security@account-verify.example>\r\nTo: bob@example.net\r\nSubject: Your mailbox will be closed today\r\n\r\nWe detected unusual sign-in activity. Confirm your password within 24 hours or your mailbox will be deleted: http://account-verify.example/login\r\n'],
	['spam', 'From: Lotteria <premio@lotteria.example>\r\nTo: bob@example.net\r\nSubject: Congratulazioni, hai vinto 1.000.000 EUR\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nSei stato selezionato come vincitore. Per ricevere il premio inviaci i tuoi dati bancari e una tassa di 50 EUR.\r\n'],
];

function datasetsFrom(values) {
	return (values.dataset || []).map(file => ({file, textColumn: values['text-column'], labelColumn: values['label-column']}));
}

function waitForClose(server) {
	return new Promise(resolve => {
		server.on('close', () => resolve(0));
	});
}

// One function per command. Each gets the parsed arguments, the scanner
// settings and the streams, and returns the exit code.
const HANDLERS = {
	async scan({positionals, values, config, session, stdin, stdout, out}) {
		const raw = await readInput(positionals[0], stdin);
		const scanner = new SpamScanner(config);
		const result = await scanner.scan(raw, {session});
		const tag = values['subject-tag'] ?? (values['prepend-subject'] ? '[SPAM]' : null);
		if (values.json) {
			out(JSON.stringify(serializeResult(result, {verbose: values.verbose}), null, 2));
		} else if (values.headers || values['add-headers'] || tag) {
			stdout.write(rewriteMessage(raw, spamHeaders(result, {version: VERSION}), {subjectTag: result.isSpam ? tag : null}));
		} else {
			out(formatResult(result, values.verbose));
		}

		return result.isSpam ? 1 : 0;
	},

	// Postfix: argv=spamscanner filter -f ${sender} -- ${recipient}
	async filter({positionals: recipients, values, config, session, stdin, stderr}) {
		const raw = await readInput('-', stdin);
		if (recipients.length === 0) {
			stderr.write('filter: no recipients given (use: spamscanner filter -f sender -- recipient...)\n');
			return 64;
		}

		let message;
		let result;
		try {
			const scanner = new SpamScanner(config);
			result = await scanner.scan(raw, {session});
			message = rewriteMessage(raw, spamHeaders(result, {version: VERSION}), {subjectTag: result.isSpam ? (values['subject-tag'] ?? null) : null});
		} catch (error) {
			// Defer: Postfix keeps the message and tries again later.
			stderr.write(`filter: scan failed, deferring: ${error.message}\n`);
			return 75;
		}

		if (result.action === 'reject' && values.reject) {
			stderr.write(`5.7.1 Message rejected as spam (score ${result.score.toFixed(1)})\n`);
			return 69;
		}

		if (result.action === 'reject' && values.discard) {
			return 0;
		}

		const code = await deliver(values.sendmail, ['-G', '-i', '-f', values.from ?? values.sender ?? '', '--', ...recipients], message);
		if (code !== 0) {
			stderr.write(`filter: sendmail exited with ${code}, deferring\n`);
			return 75;
		}

		return 0;
	},

	async milter({values, config, stderr, io}) {
		const scanner = new SpamScanner(config);
		const milter = new MilterServer(scanner, {
			reject: Boolean(values.reject), rejectCode: values['reject-code'] ? number(values['reject-code'], '--reject-code') : 451, quarantine: Boolean(values.quarantine), subjectTag: values['subject-tag'] ?? null, hostname: values.name || 'spamscanner',
		});
		milter.on('error', error => stderr.write(`milter: ${error.message}\n`));
		if (values.verbose) {
			milter.on('scan', ({session, result}) => stderr.write(`${session.remoteAddress || '-'} ${session.envelope?.mailFrom?.address || '<>'} ${result.score.toFixed(1)} ${result.action} ${result.tests.map(test => test.name).join(',')}\n`));
		}

		await listen(milter.server, values, 7831, {stderr});
		io.onListening?.(milter.server);
		return waitForClose(milter.server);
	},

	async http({values, config, env, stderr, io}) {
		const server = createHttpServer(new SpamScanner(config), {token: values.token || env.SPAMSCANNER_TOKEN || null, modelPath: values.out || null});
		await listen(server, values, 7832, {stderr});
		io.onListening?.(server);
		return waitForClose(server);
	},

	async server({values, config, stderr, io}) {
		const server = createTcpServer(new SpamScanner(config), {json: !values.verbose});
		await listen(server, values, 7830, {stderr});
		io.onListening?.(server);
		return waitForClose(server);
	},

	async spamd({values, config, stderr, io}) {
		const server = createSpamdServer(new SpamScanner(config), {allowTell: Boolean(values['allow-tell']), modelPath: values.out || null, subjectTag: values['subject-tag'] ?? null});
		await listen(server, values, 783, {stderr});
		io.onListening?.(server);
		return waitForClose(server);
	},

	async train({values, stderr, out}) {
		const datasets = datasetsFrom(values);
		if (!values.spam && !values.ham && datasets.length === 0) {
			stderr.write('train: give --spam, --ham or --dataset\n');
			return 2;
		}

		const base = values.merge ? (values.model ? loadModel(values.model) : loadDefaultModel()) : new Classifier();
		const {classifier, spam, ham} = await train({spam: values.spam, ham: values.ham, datasets}, {
			classifier: base,
			onProgress: count => stderr.write(`\r${count} messages`),
		});
		const file = values.out || 'spamscanner-model.json';
		saveModel(classifier, file, {
			metadata: {
				trainedWith: `spamscanner ${VERSION}`, spam, ham, merged: Boolean(values.merge),
			},
		});
		out(`Learned ${spam} spam and ${ham} ham messages; wrote ${file} (${classifier.size} features)`);
		return 0;
	},

	async eval({values, out}) {
		const classifier = values.model ? loadModel(values.model) : loadDefaultModel();
		const metrics = await evaluate(classifier, readExamples({spam: values.spam, ham: values.ham, datasets: datasetsFrom(values)}));
		if (values.json) {
			out(JSON.stringify(metrics, null, 2));
			return 0;
		}

		const pct = n => `${(n * 100).toFixed(2)}%`;
		out([
			`Messages: ${metrics.spam} spam, ${metrics.ham} ham`,
			`Precision: ${pct(metrics.precision)}   Recall: ${pct(metrics.recall)}   F1: ${pct(metrics.f1)}`,
			`False positives: ${metrics.falsePositive} (${pct(metrics.falsePositiveRate)} of ham)   False negatives: ${metrics.falseNegative}`,
			`Unsure: ${metrics.unsureSpam + metrics.unsureHam} (${pct(metrics.unsureRate)})`,
		].join('\n'));
		return 0;
	},

	async learn({positionals, values, config, stdin, stderr, out}) {
		const [category, source] = positionals;
		if (category !== 'spam' && category !== 'ham') {
			stderr.write('learn: say "learn spam" or "learn ham", then the message file (or - for standard input)\n');
			return 2;
		}

		const file = values.out || values.model;
		if (!file) {
			stderr.write('learn: give --model, the model file to update (it is created from the bundled model if missing)\n');
			return 2;
		}

		const raw = await readInput(source, stdin);
		const scanner = new SpamScanner({...config, classifier: existsSync(file) ? file : undefined});
		await scanner.learn(raw, category);
		scanner.saveModel(file);
		out(`Learned one ${category} message; saved ${file}`);
		return 0;
	},

	async 'llm-test'({config, stderr, out}) {
		if (!config.llm) {
			stderr.write('llm-test: choose a provider with --llm (and --llm-model)\n');
			return 2;
		}

		const scanner = new SpamScanner({...config, llm: {...config.llm, mode: 'always'}, phishing: {cloudflare: false}});
		let correct = 0;
		for (const [expected, raw] of SAMPLES) {
			// eslint-disable-next-line no-await-in-loop
			const {results: {llm}} = await scanner.scan(raw);
			if (llm.verdict) {
				const ok = (llm.verdict === 'ham') === (expected === 'ham');
				correct += ok ? 1 : 0;
				out(`${ok ? 'ok  ' : 'MISS'} expected ${expected.padEnd(4)} got ${llm.verdict} (${Math.round(llm.confidence * 100)}%, ${llm.time} ms)${llm.reasons.length > 0 ? `: ${llm.reasons[0]}` : ''}`);
			} else {
				out(`FAIL ${llm.error}`);
			}
		}

		out(`${correct} of ${SAMPLES.length} correct with ${scanner.llm.config.name} ${scanner.llm.config.model} at ${scanner.llm.config.baseUrl}`);
		return correct === SAMPLES.length ? 0 : 1;
	},

	async models({out}) {
		out('Open models for --llm ollama (and any server that runs GGUF files):\n');
		for (const model of RECOMMENDED_MODELS) {
			out(`  ${model.ollama.padEnd(24)} ${model.tier.padEnd(7)} ${model.license.padEnd(11)} ${model.size.padEnd(7)} hf.co/${model.huggingface}\n      ${model.notes}`);
		}

		out('\nText classification models for --llm tei or --llm huggingface-classifier (English):\n');
		for (const model of CLASSIFIER_MODELS) {
			out(`  ${model.huggingface}  (${model.license})\n      ${model.notes}`);
		}

		return 0;
	},
};

/**
 * Run the command-line interface.
 * @param {string[]} argv - arguments after the program name
 * @param {object} [io] - stdin, stdout, stderr, env and onListening, for tests
 * @returns {Promise<number>} the exit code (servers resolve when they stop)
 */
export async function main(argv = process.argv.slice(2), io = {}) {
	const stdin = io.stdin || process.stdin;
	const stdout = io.stdout || process.stdout;
	const stderr = io.stderr || process.stderr;
	const env = io.env || process.env;
	const out = text => stdout.write(text.endsWith('\n') ? text : `${text}\n`);
	let parsed;
	try {
		parsed = parseCli(argv);
	} catch (error) {
		stderr.write(`${error.message}\nRun "spamscanner help" for usage.\n`);
		return 2;
	}

	const {command, positionals, values} = parsed;
	if (values.version || command === 'version') {
		out(`spamscanner ${VERSION}`);
		return 0;
	}

	if (values.help || command === 'help' || !command) {
		(command || values.help ? stdout : stderr).write(HELP);
		return command || values.help ? 0 : 2;
	}

	try {
		return await HANDLERS[command]({
			positionals, values, config: buildConfig(values, env), session: buildSession(values), stdin, stdout, stderr, env, out, io,
		});
	} catch (error) {
		stderr.write(`spamscanner: ${error.message}\n`);
		if (values.debug) {
			stderr.write(`${error.stack}\n`);
		}

		// A content filter that fails must defer (EX_TEMPFAIL), so Postfix keeps
		// the message and tries again rather than bouncing it.
		return command === 'filter' ? 75 : 2;
	}
}
