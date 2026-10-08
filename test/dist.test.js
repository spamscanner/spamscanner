// The built package, as other projects load it: CommonJS require, ESM import,
// the command-line bundle and the standalone bundle. `npm test` builds first.
import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {execFile} from 'node:child_process';
import {existsSync} from 'node:fs';
import {createRequire} from 'node:module';
import process from 'node:process';
import {describe, it} from 'node:test';
import {promisify} from 'node:util';
import {GTUBE} from '../src/is-arbitrary.js';
import {VERSION} from '../src/version.js';
import {message} from './helpers/index.js';

const require = createRequire(import.meta.url);
const run = promisify(execFile);
// A package export, not a file.
const ARF = 'spamscanner/arf';

describe('built package', () => {
	it('loads with require() and works the way Forward Email calls it', async () => {
		const SpamScanner = require('spamscanner');
		assert.equal(typeof SpamScanner, 'function');
		assert.equal(SpamScanner.SpamScanner, SpamScanner);
		assert.equal(SpamScanner.default, SpamScanner);
		assert.equal(typeof SpamScanner.Classifier, 'function');
		const scanner = new SpamScanner({
			logger: console, clamscan: false, memoize: {}, phishing: {cloudflare: false},
		});
		const result = await scanner.scan(Buffer.from(message({
			from: '"PayPal" <service@paypa1-secure.top>', subject: 'Account limited', html: '<a href="http://paypa1-secure.top/login">https://www.paypal.com/signin</a>',
		})));
		assert.equal(result.isSpam, true);
		for (const key of ['phishing', 'executables', 'arbitrary', 'viruses']) {
			assert.ok(Array.isArray(result.results[key]), key);
		}

		// Earlier versions returned strings; findings still read as strings.
		assert.ok(result.results.phishing.every(item => typeof String(item) === 'string' && String(item) === item.message));
		const ArfParser = require(ARF);
		assert.equal(typeof ArfParser.parse, 'function');
		assert.equal(require('spamscanner/package.json').version, VERSION);
	});

	it('loads with import', async () => {
		const {default: SpamScanner, VERSION: version, loadDefaultModel} = await import('spamscanner');
		assert.equal(version, VERSION);
		assert.ok(loadDefaultModel().nspam > 1000);
		const result = await new SpamScanner({phishing: {cloudflare: false}}).scan(message({text: GTUBE}));
		assert.equal(result.action, 'reject');
		const {default: ArfParser} = await import(ARF);
		assert.equal(typeof ArfParser.create, 'function');
		assert.ok(existsSync(new URL('../dist/types/index.d.ts', import.meta.url)));
	});

	it('runs the command-line and standalone bundles', async () => {
		for (const file of ['dist/esm/cli.js', 'dist/standalone/cli.cjs']) {
			const {stdout} = await run(process.execPath, [file, 'version']);
			assert.equal(stdout, `spamscanner ${VERSION}\n`);
		}

		const scanned = run(process.execPath, ['dist/standalone/cli.cjs', 'scan', '-', '--no-cloudflare']);
		scanned.child.stdin.end(message({text: GTUBE}));
		await assert.rejects(scanned, error => error.code === 1 && error.stdout.startsWith('SPAM'));
	});
});
