// The built package, as other projects load it: CommonJS require, ESM import,
// the command-line bundle and the standalone bundle. `npm test` builds first.
import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {execFile} from 'node:child_process';
import {
	existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import {createRequire} from 'node:module';
import {tmpdir} from 'node:os';
import path from 'node:path';
import process from 'node:process';
import {describe, it} from 'node:test';
import {fileURLToPath} from 'node:url';
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

	it('has type declarations that TypeScript accepts for require() and import', async () => {
		const root = fileURLToPath(new URL('..', import.meta.url));
		const dir = mkdtempSync(path.join(tmpdir(), 'spamscanner-types-'));
		try {
			mkdirSync(path.join(dir, 'node_modules'));
			symlinkSync(root, path.join(dir, 'node_modules', 'spamscanner'), 'dir');
			symlinkSync(path.join(root, 'node_modules', '@types'), path.join(dir, 'node_modules', '@types'), 'dir');
			writeFileSync(path.join(dir, 'package.json'), '{"type": "module"}');
			writeFileSync(path.join(dir, 'tsconfig.json'), JSON.stringify({
				compilerOptions: {
					module: 'nodenext', target: 'es2022', strict: true, noEmit: true,
				},
				files: ['require.cts', 'import.mts'],
			}));
			writeFileSync(path.join(dir, 'require.cts'), [
				'import SpamScanner = require(\'spamscanner\');',
				'import ArfParser = require(\'spamscanner/arf\');',
				'const scanner: SpamScanner = new SpamScanner({});',
				'const result: Promise<object> = scanner.scan(\'x\');',
				'const classifier: SpamScanner.Classifier = new SpamScanner.Classifier();',
				'const same: SpamScanner.SpamScanner = new SpamScanner.default();',
				'const version: string = SpamScanner.VERSION;',
				'const legacy = new SpamScanner({clamscan: true, logger: console, macros: false});',
				'const checked: Promise<string[] | undefined> = legacy.scan(\'x\').then(({results}) => results.reputation?.checkedValues);',
				'const arf: Promise<object> = ArfParser.default.parse(\'x\');',
				// (a string message gives a string report, a Buffer a Buffer)
				'const report: string = ArfParser.create({feedbackType: \'abuse\', userAgent: \'u\', from: \'a@example.org\', to: \'b@example.org\', originalMessage: \'x\'});',
				'const bytes: Buffer = ArfParser.create({feedbackType: \'abuse\', userAgent: \'u\', from: \'a@example.org\', to: \'b@example.org\', originalMessage: Buffer.from(\'x\')});',
				'export {scanner, result, classifier, same, version, legacy, checked, arf, report, bytes};',
				'',
			].join('\n'));
			writeFileSync(path.join(dir, 'import.mts'), [
				'import SpamScanner, {Classifier, VERSION} from \'spamscanner\';',
				'import ArfParser from \'spamscanner/arf\';',
				'const scanner: SpamScanner = new SpamScanner({});',
				// (the settings documented, and those of earlier versions)
				'const configured = new SpamScanner({macros: false, dns: {resolve4: async (name: string, servers?: string[] | null) => [name]}, reputation: {apiUrl: \'https://reputation.example.com\', cacheTtl: 1000}});',
				'const legacy = new SpamScanner({clamscan: {clamdscan: {socket: \'/run/clamd.sock\'}}, enableMacroDetection: false, enableArbitraryDetection: false, enableAuthentication: true, authOptions: {ip: \'192.0.2.1\'}, enableReputation: true, reputationOptions: {apiUrl: \'https://reputation.example.com\'}, strictIDNDetection: true, logger: console, memoize: {}});',
				'const details = scanner.scan(\'x\', {macros: false, authenticationResults: {}}).then(({results}) => [results.macros[0]?.message, results.classification.coverage?.confidence, results.reputation?.checkedValues[0], results.reputation?.allowlisted[\'example.org\'], results.reputation?.details[\'example.org\']?.isTruthSource]);',
				'const coverage: number = new Classifier().classify([\'x\']).coverage.confidence;',
				'export {scanner, configured, legacy, details, coverage, Classifier, VERSION, ArfParser};',
				'',
			].join('\n'));
			const tsc = require.resolve('typescript/bin/tsc');
			let output;
			try {
				const {stdout, stderr} = await run(process.execPath, [tsc, '--project', dir]);
				output = `${stdout}${stderr}`;
			} catch (error) {
				// (tsc exits 1 or 2 with its errors on standard output; anything else is a crash)
				output = `${error.stdout ?? ''}${error.stderr ?? ''}` || error.message;
			}

			// Any error counts, in the consumer files or in any declaration file.
			assert.equal(output.trim(), '');
		} finally {
			rmSync(dir, {recursive: true, force: true});
		}
	});

	it('publishes every exported file, and not the standalone bundle', async () => {
		const root = fileURLToPath(new URL('..', import.meta.url));
		const {stdout} = await run('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], {cwd: root});
		const files = new Set(JSON.parse(stdout)[0].files.map(file => file.path));
		const pkg = require('spamscanner/package.json');
		const exported = [pkg.bin.spamscanner, pkg.main, pkg.types, ...Object.values(pkg.exports).flatMap(target => (typeof target === 'string' ? [target] : Object.values(target).flatMap(condition => Object.values(condition))))];
		for (const file of exported) {
			assert.ok(files.has(file.replace(/^\.\//, '')), file);
		}

		assert.ok(files.has('model/classifier.json'));
		assert.ok(!files.has('dist/standalone/cli.cjs'));
		assert.ok(!files.has('dist/types/cli.d.ts'));
	});
});
