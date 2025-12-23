/**
 * SEA (Single Executable Application) Binary Tests
 *
 * These tests build and verify the standalone SEA binary.
 * They are separate from regular CLI tests because they require
 * building the binary first, which takes time.
 *
 * SEA requires Node.js 20+ (--experimental-sea-config flag)
 *
 * Run with: npm run test:sea
 * Or: node --test test/sea-binary.js
 */

import assert from 'node:assert';
import {spawn, execSync} from 'node:child_process';
import {
	existsSync, unlinkSync, statSync, writeFileSync, copyFileSync, chmodSync,
} from 'node:fs';
import {platform, arch} from 'node:os';
import path from 'node:path';
import process from 'node:process';
import {
	describe, it, before, after,
} from 'node:test';
import {fileURLToPath} from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_DIR = path.join(__dirname, '..');

// Check if Node.js version supports SEA (requires Node.js 20+)
function checkSeaSupport() {
	const nodeVersion = process.versions.node;
	const majorVersion = Number.parseInt(nodeVersion.split('.')[0], 10);

	if (majorVersion < 20) {
		return {
			supported: false,
			reason: `SEA requires Node.js 20+, current version is ${nodeVersion}`,
		};
	}

	// Check if the flag is recognized (it requires an argument, so we check stderr)
	try {
		execSync('node --experimental-sea-config 2>&1', {
			stdio: 'pipe',
			timeout: 5000,
		});
		return {supported: true};
	} catch (error) {
		// If the error message says "requires an argument", the flag is supported
		if (error.stderr && error.stderr.toString().includes('requires an argument')) {
			return {supported: true};
		}

		if (error.stdout && error.stdout.toString().includes('requires an argument')) {
			return {supported: true};
		}

		return {
			supported: false,
			reason: `Node.js ${nodeVersion} does not support --experimental-sea-config flag`,
		};
	}
}

// Determine binary name based on platform
function getBinaryName() {
	const os = platform();
	let archName = arch();

	if (archName === 'x64') {
		archName = 'x64';
	} else if (archName === 'arm64') {
		archName = 'arm64';
	}

	let platformName;
	switch (os) {
		case 'darwin': {
			platformName = `darwin-${archName}`;
			break;
		}

		case 'linux': {
			platformName = `linux-${archName}`;
			break;
		}

		case 'win32': {
			platformName = 'win-x64';
			break;
		}

		default: {
			throw new Error(`Unsupported platform: ${os}`);
		}
	}

	const ext = os === 'win32' ? '.exe' : '';
	return `spamscanner-${platformName}${ext}`;
}

const BINARY_NAME = getBinaryName();
const BINARY_PATH = path.join(PROJECT_DIR, BINARY_NAME);

// Check SEA support before running tests
const seaSupport = checkSeaSupport();

/**
 * Run the SEA binary with given arguments
 * @param {string[]} args - CLI arguments
 * @param {string} [stdin] - Optional stdin input
 * @returns {Promise<{stdout: string, stderr: string, code: number}>}
 */
function runBinary(args, stdin) {
	return new Promise(resolve => {
		const proc = spawn(BINARY_PATH, args, {
			stdio: ['pipe', 'pipe', 'pipe'],
		});

		let stdout = '';
		let stderr = '';

		proc.stdout.on('data', data => {
			stdout += data.toString();
		});

		proc.stderr.on('data', data => {
			stderr += data.toString();
		});

		if (stdin) {
			proc.stdin.write(stdin);
			proc.stdin.end();
		}

		proc.on('close', code => {
			resolve({stdout, stderr, code});
		});
	});
}

describe('SEA Binary', {skip: seaSupport.supported ? false : seaSupport.reason}, () => {
	before(async function () {
		// Set longer timeout for build
		this.timeout = 120_000;

		console.log('Building SEA binary...');
		console.log(`Binary name: ${BINARY_NAME}`);
		console.log(`Binary path: ${BINARY_PATH}`);

		// Check if standalone CLI exists, if not build it
		const standalonePath = path.join(PROJECT_DIR, 'dist', 'standalone', 'cli.cjs');
		if (!existsSync(standalonePath)) {
			console.log('Building standalone CLI bundle...');
			execSync('npm run build', {cwd: PROJECT_DIR, stdio: 'inherit'});
		}

		// Create SEA config
		const seaConfig = {
			main: 'dist/standalone/cli.cjs',
			output: 'sea-prep.blob',
			disableExperimentalSEAWarning: true,
			useSnapshot: false,
			useCodeCache: true,
		};

		const configPath = path.join(PROJECT_DIR, 'sea-config.json');
		writeFileSync(configPath, JSON.stringify(seaConfig, null, 2));

		// Build SEA blob
		console.log('Building SEA blob...');
		execSync('node --experimental-sea-config sea-config.json', {
			cwd: PROJECT_DIR,
			stdio: 'inherit',
		});

		// Get node binary path
		const nodePath = process.execPath;

		// Copy node binary
		console.log('Creating SEA binary...');
		copyFileSync(nodePath, BINARY_PATH);

		// Inject SEA blob
		const os = platform();
		if (os === 'darwin') {
			// MacOS: Remove signature, inject, re-sign
			try {
				execSync(`codesign --remove-signature "${BINARY_PATH}"`, {
					cwd: PROJECT_DIR,
					stdio: 'pipe',
				});
			} catch {
				// Ignore if no signature
			}

			execSync(
				`npx postject "${BINARY_PATH}" NODE_SEA_BLOB sea-prep.blob `
				+ '--sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2 '
				+ '--macho-segment-name NODE_SEA',
				{cwd: PROJECT_DIR, stdio: 'inherit'},
			);

			try {
				execSync(`codesign --sign - "${BINARY_PATH}"`, {
					cwd: PROJECT_DIR,
					stdio: 'pipe',
				});
			} catch {
				// Ignore signing errors
			}
		} else {
			// Linux/Windows
			execSync(
				`npx postject "${BINARY_PATH}" NODE_SEA_BLOB sea-prep.blob `
				+ '--sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2',
				{cwd: PROJECT_DIR, stdio: 'inherit'},
			);
		}

		// Make executable
		if (os !== 'win32') {
			chmodSync(BINARY_PATH, 0o755);
		}

		// Cleanup config files
		unlinkSync(configPath);
		unlinkSync(path.join(PROJECT_DIR, 'sea-prep.blob'));

		console.log('SEA binary built successfully');
	});

	after(() => {
		// Cleanup binary after tests
		if (existsSync(BINARY_PATH)) {
			try {
				unlinkSync(BINARY_PATH);
				console.log('Cleaned up SEA binary');
			} catch {
				// Ignore cleanup errors
			}
		}
	});

	it('should exist and be executable', () => {
		assert.ok(existsSync(BINARY_PATH), 'Binary should exist');
		const stats = statSync(BINARY_PATH);
		assert.ok(stats.size > 0, 'Binary should have content');
		// On Unix, check executable bit
		if (platform() !== 'win32') {
			// eslint-disable-next-line no-bitwise
			assert.ok((stats.mode & 0o111) !== 0, 'Binary should be executable');
		}
	});

	it('should show version', async () => {
		const {stdout, code} = await runBinary(['--version']);

		assert.strictEqual(code, 0, 'Exit code should be 0');
		assert.ok(/\d+\.\d+\.\d+/.test(stdout), 'Should show valid version number');
		assert.ok(!stdout.includes('unknown'), 'Version should not be unknown');
	});

	it('should show help', async () => {
		const {stdout, code} = await runBinary(['--help']);

		assert.strictEqual(code, 0, 'Exit code should be 0');
		assert.ok(stdout.includes('SpamScanner CLI'), 'Should show CLI header');
		assert.ok(stdout.includes('scan'), 'Should show scan command');
		assert.ok(stdout.includes('--json'), 'Should show --json option');
	});

	it('should scan email from stdin', async () => {
		const testEmail = `From: sender@example.com
To: recipient@example.net
Subject: Test Email
Date: Thu, 1 Jan 2024 00:00:00 +0000
Message-ID: <test@example.com>

This is a test email for SEA binary testing.
`;
		const {stdout, code} = await runBinary(['scan', '-', '--no-update-check'], testEmail);

		// Should complete without crashing (exit 0 for clean, 1 for spam)
		assert.ok(code === 0 || code === 1, `Expected exit code 0 or 1, got ${code}`);
		assert.ok(stdout.length > 0, 'Should produce output');
	});

	it('should output JSON with --json flag', async () => {
		const testEmail = `From: sender@example.com
To: recipient@example.net
Subject: Test Email
Date: Thu, 1 Jan 2024 00:00:00 +0000
Message-ID: <test@example.com>

This is a test email.
`;
		const {stdout, code} = await runBinary(['scan', '-', '--json', '--no-update-check'], testEmail);

		assert.ok(code === 0 || code === 1, `Expected exit code 0 or 1, got ${code}`);

		// Extract JSON from output (may have TensorFlow warnings before it)
		const jsonMatch = stdout.match(/{[\s\S]*}/);
		assert.ok(jsonMatch, 'Output should contain JSON object');

		// Should be valid JSON
		let parsed;
		try {
			parsed = JSON.parse(jsonMatch[0]);
		} catch {
			assert.fail('Output should be valid JSON');
		}

		assert.ok('isSpam' in parsed, 'JSON should have isSpam field');
		assert.ok('score' in parsed, 'JSON should have score field');
		assert.ok('threshold' in parsed, 'JSON should have threshold field');
	});

	it('should handle auth options', async () => {
		const testEmail = `From: sender@example.com
To: recipient@example.net
Subject: Test Email
Date: Thu, 1 Jan 2024 00:00:00 +0000
Message-ID: <test@example.com>

This is a test email.
`;
		const {stdout, code} = await runBinary([
			'scan',
			'-',
			'--enable-auth',
			'--sender-ip',
			'192.168.1.1',
			'--json',
			'--no-update-check',
		], testEmail);

		assert.ok(code === 0 || code === 1, `Expected exit code 0 or 1, got ${code}`);

		// Extract JSON from output
		const jsonMatch = stdout.match(/{[\s\S]*}/);
		assert.ok(jsonMatch, 'Output should contain JSON object');

		let parsed;
		try {
			parsed = JSON.parse(jsonMatch[0]);
		} catch {
			assert.fail('Output should be valid JSON');
		}

		// Auth should be present when enabled
		assert.ok(
			parsed.results && 'authentication' in parsed.results,
			'JSON should have authentication field when --enable-auth is used',
		);
	});

	it('should add X-Spam headers with --add-headers', async () => {
		const testEmail = `From: sender@example.com
To: recipient@example.net
Subject: Test Email
Date: Thu, 1 Jan 2024 00:00:00 +0000
Message-ID: <test@example.com>

This is a test email.
`;
		const {stdout, code} = await runBinary([
			'scan',
			'-',
			'--add-headers',
			'--no-update-check',
		], testEmail);

		assert.ok(code === 0 || code === 1, `Expected exit code 0 or 1, got ${code}`);
		assert.ok(stdout.includes('X-Spam-Status:'), 'Should include X-Spam-Status header');
		assert.ok(stdout.includes('X-Spam-Score:'), 'Should include X-Spam-Score header');
	});

	it('should work with custom threshold', async () => {
		const testEmail = `From: sender@example.com
To: recipient@example.net
Subject: Test Email
Date: Thu, 1 Jan 2024 00:00:00 +0000
Message-ID: <test@example.com>

This is a test email.
`;
		const {stdout, code} = await runBinary([
			'scan',
			'-',
			'--json',
			'--threshold',
			'10.0',
			'--no-update-check',
		], testEmail);

		assert.ok(code === 0 || code === 1, `Expected exit code 0 or 1, got ${code}`);

		const jsonMatch = stdout.match(/{[\s\S]*}/);
		assert.ok(jsonMatch, 'Output should contain JSON object');

		const parsed = JSON.parse(jsonMatch[0]);
		assert.strictEqual(parsed.threshold, 10, 'Threshold should be 10.0');
	});
});
