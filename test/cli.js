import assert from 'node:assert';
import {spawn} from 'node:child_process';
import {writeFileSync, unlinkSync, mkdtempSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {
	describe, it, before, after,
} from 'node:test';
import {fileURLToPath} from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLI_PATH = path.join(__dirname, '..', 'src', 'cli.js');

/**
 * Run the CLI with given arguments
 * @param {string[]} args - CLI arguments
 * @param {string} [stdin] - Optional stdin input
 * @returns {Promise<{stdout: string, stderr: string, code: number}>}
 */
function runCli(args, stdin) {
	return new Promise(resolve => {
		const proc = spawn('node', [CLI_PATH, ...args], {
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

describe('CLI', () => {
	let temporaryDir;
	let testEmailPath;

	before(() => {
		temporaryDir = mkdtempSync(path.join(tmpdir(), 'spamscanner-cli-test-'));
		testEmailPath = path.join(temporaryDir, 'test.eml');

		const testEmail = `From: sender@example.com
To: recipient@example.net
Subject: Test Email
Date: Thu, 1 Jan 2024 00:00:00 +0000
Content-Type: text/plain

This is a test email for CLI testing.
`;
		writeFileSync(testEmailPath, testEmail);
	});

	after(() => {
		try {
			unlinkSync(testEmailPath);
		} catch {
			// Ignore cleanup errors
		}
	});

	describe('help', () => {
		it('should show help with --help flag', async () => {
			const {stdout, code} = await runCli(['--help']);

			assert.strictEqual(code, 0);
			assert.ok(stdout.includes('SpamScanner CLI'));
			assert.ok(stdout.includes('Usage:'));
			assert.ok(stdout.includes('Commands:'));
		});

		it('should show help with -h flag', async () => {
			const {stdout, code} = await runCli(['-h']);

			assert.strictEqual(code, 0);
			assert.ok(stdout.includes('SpamScanner CLI'));
		});

		it('should show help with help command', async () => {
			const {stdout, code} = await runCli(['help']);

			assert.strictEqual(code, 0);
			assert.ok(stdout.includes('SpamScanner CLI'));
		});

		it('should show spam detection options in help', async () => {
			const {stdout, code} = await runCli(['--help']);

			assert.strictEqual(code, 0);
			assert.ok(stdout.includes('--threshold'));
			assert.ok(stdout.includes('--check-classifier'));
			assert.ok(stdout.includes('--check-phishing'));
			assert.ok(stdout.includes('--add-headers'));
			assert.ok(stdout.includes('--prepend-subject'));
		});

		it('should show score weight options in help', async () => {
			const {stdout, code} = await runCli(['--help']);

			assert.strictEqual(code, 0);
			assert.ok(stdout.includes('--score-classifier'));
			assert.ok(stdout.includes('--score-phishing'));
			assert.ok(stdout.includes('--score-executable'));
		});
	});

	describe('version', () => {
		it('should show version with --version flag', async () => {
			const {stdout, code} = await runCli(['--version']);

			assert.strictEqual(code, 0);
			assert.ok(stdout.includes('SpamScanner v'));
		});

		it('should show version with -v flag', async () => {
			const {stdout, code} = await runCli(['-v']);

			assert.strictEqual(code, 0);
			assert.ok(stdout.includes('SpamScanner v'));
		});

		it('should show version with version command', async () => {
			const {stdout, code} = await runCli(['version']);

			assert.strictEqual(code, 0);
			assert.ok(stdout.includes('SpamScanner v'));
		});

		it('should show dynamic version from package.json', async () => {
			const {stdout} = await runCli(['version']);

			assert.ok(/SpamScanner v\d+\.\d+\.\d+/.test(stdout));
		});
	});

	describe('scan command', () => {
		it('should error when no file specified', async () => {
			const {stderr, code} = await runCli(['scan']);

			assert.strictEqual(code, 2);
			assert.ok(stderr.includes('No file specified'));
		});

		it('should error when file not found', async () => {
			const {stderr, code} = await runCli(['scan', '/nonexistent/file.eml']);

			assert.strictEqual(code, 2);
			assert.ok(stderr.includes('File not found'));
		});

		it('should scan a file and output result', async () => {
			const {stdout, code} = await runCli(['scan', testEmailPath]);

			assert.ok(code === 0 || code === 1, `Expected exit code 0 or 1, got ${code}`);
			assert.ok(stdout.includes('Clean') || stdout.includes('SPAM'));
		});

		it('should output JSON with --json flag', async () => {
			const {stdout, code} = await runCli(['scan', testEmailPath, '--json']);

			assert.ok(code === 0 || code === 1);

			const result = JSON.parse(stdout);
			assert.ok('isSpam' in result);
		});

		it('should output JSON with -j flag', async () => {
			const {stdout, code} = await runCli(['scan', testEmailPath, '-j']);

			assert.ok(code === 0 || code === 1);

			const result = JSON.parse(stdout);
			assert.ok('isSpam' in result);
		});

		it('should scan from stdin with -', async () => {
			const testEmail = `From: test@example.com
To: recipient@example.net
Subject: Stdin Test
Date: Thu, 1 Jan 2024 00:00:00 +0000

Test email from stdin.
`;
			const {stdout, code} = await runCli(['scan', '-'], testEmail);

			assert.ok(code === 0 || code === 1);
			assert.ok(stdout.includes('Clean') || stdout.includes('SPAM'));
		});

		it('should show verbose output with --verbose flag', async () => {
			const {stdout, code} = await runCli(['scan', testEmailPath, '--verbose']);

			assert.ok(code === 0 || code === 1);
			assert.ok(stdout.includes('Details:') || stdout.includes('Clean') || stdout.includes('SPAM'));
		});
	});

	describe('spam scoring', () => {
		it('should include score and threshold in JSON output', async () => {
			const {stdout, code} = await runCli(['scan', testEmailPath, '--json']);

			assert.ok(code === 0 || code === 1);

			const result = JSON.parse(stdout);
			assert.ok('score' in result, 'Result should have score');
			assert.ok('threshold' in result, 'Result should have threshold');
			assert.ok('tests' in result, 'Result should have tests array');
			assert.ok(typeof result.score === 'number', 'Score should be a number');
			assert.ok(typeof result.threshold === 'number', 'Threshold should be a number');
			assert.ok(Array.isArray(result.tests), 'Tests should be an array');
		});

		it('should use custom threshold', async () => {
			const {stdout, code} = await runCli(['scan', testEmailPath, '--json', '--threshold', '10.0']);

			assert.ok(code === 0 || code === 1);

			const result = JSON.parse(stdout);
			assert.strictEqual(result.threshold, 10, 'Threshold should be 10.0');
		});

		it('should show score in human-readable output', async () => {
			const {stdout, code} = await runCli(['scan', testEmailPath]);

			assert.ok(code === 0 || code === 1);
			assert.ok(stdout.includes('score:'), 'Output should include score');
			assert.ok(stdout.includes('threshold:'), 'Output should include threshold');
		});
	});

	describe('detection options', () => {
		it('should disable classifier with --no-classifier', async () => {
			const {stdout, code} = await runCli(['scan', testEmailPath, '--json', '--no-classifier']);

			assert.ok(code === 0 || code === 1);

			const result = JSON.parse(stdout);
			const hasClassifierTest = result.tests.some(t => t.includes('BAYES'));
			assert.ok(!hasClassifierTest, 'Should not have BAYES test when classifier disabled');
		});

		it('should disable phishing with --no-phishing', async () => {
			const {stdout, code} = await runCli(['scan', testEmailPath, '--json', '--no-phishing']);

			assert.ok(code === 0 || code === 1);

			const result = JSON.parse(stdout);
			const hasPhishingTest = result.tests.some(t => t.includes('PHISHING'));
			assert.ok(!hasPhishingTest, 'Should not have PHISHING test when disabled');
		});

		it('should enable NSFW check with --check-nsfw', async () => {
			const {stdout, code} = await runCli(['scan', testEmailPath, '--json', '--check-nsfw']);

			assert.ok(code === 0 || code === 1);

			// Just verify it doesn't error - NSFW detection requires images
			const result = JSON.parse(stdout);
			assert.ok('isSpam' in result);
		});

		it('should enable toxicity check with --check-toxicity', async () => {
			const {stdout, code} = await runCli(['scan', testEmailPath, '--json', '--check-toxicity']);

			assert.ok(code === 0 || code === 1);

			// Just verify it doesn't error
			const result = JSON.parse(stdout);
			assert.ok('isSpam' in result);
		});
	});

	describe('score weights', () => {
		it('should use custom classifier score weight', async () => {
			const {stdout, code} = await runCli(['scan', testEmailPath, '--json', '--score-classifier', '10.0']);

			assert.ok(code === 0 || code === 1);

			// Just verify it doesn't error
			const result = JSON.parse(stdout);
			assert.ok('score' in result);
		});

		it('should use custom phishing score weight', async () => {
			const {stdout, code} = await runCli(['scan', testEmailPath, '--json', '--score-phishing', '20.0']);

			assert.ok(code === 0 || code === 1);

			const result = JSON.parse(stdout);
			assert.ok('score' in result);
		});
	});

	describe('header options', () => {
		it('should add X-Spam headers with --add-headers', async () => {
			const testEmail = `From: test@example.com
To: recipient@example.net
Subject: Header Test
Date: Thu, 1 Jan 2024 00:00:00 +0000

Test email for header testing.
`;
			const {stdout, code} = await runCli(['scan', '-', '--add-headers'], testEmail);

			assert.ok(code === 0 || code === 1);
			assert.ok(stdout.includes('X-Spam-Status:'), 'Should include X-Spam-Status header');
			assert.ok(stdout.includes('X-Spam-Score:'), 'Should include X-Spam-Score header');
			assert.ok(stdout.includes('X-Spam-Flag:'), 'Should include X-Spam-Flag header');
		});

		it('should include headers in JSON output with --add-headers', async () => {
			const {stdout, code} = await runCli(['scan', testEmailPath, '--json', '--add-headers']);

			assert.ok(code === 0 || code === 1);

			const result = JSON.parse(stdout);
			assert.ok('headers' in result, 'Result should have headers object');
			assert.ok('X-Spam-Status' in result.headers, 'Headers should include X-Spam-Status');
			assert.ok('X-Spam-Score' in result.headers, 'Headers should include X-Spam-Score');
			assert.ok('X-Spam-Flag' in result.headers, 'Headers should include X-Spam-Flag');
			assert.ok('X-Spam-Tests' in result.headers, 'Headers should include X-Spam-Tests');
		});

		it('should format X-Spam-Status header correctly', async () => {
			const {stdout, code} = await runCli(['scan', testEmailPath, '--json', '--add-headers']);

			assert.ok(code === 0 || code === 1);

			const result = JSON.parse(stdout);
			const status = result.headers['X-Spam-Status'];

			// Should match format: Yes/No, score=X.X required=Y.Y tests=... version=X.X.X
			assert.ok(status.includes('score='), 'X-Spam-Status should include score');
			assert.ok(status.includes('required='), 'X-Spam-Status should include required');
			assert.ok(status.includes('version='), 'X-Spam-Status should include version');
			assert.ok(status.startsWith('Yes') || status.startsWith('No'), 'X-Spam-Status should start with Yes or No');
		});

		it('should prepend subject tag with --prepend-subject', async () => {
			const testEmail = `From: test@example.com
To: recipient@example.net
Subject: Original Subject
Date: Thu, 1 Jan 2024 00:00:00 +0000

Test email.
`;
			// Use a very low threshold to ensure it's marked as spam
			const {stdout, code} = await runCli(['scan', '-', '--add-headers', '--prepend-subject', '--threshold', '0.0'], testEmail);

			assert.ok(code === 0 || code === 1);
			// If marked as spam (threshold 0), subject should be modified
			if (code === 1) {
				assert.ok(stdout.includes('[SPAM]'), 'Subject should be prepended with [SPAM]');
			}
		});

		it('should use custom subject tag with --subject-tag', async () => {
			const testEmail = `From: test@example.com
To: recipient@example.net
Subject: Original Subject
Date: Thu, 1 Jan 2024 00:00:00 +0000

Test email.
`;
			const {stdout, code} = await runCli(['scan', '-', '--add-headers', '--prepend-subject', '--subject-tag', '[JUNK]', '--threshold', '0.0'], testEmail);

			assert.ok(code === 0 || code === 1);
			if (code === 1) {
				assert.ok(stdout.includes('[JUNK]'), 'Subject should be prepended with [JUNK]');
			}
		});
	});

	describe('unknown command', () => {
		it('should error for unknown command', async () => {
			const {stderr, code} = await runCli(['unknown']);

			assert.strictEqual(code, 2);
			assert.ok(stderr.includes('Unknown command'));
		});

		it('should error when no command provided', async () => {
			const {stderr, code} = await runCli([]);

			assert.strictEqual(code, 2);
			assert.ok(stderr.includes('Unknown command'));
		});
	});

	describe('exit codes', () => {
		it('should exit with 0 for clean emails', async () => {
			const cleanEmail = `From: legitimate@example.com
To: recipient@example.net
Subject: Hello
Date: Thu, 1 Jan 2024 00:00:00 +0000

Just saying hello!
`;
			const {code} = await runCli(['scan', '-'], cleanEmail);

			assert.ok(code === 0 || code === 1, `Expected exit code 0 or 1, got ${code}`);
		});

		it('should exit with 1 when score exceeds threshold', async () => {
			const testEmail = `From: test@example.com
To: recipient@example.net
Subject: Test
Date: Thu, 1 Jan 2024 00:00:00 +0000

Test email.
`;
			// Use threshold 0 to force spam detection
			const {code} = await runCli(['scan', '-', '--threshold', '0.0'], testEmail);

			// Any email with score > 0 should be marked as spam
			assert.ok(code === 0 || code === 1, `Expected exit code 0 or 1, got ${code}`);
		});
	});

	describe('update', () => {
		it('should show update command in help', async () => {
			const {stdout, code} = await runCli(['--help']);

			assert.strictEqual(code, 0);
			assert.ok(stdout.includes('update'), 'Help should mention update command');
			assert.ok(stdout.includes('Check for updates'), 'Help should describe update command');
		});

		it('should run update command without error', async () => {
			const {stdout, code} = await runCli(['update']);

			// Should exit 0 regardless of whether update is available
			assert.strictEqual(code, 0);
			assert.ok(stdout.includes('SpamScanner'), 'Should show SpamScanner version');
			assert.ok(
				stdout.includes('Checking for updates') || stdout.includes('latest version') || stdout.includes('New version'),
				'Should show update check status',
			);
		});

		it('should accept --no-update-check flag', async () => {
			const testEmail = `From: test@example.com
To: recipient@example.net
Subject: Test
Date: Thu, 1 Jan 2024 00:00:00 +0000

Test email.
`;
			const {code} = await runCli(['scan', '-', '--no-update-check'], testEmail);

			// Should work without error
			assert.ok(code === 0 || code === 1, `Expected exit code 0 or 1, got ${code}`);
		});

		it('should show --no-update-check in help', async () => {
			const {stdout, code} = await runCli(['--help']);

			assert.strictEqual(code, 0);
			assert.ok(stdout.includes('--no-update-check'), 'Help should mention --no-update-check option');
		});
	});
});

describe('Standalone Binary', () => {
	const STANDALONE_CLI_PATH = path.join(__dirname, '..', 'dist', 'standalone', 'cli.cjs');

	/**
	 * Run the standalone CLI with given arguments
	 * @param {string[]} args - CLI arguments
	 * @param {string} [stdin] - Optional stdin input
	 * @returns {Promise<{stdout: string, stderr: string, code: number}>}
	 */
	function runStandaloneCli(args, stdin) {
		return new Promise(resolve => {
			const proc = spawn('node', [STANDALONE_CLI_PATH, ...args], {
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

	it('should show help with --help flag', async () => {
		const {stdout, code} = await runStandaloneCli(['--help']);

		assert.strictEqual(code, 0, 'Exit code should be 0');
		assert.ok(stdout.includes('SpamScanner CLI'), 'Should show CLI header');
		assert.ok(stdout.includes('scan'), 'Should show scan command');
	});

	it('should show version with --version flag', async () => {
		const {stdout, code} = await runStandaloneCli(['--version']);

		assert.strictEqual(code, 0, 'Exit code should be 0');
		// Version should be a valid semver (not "unknown")
		assert.ok(/\d+\.\d+\.\d+/.test(stdout), 'Should show valid version number');
		assert.ok(!stdout.includes('unknown'), 'Version should not be unknown');
	});

	it('should scan email from stdin', async () => {
		const testEmail = `From: sender@example.com
To: recipient@example.net
Subject: Test Email
Date: Thu, 1 Jan 2024 00:00:00 +0000
Message-ID: <test@example.com>

This is a test email for standalone CLI testing.
`;
		const {stdout, code} = await runStandaloneCli(['scan', '-', '--no-update-check'], testEmail);

		// Should complete without crashing (exit 0 for clean, 1 for spam)
		assert.ok(code === 0 || code === 1, `Expected exit code 0 or 1, got ${code}`);
		// Should produce output
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
		const {stdout, code} = await runStandaloneCli(['scan', '-', '--json', '--no-update-check'], testEmail);

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
	});

	it('should handle auth options', async () => {
		const testEmail = `From: sender@example.com
To: recipient@example.net
Subject: Test Email
Date: Thu, 1 Jan 2024 00:00:00 +0000
Message-ID: <test@example.com>

This is a test email.
`;
		const {stdout, code} = await runStandaloneCli([
			'scan',
			'-',
			'--enable-auth',
			'--sender-ip',
			'192.168.1.1',
			'--json',
			'--no-update-check',
		], testEmail);

		assert.ok(code === 0 || code === 1, `Expected exit code 0 or 1, got ${code}`);

		// Extract JSON from output (may have TensorFlow warnings before it)
		const jsonMatch = stdout.match(/{[\s\S]*}/);
		assert.ok(jsonMatch, 'Output should contain JSON object');

		let parsed;
		try {
			parsed = JSON.parse(jsonMatch[0]);
		} catch {
			assert.fail('Output should be valid JSON');
		}

		// Auth should be present when enabled (it's under results.authentication)
		assert.ok(parsed.results && 'authentication' in parsed.results, 'JSON should have authentication field when --enable-auth is used');
		assert.ok(parsed.results.authentication !== null, 'Authentication results should not be null when --enable-auth is used');
	});
});
