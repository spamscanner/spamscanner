// The spamd server with SpamAssassin's own client, spamc.
//
//   SPAMSCANNER_E2E_SPAMC=1 npm run test:e2e   (needs spamc: apt install spamc)
import assert from 'node:assert/strict';
import {execFile, spawn} from 'node:child_process';
import {once} from 'node:events';
import path from 'node:path';
import process from 'node:process';
import {
	after, before, describe, it,
} from 'node:test';
import {GTUBE} from '../../src/is-arbitrary.js';
import {message, temporaryDirectory} from '../helpers/index.js';

const enabled = Boolean(process.env.SPAMSCANNER_E2E_SPAMC);
const port = 17_833;
const spam = message({subject: 'Test', text: GTUBE});
const ham = message({subject: 'Lunch', text: 'Hi Bob, are we still on for lunch on Thursday at noon?'});

// Run spamc with a message on standard input; resolves with its exit code and output.
function spamc(args, input) {
	return new Promise(resolve => {
		const child = execFile('spamc', ['-d', '127.0.0.1', '-p', String(port), ...args], (error, stdout, stderr) => {
			resolve({code: error ? error.code : 0, stdout, stderr});
		});
		child.stdin.end(input);
	});
}

describe('spamc', {skip: !enabled && 'set SPAMSCANNER_E2E_SPAMC=1', timeout: 60_000}, () => {
	let server;

	before(async () => {
		server = spawn(process.execPath, ['src/bin.js', 'spamd', '--port', String(port), '--no-cloudflare', '--allow-tell', '--out', path.join(temporaryDirectory(), 'model.json')], {stdio: ['ignore', 'inherit', 'pipe']});
		await once(server.stderr, 'data');
	});

	after(() => {
		server.kill();
	});

	it('checks messages and sets the exit code', async () => {
		const bad = await spamc(['-c'], spam);
		assert.equal(bad.code, 1);
		assert.match(bad.stdout, /^\d+\.\d\/5\.0\n$/);
		const good = await spamc(['-c'], ham);
		assert.equal(good.code, 0);
		assert.match(good.stdout, /\/5\.0\n$/);
	});

	it('returns the message with headers, a report and the symbols', async () => {
		assert.match((await spamc([], spam)).stdout, /^X-Spam-Flag: YES$/m);
		assert.match((await spamc(['-R'], spam)).stdout, /GTUBE/);
		assert.match((await spamc(['-y'], spam)).stdout, /GTUBE/);
	});

	it('learns with -L', async () => {
		const learned = await spamc(['-L', 'spam'], spam);
		assert.equal(learned.code, 0);
		assert.match(learned.stdout, /Message successfully un\/learned/);
	});
});
