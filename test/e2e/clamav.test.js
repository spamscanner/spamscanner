// Attachment scanning against a real clamd.
//
//   SPAMSCANNER_E2E_CLAMAV=1 [CLAMD_SOCKET=/var/run/clamav/clamd.ctl] npm run test:e2e
//
// clamd needs a signature for the EICAR test file: the official database has
// one, or add a line "44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test" to a .hdb file in its
// database directory.
import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {execFile} from 'node:child_process';
import {writeFileSync} from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {describe, it} from 'node:test';
import {promisify} from 'node:util';
import SpamScanner from '../../src/index.js';
import {ping, scanBuffer} from '../../src/clamav.js';
import {eicar, message, temporaryDirectory} from '../helpers/index.js';

const run = promisify(execFile);
const enabled = Boolean(process.env.SPAMSCANNER_E2E_CLAMAV);
const socket = process.env.CLAMD_SOCKET || '/var/run/clamav/clamd.ctl';

describe('ClamAV', {skip: !enabled && 'set SPAMSCANNER_E2E_CLAMAV=1'}, () => {
	it('talks to clamd', async () => {
		assert.equal(await ping({socket}), true);
		assert.match((await scanBuffer(eicar(), {socket})).viruses[0], /eicar/i);
		assert.deepEqual((await scanBuffer(Buffer.from('a clean file'), {socket})).viruses, []);
	});

	it('finds a virus in an attachment, from the API and the command line', async () => {
		const raw = message({
			subject: 'Invoice', text: 'See the attached file.', attachments: [{filename: 'invoice.txt', content: eicar()}, {filename: 'notes.txt', content: 'clean'}],
		});
		const result = await new SpamScanner({phishing: {cloudflare: false}, clamav: {socket}}).scan(raw);
		assert.equal(result.results.viruses.length, 1);
		assert.equal(result.results.viruses[0].filename, 'invoice.txt');
		assert.equal(result.action, 'reject');
		const file = path.join(temporaryDirectory(), 'infected.eml');
		writeFileSync(file, raw);
		await assert.rejects(run(process.execPath, ['src/bin.js', 'scan', file, '--no-cloudflare', '--clamav', socket]), error => error.code === 1 && /VIRUS/.test(error.stdout));
	});
});
