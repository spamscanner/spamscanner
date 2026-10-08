// Spam Scanner behind a real Postfix, as a milter and as a content filter.
//
//   SPAMSCANNER_E2E_POSTFIX=1 npm run test:e2e
//
// Postfix must be set up as in .github/workflows/ci.yml:
// - port 25 (SMTP_PORT) uses the milter at inet:127.0.0.1:7831, which this test starts;
// - port 2525 (SMTP_FILTER_PORT) passes mail to "spamscanner filter" through a pipe;
// - mail to E2E_RCPT (default testuser@mx.test) lands in E2E_MAILDIR
//   (default /home/testuser/Maildir).
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import process from 'node:process';
import {
	after, before, describe, it,
} from 'node:test';
import {GTUBE} from '../../src/is-arbitrary.js';
import {SPAM, message} from '../helpers/index.js';
import {delivered, smtpSend, waitForDelivery} from './helpers.js';

const enabled = Boolean(process.env.SPAMSCANNER_E2E_POSTFIX);
const smtpPort = Number(process.env.SMTP_PORT || 25);
const filterPort = Number(process.env.SMTP_FILTER_PORT || 2525);
const rcpt = process.env.E2E_RCPT || 'testuser@mx.test';
const maildir = process.env.E2E_MAILDIR || '/home/testuser/Maildir';
const from = 'sender@example.org';

describe('Postfix', {skip: !enabled && 'set SPAMSCANNER_E2E_POSTFIX=1', timeout: 120_000}, () => {
	let milter;

	before(async () => {
		milter = spawn(process.execPath, ['src/bin.js', 'milter', '--port', '7831', '--no-cloudflare', '--reject', '--reject-code', '550', '--subject-tag', '[SPAM]', '--verbose'], {stdio: ['ignore', 'inherit', 'pipe']});
		let log = '';
		milter.stderr.setEncoding('utf8');
		milter.stderr.on('data', chunk => {
			log += chunk;
			process.stderr.write(chunk);
		});
		while (!log.includes('Listening on')) {
			await once(milter.stderr, 'data');
		}
	});

	after(() => {
		milter.kill();
	});

	it('delivers ham with headers, and drops X-Spam headers the sender forged', async () => {
		const seen = delivered(maildir);
		const reply = await smtpSend({
			port: smtpPort,
			from,
			to: rcpt,
			data: message({
				from, to: rcpt, subject: 'Lunch on Thursday', text: 'Hi, are we still on for lunch on Thursday at noon? I can book the usual place.', headers: {'X-Spam-Flag': 'NO', 'X-Spam-Score': '-50'},
			}),
		});
		assert.match(reply.data, /^250 /);
		const mail = await waitForDelivery(maildir, seen);
		assert.ok(mail, 'the message was delivered');
		assert.equal(mail.match(/^X-Spam-Flag:/gm).length, 1);
		assert.match(mail, /^X-Spam-Flag: NO$/m);
		assert.doesNotMatch(mail, /^X-Spam-Score: -50/m);
		assert.match(mail, /^Subject: Lunch on Thursday$/m);
	});

	it('tags spam below the reject threshold and delivers it', async () => {
		const seen = delivered(maildir);
		const [, subject, text] = SPAM[0];
		const reply = await smtpSend({
			port: smtpPort, from, to: rcpt, data: message({
				from, to: rcpt, subject, text,
			}),
		});
		assert.match(reply.data, /^250 /);
		const mail = await waitForDelivery(maildir, seen);
		assert.match(mail, /^X-Spam-Flag: YES$/m);
		assert.match(mail, new RegExp(`^Subject: \\[SPAM\\] ${subject}$`, 'm'));
	});

	it('rejects spam at the reject threshold during the SMTP session', async () => {
		const reply = await smtpSend({
			port: smtpPort, from, to: rcpt, data: message({
				from, to: rcpt, subject: 'Test', text: GTUBE,
			}),
		});
		assert.match(reply.data, /^550 5\.7\.1 /);
	});

	it('adds headers as a content filter', async () => {
		const seen = delivered(maildir);
		const reply = await smtpSend({
			port: filterPort, from, to: rcpt, data: message({
				from, to: rcpt, subject: 'Test', text: GTUBE,
			}),
		});
		assert.match(reply.data, /^250 /);
		const mail = await waitForDelivery(maildir, seen);
		assert.match(mail, /^X-Spam-Flag: YES$/m);
		assert.match(mail, /^X-Spam-Action: reject$/m);
		assert.match(mail, /^Subject: \[SPAM] Test$/m);
	});
});
