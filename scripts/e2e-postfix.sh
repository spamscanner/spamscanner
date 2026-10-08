#!/bin/sh
# Set up a local Postfix for test/e2e/postfix.test.js, in CI or on a test machine:
#
#   sudo scripts/e2e-postfix.sh "$(command -v node)" /usr/local/lib/node_modules/spamscanner/dist/esm/cli.js
#
# - port 25 checks mail with the milter at 127.0.0.1:7831 (the test starts it);
# - port 2525 passes mail to "spamscanner filter" through a pipe;
# - mail for testuser@mx.test is delivered to /home/testuser/Maildir;
# - Postfix logs to /var/log/postfix.log.
set -eu
NODE=$1
CLI=$2

id spamscanner >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin spamscanner
id testuser >/dev/null 2>&1 || useradd --create-home testuser

postconf -e myhostname=mx.test 'mydestination=localhost, mx.test' inet_interfaces=loopback-only inet_protocols=ipv4 \
	mynetworks=127.0.0.0/8 home_mailbox=Maildir/ milter_protocol=6 milter_default_action=tempfail \
	smtpd_milters= non_smtpd_milters= relayhost= default_transport=error relay_transport=error \
	maillog_file=/var/log/postfix.log
postconf -M 'smtp/inet=smtp inet n - n - - smtpd -o smtpd_milters=inet:127.0.0.1:7831'
postconf -M '2525/inet=2525 inet n - n - - smtpd -o content_filter=spamscanner:dummy'
postconf -M "spamscanner/unix=spamscanner unix - n n - 10 pipe flags=Rq user=spamscanner null_sender= argv=$NODE $CLI filter --no-cloudflare --subject-tag [SPAM] -f \${sender} -- \${recipient}"
postfix check

# A reload keeps the old inet_interfaces and inet_protocols, so Postfix,
# which the package manager may already have started, is stopped and started.
postfix stop >/dev/null 2>&1 || true
postfix start

# Wait until both ports take connections; otherwise show why not.
for _ in $(seq 1 30); do
	"$NODE" -e "
		const net = require('node:net');
		let open = 0;
		for (const port of [25, 2525]) {
			net.connect(port, '127.0.0.1', function () {
				this.end();
				if (++open === 2) process.exit(0);
			}).on('error', () => process.exit(1));
		}
	" && exit 0
	sleep 1
done

postfix status || true
tail -50 /var/log/postfix.log || true
exit 1
