#!/bin/sh
# Set up a local Postfix for test/e2e/postfix.test.js, in CI or on a test machine:
#
#   sudo scripts/e2e-postfix.sh "$(command -v node)" /usr/local/lib/node_modules/spamscanner/dist/esm/cli.js [user]
#
# - port 25 checks mail with the milter at 127.0.0.1:7831 (the test starts it);
# - port 2525 passes mail to "spamscanner filter" through a pipe;
# - mail for testuser@mx.test is delivered to /home/testuser/Maildir as the user
#   who runs the tests (default: the one who ran sudo), so the test can read it;
# - Postfix logs to /var/log/postfix.log.
set -eu
NODE=$1
CLI=$2
READER=${3:-${SUDO_USER:-}}

id spamscanner >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin spamscanner
id testuser >/dev/null 2>&1 || useradd --create-home testuser
# (Postfix does not deliver mail as root)
if [ -z "$READER" ] || [ "$(id -u "$READER")" -eq 0 ]; then
	READER=testuser
fi

mkdir -p /home/testuser
chown -R "$READER:$(id -gn "$READER")" /home/testuser
chmod 755 /home/testuser

postconf -e myhostname=mx.test mydestination=localhost inet_interfaces=loopback-only inet_protocols=ipv4 \
	mynetworks=127.0.0.0/8 milter_protocol=6 milter_default_action=tempfail \
	smtpd_milters= non_smtpd_milters= relayhost= default_transport=error relay_transport=error \
	virtual_mailbox_domains=mx.test virtual_mailbox_base=/home/testuser \
	'virtual_mailbox_maps=inline:{testuser@mx.test=Maildir/}' \
	"virtual_uid_maps=static:$(id -u "$READER")" "virtual_gid_maps=static:$(id -g "$READER")" \
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
