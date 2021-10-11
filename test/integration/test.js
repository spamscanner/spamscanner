const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');

const Redis = require('@ladjs/redis');
const delay = require('delay');
const isCI = require('is-ci');
const memProfile = require('memoizee/profile');
const test = require('ava');
const { lookpath } = require('lookpath');

const SpamScanner = require('../..');
const { getTokens } = require('../../workers/get-tokens-and-mail-from-source');

function fixtures(name) {
  return path.join(__dirname, '../fixtures', name);
}

const scanner = new SpamScanner();

//
// TODO: re-enable these three tests once classifier is fixed
//
/*
test('should detect spam', async (t) => {
  const scan = await scanner.scan(fixtures('spam.eml'));
  t.true(scan.is_spam);
  t.true(typeof scan.results.classification === 'object');
  t.is(scan.results.classification.category, 'spam');
});

test('should detect spam fuzzy', async (t) => {
  const scan = await scanner.scan(fixtures('spam-fuzzy.eml'));
  t.true(scan.is_spam);
  t.true(typeof scan.results.classification === 'object');
  t.is(scan.results.classification.category, 'spam');
});

test('should detect ham', async (t) => {
  const scan = await scanner.scan(fixtures('ham.eml'));
  t.false(scan.is_spam);
  t.true(typeof scan.results.classification === 'object');
  t.is(scan.results.classification.category, 'ham');
});
*/

test('should parse eop-nam02.prod.protection.outlook.com properly', async (t) => {
  const results = await Promise.all([
    scanner.isCloudflareBlocked('eop-nam02.prod.protection.outlook.com'),
    scanner.isCloudflareBlocked('prod.protection.outlook.com'),
    scanner.isCloudflareBlocked('protection.outlook.com'),
    scanner.isCloudflareBlocked('outlook.com')
  ]);
  t.deepEqual(results, [
    {
      isAdult: false,
      isMalware: false
    },
    {
      isAdult: false,
      isMalware: false
    },
    {
      isAdult: false,
      isMalware: false
    },
    {
      isAdult: false,
      isMalware: false
    }
  ]);
});

test('should detect not phishing with different org domains (temporary)', async (t) => {
  const scan = await scanner.scan(fixtures('phishing.eml'));
  t.false(scan.is_spam);
  t.true(scan.results.phishing.length === 0);
});

test('should detect idn masquerading', async (t) => {
  const client = new Redis();
  const scanner = new SpamScanner({ client, checkIDNHomographAttack: true });
  const scan = await scanner.scan(fixtures('idn.eml'));
  t.true(scan.is_spam);
  t.true(scan.results.phishing.length > 0);
});

test('should detect executable files', async (t) => {
  const scan = await scanner.scan(fixtures('executable.eml'));
  t.true(scan.is_spam);
  t.true(scan.results.executables.length > 0);
});

test('should check against Cloudflare', async (t) => {
  const link = Buffer.from('eHZpZGVvcy5jb20=', 'base64').toString();
  const results = await scanner.getPhishingResults({
    html: `<a href="${link}">test</a>${link}<A href="${link}/foo">${link}</A>`,
    text: link
  });
  t.deepEqual(results.messages, [
    `Link hostname of "${link}" was detected by Cloudflare's Family DNS to contain adult-related content, phishing, and/or malware.`
  ]);
});

//
// NOTE: I added support for GTUBE because I have a suspicion that some
// large email providers may send test emails with the GTUBE test
// to see if the mail server has spam filtering enabled, but this is
// also a nice way for us to send test messages to see that Spam Scanner
// is actually running and parsing messages properly
//
// <https://spamassassin.apache.org/gtube/>
// <https://spamassassin.apache.org/gtube/gtube.txt>
//
test('GTUBE test', async (t) => {
  const results = await scanner.getArbitraryResults({
    html: `
Subject: Test spam mail (GTUBE)
Message-ID: <GTUBE1.1010101@example.net>
Date: Wed, 23 Jul 2003 23:30:00 +0200
From: Sender <sender@example.net>
To: Recipient <recipient@example.net>
Precedence: junk
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit

This is the GTUBE, the
  Generic
  Test for
  Unsolicited
  Bulk
  Email

If your spam filter supports it, the GTUBE provides a test by which you
can verify that the filter is installed correctly and is detecting incoming
spam. You can send yourself a test mail containing the following string of
characters (in upper case and with no white spaces and line breaks):

XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X

You should send this test mail from an account outside of your network.
    `.trim()
  });
  t.deepEqual(results, [
    'Message detected to contain the GTUBE test from <https://spamassassin.apache.org/gtube/>.'
  ]);
});

//
// virus scanning detection against EICAR test
//
// <https://en.wikipedia.org/wiki/EICAR_test_file>
// <https://secure.eicar.org/eicar_com.txt>
// <https://www.eicar.org/?page_id=3950>
//
test('EICAR test', async (t) => {
  const clamd = await lookpath('clamd');
  if (!clamd) {
    if (isCI) {
      t.fail(
        'clamd executable not available, please ensure clamscan is installed'
      );
      return;
    }

    t.pass('clamd executable not available, skipping clamscan test locally');
    return;
  }

  const content = await fs.promises.readFile(fixtures('eicar.com.txt'));
  const results = await scanner.getVirusResults({
    attachments: [{ content }]
  });
  t.true(
    results.includes(
      'Attachment #1 was infected with "Eicar-Test-Signature".'
    ) ||
      results.includes(
        'Attachment #1 was infected with "Win.Test.EICAR_HDB-1".'
      )
  );
});

// <https://github.com/sindresorhus/file-type/issues/377>
test('allows < Word 2004 doc', async (t) => {
  const content = await fs.promises.readFile(fixtures('sample.doc'));
  const results = await scanner.getExecutableResults({
    attachments: [{ content }]
  });
  t.deepEqual(results, []);
});

// <https://github.com/peerigon/parse-domain/issues/116>
test('strips zero-width characters', (t) => {
  t.is(
    scanner.getHostname(
      'https://‌www.foobar.com.br‌/12345/index.php?m=foo@bar.com'
    ),
    'www.foobar.com.br'
  );
  t.is(
    scanner.getNormalizedUrl(
      'https://‌www.foobar.com.br‌/12345/index.php?m=foo@bar.com'
    ),
    'www.foobar.com.br/12345/index.php'
  );
});

test('getUrls filters out emails to be hostname only', (t) => {
  const urls = scanner.getUrls(`
    test.it123.com.foobar123.com
        robot.itýbeep.com
      baz.iT
      bop.it
      CAPS.CO
    foo.it123
     foo.itbeep.beep.mx.bar@gmail.com
      http://duckduckgo.com
    foo.mxýbeep@gmail.com
    foo.itýbeep.com
     foo.isfoo@beep.com foo.isnic'
  `);
  t.log(urls);
  t.deepEqual(urls, [
    'test.it123.com.foobar123.com',
    'robot.xn--itbeep-cza.com',
    'bop.it',
    'caps.co',
    'gmail.com',
    'duckduckgo.com',
    'foo.mx',
    'foo.xn--itbeep-cza.com',
    'beep.com'
  ]);
});

test('caches cloudflare block results', async (t) => {
  const link = Buffer.from('cG9ybi5jb20=', 'base64').toString();
  let now = performance.now();
  let diff = 0;
  const result1 = await scanner.memoizedIsCloudflareBlocked(link);
  diff = performance.now() - now;
  t.true(diff > 1);
  now = performance.now();
  const result2 = await scanner.memoizedIsCloudflareBlocked(link);
  diff = performance.now() - now;
  t.true(diff < 1);
  now = performance.now();
  const result3 = await scanner.memoizedIsCloudflareBlocked(link);
  diff = performance.now() - now;
  t.true(diff < 1);
  t.deepEqual(result1, {
    isAdult: true,
    isMalware: false
  });
  t.deepEqual(result1, result2);
  t.deepEqual(result2, result3);
  t.true(
    memProfile.statistics[Object.keys(memProfile.statistics)[0]].cached >= 2
  );
  const good = await scanner.memoizedIsCloudflareBlocked('google.com');
  t.deepEqual(good, {
    isAdult: false,
    isMalware: false
  });
});

test('caches with redis', async (t) => {
  const client = new Redis();
  const scanner = new SpamScanner({ client });
  const key = `${scanner.config.cachePrefix}:example.com`;
  // purge cache key
  await client.del(key);
  const result1 = await scanner.memoizedIsCloudflareBlocked('example.com');
  t.deepEqual(result1, { isAdult: false, isMalware: false });
  // caches it the background so wait 0.5s
  await delay(500);
  const value = await client.get(key);
  t.is(value, 'false:false');
  const result2 = await scanner.memoizedIsCloudflareBlocked('example.com');
  t.deepEqual(result1, result2);
});

for (const locale of [
  'ar',
  'da',
  'nl',
  'en',
  'fi',
  'fa',
  'fr',
  'de',
  'hu',
  'in',
  'it',
  'ja',
  'nb',
  'nn',
  'po',
  'pt',
  'es',
  'sv',
  'ro',
  'ru',
  'ta',
  'tr',
  'vi',
  'zh'
]) {
  test(`getTokens works with locale "${locale}"`, async (t) => {
    const scanner = new SpamScanner();
    const tokens = await getTokens(
      'hello world greetings today is a new day and tomorrow is another day', // = 13
      //                           ^  ^          ^           ^   ^               = 4
      locale,
      null,
      scanner.config
    );
    t.is(tokens.length, 8);
    t.pass();
  });
}

test.todo('IDN homograph attack test');
test.todo('50/50 ham vs spam dataset test');
test.todo('test classifier.json against dataset to determine % accuracy');
test.todo('should detect nsfw using nsfw.js');
test.todo('should detect phishing querystring redirections');
