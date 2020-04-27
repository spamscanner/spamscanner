const path = require('path');

const test = require('ava');

const SpamScanner = require('..');

function fixtures(name) {
  return path.join(__dirname, 'fixtures', `${name}.eml`);
}

const scanner = new SpamScanner();

test.before(async () => {
  await scanner.load();
});

test('should detect spam', async t => {
  const scan = await scanner.scan(fixtures('spam'));
  t.log(scan);
  t.true(scan.is_spam);
  t.is(scan.results.classification.category, 'spam');
});

test('should detect spam fuzzy', async t => {
  const scan = await scanner.scan(fixtures('spam-fuzzy'));
  t.log(scan);
  t.true(scan.is_spam);
  t.is(scan.results.classification.category, 'spam');
});

test('should detect ham', async t => {
  const scan = await scanner.scan(fixtures('ham'));
  t.log(scan);
  t.false(scan.is_spam);
  t.is(scan.results.classification.category, 'ham');
});

test('should detect phishing', async t => {
  const scan = await scanner.scan(fixtures('phishing'));
  t.log(scan);
  t.true(scan.is_spam);
  t.true(scan.results.phishing.length > 0);
});

test('should detect idn masquerading', async t => {
  const scan = await scanner.scan(fixtures('idn'));
  t.log(scan);
  t.true(scan.is_spam);
  t.true(scan.results.phishing.length > 0);
});

test('should detect executable files', async t => {
  const scan = await scanner.scan(fixtures('executable'));
  t.log(scan);
  t.true(scan.is_spam);
  t.true(scan.results.executables.length > 0);
});

test.todo('should check against openphish');
test.todo('should check against phishtank');
test.todo('should detect nsfw using nsfw.js');
test.todo('should detect phishing querystring redirections');
