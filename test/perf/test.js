const test = require('ava');
const {
  performance,
  PerformanceObserver,
  createHistogram
} = require('perf_hooks');
const pMap = require('p-map');
const generateEmail = require('../fixtures/email-generator');

const SpamScanner = require('../..');

const scanner = new SpamScanner();

test('scan() should take less than 100 ms', async (t) => {
  t.plan(1);

  const obs = new PerformanceObserver((list, observer) => {
    console.table(list.getEntries());

    const stats = createHistogram();

    for (const item of list.getEntries()) {
      stats.record(Math.round(item.duration));
    }

    console.table({
      mean: stats.mean,
      stddev: stats.stddev,
      max: stats.max,
      min: stats.min,
      25: stats.percentile(25),
      50: stats.percentile(50),
      75: stats.percentile(75)
    });

    observer.disconnect();
    t.fail();
  });
  obs.observe({ entryTypes: ['measure'], buffered: true });

  const emails = [];

  for (const i of Array.from({ length: 5 })) {
    emails.push(generateEmail());
  }

  await pMap(emails, async (email, n) => {
    performance.mark(`scan-${n}-start`);
    await scanner.scan(email);
    performance.mark(`scan-${n}-end`);
    performance.measure(`scan-${n}`, `scan-${n}-start`, `scan-${n}-end`);
  });
});
