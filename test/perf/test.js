const test = require('ava');
const {
  performance,
  PerformanceObserver,
  createHistogram
} = require('perf_hooks');
const PQueue = require('p-queue').default;
const generateEmail = require('../fixtures/email-generator');

const SpamScanner = require('../..');

const scanner = new SpamScanner();

// LOAD per second
const LOAD = 30;

test('scan() should take less than 100 ms', async (t) => {
  t.plan(1);

  const measures = [];

  const obs = new PerformanceObserver((list, observer) => {
    measures.push(list.getEntries()[0]);
  });
  obs.observe({ entryTypes: ['measure'] });

  let n = 0;
  const fn = async () => {
    const email = generateEmail({ urls: { max: 10, min: 5 } });
    const startMark = `scan-${n}-start`;
    const endMark = `scan-${n}-end`;
    const measureLabel = `scan-${n}`;

    performance.mark(startMark);

    await scanner.scan(email);

    performance.mark(endMark);
    performance.measure(measureLabel, startMark, endMark);
  };

  // 30 per second
  const queue = new PQueue({
    intervalCap: LOAD / 10,
    interval: 100
  });

  queue.on('next', () => {
    // run for 5 seconds
    if (n === LOAD * 5) {
      return;
    }

    queue.add(fn);
    n++;
  });

  // pre-load queue
  for (let i = 0; i < 30; i++) {
    queue.add(fn);
    n++;
  }

  await queue.onIdle();

  obs.disconnect();

  // console.table(measures);

  const stats = createHistogram();

  for (const item of measures) {
    stats.record(Math.round(item.duration));
  }

  console.table({
    mean: stats.mean,
    stddev: stats.stddev,
    max: stats.max,
    min: stats.min,
    25: stats.percentile(25),
    50: stats.percentile(50),
    75: stats.percentile(75),
    count: measures.length
  });

  t.true(stats.mean <= 100);
});
