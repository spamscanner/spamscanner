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

  const queue = new PQueue({
    intervalCap: 3,
    interval: 100
  });

  const startTime = Date.now();

  queue.on('next', () => {
    const currTime = Date.now();

    if (currTime - startTime >= 5000) {
      queue.clear();
      return;
    }

    queue.add(fn);
    n++;
  });

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
    75: stats.percentile(75)
  });
});
