const test = require('ava');
const {
  monitorEventLoopDelay,
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

// store resulting statistics
// to be printed/saved at end
const results = {};

test.after(() => {
  // print results
  console.log('Overall Execution Times(ms):');
  console.table(results.overallExecutionTime);

  console.log('Overall Delay Times(ms):');
  console.table(results.overallDelayTime);
});

test('scan() should take less than 100 ms on average', async (t) => {
  t.plan(1);

  const measures = [];

  const obs = new PerformanceObserver((list) => {
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
  for (let i = 0; i < LOAD; i++) {
    queue.add(fn);
    n++;
  }

  await queue.onIdle();

  obs.disconnect();
  performance.clearMarks();

  // console.table(measures);

  const stats = createHistogram();

  for (const item of measures) {
    stats.record(Math.round(item.duration));
  }

  results.overallExecutionTime = {
    mean: stats.mean,
    stddev: stats.stddev,
    max: stats.max,
    min: stats.min,
    25: stats.percentile(25),
    50: stats.percentile(50),
    75: stats.percentile(75),
    count: measures.length
  };

  t.true(stats.mean <= 100);
});

test(`scan() should have no more than a 50 ms delay`, async (t) => {
  let n = 0;
  const h = monitorEventLoopDelay();
  const fn = async () => {
    const email = generateEmail({ urls: { max: 10, min: 5 } });

    h.enable();
    await scanner.scan(email);
    h.disable();
  };

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
  for (let i = 0; i < LOAD; i++) {
    queue.add(fn);
    n++;
  }

  await queue.onIdle();

  results.overallDelayTime = {
    mean: h.mean / 1000000,
    stddev: h.stddev / 1000000,
    max: h.max / 1000000,
    min: h.min / 1000000,
    25: h.percentile(25) / 1000000,
    50: h.percentile(50) / 1000000,
    75: h.percentile(75) / 1000000
  };

  t.true(results.overallDelayTime.max <= 50);
});
