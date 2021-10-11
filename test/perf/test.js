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

// LOAD per second
const LOAD = 30;
const WARMUP_LOAD = 10;

// store resulting statistics
// to be printed/saved at end
const results = {};

test.after(() => {
  // print results
  console.table(results);
});

test.beforeEach(async (t) => {
  t.context.scanner = new SpamScanner();

  // warmup
  const fn = async () => {
    const email = generateEmail({ urls: { max: 10, min: 5 } });

    await t.context.scanner.scan(email);
  };

  const queue = new PQueue({
    intervalCap: WARMUP_LOAD / 10,
    interval: 100,
    autoStart: false
  });

  // pre-load queue
  // for 5 seconds
  for (let i = 0; i < LOAD * 5; i++) {
    queue.add(fn);
  }

  console.log('warmup started');
  await queue.start().onIdle();
  console.log('warmup completed');
});

test.beforeEach(async (t) => {
  t.context.scanner = new SpamScanner();

  // warmup
  const fn = async () => {
    const email = generateEmail({ urls: { max: 10, min: 5 } });

    await t.context.scanner.scan(email);
  };

  const queue = new PQueue({
    intervalCap: WARMUP_LOAD / 10,
    interval: 100,
    autoStart: false
  });

  // pre-load queue
  // for 5 seconds
  for (let i = 0; i < LOAD * 5; i++) {
    queue.add(fn);
  }

  console.log('warmup started');
  await queue.start().onIdle();
  console.log('warmup completed');
});

test.beforeEach(async (t) => {
  t.context.scanner = new SpamScanner();

  // warmup
  const fn = async () => {
    const email = generateEmail({ urls: { max: 10, min: 5 } });

    await t.context.scanner.scan(email);
  };

  const queue = new PQueue({
    intervalCap: WARMUP_LOAD / 10,
    interval: 100,
    autoStart: false
  });

  // pre-load queue
  // for 5 seconds
  for (let i = 0; i < LOAD * 5; i++) {
    queue.add(fn);
  }

  console.log('warmup started');
  await queue.start().onIdle();
  console.log('warmup completed');
});

test('scan() should take less than 100 ms on average', async (t) => {
  t.plan(1);

  const measures = [];

  const obs = new PerformanceObserver((list) => {
    measures.push(list.getEntries()[0]);
  });
  obs.observe({ entryTypes: ['measure'] });

  const queue = new PQueue({
    intervalCap: LOAD / 10,
    interval: 100,
    autoStart: false
  });

  let n = 0;
  const fn = async () => {
    const email = generateEmail({ urls: { max: 10, min: 5 } });
    const startMark = `scan-${n}-start`;
    const endMark = `scan-${n}-end`;
    const measureLabel = `scan-${n}`;
    n++;

    performance.mark(startMark);

    await t.context.scanner.scan(email);

    performance.mark(endMark);
    performance.measure(measureLabel, startMark, endMark);
  };

  // pre-load queue
  // run for 5 seconds
  for (let i = 0; i < LOAD * 5; i++) {
    queue.add(fn);
  }

  await queue.start().onIdle();

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

test(`scan() should have no more than a 50 ms delay within 2 SD of mean`, async (t) => {
  const h = monitorEventLoopDelay();
  const fn = async () => {
    const email = generateEmail({ urls: { max: 10, min: 5 } });

    h.enable();
    await t.context.scanner.scan(email);
    h.disable();
  };

  const queue = new PQueue({
    intervalCap: LOAD / 10,
    interval: 100,
    autoStart: false
  });

  // pre-load queue
  // for 5 seconds
  for (let i = 0; i < LOAD * 5; i++) {
    queue.add(fn);
  }

  await queue.start().onIdle();

  results.overallDelayTime = {
    mean: h.mean / 1000000,
    stddev: h.stddev / 1000000,
    max: h.max / 1000000,
    min: h.min / 1000000,
    25: h.percentile(25) / 1000000,
    50: h.percentile(50) / 1000000,
    75: h.percentile(75) / 1000000
  };

  t.true(
    results.overallDelayTime.mean + 2 * results.overallDelayTime.mean <= 50
  );
});
