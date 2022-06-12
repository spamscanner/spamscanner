const {
  monitorEventLoopDelay,
  performance,
  PerformanceObserver,
  createHistogram
} = require('perf_hooks');

const test = require('ava');
const { default: PQueue } = require('p-queue');

const SpamScanner = require('../');
const generateEmail = require('./fixtures/email-generator');

// LOAD per second
const LOAD = 25;
const WARMUP_LOAD = 10;

// store resulting statistics
// to be printed/saved at end
const results = {};

test.after((t) => {
  //
  // TODO: add cli-table3 or something so we have console.table
  //

  // print results
  t.log('Overall Execution Times(ms):');
  t.log(JSON.stringify(results.overallExecutionTime, null, 2));

  t.log('Overall Delay Times(ms):');
  t.log(JSON.stringify(results.overallDelayTime, null, 2));
});

test.beforeEach(async (t) => {
  t.context.scanner = new SpamScanner({ clamscan: false });

  // warmup
  async function fn() {
    const email = generateEmail({ urls: { max: 10, min: 5 } });

    await t.context.scanner.scan(email);
  }

  const queue = new PQueue({
    intervalCap: WARMUP_LOAD / 10,
    interval: 100,
    autoStart: false
  });

  // pre-load queue
  // for 5 seconds
  queue.addAll(Array.from({ length: LOAD * 5 }).fill(fn));

  t.log('warmup started');
  await queue.start().onIdle();
  t.log('warmup completed');
});

test('scan() should take less than 10 ms on average', async (t) => {
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

  queue.on('add', () => {
    t.log(
      `added to queue, size is ${queue.size} with ${queue.pending} pending`
    );
  });

  queue.on('next', () => {
    t.log(
      `task completed, size is ${queue.size} with ${queue.pending} pending`
    );
  });

  queue.on('completed', (result) => {
    t.log('completed', result);
  });

  let n = 0;

  async function fn() {
    const email = generateEmail({ urls: { max: 10, min: 5 } });
    const startMark = `scan-${n}-start`;
    const endMark = `scan-${n}-end`;
    const measureLabel = `scan-${n}`;
    n++;

    performance.mark(startMark);

    await t.context.scanner.scan(email);

    performance.mark(endMark);
    performance.measure(measureLabel, startMark, endMark);
  }

  // pre-load queue
  // run for 5 seconds
  queue.addAll(Array.from({ length: LOAD * 5 }).fill(fn));

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

  t.true(measures.length > 0);
  t.true(stats.mean <= 10);
});

//
// there's too much work happening on the CPU if this event loop delay is high
// (so we need to improve the code to run faster, or use setImmediate)
//
test(`scan() should have no more than a 200 ms mean delay within 2 SD of mean`, async (t) => {
  const h = monitorEventLoopDelay({ resolution: 3 });
  async function fn() {
    const email = generateEmail({ urls: { max: 10, min: 5 } });

    h.enable();
    await t.context.scanner.scan(email);
    h.disable();
  }

  const queue = new PQueue({
    intervalCap: LOAD / 10,
    interval: 100,
    autoStart: false
  });

  queue.on('add', () => {
    t.log(
      `added to queue, size is ${queue.size} with ${queue.pending} pending`
    );
  });

  queue.on('next', () => {
    t.log(
      `task completed, size is ${queue.size} with ${queue.pending} pending`
    );
  });

  queue.on('completed', (result) => {
    t.log('completed', result);
  });

  // pre-load queue
  // for 5 seconds
  queue.addAll(Array.from({ length: LOAD * 5 }).fill(fn));

  await queue.start().onIdle();

  results.overallDelayTime = {
    mean: h.mean / 1000000,
    stddev: h.stddev / 1000000,
    max: h.max / 1000000,
    min: h.min / 1000000,
    25: h.percentile(25) / 1000000,
    50: h.percentile(50) / 1000000,
    75: h.percentile(75) / 1000000,
    count: h.count
  };

  t.log(h);
  t.log(results.overallDelayTime);
  t.true(h.count > 0);
  t.true(
    results.overallDelayTime.mean + 2 * results.overallDelayTime.stddev <= 200
  );
});
