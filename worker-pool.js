const path = require('path');
const { AsyncResource } = require('async_hooks');
const { EventEmitter } = require('events');
const { Worker } = require('worker_threads');

const kTaskInfo = Symbol('kTaskInfo');
const kWorkerFreedEvent = Symbol('kWorkerFreedEvent');

class WorkerPoolTaskInfo extends AsyncResource {
  constructor(callback) {
    super('WorkerPoolTaskInfo');
    this.callback = callback;
  }

  done(err, result) {
    this.runInAsyncScope(this.callback, null, err, result);
    this.emitDestroy(); // `TaskInfo`s are used only once.
  }
}

class WorkerPool extends EventEmitter {
  constructor(numThreads, config) {
    super();
    this.freeWorkers = [];
    this.numThreads = numThreads;
    this.tasks = [];
    this.workers = [];

    this.logger = config.logger;
    delete config.logger;
    this.config = config;

    for (let i = 0; i < numThreads; i++) {
      this.addNewWorker();
    }

    // Any time the kWorkerFreedEvent is emitted, dispatch
    // the next task pending in the queue, if any.
    this.on(kWorkerFreedEvent, () => {
      if (this.tasks.length > 0) {
        const { task, callback } = this.tasks.shift();
        this.runTask(task, callback);
      }
    });
  }

  addNewWorker() {
    const worker = new Worker(
      path.resolve(__dirname, 'workers', 'get-tokens-and-mail.js'),
      { workerData: { config: this.config } }
    );

    worker.on('message', (result) => {
      const { type, data } = result;

      if (type === 'log') {
        this.logger.log(data);
      } else if (type === 'done') {
        // In case of success: Call the callback that was passed to `runTask`,
        // remove the `TaskInfo` associated with the Worker, and mark it as free
        // again.
        worker[kTaskInfo].done(null, data);
        worker[kTaskInfo] = null;
        this.freeWorkers.push(worker);
        this.emit(kWorkerFreedEvent);
      }
    });

    worker.on('error', (err) => {
      // In case of an uncaught exception: Call the callback that was passed to
      // `runTask` with the error.
      if (worker[kTaskInfo]) worker[kTaskInfo].done(err, null);
      else this.emit('error', err);
      // Remove the worker from the list and start a new Worker to replace the
      // current one.
      this.workers.splice(this.workers.indexOf(worker), 1);
      this.addNewWorker();
    });

    this.workers.push(worker);
    this.freeWorkers.push(worker);
    this.emit(kWorkerFreedEvent);
  }

  async runTask(task, cb) {
    return new Promise((resolve, reject) => {
      const callback = cb
        ? cb
        : (err, data) => {
            if (err) reject(err);
            else resolve(data);
          };

      if (this.freeWorkers.length === 0) {
        // No free threads, wait until a worker thread becomes free.
        this.tasks.push({ task, callback });
        return;
      }

      const worker = this.freeWorkers.pop();
      worker[kTaskInfo] = new WorkerPoolTaskInfo(callback);
      worker.postMessage(task);
    });
  }

  close() {
    for (const worker of this.workers) worker.terminate();
  }
}

module.exports = WorkerPool;
