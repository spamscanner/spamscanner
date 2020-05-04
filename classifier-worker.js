const { workerData, parentPort } = require('worker_threads');

const SpamScanner = require('.');

(async () => {
  const scanner = new SpamScanner({
    replacements: workerData.replacements,
    classifier: true
  });

  // now we can use worker threads in v3.x of iconv thanks to @bnoordhuis
  // <https://github.com/bnoordhuis/node-iconv/issues/211>
  const { tokens } = await scanner.getTokensAndMailFromSource(
    workerData.source
  );

  // to bias against false positives we can (at least for now)
  // take the token count for ham and double it (duplicate it)
  if (process.env.SPAM_CATEGORY === 'ham') {
    const { length } = tokens;
    // NOTE: concat is slower than push so we use push
    for (let i = 0; i < length; i++) {
      tokens.push(tokens[i]);
    }
  }

  parentPort.postMessage(tokens);
})();
