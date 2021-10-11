const { isMainThread, parentPort, workerData } = require('worker_threads');

const NaiveBayes = require('@ladjs/naivebayes');
const isValidPath = require('is-valid-path');

let config;
let classifier;
if (!isMainThread) {
  config = workerData.config;
  setupClassifier();
}

function setupClassifier() {
  classifier =
    typeof config.classifier === 'object'
      ? config.classifier
      : typeof config.classifier === 'string'
      ? isValidPath(config.classifier)
        ? require(config.classifier)
        : JSON.parse(config.classifier)
      : false;

  classifier = NaiveBayes.fromJson(classifier, config.vocabularyLimit);
  // since we do tokenization ourselves
  classifier.tokenizer = function (tokens) {
    return tokens;
  };
}

function getClassification(tokens) {
  return Promise.resolve(classifier.categorize(tokens, true));
}

if (!isMainThread) {
  parentPort.on('message', async (task) => {
    const res = await getClassification(task.tokens);
    parentPort.postMessage({ type: 'done', data: res });
  });
}
