const NaiveBayes = require('@ladjs/naivebayes');
const debug = require('debug')('spamscanner');

let classifier = new NaiveBayes().toJsonObject();

try {
  classifier = require('./classifier.json');
} catch (err) {
  debug(err);
}

module.exports = classifier;
