const fs = require('fs');
const path = require('path');

const natural = require('natural');
const { readDirDeepSync } = require('read-dir-deep');

const SpamScanner = require('.');

const scanner = new SpamScanner();

const classifier = new natural.BayesClassifier();

(async () => {
  for (const file of readDirDeepSync(path.join(__dirname, 'data', 'ham'))) {
    console.log(file);
    try {
      // eslint-disable-next-line no-await-in-loop
      const { tokens } = await scanner.getTokensAndMailFromSource(
        fs.readFileSync(file)
      );
      classifier.addDocument(tokens, 'ham');
    } catch (err) {
      console.log('error file', file);
      console.error(err);
    }
  }

  for (const file of readDirDeepSync(path.join(__dirname, 'data', 'spam'))) {
    console.log(file);
    try {
      // eslint-disable-next-line no-await-in-loop
      const { tokens } = await scanner.getTokensAndMailFromSource(
        fs.readFileSync(file)
      );
      classifier.addDocument(tokens, 'spam');
    } catch (err) {
      console.log('error file', file);
      console.error(err);
    }
  }

  classifier.events.on('doneTraining', () => console.log('done training'));

  console.log('training');

  classifier.train();

  console.log('saving');

  await new Promise((resolve, reject) => {
    classifier.save(path.join(__dirname, 'classifier.json'), function(err) {
      if (err) return reject(err);
      resolve();
    });
  });
})();
