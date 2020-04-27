const fs = require('fs');
const os = require('os');
const path = require('path');
const { promisify } = require('util');

const { readDirDeep } = require('read-dir-deep');
const Mbox = require('node-mbox');
const makeDir = require('make-dir');
const pMap = require('p-map');

const concurrency = os.cpus().length * 4;
const writeFile = promisify(fs.writeFile);

if (typeof process.env.SCAN_DIR === 'undefined')
  throw new Error('SCAN_DIR environment variable required');

function mapper(source) {
  return new Promise((resolve, reject) => {
    const stream = fs.createReadStream(source);
    const mbox = new Mbox(stream);
    const messages = [];
    mbox.on('message', message => messages.push(message));
    mbox.on('end', async () => {
      try {
        const basename = path.basename(source, path.extname(source));
        const dir = path.dirname(source);
        const mboxDir = path.join(dir, basename);
        try {
          await makeDir(mboxDir);
        } catch (err) {
          if (err.code !== 'EEXIST') return reject(err);
        }

        await Promise.all(
          messages.map((message, i) => {
            return writeFile(
              path.join(mboxDir, `${i}.txt`),
              message.toString()
            );
          })
        );
        console.log(
          `wrote ${source} with ${messages.length} messages to ${mboxDir}`
        );
        resolve();
      } catch (err) {
        reject(err);
      }
    });
  });
}

(async () => {
  try {
    const sources = await readDirDeep(process.env.SCAN_DIR, {
      patterns: [
        '*.mbox',
        '*.mail',
        '**/*.mail',
        '**/*.mbox',
        '**/**/*.mail',
        '**/**/*.mbox'
      ]
    });

    console.log('sources.length', sources.length);

    await pMap(sources, mapper, { concurrency });
  } catch (err) {
    throw err;
  }
})();
