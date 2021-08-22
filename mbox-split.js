const fs = require('fs');
const os = require('os');
const path = require('path');
const { promisify } = require('util');

const Mbox = require('node-mbox');
const makeDir = require('make-dir');
const pMap = require('p-map');
const trim = require('trim-leading-whitespace');
const { readDirDeep } = require('read-dir-deep');

const MBOX_PATTERNS = require('./mbox-patterns.js');

const concurrency = os.cpus().length * 4;
const writeFile = promisify(fs.writeFile);

if (typeof process.env.SCAN_DIR === 'undefined')
  throw new Error('SCAN_DIR environment variable required');

function mapper(source) {
  return new Promise((resolve, reject) => {
    console.log('source', source);
    const stream = fs.createReadStream(source);
    const input = stream.pipe(trim());
    const mbox = new Mbox(input);
    const messages = [];
    mbox.on('message', (message) => messages.push(message));
    mbox.on('end', async () => {
      try {
        const basename = path.basename(source, path.extname(source));
        const dir = path.dirname(source);
        const mboxDir = path.join(dir, basename);
        try {
          await makeDir(mboxDir);
        } catch (err) {
          console.log('source', source, 'err', err);
          if (err.code !== 'EEXIST') return reject(err);
        }

        await Promise.all(
          messages.map(async (message, i) => {
            try {
              await writeFile(
                path.join(mboxDir, `${i}.txt`),
                message.toString()
              );
            } catch (err) {
              console.error('message', message, 'i', i, 'err', err);
              try {
                await writeFile(
                  path.join(mboxDir, '..', `${i}.txt`),
                  message.toString()
                );
              } catch (err) {
                console.error('message', message, 'i', i, 'err', err);
              }
            }
          })
        );
        console.log(
          `wrote ${source} with ${messages.length} messages to ${mboxDir}`
        );

        resolve();
      } catch (err) {
        console.log('source', source, 'err', err);
        reject(err);
      }
    });
  });
}

(async () => {
  const sources = await readDirDeep(process.env.SCAN_DIR, {
    patterns: MBOX_PATTERNS
  });

  console.log('sources.length', sources.length);

  await pMap(sources, mapper, { concurrency });
})();
