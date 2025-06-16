const process = require('node:process');

module.exports =
  process.env.VOCABULARY_LIMIT !== undefined &&
  Number.isFinite(Number.parseInt(process.env.VOCABULARY_LIMIT, 10))
    ? Number.parseInt(process.env.VOCABULARY_LIMIT, 10)
    : 20000;
