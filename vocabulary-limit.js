module.exports =
  typeof process.env.VOCABULARY_LIMIT !== 'undefined' &&
  Number.isFinite(parseInt(process.env.VOCABULARY_LIMIT, 10))
    ? parseInt(process.env.VOCABULARY_LIMIT, 10)
    : 20000;
