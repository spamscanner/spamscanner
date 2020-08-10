module.exports =
  typeof process.env.VOCABULARY_LIMIT !== 'undefined' &&
  Number.isFinite(Number.parseInt(process.env.VOCABULARY_LIMIT, 10))
    ? Number.parseInt(process.env.VOCABULARY_LIMIT, 10)
    : 20000;
