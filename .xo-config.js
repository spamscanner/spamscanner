module.exports = {
  prettier: true,
  space: true,
  extends: ['xo-lass'],
  ignores: [
    'data',
    'classifier.json',
    'bag-of-words.json'
  ],
  rules: {
    'unicorn/prefer-top-level-await': 'off',
    'import/order': 'off',
    'no-warning-comments': 'off'
  }
};
