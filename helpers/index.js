const i18nLocales = require('i18n-locales');

const env = require('./env');

const locales = new Set(i18nLocales.map((l) => l.toLowerCase()));

module.exports = {
  env,
  locales
};
