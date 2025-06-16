module.exports = {
  '*.{js,mjs,ts,tsx,json,md,yml,yaml}': ['prettier --write'],
  '*.{js,mjs,ts,tsx}': ['xo --fix'],
  '*.md': filenames => filenames.map(filename => `remark ${filename} -qfo`),
  'package.json': ['fixpack']
};
