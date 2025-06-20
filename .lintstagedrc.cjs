module.exports = {
  '*.{js,mjs,ts,tsx,json,md,yml,yaml}': ['xo --fix'],
  '*.{js,mjs,ts,tsx}': ['xo --fix'],
  '*.md': filenames => filenames.map(filename => `remark ${filename} -qfo`),
  'package.json': ['fixpack']
};
