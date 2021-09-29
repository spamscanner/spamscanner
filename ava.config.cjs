const baseFiles = ['!test/fixtures'];

module.exports = {
  baseFiles,
  timeout: '30s',
  verbose: true,
  files: ['test/integration/**/*', ...baseFiles],
  serial: true
};
