const { checkFilename } = require('./filenames');
const { scanPayloads } = require('./payloads');
const { scanSecrets } = require('./secrets');
const { inspectIdeConfig } = require('./ideConfig');

module.exports = {
  checkFilename,
  scanPayloads,
  scanSecrets,
  inspectIdeConfig
};

