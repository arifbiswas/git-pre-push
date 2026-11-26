/**
 * Builds the installers for this OS. The app gets the GitSafty package version.
 *   node scripts/dist.js            (current OS)
 */
require('./prepare');
const path = require('path');
const builder = require('electron-builder');

const pkg = require('../package.json');
const version = require(path.resolve(__dirname, '..', '..', '..', 'package.json')).version;

builder.build({
  publish: 'never',
  config: { ...pkg.build, extraMetadata: { version } }
}).then((files) => {
  console.log(files.join('\n'));
}).catch((err) => {
  console.error(err);
  process.exit(1);
});
