/**
 * Copies the GitSafty engine (repo src/ + app/engine) and the shared UI into
 * this app folder. Run before `electron .` and before a build.
 */
const fs = require('fs');
const path = require('path');

const here = path.resolve(__dirname, '..');
const repo = path.resolve(here, '..', '..');

function copy(from, to) {
  fs.rmSync(to, { recursive: true, force: true });
  fs.cpSync(from, to, { recursive: true });
}

copy(path.join(repo, 'src'), path.join(here, 'engine', 'src'));
copy(path.join(repo, 'app', 'engine'), path.join(here, 'engine', 'app'));
copy(path.join(repo, 'app', 'ui'), path.join(here, 'ui'));
fs.copyFileSync(path.join(repo, 'package.json'), path.join(here, 'engine', 'package.json'));

console.log(`GitSafty engine ${require(path.join(repo, 'package.json')).version} ready.`);
