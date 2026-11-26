/**
 * Builds www/ for the Android app: the shared UI + the GitSafty engine
 * bundled for the browser (Node.js built-ins replaced by small shims).
 */
const fs = require('fs');
const path = require('path');
const esbuild = require('esbuild');

const here = __dirname;
const www = path.join(here, 'www');
const shim = (n) => path.join(here, 'shims', n);

fs.rmSync(www, { recursive: true, force: true });
fs.cpSync(path.join(here, '..', 'ui'), www, { recursive: true });

esbuild.buildSync({
  entryPoints: [path.join(here, 'mobile-api.js')],
  bundle: true,
  outfile: path.join(www, 'engine.js'),
  platform: 'browser',
  format: 'iife',
  target: ['chrome90'],
  minify: true,
  inject: [shim('globals.js')],
  alias: {
    crypto: shim('crypto.js'),
    zlib: shim('zlib.js'),
    child_process: shim('child_process.js'),
    fs: shim('empty.js'),
    os: shim('empty.js'),
    path: 'path-browserify'
  },
  logLevel: 'warning'
});

// Load the engine before the UI.
const index = path.join(www, 'index.html');
fs.writeFileSync(index, fs.readFileSync(index, 'utf8').replace('<script src="app.js"></script>', '<script src="engine.js"></script>\n  <script src="app.js"></script>'));
console.log(`Built ${path.relative(process.cwd(), www)} (engine ${Math.round(fs.statSync(path.join(www, 'engine.js')).size / 1024)} KB)`);
