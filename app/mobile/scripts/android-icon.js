/**
 * Puts the GitSafty icon into the generated Android project (run after
 * `npx cap add android`). Uses plain PNG launcher icons for every density.
 */
const fs = require('fs');
const path = require('path');
const { pngIcon } = require('../../icon');

const res = path.join(__dirname, '..', 'android', 'app', 'src', 'main', 'res');
const sizes = { mdpi: 48, hdpi: 72, xhdpi: 96, xxhdpi: 144, xxxhdpi: 192 };
for (const [density, size] of Object.entries(sizes)) {
  const dir = path.join(res, `mipmap-${density}`);
  fs.mkdirSync(dir, { recursive: true });
  const png = pngIcon(size);
  for (const name of ['ic_launcher.png', 'ic_launcher_round.png']) fs.writeFileSync(path.join(dir, name), png);
  fs.rmSync(path.join(dir, 'ic_launcher_foreground.png'), { force: true });
}
// Without the adaptive-icon XML, Android uses the PNGs above on every version.
fs.rmSync(path.join(res, 'mipmap-anydpi-v26'), { recursive: true, force: true });
console.log('Android icons written.');
