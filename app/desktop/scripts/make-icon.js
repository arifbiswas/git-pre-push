/** Writes build/icon.png (1024x1024) for the desktop installers. */
const fs = require('fs');
const path = require('path');
const { pngIcon } = require('../../icon');

const out = path.join(__dirname, '..', 'build', 'icon.png');
fs.writeFileSync(out, pngIcon(1024));
console.log(out);
