/**
 * Dev check: opens the app, clicks through the main screens and saves
 * screenshots. Not part of the installers.
 *   SMOKE_DIR=<folder to scan> SMOKE_OUT=<png folder> npx electron scripts/smoke.js
 */
const { app, BrowserWindow, dialog } = require('electron');
const fs = require('fs');
const path = require('path');

const out = process.env.SMOKE_OUT || path.join(__dirname, '..', 'smoke-out');
fs.mkdirSync(out, { recursive: true });
dialog.showOpenDialog = async () => ({ canceled: false, filePaths: [process.env.SMOKE_DIR] });
require('../main.js');

const wait = (ms) => new Promise(r => setTimeout(r, ms));
async function shot(win, name) {
  const img = await win.webContents.capturePage();
  fs.writeFileSync(path.join(out, `${name}.png`), img.toPNG());
}

app.whenReady().then(async () => {
  console.log('SMOKE ready');
  await wait(2500);
  console.log('SMOKE windows', BrowserWindow.getAllWindows().length);
  const win = BrowserWindow.getAllWindows()[0];
  const js = (code) => win.webContents.executeJavaScript(code);
  try {
    await shot(win, '1-protection');
    await js("document.querySelector('[data-page=scan]').click()");
    await js("document.querySelector('[data-mode=everything]').click()");
    for (let i = 0; i < 60 && await js("!document.querySelector('#scan-result .summary') && !document.querySelector('#scan-result .error')"); i++) await wait(500);
    await shot(win, '2-scan-result');
    console.log('RESULT:', await js("document.querySelector('#scan-result').innerText.slice(0, 600)"));
    if (process.env.SMOKE_REMOVE === '1') {
      await js("document.querySelector('#remove-btn').click()");
      for (let i = 0; i < 40 && await js("!!document.querySelector('#remove-btn')"); i++) await wait(500);
      await shot(win, '3-after-remove');
      console.log('AFTER:', await js("document.querySelector('#scan-result .summary').innerText"));
    }
    await js("document.querySelector('[data-page=fix]').click()");
    await shot(win, '4-fix');
  } catch (err) {
    console.error('SMOKE ERROR', err);
  }
  app.exit(0);
});
