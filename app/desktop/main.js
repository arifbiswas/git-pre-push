/**
 * GitSafty desktop app (Electron main process).
 *
 * Scans run with the engine bundled in this app (engine/), in a worker thread.
 * Protection (git hooks, pull scan, doctor) is done by the installed
 * `gitsafty` command, so hooks never point into this app's folder, which
 * moves on every app update.
 */
const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const { spawn, spawnSync } = require('child_process');
const { Worker } = require('worker_threads');
const fs = require('fs');
const os = require('os');
const path = require('path');

const isWin = process.platform === 'win32';
const engine = (p) => require(path.join(__dirname, 'engine', p));
const ENGINE_VERSION = engine('package.json').version;
const PACKAGE = '@arifbiswas/git-pre-push';

// Apps started from Finder / the dock don't get the PATH of the user's shell
// (nvm, Homebrew, npm global bin). Ask the login shell for it once.
function loadShellPath() {
  if (isWin) return;
  try {
    const sh = process.env.SHELL || '/bin/zsh';
    const r = spawnSync(sh, ['-ilc', 'printf "__PATH__%s" "$PATH"'], { encoding: 'utf8', timeout: 5000 });
    const m = (r.stdout || '').match(/__PATH__(.*)$/s);
    if (m && m[1].trim()) process.env.PATH = m[1].trim();
  } catch (_) {}
}

const stripAnsi = (s) => String(s || '').replace(/\x1b\[[0-9;]*[A-Za-z]/g, '');

/** Full path of a command on PATH, or null. */
function which(cmd) {
  const r = spawnSync(isWin ? 'where' : 'which', [cmd], { encoding: 'utf8' });
  const first = (r.stdout || '').split(/\r?\n/).find(Boolean);
  return r.status === 0 && first ? first.trim() : null;
}

/** Installed gitsafty command and its version (read from its package.json, nothing is run). */
function cliInfo() {
  const bin = which('gitsafty');
  if (!bin) return { installed: false };
  let version = null;
  try {
    const pkgFile = isWin
      ? path.join(path.dirname(bin), 'node_modules', '@arifbiswas', 'git-pre-push', 'package.json')
      : path.join(path.dirname(fs.realpathSync(bin)), '..', 'package.json');
    version = JSON.parse(fs.readFileSync(pkgFile, 'utf8')).version;
  } catch (_) {}
  return { installed: true, version, bin };
}

/** Runs a command, collects its output. Never waits for input. */
function run(cmd, args, { timeout = 5 * 60 * 1000 } = {}) {
  return new Promise((resolve) => {
    let output = '';
    const child = spawn(cmd, args, {
      shell: isWin,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, NO_UPDATE_NOTIFIER: '1', GITSAFTY_NO_UPDATE_PROMPT: '1', NO_COLOR: '1', FORCE_COLOR: '0' }
    });
    const timer = setTimeout(() => child.kill(), timeout);
    child.stdout.on('data', d => { output += d; });
    child.stderr.on('data', d => { output += d; });
    child.on('error', (err) => { clearTimeout(timer); resolve({ code: -1, output: err.message }); });
    child.on('close', (code) => {
      clearTimeout(timer);
      const clean = stripAnsi(output).split('\n').filter(l => !/^=+$/.test(l.trim()) && !/GitSafty: Malware & Secret Guard/.test(l)).join('\n').trim();
      resolve({ code, output: clean });
    });
  });
}

function home() {
  return os.homedir();
}

function globalHooksOn() {
  const r = spawnSync('git', ['config', '--global', '--get', 'core.hooksPath'], { encoding: 'utf8' });
  const value = (r.stdout || '').trim().replace(/^~(?=$|[\\/])/, home());
  const dir = path.join(home(), '.git-hooks-safty');
  return !!value && path.resolve(value) === path.resolve(dir) && fs.existsSync(path.join(dir, 'pre-push'));
}

// ------------------------------------------------------------------ window

let win;
function createWindow() {
  win = new BrowserWindow({
    width: 1100,
    height: 760,
    minWidth: 760,
    minHeight: 560,
    title: 'GitSafty',
    backgroundColor: '#f6f7f9',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });
  win.loadFile(path.join(__dirname, 'ui', 'index.html'));
  // Links open in the browser; the app window never navigates away.
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https:\/\//.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
  win.webContents.on('will-navigate', (e) => e.preventDefault());
}

app.whenReady().then(() => {
  loadShellPath();
  createWindow();
  // Fetch newer learned signatures (signed, checked) in the background.
  engine('src/signatures').update().catch(() => {});
  app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });

// ------------------------------------------------------------------ scans

const scans = new Map(); // id -> { kind, raw, title }
const { fromFullScan, fromProjects, fromGitHub } = engine('app/normalize');

function normalize(entry, id) {
  const out = entry.kind === 'projects' ? fromProjects(entry.raw, entry.title)
    : entry.kind === 'github' ? fromGitHub(entry.raw)
      : fromFullScan(entry.raw, entry.title);
  out.id = id || out.id;
  // CLI wording ("run with --clean") does not apply in the app.
  for (const f of out.findings) {
    if (f.action && /--clean/.test(f.action.text)) f.action = { removed: false, text: 'Not removed' };
  }
  return out;
}

function runWorker(job, args, sender, progressId) {
  // Workers can't load files from inside app.asar; worker.js and engine/ are unpacked.
  const file = path.join(__dirname, 'worker.js').replace(`app.asar${path.sep}`, `app.asar.unpacked${path.sep}`);
  return new Promise((resolve, reject) => {
    const w = new Worker(file, { workerData: { job, args } });
    w.on('message', (msg) => {
      if (msg.type === 'progress') sender.send('progress', { id: progressId, done: msg.done, total: msg.total, label: msg.label });
      else if (msg.type === 'done') resolve(msg.result);
      else if (msg.type === 'error') reject(new Error(msg.message));
    });
    w.on('error', reject);
  });
}

ipcMain.handle('info', () => {
  const st = engine('src/signatures').status();
  return { platform: 'desktop', version: ENGINE_VERSION, os: process.platform, signatures: st.installed ? st.generatedAt : null };
});

ipcMain.handle('pick-folder', async () => {
  const r = await dialog.showOpenDialog(win, { properties: ['openDirectory'] });
  return r.canceled ? null : r.filePaths[0];
});

ipcMain.handle('pick-files', async () => {
  const r = await dialog.showOpenDialog(win, { properties: ['openFile', 'multiSelections'] });
  return r.canceled ? [] : r.filePaths;
});

ipcMain.handle('scan', async (e, { mode, target, progressId }) => {
  const args = mode === 'files' ? { files: target } : { folder: target };
  const { kind, raw } = await runWorker(mode, args, e.sender, progressId);
  const title = mode === 'files' ? `${target.length} file(s)` : path.basename(target);
  const entry = { kind, raw, title };
  const out = normalize(entry);
  scans.set(out.id, entry);
  return out;
});

ipcMain.handle('scan-github', async (e, { url, token, progressId }) => {
  const { kind, raw } = await runWorker('github', { url, token: token || undefined }, e.sender, progressId);
  return normalize({ kind, raw });
});

ipcMain.handle('remove-malware', (_e, { id }) => {
  const entry = scans.get(id);
  if (!entry) throw new Error('Scan again first.');
  const { CONFIRMED } = engine('src/rules/malware');
  if (entry.kind === 'full') {
    const { removeFullScanMalware, annotate } = engine('src/fullScanner');
    for (const r of entry.raw) {
      const has = r.findings.some(f => f.verdict === CONFIRMED && f.category === 'malware' && !(f.action && f.action.removed));
      annotate(r, has ? removeFullScanMalware(r) : null);
    }
  } else if (entry.kind === 'projects') {
    const { removeConfirmedMalware } = engine('src/malwareCleaner');
    const { scanProject, annotateActions } = engine('src/advancedScanner');
    for (const r of entry.raw) {
      const files = [...new Set(r.findings.filter(f => f.verdict === CONFIRMED && f.category === 'malware').map(f => f.filePath))];
      if (files.length) r.clean = removeConfirmedMalware(files, r.path, { reason: 'app' });
      annotateActions(r, r.clean ? scanProject(r.path) : null);
    }
  }
  return normalize(entry, id);
});

// ------------------------------------------------------------------ protection (via the gitsafty command)

ipcMain.handle('status', () => {
  const shellInt = engine('src/shellIntegration');
  const st = shellInt.shellIntegrationStatus();
  return {
    cli: cliInfo(),
    node: !!which('node') && !!which('npm'),
    globalHooks: globalHooksOn(),
    pullScan: st.installed.length ? 'on' : st.optedOut ? 'off-by-user' : 'off',
    vault: fs.existsSync(path.join(home(), '.gitsafty', 'vault.json')) ? 'on' : 'off'
  };
});

async function needCli() {
  if (cliInfo().installed) return '';
  if (!which('npm')) throw new Error('Node.js is needed for protection. Install it from https://nodejs.org, then reopen GitSafty.');
  const r = await run('npm', ['install', '-g', PACKAGE]);
  if (r.code !== 0 || !cliInfo().installed) throw new Error(`Could not install the gitsafty command:\n${r.output}`);
  return `${r.output}\n\n`;
}

ipcMain.handle('set-protection', async (_e, { on }) => {
  if (on) {
    const installLog = await needCli();
    const r = await run('gitsafty', ['init', '--global']);
    return { ok: r.code === 0, output: installLog + r.output };
  }
  const r = await run('gitsafty', ['uninstall', '--global']);
  return { ok: r.code === 0, output: r.output };
});

ipcMain.handle('set-pull-scan', async (_e, { on }) => {
  await needCli();
  const r = await run('gitsafty', ['pull-scan', on ? 'on' : 'off']);
  return { ok: r.code === 0, output: r.output };
});

ipcMain.handle('doctor', async (_e, { fix }) => {
  if (!cliInfo().installed) {
    return { output: 'The gitsafty command is not installed yet. Go to Protection and turn it on.' };
  }
  const r = await run('gitsafty', fix ? ['doctor', '--fix'] : ['doctor']);
  return { output: r.output };
});
