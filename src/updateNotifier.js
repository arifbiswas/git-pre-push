const fs = require('fs');
const path = require('path');
const os = require('os');
const { colors } = require('./reporter');

const CACHE_FILE = path.join(os.homedir(), '.gitsafty-update.json');
const CHECK_INTERVAL_MS = 60 * 60 * 1000; // Check at most once an hour (menu/update always check)
const SKIP_PROMPT_MS = 24 * 60 * 60 * 1000; // "No" silences the prompt for that version for a day
const PACKAGE_NAME = '@arifbiswas/git-pre-push';

/**
 * Checks if latest semver string is strictly newer than current semver string
 * @param {string} current 
 * @param {string} latest 
 * @returns {boolean}
 */
function isNewerVersion(current, latest) {
  if (!current || !latest) return false;
  const c = current.replace(/^v/, '').split('.').map(n => parseInt(n, 10) || 0);
  const l = latest.replace(/^v/, '').split('.').map(n => parseInt(n, 10) || 0);

  for (let i = 0; i < 3; i++) {
    const cv = c[i] || 0;
    const lv = l[i] || 0;
    if (lv > cv) return true;
    if (lv < cv) return false;
  }
  return false;
}

/**
 * Reads cached update info
 */
function readCache() {
  try {
    if (fs.existsSync(CACHE_FILE)) {
      return JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8'));
    }
  } catch (_) {}
  return null;
}

/**
 * Writes cached update info
 * @param {string} latestVersion 
 */
function writeCache(latestVersion, extra = {}) {
  try {
    const prev = readCache() || {};
    fs.writeFileSync(
      CACHE_FILE,
      JSON.stringify({ ...prev, lastChecked: Date.now(), latestVersion, ...extra }, null, 2),
      'utf8'
    );
  } catch (_) {}
}

/**
 * How this copy of GitSafty was installed.
 * @returns {'global'|'npx'|'local-dependency'|'source'}
 */
function installKind(cliFile = path.resolve(__dirname, '..', 'bin', 'cli.js')) {
  const p = cliFile.replace(/\\/g, '/');
  if (/\/_npx\//.test(p) || /\/npm-cache\//.test(p)) return 'npx';
  if (process.env.npm_config_global === 'true') return 'global';
  // Global installs live in <prefix>/lib/node_modules (unix) or <prefix>/node_modules (Windows npm prefix).
  try {
    const { execFileSync } = require('child_process');
    const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
    const root = execFileSync(npm, ['root', '-g'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 5000, shell: process.platform === 'win32' }).trim().replace(/\\/g, '/');
    if (root && p.toLowerCase().startsWith(root.toLowerCase() + '/')) return 'global';
  } catch (_) {}
  if (/\/node_modules\//.test(p)) return 'local-dependency';
  return 'source';
}

function isInteractive() {
  return !!(process.stdin.isTTY && process.stdout.isTTY) && !process.env.CI && !process.env.CONTINUOUS_INTEGRATION;
}

function askYesNo(question, defaultYes = true) {
  const readline = require('readline');
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      const a = answer.trim().toLowerCase();
      resolve(a === '' ? defaultYes : (a === 'y' || a === 'yes'));
    });
  });
}

/**
 * Installs <PACKAGE_NAME>@version globally. Shows npm's output live and
 * explains what to do when it fails.
 * @returns {boolean} success
 */
function installVersion(version) {
  const { spawnSync } = require('child_process');
  const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
  const spec = `${PACKAGE_NAME}@${version}`;
  console.log(`\n${colors.cyan}Installing ${spec} ...${colors.reset}\n`);
  const r = spawnSync(npm, ['install', '-g', spec, '--prefer-online', '--no-fund', '--no-audit'], {
    stdio: ['inherit', 'inherit', 'pipe'],
    encoding: 'utf8',
    shell: process.platform === 'win32'
  });
  if (r.stderr) process.stderr.write(r.stderr);
  if (r.status === 0) return true;

  console.error(`\n${colors.red}${colors.bold}✖ Update failed.${colors.reset}`);
  try {
    const { printHint, commands } = require('./doctor');
    const err = new Error((r.error && r.error.message) || r.stderr || 'npm install failed');
    if (r.error && r.error.code) err.code = r.error.code;
    if (/EACCES|EPERM/.test(r.stderr || '')) err.code = 'EACCES';
    const m = (r.stderr || '').match(/path (\S+)/);
    if (m) err.path = m[1];
    printHint(err, 'What to do');
    console.error(`  ${colors.dim}Can't update at all? Turn GitSafty off:${colors.reset}`);
    for (const c of commands.removeHooks()) console.error(`    ${colors.cyan}${c}${colors.reset}`);
    console.error('');
  } catch (_) {}
  return false;
}

/**
 * Re-runs the freshly installed CLI with the same arguments, then exits.
 */
function relaunch() {
  const { spawnSync } = require('child_process');
  const cli = path.resolve(__dirname, '..', 'bin', 'cli.js');
  const r = spawnSync(process.execPath, [cli, ...process.argv.slice(2)], {
    stdio: 'inherit',
    env: { ...process.env, GITSAFTY_JUST_UPDATED: '1' }
  });
  process.exit(r.status == null ? 0 : r.status);
}

/**
 * Offers to install a newer version (interactive terminals only).
 * @returns {Promise<boolean>} true if it updated (and relaunched)
 */
async function offerUpdate(currentVersion, latestVersion) {
  const kind = installKind();
  printUpdateNotification(currentVersion, latestVersion, kind);
  if (!isInteractive() || process.env.GITSAFTY_JUST_UPDATED === '1' || process.env.GITSAFTY_NO_UPDATE_PROMPT === '1') return false;
  if (kind !== 'global') return false;

  const cache = readCache() || {};
  if (cache.skippedVersion === latestVersion && Date.now() - (cache.skippedAt || 0) < SKIP_PROMPT_MS) return false;

  const yes = await askYesNo(`${colors.bold}${colors.cyan}? Install GitSafty ${latestVersion} now? (Y/n): ${colors.reset}`);
  if (!yes) {
    writeCache(latestVersion, { skippedVersion: latestVersion, skippedAt: Date.now() });
    console.log(`${colors.dim}OK, I'll ask again tomorrow. Update any time with: gitsafty update${colors.reset}\n`);
    return false;
  }
  if (!installVersion(latestVersion)) return false;

  console.log(`\n${colors.green}${colors.bold}✔ Updated to ${latestVersion}.${colors.reset} ${colors.dim}Global hooks were refreshed by the installer.${colors.reset}\n`);
  relaunch();
  return true;
}

/**
 * Fetches latest version from npm registry with timeout
 * @returns {Promise<string | null>}
 */
async function fetchLatestFromNpm() {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 1200);

    const res = await fetch(`https://registry.npmjs.org/${PACKAGE_NAME}/latest`, {
      signal: controller.signal,
      headers: { 'User-Agent': 'git-pre-push-update-check' }
    });
    clearTimeout(timeout);

    if (res.ok) {
      const data = await res.json();
      return data.version || null;
    }
  } catch (_) {}
  return null;
}

/**
 * Prints a clean update notification box
 * @param {string} currentVersion 
 * @param {string} latestVersion 
 */
function printUpdateNotification(currentVersion, latestVersion, kind = 'global') {
  const line1 = `   Update available! ${colors.dim}${currentVersion}${colors.reset} → ${colors.green}${colors.bold}${latestVersion}${colors.reset}`;
  const line2 = kind === 'npx'
    ? `   Run ${colors.cyan}${colors.bold}npx ${PACKAGE_NAME}@latest${colors.reset} to use it`
    : `   Run ${colors.cyan}${colors.bold}npm install -g ${PACKAGE_NAME}@latest${colors.reset} to update`;
  const line3 = kind === 'local-dependency'
    ? `   In this project: ${colors.cyan}npm install -D ${PACKAGE_NAME}@latest${colors.reset}`
    : kind === 'source' ? `   ${colors.dim}(running from a source checkout: git pull to update)${colors.reset}` : `   ${colors.dim}What's new: https://www.npmjs.com/package/${PACKAGE_NAME}${colors.reset}`;

  console.log(`\n${colors.yellow}╭─────────────────────────────────────────────────────────────╮${colors.reset}`);
  console.log(`${colors.yellow}│${colors.reset}${line1}`);
  console.log(`${colors.yellow}│${colors.reset}${line2}`);
  console.log(`${colors.yellow}│${colors.reset}${line3}`);
  console.log(`${colors.yellow}╰─────────────────────────────────────────────────────────────╯${colors.reset}\n`);
}

/**
 * Automatically checks for updates (non-blocking, cached)
 * @param {string} currentVersion 
 */
async function notifyIfUpdateAvailable(currentVersion, { force = false } = {}) {
  if (process.env.NO_UPDATE_NOTIFIER || process.env.GITSAFTY_JUST_UPDATED === '1') return;
  const cache = readCache();
  const now = Date.now();

  let latestVersion = cache ? cache.latestVersion : null;
  const shouldCheckRegistry = force || !cache || (now - (cache.lastChecked || 0) > CHECK_INTERVAL_MS);

  if (shouldCheckRegistry) {
    const fetched = await fetchLatestFromNpm();
    if (fetched) {
      latestVersion = fetched;
      writeCache(latestVersion);
    }
  }

  if (latestVersion && isNewerVersion(currentVersion, latestVersion)) {
    await offerUpdate(currentVersion, latestVersion);
  }
}

/**
 * Manual check command: gitsafty update
 * @param {string} currentVersion 
 */
async function checkUpdateManual(currentVersion) {
  console.log(`\n${colors.cyan}Checking npm registry for updates...${colors.reset}`);
  const latest = await fetchLatestFromNpm();

  if (!latest) {
    console.log(`${colors.red}Could not fetch latest version from npm registry.${colors.reset}\n`);
    return;
  }

  writeCache(latest);

  if (isNewerVersion(currentVersion, latest)) {
    writeCache(latest, { skippedVersion: null });
    await offerUpdate(currentVersion, latest);
  } else {
    console.log(`\n${colors.green}${colors.bold}✔ You are on the latest version! (v${currentVersion})${colors.reset}\n`);
  }
}

module.exports = {
  isNewerVersion,
  installKind,
  offerUpdate,
  notifyIfUpdateAvailable,
  checkUpdateManual,
  printUpdateNotification
};

