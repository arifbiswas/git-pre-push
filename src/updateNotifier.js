const fs = require('fs');
const path = require('path');
const os = require('os');
const { colors } = require('./reporter');

const CACHE_FILE = path.join(os.homedir(), '.gitsafty-update.json');
const CHECK_INTERVAL_MS = 12 * 60 * 60 * 1000; // Check at most once every 12 hours
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
function writeCache(latestVersion) {
  try {
    fs.writeFileSync(
      CACHE_FILE,
      JSON.stringify({ lastChecked: Date.now(), latestVersion }, null, 2),
      'utf8'
    );
  } catch (_) {}
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
function printUpdateNotification(currentVersion, latestVersion) {
  const line1 = `   Update available! ${colors.dim}${currentVersion}${colors.reset} → ${colors.green}${colors.bold}${latestVersion}${colors.reset}`;
  const line2 = `   Run ${colors.cyan}${colors.bold}npm install -g ${PACKAGE_NAME}${colors.reset} to update`;
  const line3 = `   Or in project: ${colors.cyan}npm install -D ${PACKAGE_NAME}${colors.reset}`;

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
async function notifyIfUpdateAvailable(currentVersion) {
  const cache = readCache();
  const now = Date.now();

  let latestVersion = cache ? cache.latestVersion : null;
  const shouldCheckRegistry = !cache || (now - (cache.lastChecked || 0) > CHECK_INTERVAL_MS);

  if (shouldCheckRegistry) {
    const fetched = await fetchLatestFromNpm();
    if (fetched) {
      latestVersion = fetched;
      writeCache(latestVersion);
    }
  }

  if (latestVersion && isNewerVersion(currentVersion, latestVersion)) {
    printUpdateNotification(currentVersion, latestVersion);
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
    printUpdateNotification(currentVersion, latest);
  } else {
    console.log(`\n${colors.green}${colors.bold}✔ You are on the latest version! (v${currentVersion})${colors.reset}\n`);
  }
}

module.exports = {
  isNewerVersion,
  notifyIfUpdateAvailable,
  checkUpdateManual,
  printUpdateNotification
};
