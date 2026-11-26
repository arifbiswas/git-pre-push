/**
 * Signature feed: lets GitSafty learn new malware every day without a new
 * release.
 *
 * A GitHub Action (.github/workflows/signatures.yml) builds feed.json.gz from
 * public malware databases (OpenSSF / OSV malicious packages) plus the
 * maintainers' own rules, signs it with Ed25519, and publishes it on the
 * `signatures` branch. Every GitSafty downloads it in the background
 * (at most every 12 hours) and only accepts it when:
 *   - the Ed25519 signature matches the public key built into GitSafty, and
 *   - its sequence number is newer than the one already installed.
 * So nobody can push fake patterns or roll back to an old feed.
 *
 * Stored in ~/.gitsafty/signatures/.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const { spawn } = require('child_process');
const feedRules = require('./rules/feedRules');

const FEED_URL = 'https://raw.githubusercontent.com/arifbiswas/git-pre-push/signatures/feed.json.gz';
// Ed25519 public key (SPKI, DER, base64). The private key exists only as a GitHub Actions secret.
const PUBLIC_KEY = 'MCowBQYDK2VwAyEAEUJR6dTBS+Zym4o3wdSnOxrs2Zt/K1wxb/bOq9TfGOg=';
const CHECK_EVERY_MS = 12 * 60 * 60 * 1000;
const MAX_FEED_BYTES = 40 * 1024 * 1024;

function dir() {
  return path.join(process.env.HOME || process.env.USERPROFILE || os.homedir(), '.gitsafty', 'signatures');
}
const file = (name) => path.join(dir(), name);

function readJson(p) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch (_) { return null; }
}

function writeAtomic(p, data) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  const tmp = `${p}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, data);
  fs.renameSync(tmp, p);
}

/** True when `sig` (base64) is a valid signature of `data` by `publicKey` (SPKI DER base64). */
function verify(data, sig, publicKey = PUBLIC_KEY) {
  try {
    const key = crypto.createPublicKey({ key: Buffer.from(publicKey, 'base64'), format: 'der', type: 'spki' });
    return crypto.verify(null, data, key, Buffer.from(String(sig).trim(), 'base64'));
  } catch (_) {
    return false;
  }
}

/** Verifies and parses a feed. Throws with a clear reason when it is not acceptable. */
function parseFeed(gz, sig, publicKey) {
  if (!verify(gz, sig, publicKey)) throw new Error('signature does not match: feed ignored');
  const feed = JSON.parse(zlib.gunzipSync(gz, { maxOutputLength: 256 * 1024 * 1024 }).toString('utf8'));
  if (!feed || feed.schema !== 1 || !Number.isFinite(feed.sequence)) throw new Error('unknown feed format');
  return feed;
}

let cache;
/** The installed feed (verified again on load), or null. */
function loadInstalled() {
  if (cache !== undefined) return cache;
  cache = null;
  try {
    const gz = fs.readFileSync(file('feed.json.gz'));
    const sig = fs.readFileSync(file('feed.json.gz.sig'), 'utf8');
    cache = parseFeed(gz, sig);
  } catch (_) {}
  return cache;
}

/** Makes every scan in this process use the installed feed. */
function register() {
  feedRules.setLoader(loadInstalled);
}

function meta() {
  return readJson(file('meta.json')) || {};
}

function counts(feed) {
  return {
    npm: Object.keys((feed.packages && feed.packages.npm) || {}).length,
    pypi: Object.keys((feed.packages && feed.packages.PyPI) || {}).length,
    hashes: Object.keys(feed.hashes || {}).length,
    markers: (feed.markers || []).length
  };
}

async function download(url) {
  const res = await fetch(url, { signal: AbortSignal.timeout(30000), headers: { 'Cache-Control': 'no-cache' } });
  if (!res.ok) throw new Error(`download failed (${res.status})`);
  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length > MAX_FEED_BYTES) throw new Error('feed too large');
  return buf;
}

/**
 * Downloads the newest feed if it is newer than the installed one.
 * @returns {Promise<{ updated: boolean, sequence: number, generatedAt: string, counts: object }>}
 */
async function update({ url = FEED_URL, publicKey = PUBLIC_KEY } = {}) {
  const m = meta();
  writeAtomic(file('meta.json'), JSON.stringify({ ...m, checkedAt: Date.now() }));
  const [gz, sig] = await Promise.all([download(url), download(`${url}.sig`)]);
  const feed = parseFeed(gz, sig.toString('utf8'), publicKey);
  const installed = loadInstalled();
  if (installed && feed.sequence <= installed.sequence) {
    return { updated: false, sequence: installed.sequence, generatedAt: installed.generatedAt, counts: counts(installed) };
  }
  writeAtomic(file('feed.json.gz.sig'), sig);
  writeAtomic(file('feed.json.gz'), gz);
  writeAtomic(file('meta.json'), JSON.stringify({ checkedAt: Date.now(), sequence: feed.sequence, generatedAt: feed.generatedAt, counts: counts(feed) }));
  cache = feed;
  feedRules.setFeed(feed);
  return { updated: true, sequence: feed.sequence, generatedAt: feed.generatedAt, counts: counts(feed) };
}

function isStale() {
  return Date.now() - (meta().checkedAt || 0) > CHECK_EVERY_MS;
}

/** Starts `gitsafty signatures update` in the background when the last check is old. Never blocks. */
function updateInBackground(cliPath) {
  if (process.env.CI || process.env.GITSAFTY_NO_FEED_UPDATE === '1' || !isStale()) return false;
  try {
    writeAtomic(file('meta.json'), JSON.stringify({ ...meta(), checkedAt: Date.now() }));
    const child = spawn(process.execPath, [cliPath, 'signatures', 'update', '--quiet'], {
      detached: true, stdio: 'ignore', windowsHide: true, env: { ...process.env, GITSAFTY_NO_SELF_REFRESH: '1' }
    });
    child.unref();
    return true;
  } catch (_) {
    return false;
  }
}

function status() {
  const feed = loadInstalled();
  const m = meta();
  return feed
    ? { installed: true, sequence: feed.sequence, generatedAt: feed.generatedAt, counts: counts(feed), checkedAt: m.checkedAt || null }
    : { installed: false, checkedAt: m.checkedAt || null };
}

module.exports = { register, update, updateInBackground, status, verify, parseFeed, loadInstalled, FEED_URL, PUBLIC_KEY };
