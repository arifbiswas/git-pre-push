/**
 * GitSafty Vault: "always logged out" Git credentials.
 *
 * The device never keeps a usable GitHub token:
 *   - The token lives only in ~/.gitsafty/vault.json, encrypted with
 *     AES-256-GCM. The key is derived from the user's passphrase with scrypt
 *     (N=2^17, r=8, p=1: ~128 MB RAM per guess, so offline brute force is slow).
 *     The vault metadata is bound as GCM additional data, so it can't be edited.
 *   - GitSafty is registered as the ONLY git credential helper for github.com.
 *     When git needs to push (or fetch a private repo), git asks GitSafty,
 *     GitSafty asks for the passphrase, decrypts the token in memory, hands it
 *     to git for that single command, and wipes it. Nothing is cached, so
 *     after the push finishes the device is logged out again.
 *   - Other stored GitHub logins (macOS Keychain, ~/.git-credentials,
 *     gh CLI helper) are removed during setup.
 *   - Every unlock and every wrong passphrase shows a desktop notification,
 *     so a push you did not start is visible immediately.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const { execFileSync, spawnSync } = require('child_process');

const VAULT_VERSION = 1;
const CIPHER = 'aes-256-gcm';
const KDF = { name: 'scrypt', N: 1 << 17, r: 8, p: 1, keyLen: 32 };
const SCRYPT_MAXMEM = 256 * 1024 * 1024;
const MIN_PASSPHRASE = 12;
const MAX_ATTEMPTS = 3;

function vaultDir() {
  return path.join(process.env.HOME || os.homedir(), '.gitsafty');
}

function vaultPath() {
  return path.join(vaultDir(), 'vault.json');
}

// ---------------------------------------------------------------------------
// Crypto
// ---------------------------------------------------------------------------

function deriveKey(passphrase, salt, kdf = KDF) {
  if (kdf.name !== 'scrypt') throw new Error(`Unsupported KDF ${kdf.name}`);
  return crypto.scryptSync(Buffer.from(passphrase.normalize('NFKC'), 'utf8'), salt, kdf.keyLen, {
    N: kdf.N, r: kdf.r, p: kdf.p, maxmem: SCRYPT_MAXMEM
  });
}

function aadOf(vault) {
  return Buffer.from(JSON.stringify({ version: vault.version, cipher: vault.cipher, kdf: vault.kdf, meta: vault.meta }), 'utf8');
}

/**
 * Encrypts a token into a vault object.
 * @param {string} token
 * @param {string} passphrase
 * @param {object} meta { host, username, ... } (authenticated, not secret)
 */
function encryptToken(token, passphrase, meta) {
  const salt = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const kdf = { ...KDF, salt: salt.toString('base64') };
  const vault = { version: VAULT_VERSION, cipher: CIPHER, kdf, meta };

  const key = deriveKey(passphrase, salt, kdf);
  try {
    const cipher = crypto.createCipheriv(CIPHER, key, iv);
    cipher.setAAD(aadOf(vault));
    const plain = Buffer.from(token, 'utf8');
    const data = Buffer.concat([cipher.update(plain), cipher.final()]);
    plain.fill(0);
    return { ...vault, iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: data.toString('base64') };
  } finally {
    key.fill(0);
  }
}

/**
 * Decrypts the token. Throws on wrong passphrase or tampering.
 * @returns {Buffer} token bytes (caller must .fill(0) after use)
 */
function decryptToken(vault, passphrase) {
  if (!vault || vault.version !== VAULT_VERSION || vault.cipher !== CIPHER) {
    throw new Error('Unsupported vault format');
  }
  const key = deriveKey(passphrase, Buffer.from(vault.kdf.salt, 'base64'), vault.kdf);
  try {
    const decipher = crypto.createDecipheriv(CIPHER, key, Buffer.from(vault.iv, 'base64'));
    decipher.setAAD(aadOf(vault));
    decipher.setAuthTag(Buffer.from(vault.tag, 'base64'));
    return Buffer.concat([decipher.update(Buffer.from(vault.data, 'base64')), decipher.final()]);
  } catch (_) {
    throw new Error('Wrong passphrase (or the vault file was modified)');
  } finally {
    key.fill(0);
  }
}

// --- v2: hardware-bound secret (Secure Enclave / Windows Hello) -----------

const VAULT_V2 = 2;

function aadOfV2(vault) {
  return Buffer.from(JSON.stringify({ version: vault.version, cipher: vault.cipher, kdf: vault.kdf, protector: vault.protector, meta: vault.meta }), 'utf8');
}

function dataKeyFromSecret(secret, salt) {
  return Buffer.from(crypto.hkdfSync('sha256', secret, salt, Buffer.from('gitsafty-vault-v2'), 32));
}

/** Encrypts the token with a 32-byte secret produced by a hardware key. */
function encryptWithSecret(token, secret, protector, meta) {
  const salt = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const vault = { version: VAULT_V2, cipher: CIPHER, kdf: { name: 'hkdf-sha256', salt: salt.toString('base64') }, protector, meta };
  const key = dataKeyFromSecret(secret, salt);
  try {
    const cipher = crypto.createCipheriv(CIPHER, key, iv);
    cipher.setAAD(aadOfV2(vault));
    const plain = Buffer.from(token, 'utf8');
    const data = Buffer.concat([cipher.update(plain), cipher.final()]);
    plain.fill(0);
    return { ...vault, iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), data: data.toString('base64') };
  } finally {
    key.fill(0);
  }
}

function decryptWithSecret(vault, secret) {
  if (!vault || vault.version !== VAULT_V2 || vault.cipher !== CIPHER) throw new Error('Unsupported vault format');
  const key = dataKeyFromSecret(secret, Buffer.from(vault.kdf.salt, 'base64'));
  try {
    const decipher = crypto.createDecipheriv(CIPHER, key, Buffer.from(vault.iv, 'base64'));
    decipher.setAAD(aadOfV2(vault));
    decipher.setAuthTag(Buffer.from(vault.tag, 'base64'));
    return Buffer.concat([decipher.update(Buffer.from(vault.data, 'base64')), decipher.final()]);
  } catch (_) {
    throw new Error('Hardware key did not match (or the vault file was modified)');
  } finally {
    key.fill(0);
  }
}

/** Unlocks a vault of any version. Prompts the user. Returns token Buffer. */
function unlockVault(vault, reason) {
  if (vault.version === VAULT_V2) {
    const { providerFor } = require('./hwkey');
    const provider = providerFor(vault.protector && vault.protector.type);
    if (!provider) throw new Error(`This vault is protected by ${vault.protector && vault.protector.type}, which is not available on this OS`);
    const secret = provider.unlock(vault.protector, reason);
    try {
      return decryptWithSecret(vault, secret);
    } finally {
      secret.fill(0);
    }
  }
  return null; // v1 handled by the passphrase loop
}

function readVault() {
  try {
    return JSON.parse(fs.readFileSync(vaultPath(), 'utf8'));
  } catch (_) {
    return null;
  }
}

function writeVault(vault) {
  fs.mkdirSync(vaultDir(), { recursive: true, mode: 0o700 });
  try { fs.chmodSync(vaultDir(), 0o700); } catch (_) {}
  const tmp = vaultPath() + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(vault, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, vaultPath());
  try { fs.chmodSync(vaultPath(), 0o600); } catch (_) {}
}

// ---------------------------------------------------------------------------
// Secret input (works while git owns stdin/stdout)
// ---------------------------------------------------------------------------

function readFromTty(prompt) {
  if (process.platform === 'win32') return undefined;
  let fd;
  try {
    fd = fs.openSync('/dev/tty', 'r+');
  } catch (_) {
    return undefined; // no terminal (IDE / GUI client)
  }
  try {
    fs.writeSync(fd, prompt);
    spawnSync('stty', ['-echo'], { stdio: [fd, 'ignore', 'ignore'] });
    const bytes = [];
    const one = Buffer.alloc(1);
    for (;;) {
      let n;
      try { n = fs.readSync(fd, one, 0, 1, null); } catch (err) {
        if (err.code === 'EAGAIN') continue;
        break;
      }
      if (n === 0 || one[0] === 10 || one[0] === 13) break;
      if (one[0] === 3) { bytes.length = 0; return null; } // Ctrl-C
      bytes.push(one[0]);
    }
    const buf = Buffer.from(bytes);
    const out = buf.toString('utf8');
    buf.fill(0);
    bytes.fill(0);
    return out;
  } finally {
    spawnSync('stty', ['echo'], { stdio: [fd, 'ignore', 'ignore'] });
    try { fs.writeSync(fd, '\n'); } catch (_) {}
    try { fs.closeSync(fd); } catch (_) {}
  }
}

function readFromWindowsConsole(prompt) {
  if (process.platform !== 'win32') return undefined;
  const root = process.env.SystemRoot || process.env.windir || 'C:\\Windows';
  const ps = path.join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  if (!fs.existsSync(ps)) return undefined;
  // Read-Host talks to the console directly, so this works while git owns stdin.
  const script = '$p = $env:GITSAFTY_PROMPT; $s = Read-Host -AsSecureString -Prompt $p; ' +
    '$b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s); ' +
    'try { [Console]::Out.Write([Runtime.InteropServices.Marshal]::PtrToStringBSTR($b)) } ' +
    'finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }';
  const r = spawnSync(ps, ['-NoProfile', '-NonInteractive', '-Command', script], {
    encoding: 'utf8',
    stdio: ['inherit', 'pipe', 'inherit'],
    env: { ...process.env, GITSAFTY_PROMPT: prompt.replace(/:\s*$/, '') },
    timeout: 300000
  });
  if (r.status !== 0) return undefined;
  return r.stdout;
}

function readFromAskpass(prompt) {
  const askpass = process.env.GIT_ASKPASS || process.env.SSH_ASKPASS;
  if (!askpass) return undefined;
  const r = spawnSync(askpass, [prompt], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 300000 });
  if (r.status !== 0) return null;
  return r.stdout.replace(/\r?\n$/, '');
}

function readFromDialog(prompt) {
  if (process.platform !== 'darwin') return undefined;
  try {
    return execFileSync('osascript', [
      '-e', 'on run argv',
      '-e', 'display dialog (item 1 of argv) default answer "" with hidden answer with title "GitSafty Vault" with icon caution',
      '-e', 'return text returned of result',
      '-e', 'end run',
      prompt
    ], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 300000 }).replace(/\r?\n$/, '');
  } catch (_) {
    return null;
  }
}

/** Hidden prompt: terminal first, then IDE askpass, then a macOS dialog. */
function readSecret(prompt) {
  for (const source of [readFromTty, readFromWindowsConsole, readFromAskpass, readFromDialog]) {
    const value = source(prompt);
    if (value !== undefined) return value;
  }
  return null;
}

function readLineFromTty(prompt) {
  let fd;
  try { fd = fs.openSync('/dev/tty', 'r+'); } catch (_) { return null; }
  try {
    fs.writeSync(fd, prompt);
    const bytes = [];
    const one = Buffer.alloc(1);
    for (;;) {
      const n = fs.readSync(fd, one, 0, 1, null);
      if (n === 0 || one[0] === 10 || one[0] === 13) break;
      bytes.push(one[0]);
    }
    return Buffer.from(bytes).toString('utf8').trim();
  } finally {
    try { fs.closeSync(fd); } catch (_) {}
  }
}

function confirm(prompt) {
  const ans = readLineFromTty(prompt);
  return !!ans && /^y(es)?$/i.test(ans);
}

// ---------------------------------------------------------------------------
// Git configuration
// ---------------------------------------------------------------------------

function git(args, opts = {}) {
  return execFileSync('git', args, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'ignore'], ...opts });
}

function tryGit(args, opts) {
  try { return git(args, opts); } catch (_) { return null; }
}

function cliPath() {
  return path.resolve(__dirname, '..', 'bin', 'cli.js');
}

function shq(s) {
  return `'${String(s).replace(/'/g, `'\\''`)}'`;
}

function helperCommand() {
  // Absolute node + absolute CLI path: a PATH hijack can't swap the helper.
  return `!${shq(process.execPath)} ${shq(cliPath())} credential`;
}

function helperSection(host) {
  return `credential.https://${host}`;
}

/**
 * Makes GitSafty the only credential helper for https://<host>.
 * An empty helper entry first resets helpers inherited from system config
 * (e.g. macOS osxkeychain). The section is recreated at the end of the
 * global config so later generic helpers can't sneak in after it.
 */
function installHelper(host) {
  const section = helperSection(host);
  tryGit(['config', '--global', '--remove-section', section]);
  git(['config', '--global', '--add', `${section}.helper`, '']);
  git(['config', '--global', '--add', `${section}.helper`, helperCommand()]);
}

function removeHelper(host) {
  tryGit(['config', '--global', '--remove-section', helperSection(host)]);
}

/**
 * Lists the helpers git will actually use for https://<host>, in order.
 * Mirrors git's rule: an empty value resets the list.
 */
function effectiveHelpers(host, cwd) {
  const out = tryGit(['config', '--get-regexp', '^credential\\..*helper$'], { cwd }) || '';
  let list = [];
  for (const line of out.split('\n')) {
    const m = line.match(/^credential\.(?:(.*)\.)?helper(?: (.*))?$/i);
    if (!m) continue;
    const urlPart = m[1];
    if (urlPart && !new RegExp(`^https?://([^/]*@)?${host.replace(/\./g, '\\.')}(/|$)`, 'i').test(urlPart)) continue;
    const value = m[2] || '';
    if (value === '') list = []; else list.push(value);
  }
  return list;
}

function isOurHelper(value) {
  return value.includes(cliPath()) && /\bcredential$/.test(value);
}

// ---------------------------------------------------------------------------
// Removing other stored logins ("logout")
// ---------------------------------------------------------------------------

function eraseKeychain(host) {
  if (process.platform !== 'darwin') return 0;
  let erased = 0;
  for (let i = 0; i < 10; i++) {
    const query = `protocol=https\nhost=${host}\n\n`;
    const found = spawnSync('git', ['credential-osxkeychain', 'get'], { input: query, encoding: 'utf8' });
    if (found.status !== 0 || !/password=/.test(found.stdout || '')) break;
    const user = (found.stdout.match(/^username=(.*)$/m) || [])[1];
    spawnSync('git', ['credential-osxkeychain', 'erase'], {
      input: `protocol=https\nhost=${host}\n${user ? `username=${user}\n` : ''}\n`, encoding: 'utf8'
    });
    erased++;
  }
  return erased;
}

function eraseGitCredentialsFile(host) {
  const files = [
    path.join(process.env.HOME || os.homedir(), '.git-credentials'),
    path.join(process.env.XDG_CONFIG_HOME || path.join(process.env.HOME || os.homedir(), '.config'), 'git', 'credentials')
  ];
  let removed = 0;
  for (const file of files) {
    let text;
    try { text = fs.readFileSync(file, 'utf8'); } catch (_) { continue; }
    const lines = text.split('\n');
    const keep = lines.filter(l => !new RegExp(`@${host.replace(/\./g, '\\.')}(:|/|$)`, 'i').test(l.trim()));
    removed += lines.length - keep.length;
    if (keep.length !== lines.length) fs.writeFileSync(file, keep.join('\n'), { mode: 0o600 });
  }
  return removed;
}

function ghLoggedIn() {
  const r = spawnSync('gh', ['auth', 'status'], { encoding: 'utf8' });
  return r.status === 0;
}

/** Private SSH keys without a passphrase: a thief can push with them. */
function unprotectedSshKeys() {
  const dir = path.join(process.env.HOME || os.homedir(), '.ssh');
  const out = [];
  let entries = [];
  try { entries = fs.readdirSync(dir); } catch (_) { return out; }
  for (const name of entries) {
    const file = path.join(dir, name);
    let text;
    try {
      if (!fs.statSync(file).isFile() || fs.statSync(file).size > 64 * 1024) continue;
      text = fs.readFileSync(file, 'utf8');
    } catch (_) { continue; }
    if (/-----BEGIN OPENSSH PRIVATE KEY-----/.test(text)) {
      const b64 = text.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
      const raw = Buffer.from(b64, 'base64');
      // openssh-key-v1\0 | uint32 len | ciphername
      const magic = 'openssh-key-v1\0';
      if (raw.subarray(0, magic.length).toString('latin1') === magic) {
        const len = raw.readUInt32BE(magic.length);
        const cipher = raw.subarray(magic.length + 4, magic.length + 4 + len).toString('latin1');
        if (cipher === 'none') out.push(file);
      }
    } else if (/-----BEGIN (RSA|EC|DSA) PRIVATE KEY-----/.test(text) && !/ENCRYPTED/.test(text)) {
      out.push(file);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// GitHub token check
// ---------------------------------------------------------------------------

function fetchGitHubUser(token, host) {
  const apiHost = host === 'github.com' ? 'api.github.com' : host;
  const apiPath = host === 'github.com' ? '/user' : '/api/v3/user';
  return new Promise((resolve) => {
    const req = https.request({
      host: apiHost,
      path: apiPath,
      method: 'GET',
      headers: { Authorization: `Bearer ${token}`, 'User-Agent': 'gitsafty-vault', Accept: 'application/vnd.github+json' },
      timeout: 15000
    }, (res) => {
      let body = '';
      res.on('data', c => { body += c; });
      res.on('end', () => {
        let login = null;
        try { login = JSON.parse(body).login || null; } catch (_) {}
        resolve({
          ok: res.statusCode === 200,
          status: res.statusCode,
          login,
          expiresAt: res.headers['github-authentication-token-expiration'] || null,
          scopes: res.headers['x-oauth-scopes'] || null
        });
      });
    });
    req.on('error', () => resolve({ ok: false, status: 0 }));
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, status: 0 }); });
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Credential helper (called by git)
// ---------------------------------------------------------------------------

function parseCredentialInput(text) {
  const attrs = {};
  for (const line of text.split('\n')) {
    const idx = line.indexOf('=');
    if (idx > 0) attrs[line.slice(0, idx)] = line.slice(idx + 1).replace(/\r$/, '');
  }
  return attrs;
}

function notify(title, message) {
  try {
    require('./malwareCleaner').notifyDesktop(title, message);
  } catch (_) {}
}

/**
 * git credential helper entry point: `gitsafty credential get|store|erase`.
 * Writes the credential to `out` (stdout) only for `get` with a good passphrase.
 */
function runCredentialHelper(operation, inputText, out = process.stdout) {
  if (operation !== 'get') {
    // store: never persist anything (this is what keeps the device logged out)
    // erase: nothing to erase, the token only ever lived in memory
    return 0;
  }

  const attrs = parseCredentialInput(inputText);
  const vault = readVault();
  if (!vault) return 0;
  if (attrs.protocol !== 'https' || (attrs.host || '').toLowerCase() !== vault.meta.host) return 0;

  const repo = path.basename(process.cwd());
  const who = vault.meta.username ? `${vault.meta.username}@${vault.meta.host}` : vault.meta.host;

  if (vault.version === VAULT_V2) {
    let token;
    try {
      token = unlockVault(vault, `log in ${who} for one git command in "${repo}"`);
    } catch (err) {
      process.stderr.write(`GitSafty Vault: ${err.message}. Staying logged out.\n`);
      try {
        const hint = require('./doctor').hintForError(err);
        process.stderr.write(`  What to do: ${hint.problem}\n${hint.commands.map(c => `    ${c}\n`).join('')}`);
      } catch (_) {}
      notify('GitSafty Vault: login refused', `A git command in "${repo}" asked for your GitHub login and was refused. If you did not start it, your PC may be compromised.`);
      out.write('quit=1\n\n');
      return 0;
    }
    try {
      out.write(`protocol=https\nhost=${vault.meta.host}\nusername=${vault.meta.username || 'x-access-token'}\npassword=`);
      out.write(token);
      out.write('\n\n');
    } finally {
      token.fill(0);
    }
    notify('GitSafty Vault: GitHub login used', `Unlocked for one git command in "${repo}". Logged out again right after.`);
    return 0;
  }

  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    const passphrase = readSecret(`🔐 GitSafty Vault: passphrase to log in ${who} for this push (${repo}): `);
    if (passphrase === null || passphrase === '') {
      process.stderr.write('GitSafty Vault: no passphrase given, staying logged out.\n');
      out.write('quit=1\n\n'); // stop git from asking for a password some other way
      return 0;
    }
    let token;
    try {
      token = decryptToken(vault, passphrase);
    } catch (err) {
      process.stderr.write(`GitSafty Vault: ${err.message}. (${attempt}/${MAX_ATTEMPTS})\n`);
      notify('GitSafty Vault: wrong passphrase', `Someone tried to unlock your GitHub login in "${repo}". If this was not you, your PC may be compromised.`);
      continue;
    }
    try {
      out.write(`protocol=https\nhost=${vault.meta.host}\nusername=${vault.meta.username || 'x-access-token'}\npassword=`);
      out.write(token);
      out.write('\n\n');
    } finally {
      token.fill(0);
    }
    notify('GitSafty Vault: GitHub login used', `Unlocked for one git command in "${repo}". Logged out again right after.`);
    return 0;
  }
  out.write('quit=1\n\n');
  return 0;
}

// ---------------------------------------------------------------------------
// User commands
// ---------------------------------------------------------------------------

async function setupVault({ host = 'github.com', mode = 'auto', log = console.log } = {}) {
  log(`\nGitSafty Vault keeps this device logged OUT of ${host}.`);
  log('Your token is stored only encrypted (AES-256-GCM, key from your passphrase via scrypt).');
  log('Every push needs your approval (security chip prompt or passphrase), logs in for that one command, then forgets it.\n');
  log('Use a fine-grained personal access token with a short expiry, only the repos you need,');
  log('and only "Contents: Read and write": https://github.com/settings/personal-access-tokens/new\n');

  const token = readSecret('Paste GitHub token (hidden): ');
  if (!token) return { success: false, message: 'No token given.' };

  log('Checking the token with GitHub...');
  const check = await fetchGitHubUser(token, host);
  if (!check.ok) {
    return { success: false, message: `GitHub rejected the token (HTTP ${check.status}). Nothing was changed.` };
  }
  log(`Token belongs to: ${check.login}${check.expiresAt ? ` (expires ${check.expiresAt})` : ' (WARNING: never expires, prefer an expiring token)'}`);
  if (check.scopes && /\b(admin:|delete_repo|admin:org|workflow)\b/.test(check.scopes)) {
    log(`WARNING: token has broad scopes (${check.scopes}). A fine-grained token is safer.`);
  }

  const meta = {
    host,
    username: check.login,
    createdAt: new Date().toISOString(),
    tokenExpiresAt: check.expiresAt
  };

  let vault = null;
  const { platformProvider } = require('./hwkey');
  const provider = mode === 'passphrase' ? null : platformProvider();
  if (provider) {
    log(`Setting up hardware protection: ${provider.label} ...`);
    const avail = provider.available();
    if (avail.ok) {
      try {
        const { protector, secret } = provider.create();
        try {
          vault = encryptWithSecret(token, secret, protector, { ...meta, protection: provider.type });
        } finally {
          secret.fill(0);
        }
        log('Confirm once to test the unlock (this is what every push will look like)...');
        const back = unlockVault(vault, `confirm GitSafty setup for ${check.login}`);
        const same = back.toString('utf8') === token;
        back.fill(0);
        if (!same) throw new Error('hardware self-test returned a different key');
      } catch (err) {
        log(`Hardware protection failed: ${err.message}`);
        vault = null;
      }
    } else {
      log(`Hardware protection not available: ${avail.reason}`);
    }
    if (!vault) log('Falling back to a passphrase vault.');
  }

  if (!vault) {
    const pass1 = readSecret(`Choose a vault passphrase (min ${MIN_PASSPHRASE} chars, NOT your GitHub password): `);
    if (!pass1 || pass1.length < MIN_PASSPHRASE) return { success: false, message: `Passphrase must be at least ${MIN_PASSPHRASE} characters.` };
    if (pass1 === token) return { success: false, message: 'Passphrase must not be the token.' };
    const pass2 = readSecret('Repeat passphrase: ');
    if (pass1 !== pass2) return { success: false, message: 'Passphrases did not match. Nothing was changed.' };

    vault = encryptToken(token, pass1, { ...meta, protection: 'passphrase' });
    // Self-test before switching git over.
    const back = decryptToken(vault, pass1);
    const same = back.toString('utf8') === token;
    back.fill(0);
    if (!same) return { success: false, message: 'Vault self-test failed. Nothing was changed.' };
  }

  writeVault(vault);
  installHelper(host);

  // Log out everywhere else on this device.
  const steps = [];
  const keychain = eraseKeychain(host);
  if (keychain) steps.push(`removed ${keychain} saved login(s) from macOS Keychain`);
  const fileLines = eraseGitCredentialsFile(host);
  if (fileLines) steps.push(`removed ${fileLines} plain-text login(s) from ~/.git-credentials`);
  if (ghLoggedIn()) {
    if (confirm('GitHub CLI (gh) is also logged in and keeps its own token. Log it out? (y/N): ')) {
      spawnSync('gh', ['auth', 'logout', '--hostname', host], { stdio: 'inherit' });
      steps.push('logged out GitHub CLI');
    } else {
      steps.push('GitHub CLI is still logged in (its token can still be stolen)');
    }
  }

  return {
    success: true,
    message: vault.version === VAULT_V2
      ? `Vault ready for ${check.login}@${host}, locked to this device's security chip. This device is now logged out; each push shows a system prompt (${vault.protector.type === 'secure-enclave' ? 'Touch ID / Mac password' : 'Windows Hello PIN / face / fingerprint'}).`
      : `Vault ready for ${check.login}@${host}. This device is now logged out; each push asks for your passphrase.`,
    steps,
    sshWarnings: unprotectedSshKeys()
  };
}

function vaultStatus({ host, cwd = process.cwd() } = {}) {
  const vault = readVault();
  const h = host || (vault && vault.meta.host) || 'github.com';
  const helpers = effectiveHelpers(h, cwd);
  const ours = helpers.length > 0 && helpers.every(isOurHelper);
  const others = helpers.filter(v => !isOurHelper(v));
  let mode = null;
  try { mode = (fs.statSync(vaultPath()).mode & 0o777).toString(8); } catch (_) {}
  return {
    host: h,
    vaultExists: !!vault,
    vaultPath: vaultPath(),
    vaultMode: mode,
    username: vault && vault.meta.username,
    protection: vault ? (vault.version === VAULT_V2 ? vault.protector.type : 'passphrase') : null,
    tokenExpiresAt: vault && vault.meta.tokenExpiresAt,
    helperActive: helpers.some(isOurHelper),
    onlyHelper: ours,
    otherHelpers: others,
    sshWarnings: unprotectedSshKeys()
  };
}

/** Unlocks once without giving the token to anyone (checks the setup works). */
function testUnlock() {
  const vault = readVault();
  if (!vault) return { success: false, message: 'No vault. Run: gitsafty vault setup' };
  try {
    let token;
    if (vault.version === VAULT_V2) {
      token = unlockVault(vault, 'test GitSafty vault unlock');
    } else {
      const pass = readSecret('Vault passphrase: ');
      token = decryptToken(vault, pass || '');
    }
    const ok = token.length > 0;
    token.fill(0);
    return { success: ok, message: ok ? 'Unlock works. The token was decrypted in memory and wiped.' : 'Vault is empty.' };
  } catch (err) {
    return { success: false, message: err.message };
  }
}

function removeVault({ host } = {}) {
  const vault = readVault();
  const h = host || (vault && vault.meta.host) || 'github.com';
  removeHelper(h);
  if (vault) {
    // Overwrite before unlinking (best effort; SSDs may keep old blocks).
    try { fs.writeFileSync(vaultPath(), crypto.randomBytes(fs.statSync(vaultPath()).size)); } catch (_) {}
    try { fs.unlinkSync(vaultPath()); } catch (_) {}
  }
  return { success: true, message: `Vault removed and GitSafty helper unregistered for ${h}. Git will use your normal login again.` };
}

module.exports = {
  KDF,
  encryptToken,
  decryptToken,
  readVault,
  writeVault,
  vaultPath,
  installHelper,
  removeHelper,
  effectiveHelpers,
  helperCommand,
  runCredentialHelper,
  encryptWithSecret,
  decryptWithSecret,
  unlockVault,
  setupVault,
  testUnlock,
  vaultStatus,
  removeVault,
  unprotectedSshKeys,
  parseCredentialInput
};
