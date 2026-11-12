const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync, spawnSync } = require('child_process');
const vault = require('../src/vault');

const PASS = 'correct horse battery staple';
const TOKEN = 'github_pat_TEST_ONLY_not_a_real_token_123';

describe('Vault encryption (AES-256-GCM + scrypt)', () => {
  it('round-trips and never stores the token in plain text', () => {
    const v = vault.encryptToken(TOKEN, PASS, { host: 'github.com', username: 'u' });
    assert.ok(!JSON.stringify(v).includes(TOKEN));
    assert.strictEqual(v.cipher, 'aes-256-gcm');
    assert.strictEqual(v.kdf.name, 'scrypt');
    assert.ok(v.kdf.N >= 1 << 17);
    const out = vault.decryptToken(v, PASS);
    assert.strictEqual(out.toString('utf8'), TOKEN);
  });

  it('uses a fresh salt and IV every time', () => {
    const a = vault.encryptToken(TOKEN, PASS, { host: 'github.com' });
    const b = vault.encryptToken(TOKEN, PASS, { host: 'github.com' });
    assert.notStrictEqual(a.kdf.salt, b.kdf.salt);
    assert.notStrictEqual(a.iv, b.iv);
    assert.notStrictEqual(a.data, b.data);
  });

  it('rejects a wrong passphrase', () => {
    const v = vault.encryptToken(TOKEN, PASS, { host: 'github.com' });
    assert.throws(() => vault.decryptToken(v, 'wrong passphrase!!'), /Wrong passphrase/);
  });

  it('detects tampering with metadata or ciphertext', () => {
    const v = vault.encryptToken(TOKEN, PASS, { host: 'github.com', username: 'me' });
    assert.throws(() => vault.decryptToken({ ...v, meta: { ...v.meta, host: 'evil.example' } }, PASS));
    const data = Buffer.from(v.data, 'base64');
    data[0] ^= 1;
    assert.throws(() => vault.decryptToken({ ...v, data: data.toString('base64') }, PASS));
  });
});

describe('Vault v2 (hardware-bound secret)', () => {
  const crypto = require('crypto');
  const protector = { type: 'secure-enclave', blob: 'b', peer: 'p', helperSha256: 'x' };

  it('round-trips with the device secret and rejects any other secret', () => {
    const secret = crypto.randomBytes(32);
    const v = vault.encryptWithSecret(TOKEN, secret, protector, { host: 'github.com' });
    assert.strictEqual(v.version, 2);
    assert.ok(!JSON.stringify(v).includes(TOKEN));
    assert.strictEqual(vault.decryptWithSecret(v, secret).toString('utf8'), TOKEN);
    assert.throws(() => vault.decryptWithSecret(v, crypto.randomBytes(32)), /did not match/);
  });

  it('binds the protector, so swapping the hardware key reference is detected', () => {
    const secret = crypto.randomBytes(32);
    const v = vault.encryptWithSecret(TOKEN, secret, protector, { host: 'github.com' });
    const swapped = { ...v, protector: { ...protector, blob: 'attacker-key' } };
    assert.throws(() => vault.decryptWithSecret(swapped, secret));
  });
});

describe('Vault as git credential helper', () => {
  let sandbox;
  const saved = {};

  before(() => {
    sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'gitsafty-vault-'));
    for (const k of ['HOME', 'GIT_CONFIG_GLOBAL', 'GITSAFTY_NO_NOTIFY']) saved[k] = process.env[k];
    process.env.HOME = sandbox;
    process.env.GIT_CONFIG_GLOBAL = path.join(sandbox, '.gitconfig');
    process.env.GITSAFTY_NO_NOTIFY = '1';
    // A plain-text helper that would normally save the token after a push.
    execFileSync('git', ['config', '--global', 'credential.helper', 'store']);
    vault.writeVault(vault.encryptToken(TOKEN, PASS, { host: 'github.com', username: 'tester' }));
    vault.installHelper('github.com');
    for (const [name, value] of [['good', PASS], ['bad', 'not the passphrase']]) {
      const file = path.join(sandbox, `askpass-${name}`);
      fs.writeFileSync(file, `#!/bin/sh\necho '${value}'\n`, { mode: 0o755 });
    }
  });

  after(() => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
    fs.rmSync(sandbox, { recursive: true, force: true });
  });

  const fill = (askpass, host = 'github.com') => spawnSync('git', ['credential', 'fill'], {
    cwd: sandbox,
    input: `protocol=https\nhost=${host}\n\n`,
    encoding: 'utf8',
    env: { ...process.env, GIT_ASKPASS: path.join(sandbox, `askpass-${askpass}`), GIT_TERMINAL_PROMPT: '0' }
  });

  it('is the only helper git will use for github.com', () => {
    const helpers = vault.effectiveHelpers('github.com', sandbox);
    assert.strictEqual(helpers.length, 1);
    assert.match(helpers[0], /cli\.js' credential$/);
  });

  it('logs in with the right passphrase', function () {
    if (process.platform === 'win32') return this.skip();
    const r = fill('good');
    assert.strictEqual(r.status, 0);
    assert.match(r.stdout, new RegExp(`password=${TOKEN}`));
    assert.match(r.stdout, /username=tester/);
  });

  it('stays logged out and stops git on a wrong passphrase', function () {
    if (process.platform === 'win32') return this.skip();
    const r = fill('bad');
    assert.notStrictEqual(r.status, 0);
    assert.ok(!r.stdout.includes(TOKEN));
  });

  it('never saves the token after a successful push', () => {
    spawnSync('git', ['credential', 'approve'], {
      cwd: sandbox,
      input: `protocol=https\nhost=github.com\nusername=tester\npassword=${TOKEN}\n\n`
    });
    assert.ok(!fs.existsSync(path.join(sandbox, '.git-credentials')));
  });

  it('removes itself cleanly', () => {
    vault.removeVault({ host: 'github.com' });
    assert.ok(!fs.existsSync(vault.vaultPath()));
    assert.ok(!vault.effectiveHelpers('github.com', sandbox).some(h => h.includes('credential') && h.includes('cli.js')));
  });
});
