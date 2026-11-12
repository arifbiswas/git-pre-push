/**
 * Hardware-bound vault keys.
 *
 *   macOS   -> Secure Enclave key, every use needs Touch ID or the Mac password
 *   Windows -> Windows Hello key in the TPM, every use needs PIN / face / fingerprint
 *
 * Both give a 32-byte secret that only this physical device can produce, and
 * only after the person at the keyboard approves a system prompt. Malware can
 * copy the vault file but can't decrypt it elsewhere, and can't approve the
 * system prompt for you.
 *
 * Interface (per provider):
 *   available()               -> { ok, reason }
 *   create()                  -> { protector, secret }   (protector is stored in the vault)
 *   unlock(protector, reason) -> secret Buffer           (prompts the user)
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync, spawnSync } = require('child_process');

function homeDir() {
  return process.env.HOME || process.env.USERPROFILE || os.homedir();
}

function sha256File(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function hkdf(secret, label) {
  return Buffer.from(crypto.hkdfSync('sha256', secret, Buffer.from('gitsafty-hwkey'), Buffer.from(label), 32));
}

// ---------------------------------------------------------------------------
// macOS: Secure Enclave
// ---------------------------------------------------------------------------

const SWIFT_SOURCE = path.join(__dirname, 'secure-enclave.swift');

function macHelperPath() {
  return path.join(homeDir(), '.gitsafty', 'bin', 'gitsafty-se');
}

function findSwiftc() {
  for (const candidate of ['/usr/bin/swiftc', '/usr/bin/xcrun']) {
    if (fs.existsSync(candidate)) return candidate;
  }
  return null;
}

/** Compiles the Swift helper once (and again when the source changes). */
function ensureMacHelper() {
  const out = macHelperPath();
  const stamp = out + '.src-sha256';
  const sourceSha = sha256File(SWIFT_SOURCE);
  try {
    if (fs.existsSync(out) && fs.readFileSync(stamp, 'utf8').trim() === sourceSha) return out;
  } catch (_) {}

  const swiftc = findSwiftc();
  if (!swiftc) throw new Error('Swift compiler not found. Install it with: xcode-select --install');
  fs.mkdirSync(path.dirname(out), { recursive: true, mode: 0o700 });
  const args = swiftc.endsWith('xcrun')
    ? ['swiftc', '-O', SWIFT_SOURCE, '-o', out]
    : ['-O', SWIFT_SOURCE, '-o', out];
  const r = spawnSync(swiftc, args, { encoding: 'utf8', timeout: 300000 });
  if (r.status !== 0) throw new Error(`Could not build Secure Enclave helper: ${(r.stderr || '').trim().split('\n').pop()}`);
  fs.chmodSync(out, 0o700);
  fs.writeFileSync(stamp, sourceSha, { mode: 0o600 });
  return out;
}

const macos = {
  type: 'secure-enclave',
  label: 'Apple Secure Enclave (Touch ID / Mac password)',

  available() {
    if (process.platform !== 'darwin') return { ok: false, reason: 'not macOS' };
    try {
      const helper = ensureMacHelper();
      const r = spawnSync(helper, ['check'], { encoding: 'utf8', timeout: 10000 });
      if (r.status === 0) return { ok: true };
      return { ok: false, reason: (r.stderr || 'Secure Enclave not available').trim() };
    } catch (err) {
      return { ok: false, reason: err.message };
    }
  },

  create() {
    const helper = ensureMacHelper();
    const r = spawnSync(helper, ['create'], { encoding: 'utf8', timeout: 30000 });
    if (r.status !== 0) throw new Error((r.stderr || 'Secure Enclave key creation failed').trim());
    const out = JSON.parse(r.stdout);
    const secret = Buffer.from(out.secret, 'hex');
    out.secret = '';
    return {
      protector: { type: this.type, blob: out.blob, peer: out.peer, helperSha256: sha256File(helper) },
      secret
    };
  },

  unlock(protector, reason) {
    const helper = macHelperPath();
    if (!fs.existsSync(helper)) throw new Error('Secure Enclave helper missing. Run: gitsafty vault setup');
    if (sha256File(helper) !== protector.helperSha256) {
      throw new Error('Secure Enclave helper was modified since setup. Refusing to unlock (possible tampering). Run gitsafty vault setup again if you updated GitSafty.');
    }
    const r = spawnSync(helper, ['unlock', reason], {
      input: JSON.stringify({ blob: protector.blob, peer: protector.peer }),
      encoding: 'utf8',
      timeout: 300000
    });
    if (r.status !== 0) throw new Error((r.stderr || 'Unlock refused').trim());
    return Buffer.from(r.stdout.trim(), 'hex');
  }
};

// ---------------------------------------------------------------------------
// Windows: Windows Hello (TPM)
// ---------------------------------------------------------------------------

const PS_SCRIPT = path.join(__dirname, 'windows-hello.ps1');

function powershellPath() {
  const root = process.env.SystemRoot || process.env.windir || 'C:\\Windows';
  return path.join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
}

function runHello(op, extra = []) {
  return spawnSync(powershellPath(), [
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
    '-File', PS_SCRIPT, '-Op', op, ...extra
  ], { encoding: 'utf8', timeout: 300000, windowsHide: false });
}

function helloSign(name, challengeB64) {
  const r = runHello('sign', ['-Name', name, '-Challenge', challengeB64]);
  if (r.status !== 0) throw new Error((r.stderr || 'Windows Hello refused').trim());
  return Buffer.from(r.stdout.trim(), 'base64');
}

const windows = {
  type: 'windows-hello',
  label: 'Windows Hello + TPM (PIN / face / fingerprint)',

  available() {
    if (process.platform !== 'win32') return { ok: false, reason: 'not Windows' };
    if (!fs.existsSync(powershellPath())) return { ok: false, reason: 'Windows PowerShell not found' };
    const r = runHello('check');
    if (r.status === 0) return { ok: true };
    return { ok: false, reason: (r.stderr || 'Windows Hello not available').trim() };
  },

  create() {
    const name = `GitSafty-Vault-${crypto.randomBytes(4).toString('hex')}`;
    const c = runHello('create', ['-Name', name]);
    if (c.status !== 0) throw new Error((c.stderr || 'Windows Hello key creation failed').trim());

    const challenge = crypto.randomBytes(32).toString('base64');
    const sig1 = helloSign(name, challenge);
    // Second signature proves the derivation is stable before we rely on it.
    const sig2 = helloSign(name, challenge);
    if (!sig1.equals(sig2)) {
      throw new Error('Windows Hello signatures are not deterministic on this PC; use the passphrase vault instead (gitsafty vault setup --passphrase).');
    }
    const secret = hkdf(crypto.createHash('sha256').update(sig1).digest(), 'windows-hello-v2');
    sig1.fill(0); sig2.fill(0);
    return {
      protector: { type: this.type, name, challenge, scriptSha256: sha256File(PS_SCRIPT) },
      secret
    };
  },

  unlock(protector) {
    if (sha256File(PS_SCRIPT) !== protector.scriptSha256) {
      throw new Error('Windows Hello helper script changed since setup. Refusing to unlock (possible tampering). Run gitsafty vault setup again if you updated GitSafty.');
    }
    const sig = helloSign(protector.name, protector.challenge);
    const secret = hkdf(crypto.createHash('sha256').update(sig).digest(), 'windows-hello-v2');
    sig.fill(0);
    return secret;
  }
};

// ---------------------------------------------------------------------------

const PROVIDERS = { [macos.type]: macos, [windows.type]: windows };

/** Hardware provider for this OS, or null. */
function platformProvider() {
  if (process.platform === 'darwin') return macos;
  if (process.platform === 'win32') return windows;
  return null;
}

function providerFor(type) {
  return PROVIDERS[type] || null;
}

module.exports = {
  platformProvider,
  providerFor,
  macHelperPath,
  ensureMacHelper
};
