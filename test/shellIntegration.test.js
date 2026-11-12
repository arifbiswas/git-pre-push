const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

describe('Pull scan shell integration', () => {
  it('adds, refreshes and removes the git function without touching the rest of the profile', function () {
    if (process.platform === 'win32') return this.skip();
    const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'gitsafty-shell-'));
    const saved = { HOME: process.env.HOME, SHELL: process.env.SHELL };
    process.env.HOME = sandbox;
    process.env.SHELL = '/bin/zsh';
    try {
      const shell = require('../src/shellIntegration');
      const rc = path.join(sandbox, '.zshrc');
      fs.writeFileSync(rc, 'export FOO=1\nalias ll="ls -l"\n');

      shell.installShellIntegration();
      shell.installShellIntegration(); // twice: still one block
      const text = fs.readFileSync(rc, 'utf8');
      assert.strictEqual(text.split(shell.START).length - 1, 1);
      assert.match(text, /export FOO=1/);
      assert.match(text, /scan-pull/);
      assert.deepStrictEqual(shell.shellIntegrationStatus().installed, [rc]);

      shell.removeShellIntegration();
      const after = fs.readFileSync(rc, 'utf8');
      assert.ok(!after.includes(shell.START));
      assert.strictEqual(after.trim(), 'export FOO=1\nalias ll="ls -l"');
    } finally {
      for (const [k, v] of Object.entries(saved)) {
        if (v === undefined) delete process.env[k]; else process.env[k] = v;
      }
      fs.rmSync(sandbox, { recursive: true, force: true });
    }
  });

  it('generates a function that bash accepts and that keeps git\'s exit code', function () {
    if (process.platform === 'win32') return this.skip();
    const shell = require('../src/shellIntegration');
    const script = shell.posixBlock() + '\ngit --definitely-not-a-real-flag >/dev/null 2>&1; echo "rc=$?"\n';
    const r = spawnSync('bash', ['-c', script], { encoding: 'utf8' });
    assert.match(r.stdout, /rc=129/);
  });
});
