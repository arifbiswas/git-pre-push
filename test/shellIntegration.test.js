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

  it('is on by default, and stays off once the user turns it off', function () {
    if (process.platform === 'win32') return this.skip();
    const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'gitsafty-shell-default-'));
    const saved = { HOME: process.env.HOME, SHELL: process.env.SHELL, CI: process.env.CI, GIT_CONFIG_GLOBAL: process.env.GIT_CONFIG_GLOBAL };
    process.env.HOME = sandbox;
    process.env.SHELL = '/bin/zsh';
    process.env.GIT_CONFIG_GLOBAL = path.join(sandbox, '.gitconfig');
    delete process.env.CI;
    try {
      const shell = require('../src/shellIntegration');
      const rc = path.join(sandbox, '.zshrc');
      fs.writeFileSync(rc, 'export FOO=1\n');

      // Existing install without global GitSafty hooks: left alone
      assert.deepStrictEqual(shell.enableByDefault({ onlyIfGlobalHooks: true }), []);
      spawnSync('git', ['config', '--global', 'core.hooksPath', path.join(sandbox, '.git-hooks-safty')]);
      assert.deepStrictEqual(shell.enableByDefault({ onlyIfGlobalHooks: true }), [rc], 'turned on by default');
      assert.deepStrictEqual(shell.enableByDefault(), [], 'already on: nothing to do');

      shell.removeShellIntegration({ optOut: true });
      assert.ok(shell.isOptedOut());
      assert.deepStrictEqual(shell.enableByDefault(), [], 'user turned it off: never re-added');
      assert.ok(!fs.readFileSync(rc, 'utf8').includes(shell.START));

      shell.installShellIntegration();
      assert.ok(!shell.isOptedOut(), 'turning it on clears the opt-out');
      shell.removeShellIntegration(); // uninstall (not an opt-out)
      assert.deepStrictEqual(shell.enableByDefault(), [rc]);
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
