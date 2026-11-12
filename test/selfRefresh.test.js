const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { isPermanentGlobalInstall, refreshOutdatedHooks, installHook, HOOK_TYPES } = require('../src/installer');

describe('Self-refresh after updates (npm may skip postinstall)', () => {
  it('only a real global install may take over hooks', () => {
    assert.ok(isPermanentGlobalInstall('/Users/a/.nvm/versions/node/v24/lib/node_modules/@arifbiswas/git-pre-push/bin/cli.js'));
    assert.ok(isPermanentGlobalInstall('/usr/local/lib/node_modules/@arifbiswas/git-pre-push/bin/cli.js'));
    assert.ok(isPermanentGlobalInstall('C:/Users/a/AppData/Roaming/npm/node_modules/@arifbiswas/git-pre-push/bin/cli.js'));
    assert.ok(!isPermanentGlobalInstall('/Users/a/.npm/_npx/abc/node_modules/@arifbiswas/git-pre-push/bin/cli.js'));
    assert.ok(!isPermanentGlobalInstall('/work/app/node_modules/@arifbiswas/git-pre-push/bin/cli.js'));
    assert.ok(!isPermanentGlobalInstall('/Volumes/D/src/git-safty/bin/cli.js'));
  });

  it('rewrites outdated hooks that belong to this copy, and nothing when up to date', () => {
    const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'gitsafty-refresh-'));
    const saved = { HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE, GIT_CONFIG_GLOBAL: process.env.GIT_CONFIG_GLOBAL };
    process.env.HOME = sandbox;
    process.env.USERPROFILE = sandbox;
    process.env.GIT_CONFIG_GLOBAL = path.join(sandbox, '.gitconfig');
    try {
      assert.ok(installHook(sandbox, true).success);
      assert.deepStrictEqual(refreshOutdatedHooks(), []);

      const dir = path.join(sandbox, '.git-hooks-safty');
      const merge = path.join(dir, 'post-merge');
      fs.writeFileSync(merge, fs.readFileSync(merge, 'utf8').replace('Never fails the git command itself.', 'old version'));
      fs.unlinkSync(path.join(dir, 'post-rewrite'));
      assert.deepStrictEqual(refreshOutdatedHooks().sort(), ['post-merge', 'post-rewrite']);
      for (const t of HOOK_TYPES) assert.ok(fs.existsSync(path.join(dir, t)));

      // Hooks owned by another (non-global) copy are left alone by a source checkout.
      const pre = path.join(dir, 'pre-push');
      fs.writeFileSync(pre, fs.readFileSync(pre, 'utf8').replace(/^GITSAFTY_CLI='[^']*'/m, "GITSAFTY_CLI='/elsewhere/bin/cli.js'"));
      assert.deepStrictEqual(refreshOutdatedHooks(), []);
    } finally {
      for (const [k, v] of Object.entries(saved)) {
        if (v === undefined) delete process.env[k]; else process.env[k] = v;
      }
      fs.rmSync(sandbox, { recursive: true, force: true });
    }
  });
});
