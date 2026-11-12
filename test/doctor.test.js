const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { hintForError, runChecks } = require('../src/doctor');

describe('Doctor: error hints', () => {
  const cases = [
    [Object.assign(new Error("EACCES: permission denied, mkdir '/usr/local/lib/node_modules/x'"), { code: 'EACCES', path: '/usr/local/lib/node_modules/x' }), /npm has no permission/, /npm install -g/],
    [Object.assign(new Error('getaddrinfo ENOTFOUND registry.npmjs.org'), { code: 'ENOTFOUND' }), /Network problem/, /npm cache verify/],
    [new Error("'git' is not recognized as an internal or external command"), /git is not installed/, /./],
    [new SyntaxError('Unexpected token ?'), /too old/, /nvm install|winget/],
    [new Error("Cannot find module '../src/rules/malware'"), /files are missing/, /npm install -g/],
    [new Error('Swift compiler not found. Install it with: xcode-select --install'), /command line tools/, /xcode-select --install/],
    [new Error('Wrong passphrase (or the vault file was modified)'), /Wrong passphrase/, /vault setup/],
    [new Error('something nobody expected'), /something nobody expected/, /gitsafty doctor/]
  ];
  for (const [err, problem, command] of cases) {
    it(`explains: ${err.message.slice(0, 50)}`, () => {
      const hint = hintForError(err);
      assert.match(hint.problem, problem);
      assert.ok(hint.commands.some(c => command.test(c)), JSON.stringify(hint.commands));
    });
  }
});

describe('Doctor: broken installs', () => {
  it('detects global hooks whose GitSafty was deleted, and fixes them', () => {
    const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'gitsafty-doctor-'));
    const saved = { HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE, GIT_CONFIG_GLOBAL: process.env.GIT_CONFIG_GLOBAL, PATH: process.env.PATH };
    process.env.HOME = sandbox;
    process.env.USERPROFILE = sandbox;
    process.env.GIT_CONFIG_GLOBAL = path.join(sandbox, '.gitconfig');
    try {
      const { installHook } = require('../src/installer');
      assert.ok(installHook(sandbox, true).success);
      // Point the hooks at a GitSafty that no longer exists.
      const dir = path.join(sandbox, '.git-hooks-safty');
      for (const f of fs.readdirSync(dir)) {
        const p = path.join(dir, f);
        fs.writeFileSync(p, fs.readFileSync(p, 'utf8').replace(/^GITSAFTY_CLI='[^']*'/m, "GITSAFTY_CLI='/gone/gitsafty/bin/cli.js'"));
      }
      // PATH with only git (and the OS basics): hides any installed gitsafty command.
      const whichGit = execFileSync(process.platform === 'win32' ? 'where' : 'which', ['git'], { encoding: 'utf8' }).split(/\r?\n/)[0].trim();
      const sysDirs = process.platform === 'win32' ? [path.join(process.env.SystemRoot || 'C:\\Windows', 'System32')] : ['/bin'];
      process.env.PATH = [path.dirname(whichGit), ...sysDirs].join(path.delimiter);
      if (fs.existsSync(path.join(path.dirname(whichGit), 'gitsafty'))) return; // gitsafty lives next to git: can't hide it

      const broken = runChecks({ cwd: sandbox }).find(c => c.id === 'hook-broken');
      assert.ok(broken, 'broken hooks detected');
      assert.ok(broken.commands.includes('git config --global --unset core.hooksPath'));
      assert.ok(broken.commands.some(c => /npm install -g @arifbiswas\/git-pre-push/.test(c)));

      broken.fix();
      assert.ok(!runChecks({ cwd: sandbox }).some(c => c.level === 'error'), 'fixed');

      // The hook itself tells the user what to do when GitSafty is missing.
      const hook = fs.readFileSync(path.join(dir, 'pre-push'), 'utf8');
      assert.match(hook, /gitsafty_missing/);
      assert.match(hook, /rm -rf ~\/\.git-hooks-safty/);
      execFileSync('git', ['--version']);
    } finally {
      for (const [k, v] of Object.entries(saved)) {
        if (v === undefined) delete process.env[k]; else process.env[k] = v;
      }
      fs.rmSync(sandbox, { recursive: true, force: true });
    }
  });
});
