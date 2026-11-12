/**
 * End-to-end self test: GitSafty protects a real git workflow.
 *
 * Builds an "attacker" repository with inert stand-ins for the real infections
 * (hidden loader in tailwind.js, JavaScript disguised as a .woff2 font, a
 * folderOpen VS Code task and an npm postinstall that run that font), installs
 * GitSafty's global hooks in an isolated HOME / git config, and then runs real
 * `git clone`, `git pull` and `git push` commands against it.
 *
 * Nothing here is executable malware: the payloads only have the same shape.
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

// Marker assembled at runtime so this file never matches the signature itself.
const MARK = 'glo' + "bal['!']";
const LOADER = MARK + "='9-5756';var _$_1e42=(function(l,e){var g=[];var x=String.fromCharCode(127);" +
  "var k='\\x25';return g.join('').split(k).join(x).split(x)})('abc',1);global[_$_1e42[0]]= require;" +
  '(function(){var a="' + 'x'.repeat(300) + '";})()';
const FAKE_FONT = MARK + "='9-0777-1';(function(_0xda4c00,_0x229911){var _0x35893f=_0x490c;" +
  "while(!![]){try{var _0x50e4cd=parseInt(_0x35893f(0x21f));if(_0x50e4cd===_0x229911)break;}" +
  "catch(_0x25b35f){}}}(_0xcc75,0x1));var cp=require('child_process');";
const CLEAN_TAILWIND = '// lib/tailwind.js\n\nimport { create } from "twrnc";\n\n' +
  'const tw = create(require(`@/tailwind.config`));\n\nexport default tw;';
const TASKS = JSON.stringify({
  version: '2.0.0',
  tasks: [
    { label: 'build', type: 'shell', command: 'npm run build' },
    { label: 'eslint-check', type: 'shell', command: 'node public/fonts/fa-solid-900.woff2', runOptions: { runOn: 'folderOpen' } }
  ]
}, null, 2);
const PKG = JSON.stringify({ name: 'demo', scripts: { dev: 'next dev', postinstall: 'node public/fonts/fa-solid-900.woff2' } }, null, 2);

const { installHook } = require('../src/installer');

let sandbox;
let env;
const saved = {};

function git(args, cwd, extraEnv = {}) {
  return spawnSync('git', args, { cwd, env: { ...env, ...extraEnv }, encoding: 'utf8' });
}

function mustGit(args, cwd, extraEnv) {
  const r = git(args, cwd, extraEnv);
  assert.strictEqual(r.status, 0, `git ${args.join(' ')} failed:\n${r.stdout}\n${r.stderr}`);
  return r;
}

function writeInfection(dir) {
  fs.mkdirSync(path.join(dir, 'lib'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'public/fonts'), { recursive: true });
  fs.mkdirSync(path.join(dir, '.vscode'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'lib/tailwind.js'), CLEAN_TAILWIND + ' '.repeat(500) + LOADER + '\n');
  fs.writeFileSync(path.join(dir, 'public/fonts/fa-solid-900.woff2'), FAKE_FONT);
  fs.writeFileSync(path.join(dir, '.vscode/tasks.json'), TASKS);
  fs.writeFileSync(path.join(dir, 'package.json'), PKG);
}

function assertCleaned(dir) {
  const read = (p) => fs.readFileSync(path.join(dir, p), 'utf8');
  assert.strictEqual(read('lib/tailwind.js').replace(/\r\n/g, '\n'), CLEAN_TAILWIND + '\n', 'hidden loader stripped, real code kept');
  assert.ok(!fs.existsSync(path.join(dir, 'public/fonts/fa-solid-900.woff2')), 'fake font quarantined');
  const tasks = JSON.parse(read('.vscode/tasks.json'));
  assert.deepStrictEqual(tasks.tasks.map(t => t.label), ['build'], 'only the malicious task removed');
  const pkg = JSON.parse(read('package.json'));
  assert.deepStrictEqual(Object.keys(pkg.scripts), ['dev'], 'only the malicious postinstall removed');
  const qdir = path.join(dir, '.git', 'gitsafty-quarantine');
  assert.ok(fs.existsSync(qdir), 'backups kept');
}

describe('End-to-end: clone, pull and push are protected', () => {
  before(() => {
    sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'gitsafty-e2e-'));
    const home = path.join(sandbox, 'home');
    fs.mkdirSync(home);
    for (const k of ['HOME', 'USERPROFILE', 'GIT_CONFIG_GLOBAL']) saved[k] = process.env[k];
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    process.env.GIT_CONFIG_GLOBAL = path.join(home, '.gitconfig');
    env = {
      ...process.env,
      GIT_CONFIG_NOSYSTEM: '1',
      GITSAFTY_NO_NOTIFY: '1',
      NO_UPDATE_NOTIFIER: '1',
      GIT_TERMINAL_PROMPT: '0'
    };
    mustGit(['config', '--global', 'user.name', 'e2e'], sandbox);
    mustGit(['config', '--global', 'user.email', 'e2e@example.invalid'], sandbox);
    mustGit(['config', '--global', 'init.defaultBranch', 'main'], sandbox);
    mustGit(['config', '--global', 'core.autocrlf', 'false'], sandbox);

    const res = installHook(sandbox, true);
    assert.ok(res.success, res.message);

    // Attacker repository with every infection type.
    const attacker = path.join(sandbox, 'attacker');
    fs.mkdirSync(attacker);
    mustGit(['init', '-q'], attacker);
    writeInfection(attacker);
    fs.writeFileSync(path.join(attacker, 'app.js'), 'export const ok = 1;\n');
    mustGit(['add', '-A'], attacker);
    mustGit(['commit', '-q', '--no-verify', '-m', 'init'], attacker);
  });

  after(() => {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
    fs.rmSync(sandbox, { recursive: true, force: true });
  });

  it('git clone: detects and removes every infection automatically', () => {
    const r = mustGit(['clone', 'attacker', 'victim'], sandbox);
    const output = r.stdout + r.stderr;
    assert.match(output, /MALWARE/);
    assertCleaned(path.join(sandbox, 'victim'));
  });

  it('git push: blocks malware and keeps the remote clean', () => {
    const remote = path.join(sandbox, 'remote.git');
    mustGit(['init', '-q', '--bare', remote], sandbox);
    const dev = path.join(sandbox, 'dev');
    mustGit(['clone', '-q', remote, dev], sandbox);
    fs.writeFileSync(path.join(dev, 'a.js'), 'export default 1;\n');
    mustGit(['add', '-A'], dev);
    mustGit(['commit', '-q', '-m', 'clean'], dev);
    mustGit(['push', '-q', 'origin', 'main'], dev);
    const cleanTip = mustGit(['rev-parse', 'HEAD'], dev).stdout.trim();

    writeInfection(dev);
    mustGit(['add', '-A'], dev);
    mustGit(['commit', '-q', '-m', 'update deps'], dev);
    const push = git(['push', 'origin', 'main'], dev);

    assert.notStrictEqual(push.status, 0, 'push must be rejected');
    assert.match(push.stdout + push.stderr, /PUSH BLOCKED/);
    const remoteTip = mustGit(['rev-parse', 'main'], remote).stdout.trim();
    assert.strictEqual(remoteTip, cleanTip, 'remote unchanged');
    assertCleaned(dev);
  });

  it('git pull: cleans malware that someone pushed with --no-verify', () => {
    const remote = path.join(sandbox, 'remote.git');
    const dev = path.join(sandbox, 'dev');
    // Attacker bypasses the hook (e.g. stolen token): the infected commit lands.
    mustGit(['reset', '-q', '--hard', 'HEAD'], dev);
    mustGit(['push', '-q', '--no-verify', 'origin', 'main'], dev);

    const other = path.join(sandbox, 'other');
    mustGit(['clone', '-q', remote, other], sandbox, { GITSAFTY_SKIP: '1' });
    mustGit(['reset', '-q', '--hard', 'HEAD~1'], other);
    const pull = mustGit(['pull', '--ff-only', 'origin', 'main'], other);
    assert.match(pull.stdout + pull.stderr, /MALWARE/);
    assertCleaned(other);
  });
});
