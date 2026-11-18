/**
 * .env guard: a real `git push` with a .env file is blocked and fixed.
 * Runs in an isolated HOME / git config, never touches the real one.
 */
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { isEnvFile } = require('../src/envGuard');
const { installHook } = require('../src/installer');

let sandbox; let env; const saved = {};
const git = (args, cwd) => spawnSync('git', args, { cwd, env, encoding: 'utf8' });
function must(args, cwd) {
  const r = git(args, cwd);
  assert.strictEqual(r.status, 0, `git ${args.join(' ')}:\n${r.stdout}\n${r.stderr}`);
  return r.stdout.trim();
}
const filesIn = (rev, cwd) => must(['ls-tree', '-r', '--name-only', rev], cwd).split('\n');
// Every commit reachable from the remote branch: none may contain a .env
function envEverOnRemote(remote) {
  return must(['log', '--format=%H', 'main'], remote).split('\n')
    .some(c => filesIn(c, remote).some(isEnvFile));
}

describe('.env guard on git push', () => {
  before(() => {
    sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'gitsafty-env-'));
    const home = path.join(sandbox, 'home');
    fs.mkdirSync(home);
    for (const k of ['HOME', 'USERPROFILE', 'GIT_CONFIG_GLOBAL']) saved[k] = process.env[k];
    process.env.HOME = home; process.env.USERPROFILE = home;
    process.env.GIT_CONFIG_GLOBAL = path.join(home, '.gitconfig');
    env = { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GITSAFTY_NO_NOTIFY: '1', NO_UPDATE_NOTIFIER: '1', GIT_TERMINAL_PROMPT: '0' };
    must(['config', '--global', 'user.name', 'env'], sandbox);
    must(['config', '--global', 'user.email', 'env@example.invalid'], sandbox);
    must(['config', '--global', 'init.defaultBranch', 'main'], sandbox);
    assert.ok(installHook(sandbox, true).success);
  });
  after(() => {
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    fs.rmSync(sandbox, { recursive: true, force: true });
  });

  it('knows which files are .env files', () => {
    for (const f of ['.env', 'api/.env', '.env.local', '.env.production', '.env.development.local']) assert.ok(isEnvFile(f), f);
    for (const f of ['.env.example', '.env.sample', '.env.template', 'env.js', '.envrc', 'src/.environment']) assert.ok(!isEnvFile(f), f);
  });

  it('blocks the push, ignores .env, removes it from unpushed commits, keeps it on disk', () => {
    const remote = path.join(sandbox, 'remote.git');
    must(['init', '-q', '--bare', remote], sandbox);
    const dev = path.join(sandbox, 'dev');
    must(['clone', '-q', remote, dev], sandbox);
    fs.writeFileSync(path.join(dev, 'app.js'), 'export default 1;\n');
    must(['add', '-A'], dev); must(['commit', '-q', '-m', 'first'], dev);
    must(['push', '-q', 'origin', 'main'], dev);

    // Unpushed: a commit mixing code + .env, a commit that only adds .env.local, an allowed example
    fs.writeFileSync(path.join(dev, '.env'), 'DB_PASSWORD=hunter2\n');
    fs.writeFileSync(path.join(dev, '.env.example'), 'DB_PASSWORD=\n');
    fs.writeFileSync(path.join(dev, 'b.js'), 'export const b = 2;\n');
    must(['add', '-A'], dev); must(['commit', '-q', '-m', 'feature b'], dev);
    fs.writeFileSync(path.join(dev, '.env.local'), 'TOKEN=abc\n');
    must(['add', '-A'], dev); must(['commit', '-q', '-m', 'local env'], dev);
    // Uncommitted work must survive the fix
    fs.writeFileSync(path.join(dev, 'app.js'), 'export default 42; // work in progress\n');

    const push = git(['push', 'origin', 'main'], dev);
    assert.notStrictEqual(push.status, 0, 'original push (with .env) refused');
    assert.match(push.stdout + push.stderr, /\.env file in this push/);
    assert.match(push.stdout + push.stderr, /Fixed and pushed without \.env/);
    assert.ok(!envEverOnRemote(remote), 'no .env ever reached the remote');
    assert.strictEqual(must(['rev-parse', 'main'], remote), must(['rev-parse', 'main'], dev), 'cleaned branch was pushed automatically');

    // Fixed locally
    assert.ok(fs.existsSync(path.join(dev, '.env')), '.env kept on disk');
    assert.ok(fs.existsSync(path.join(dev, '.env.local')), '.env.local kept on disk');
    assert.strictEqual(fs.readFileSync(path.join(dev, 'app.js'), 'utf8'), 'export default 42; // work in progress\n', 'uncommitted work untouched');
    assert.match(fs.readFileSync(path.join(dev, '.gitignore'), 'utf8'), /^\.env$/m);
    assert.strictEqual(git(['check-ignore', '-q', '.env'], dev).status, 0);
    assert.notStrictEqual(git(['check-ignore', '-q', '.env.example'], dev).status, 0, 'examples stay allowed');
    const msgs = must(['log', '--format=%s', 'main'], dev).split('\n');
    assert.deepStrictEqual(msgs, ['chore: never commit .env files', 'feature b', 'first'], 'env-only commit dropped, code commit kept');
    assert.ok(filesIn('HEAD', dev).includes('b.js') && filesIn('HEAD', dev).includes('.env.example'));
    assert.match(must(['status', '--porcelain'], dev), /M app\.js/);

    // Nothing left to push
    const again = git(['push', 'origin', 'main'], dev);
    assert.strictEqual(again.status, 0, again.stdout + again.stderr);
    assert.match(again.stderr, /up-to-date|Everything/i);
  });

  it('a .env git still tracks ("cached") is untracked and removed from the remote', () => {
    const remote = path.join(sandbox, 'remote2.git');
    must(['init', '-q', '--bare', remote], sandbox);
    const dev = path.join(sandbox, 'dev2');
    must(['clone', '-q', remote, dev], sandbox);
    fs.writeFileSync(path.join(dev, '.env'), 'KEY=1\n');
    fs.writeFileSync(path.join(dev, 'a.js'), '1\n');
    must(['add', '-A'], dev); must(['commit', '-q', '-m', 'oops'], dev);
    must(['push', '-q', '--no-verify', 'origin', 'main'], dev);
    // Developer adds it to .gitignore, but git keeps tracking the cached file
    fs.writeFileSync(path.join(dev, '.gitignore'), '.env\n');
    fs.writeFileSync(path.join(dev, 'a.js'), '2\n');
    must(['add', '-A'], dev); must(['commit', '-qm', 'more'], dev);
    assert.ok(filesIn('HEAD', dev).includes('.env'), 'still tracked despite .gitignore');

    const push = git(['push', 'origin', 'main'], dev);
    assert.notStrictEqual(push.status, 0);
    assert.match(push.stdout + push.stderr, /rotate/);
    assert.ok(!filesIn('main', remote).includes('.env'), 'remote tip no longer has .env');
    assert.ok(!must(['ls-files'], dev).split('\n').includes('.env'), 'no longer in the git cache');
    assert.ok(fs.existsSync(path.join(dev, '.env')), 'still on disk');
    assert.strictEqual(must(['status', '--porcelain'], dev), '', 'clean afterwards');
  });
});
