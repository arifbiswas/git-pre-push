/**
 * GitSafty doctor: finds broken or outdated installs and says exactly what to run.
 *
 *   gitsafty doctor        -> report problems + fix commands
 *   gitsafty doctor --fix  -> also apply the safe fixes
 *
 * Also exports hintForError(), used everywhere GitSafty can fail, so every
 * error message ends with a concrete next step.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { colors } = require('./reporter');

const PACKAGE = '@arifbiswas/git-pre-push';
const isWin = process.platform === 'win32';

function homeDir() {
  return process.env.HOME || process.env.USERPROFILE || os.homedir();
}

function globalHooksDir() {
  return path.join(homeDir(), '.git-hooks-safty');
}

function gitOut(args, cwd) {
  const r = spawnSync('git', args, { cwd, encoding: 'utf8' });
  if (r.error || r.status !== 0) return null;
  return (r.stdout || '').trim();
}

function onPath(cmd) {
  const r = spawnSync(isWin ? 'where' : 'command', isWin ? [cmd] : ['-v', cmd], { encoding: 'utf8', shell: !isWin });
  return r.status === 0;
}

// ---------------------------------------------------------------------------
// Ready-to-paste commands (per OS)
// ---------------------------------------------------------------------------

const commands = {
  reinstall: () => [`npm install -g ${PACKAGE}`, 'gitsafty init --global'],
  removeHooks: () => [
    'git config --global --unset core.hooksPath',
    isWin ? 'Remove-Item -Recurse -Force "$HOME\\.git-hooks-safty"' : 'rm -rf ~/.git-hooks-safty'
  ],
  removeVaultHelper: (host = 'github.com') => [`git config --global --remove-section credential.https://${host}`],
  npmPermission: () => isWin
    ? ['Run the terminal as Administrator, or install Node.js with nvm-windows', `npm install -g ${PACKAGE}`]
    : ['mkdir -p ~/.npm-global && npm config set prefix ~/.npm-global',
      'echo \'export PATH="$HOME/.npm-global/bin:$PATH"\' >> ~/.zshrc && source ~/.zshrc',
      `npm install -g ${PACKAGE}`],
  network: () => ['npm config get registry   # should be https://registry.npmjs.org/', 'npm cache verify', `npm install -g ${PACKAGE}`]
};

function printCommands(title, cmds) {
  console.log(`  ${colors.bold}${title}${colors.reset}`);
  for (const c of cmds) console.log(`    ${colors.cyan}${c}${colors.reset}`);
}

/** The two "get me out of here" commands, shown whenever GitSafty itself is broken. */
function printEscapeHatch() {
  printCommands('Reinstall GitSafty:', commands.reinstall());
  printCommands('Or turn GitSafty off completely:', commands.removeHooks());
}

// ---------------------------------------------------------------------------
// Error -> hint
// ---------------------------------------------------------------------------

/**
 * Maps an error (or message) to a short explanation + commands.
 * @returns {{ problem: string, commands: string[] }}
 */
function hintForError(err) {
  const code = err && err.code;
  const msg = String((err && err.message) || err || '');

  if (code === 'EACCES' || code === 'EPERM' || /permission denied|EACCES|EPERM/i.test(msg)) {
    const file = (err && err.path) || (msg.match(/'([^']+)'/) || [])[1];
    if (file && /node_modules|npm/.test(file)) {
      return { problem: 'npm has no permission to write its global folder.', commands: commands.npmPermission() };
    }
    return {
      problem: `No permission to change ${file || 'a file'}. It may be read-only or owned by another user.`,
      commands: file ? [isWin ? `icacls "${file}"` : `ls -l "${file}"`, isWin ? 'Run the terminal as your normal user' : `chmod u+w "${file}"`] : []
    };
  }
  if (['ENOTFOUND', 'ETIMEDOUT', 'ECONNRESET', 'EAI_AGAIN', 'ECONNREFUSED'].includes(code) || /ENOTFOUND|ETIMEDOUT|ECONNRESET|EAI_AGAIN|network|socket hang up/i.test(msg)) {
    return { problem: 'Network problem: GitSafty/npm could not reach the internet.', commands: commands.network() };
  }
  if ((code === 'ENOENT' && /\bgit\b/.test(msg)) || /git: command not found|'git' is not recognized/i.test(msg)) {
    return { problem: 'git is not installed or not on PATH.', commands: [isWin ? 'winget install Git.Git' : (process.platform === 'darwin' ? 'xcode-select --install' : 'sudo apt install git')] };
  }
  if (err instanceof SyntaxError || /Unexpected token|SyntaxError|is not a function/i.test(msg)) {
    return { problem: `This Node.js (${process.version}) may be too old for GitSafty (needs 16+).`, commands: ['node --version', isWin ? 'winget install OpenJS.NodeJS.LTS' : 'nvm install --lts && nvm use --lts', `npm install -g ${PACKAGE}`] };
  }
  if (/Cannot find module/i.test(msg)) {
    return { problem: 'GitSafty files are missing (broken or half-finished install).', commands: commands.reinstall() };
  }
  if (/Swift compiler not found|xcode-select/i.test(msg)) {
    return { problem: 'Touch ID / Secure Enclave mode needs Apple command line tools.', commands: ['xcode-select --install', 'gitsafty vault setup', 'gitsafty vault setup --passphrase   # or use a passphrase instead'] };
  }
  if (/Windows Hello is not set up/i.test(msg)) {
    return { problem: 'Windows Hello (PIN) is not set up on this PC.', commands: ['start ms-settings:signinoptions   # add a PIN', 'gitsafty vault setup', 'gitsafty vault setup --passphrase   # or use a passphrase instead'] };
  }
  if (/helper was modified|script changed since setup/i.test(msg)) {
    return { problem: 'The vault unlock helper changed (GitSafty update, or tampering).', commands: ['gitsafty vault setup   # re-create the vault with the current version'] };
  }
  if (/Wrong passphrase|did not match/i.test(msg)) {
    return { problem: 'Wrong passphrase / key. Forgot it? Create a new vault with a new token.', commands: ['gitsafty vault setup'] };
  }
  return { problem: msg || 'Unexpected error.', commands: ['gitsafty doctor   # find out what is wrong', 'gitsafty doctor --fix'] };
}

function printHint(err, prefix = 'What to do') {
  const hint = hintForError(err);
  console.error(`\n${colors.yellow}${colors.bold}💡 ${prefix}:${colors.reset} ${hint.problem}`);
  for (const c of hint.commands) console.error(`    ${colors.cyan}${c}${colors.reset}`);
  console.error('');
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

/**
 * @param {{ cwd?: string, cliPath?: string }} [opts]
 * @returns {Array<{ id: string, ok: boolean, level: 'ok'|'warn'|'error', title: string, detail?: string, commands?: string[], fix?: Function }>}
 */
function runChecks({ cwd = process.cwd(), cliPath } = {}) {
  const installer = require('./installer');
  const checks = [];
  const add = (c) => checks.push({ level: c.ok ? 'ok' : 'error', ...c });
  const thisCli = (cliPath || path.resolve(__dirname, '..', 'bin', 'cli.js')).replace(/\\/g, '/');

  // Node
  const major = Number(process.versions.node.split('.')[0]);
  add({
    id: 'node', ok: major >= 16, title: `Node.js ${process.version}`,
    detail: major >= 16 ? undefined : 'GitSafty needs Node.js 16 or newer.',
    commands: major >= 16 ? undefined : hintForError(new SyntaxError('old node')).commands
  });

  // git
  const gitVersion = gitOut(['--version'], cwd);
  add({
    id: 'git', ok: !!gitVersion, title: gitVersion || 'git not found',
    commands: gitVersion ? undefined : hintForError(new Error("'git' is not recognized")).commands
  });
  if (!gitVersion) return checks;

  // Global hooks
  const hooksPath = gitOut(['config', '--global', 'core.hooksPath'], cwd);
  const gdir = globalHooksDir();
  const pointsToOurs = hooksPath && path.resolve(hooksPath.replace(/^~/, homeDir())).toLowerCase() === path.resolve(gdir).toLowerCase();

  if (!hooksPath) {
    checks.push({ id: 'global-hooks', ok: true, level: 'warn', title: 'Global protection is off (clone/pull/push on other repos are not scanned)', commands: ['gitsafty init --global'] });
  } else if (pointsToOurs && !fs.existsSync(gdir)) {
    add({
      id: 'global-hooks-missing', ok: false,
      title: 'git points to ~/.git-hooks-safty but the folder is missing (no repo runs any hook)',
      commands: ['gitsafty init --global', ...commands.removeHooks().slice(0, 1)],
      fix: () => installer.installHook(cwd, true)
    });
  } else if (pointsToOurs) {
    const missing = [];
    const broken = [];
    const outdated = [];
    let goneTarget = null;
    for (const type of installer.HOOK_TYPES) {
      const file = path.join(gdir, type);
      if (!fs.existsSync(file)) { missing.push(type); continue; }
      const content = fs.readFileSync(file, 'utf8');
      if (!content.includes(installer.HOOK_MARKER)) continue; // user's own hook
      const m = content.match(/^GITSAFTY_CLI='([^']*)'/m);
      const target = m ? m[1] : null;
      const reachable = (target && fs.existsSync(target)) || onPath('gitsafty');
      if (!reachable) {
        broken.push(type);
        goneTarget = goneTarget || target;
      } else if (!m || !content.includes(installer.generateHookContent(type).trim())) {
        outdated.push(type);
      }
    }
    const refresh = () => installer.installHook(cwd, true);
    if (broken.length) {
      add({
        id: 'hook-broken', ok: false,
        title: `Global hooks can't find GitSafty (${broken.join(', ')})${goneTarget ? `: ${goneTarget} is gone` : ''}`,
        detail: 'GitSafty was uninstalled or moved, but git still runs its hooks, so nothing is scanned.',
        commands: [...commands.reinstall(), '# or turn it off:', ...commands.removeHooks()],
        fix: refresh
      });
    }
    if (missing.length) {
      add({
        id: 'hook-missing', ok: false,
        title: `Global hooks missing: ${missing.join(', ')}`,
        detail: missing.includes('pre-push') ? 'Pushes are not scanned.' : 'Clones/pulls are not scanned.',
        commands: ['gitsafty init --global'],
        fix: refresh
      });
    }
    if (outdated.length) {
      checks.push({
        id: 'hook-outdated', ok: true, level: 'warn',
        title: `Global hooks are from another GitSafty version (${outdated.join(', ')})`,
        commands: ['gitsafty init --global'],
        fix: refresh
      });
    }
    if (!checks.some(c => c.id.startsWith('hook-'))) {
      checks.push({ id: 'global-hooks', ok: true, level: 'ok', title: `Global hooks OK (${gdir})` });
    }
  } else {
    checks.push({ id: 'global-hooks-foreign', ok: true, level: 'warn', title: `core.hooksPath points to another tool's folder: ${hooksPath}`, detail: 'GitSafty global hooks are not active.' });
  }

  // Shell pull-scan function
  try {
    const shell = require('./shellIntegration');
    const st = shell.shellIntegrationStatus();
    if (!st.installed.length) {
      checks.push({ id: 'pull-scan', ok: true, level: 'warn', title: 'Pulls that are "Already up to date" are not scanned (git runs no hook then)', commands: ['gitsafty pull-scan on'] });
    } else {
      checks.push({ id: 'pull-scan', ok: true, level: 'ok', title: `Every git pull is scanned (${st.installed.join(', ')})`, fix: () => shell.installShellIntegration() });
    }
  } catch (_) {}

  // Credential helper / vault
  try {
    const vault = require('./vault');
    const v = vault.readVault();
    const host = (v && v.meta && v.meta.host) || 'github.com';
    const helpers = vault.effectiveHelpers(host, cwd);
    const ours = helpers.filter(h => /\bcredential$/.test(h) && /cli\.js/.test(h));
    for (const h of ours) {
      const paths = [...h.matchAll(/'([^']+)'/g)].map(x => x[1]);
      const missing = paths.filter(p => !fs.existsSync(p));
      if (missing.length) {
        add({
          id: 'vault-helper-broken', ok: false,
          title: `GitHub login helper points to a missing file: ${missing.join(', ')}`,
          detail: 'Every git push to GitHub will fail or ask for a password (Node version changed, or GitSafty moved).',
          commands: v ? ['gitsafty vault setup   # re-register with the current paths'] : commands.removeVaultHelper(host),
          fix: () => {
            if (v) {
              vault.installHelper(host);
            } else {
              vault.removeHelper(host);
            }
          }
        });
      }
    }
    if (ours.length && !v) {
      add({
        id: 'vault-missing', ok: false,
        title: `GitSafty is the GitHub login helper but there is no vault (${vault.vaultPath()})`,
        detail: 'git can not get a login for github.com.',
        commands: ['gitsafty vault setup', '# or go back to normal login:', ...commands.removeVaultHelper(host)],
        fix: () => vault.removeHelper(host)
      });
    } else if (v && !ours.length) {
      checks.push({ id: 'vault-inactive', ok: true, level: 'warn', title: 'A vault exists but git is not using it', commands: ['gitsafty vault setup'] });
    } else if (v && ours.length && !checks.some(c => c.id.startsWith('vault'))) {
      checks.push({ id: 'vault', ok: true, level: 'ok', title: `GitHub login vault OK (${v.meta.username || host}, ${v.version === 2 ? v.protector.type : 'passphrase'})` });
    }
  } catch (_) {}

  return checks;
}

/**
 * Prints the doctor report. With fix=true, applies the safe fixes.
 * @returns {number} exit code (1 if errors remain)
 */
function runDoctor({ fix = false, cwd = process.cwd() } = {}) {
  console.log(`\n${colors.bold}GitSafty doctor${colors.reset} ${colors.dim}(${process.platform}, ${path.resolve(__dirname, '..')})${colors.reset}\n`);
  let checks = runChecks({ cwd });

  if (fix) {
    const fixable = checks.filter(c => c.fix && c.level !== 'ok');
    const done = new Set();
    for (const c of fixable) {
      const key = c.fix.toString();
      if (done.has(key)) continue;
      done.add(key);
      try {
        c.fix();
        console.log(`  ${colors.green}🔧 Fixed:${colors.reset} ${c.title}`);
      } catch (err) {
        console.log(`  ${colors.red}✖ Could not fix:${colors.reset} ${c.title}: ${err.message}`);
      }
    }
    if (fixable.length) console.log('');
    checks = runChecks({ cwd });
  }

  for (const c of checks) {
    const icon = c.level === 'ok' ? `${colors.green}✔` : c.level === 'warn' ? `${colors.yellow}⚠` : `${colors.red}✖`;
    console.log(`  ${icon}${colors.reset} ${c.title}`);
    if (c.detail) console.log(`     ${colors.dim}${c.detail}${colors.reset}`);
    if (c.level !== 'ok' && c.commands) {
      for (const cmd of c.commands) console.log(`     ${colors.cyan}${cmd}${colors.reset}`);
    }
  }

  const errors = checks.filter(c => c.level === 'error');
  const fixable = checks.filter(c => c.fix && c.level !== 'ok');
  console.log('');
  if (!errors.length && !checks.some(c => c.level === 'warn')) {
    console.log(`${colors.green}${colors.bold}✔ Everything looks good.${colors.reset}\n`);
  } else if (fixable.length && !fix) {
    console.log(`${colors.bold}Fix automatically:${colors.reset} ${colors.cyan}gitsafty doctor --fix${colors.reset}\n`);
  }
  if (errors.length) {
    const helperSet = checks.some(c => c.id.startsWith('vault'));
    printCommands('If nothing helps, turn GitSafty off completely:', [...commands.removeHooks(), ...(helperSet ? commands.removeVaultHelper() : [])]);
    console.log('');
  }
  return errors.length ? 1 : 0;
}

module.exports = {
  runDoctor,
  runChecks,
  hintForError,
  printHint,
  printEscapeHatch,
  commands
};
