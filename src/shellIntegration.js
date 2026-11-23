/**
 * Optional shell integration: scan after EVERY `git pull`.
 *
 * git runs no hook at all when a pull is "Already up to date", so hooks alone
 * can't do this. This adds a small `git` shell function that runs the real
 * git, keeps its exit code, and after `git pull` runs `gitsafty scan-pull`
 * (which skips the scan when a hook already scanned the same commit).
 *
 * On by default with the global install (`init --global`, and on update for
 * existing global installs). `gitsafty pull-scan off` removes it and is
 * remembered, so it is never added back by itself. It is written between
 * clear markers, in:
 *   macOS / Linux: the current shell's rc file (~/.zshrc, ~/.bashrc, fish config)
 *   Windows: PowerShell profiles, and ~/.bashrc for Git Bash
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const START = '# >>> gitsafty pull scan >>>';
const END = '# <<< gitsafty pull scan <<<';
const isWin = process.platform === 'win32';

function home() {
  return process.env.HOME || process.env.USERPROFILE || os.homedir();
}

function cliPath() {
  return path.resolve(__dirname, '..', 'bin', 'cli.js').replace(/\\/g, '/');
}

function shQuote(s) {
  return `'${String(s).replace(/'/g, `'\\''`)}'`;
}

function posixBlock() {
  return `${START}
# Added by GitSafty: scan the repository after every git pull, also when it
# is "Already up to date". Remove with: gitsafty pull-scan off
git() {
  command git "$@"
  local __gs_rc=$?
  local __gs_sub="" __gs_dir="" __gs_skip="" __gs_a
  for __gs_a in "$@"; do
    if [ -n "$__gs_skip" ]; then
      [ "$__gs_skip" = "-C" ] && __gs_dir="$__gs_a"
      __gs_skip=""
      continue
    fi
    case "$__gs_a" in
      -C|-c) __gs_skip="$__gs_a" ;;
      -*) ;;
      *) __gs_sub="$__gs_a"; break ;;
    esac
  done
  if [ "$__gs_sub" = "pull" ] && [ $__gs_rc -eq 0 ]; then
    (
      [ -n "$__gs_dir" ] && cd "$__gs_dir"
      if [ -f ${shQuote(cliPath())} ] && command -v node >/dev/null 2>&1; then
        node ${shQuote(cliPath())} scan-pull
      elif command -v gitsafty >/dev/null 2>&1; then
        gitsafty scan-pull
      fi
    )
  fi
  return $__gs_rc
}
${END}
`;
}

function fishBlock() {
  return `${START}
# Added by GitSafty: scan after every git pull. Remove with: gitsafty pull-scan off
function git --wraps git
    command git $argv
    set -l __gs_rc $status
    if test $__gs_rc -eq 0; and contains -- pull $argv[1]
        if test -f '${cliPath()}'; and type -q node
            node '${cliPath()}' scan-pull
        else if type -q gitsafty
            gitsafty scan-pull
        end
    end
    return $__gs_rc
end
${END}
`;
}

function powershellBlock() {
  const cli = cliPath().replace(/'/g, "''");
  return `${START}
# Added by GitSafty: scan after every git pull, also when "Already up to date".
# Remove with: gitsafty pull-scan off
function git {
  $gsGit = (Get-Command git -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source
  & $gsGit @args
  $gsRc = $LASTEXITCODE
  $gsSub = $null; $gsDir = $null; $gsSkip = $null
  foreach ($gsA in $args) {
    if ($gsSkip) { if ($gsSkip -eq '-C') { $gsDir = $gsA }; $gsSkip = $null; continue }
    if ($gsA -in @('-C', '-c')) { $gsSkip = $gsA; continue }
    if ("$gsA".StartsWith('-')) { continue }
    $gsSub = $gsA; break
  }
  if ($gsSub -eq 'pull' -and $gsRc -eq 0) {
    if ($gsDir) { Push-Location $gsDir }
    try {
      if ((Test-Path '${cli}') -and (Get-Command node -ErrorAction SilentlyContinue)) { & node '${cli}' scan-pull }
      elseif (Get-Command gitsafty -ErrorAction SilentlyContinue) { gitsafty scan-pull }
    } finally { if ($gsDir) { Pop-Location } }
  }
  $global:LASTEXITCODE = $gsRc
}
${END}
`;
}

function powershellProfiles() {
  const docs = path.join(home(), 'Documents');
  return [
    path.join(docs, 'WindowsPowerShell', 'Microsoft.PowerShell_profile.ps1'),
    path.join(docs, 'PowerShell', 'Microsoft.PowerShell_profile.ps1')
  ];
}

/** rc files GitSafty would write to, with the block flavour for each. */
function targets() {
  const out = [];
  const add = (file, kind, create) => out.push({ file, kind, create });
  if (isWin) {
    for (const p of powershellProfiles()) add(p, 'powershell', true);
    add(path.join(home(), '.bashrc'), 'posix', false); // Git Bash, only if it exists
    return out;
  }
  const shell = path.basename(process.env.SHELL || '');
  add(path.join(home(), '.zshrc'), 'posix', shell === 'zsh' || process.platform === 'darwin');
  add(path.join(home(), '.bashrc'), 'posix', shell === 'bash');
  add(path.join(home(), '.config', 'fish', 'config.fish'), 'fish', shell === 'fish');
  return out;
}

function blockFor(kind) {
  return kind === 'powershell' ? powershellBlock() : kind === 'fish' ? fishBlock() : posixBlock();
}

function stripBlock(text) {
  const re = new RegExp(`\\n?${START.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}[\\s\\S]*?${END.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\n?`, 'g');
  return text.replace(re, '\n').replace(/\n{3,}$/, '\n\n');
}

// Written when the user turns pull scan off, so the default never turns it back on.
function optOutFile() {
  return path.join(home(), '.gitsafty', 'pull-scan-off');
}

function isOptedOut() {
  return fs.existsSync(optOutFile());
}

/**
 * Adds (or refreshes) the git wrapper.
 * @returns {{ files: string[] }}
 */
function installShellIntegration() {
  try { fs.rmSync(optOutFile(), { force: true }); } catch (_) {}
  const files = [];
  for (const t of targets()) {
    const exists = fs.existsSync(t.file);
    if (!exists && !t.create) continue;
    fs.mkdirSync(path.dirname(t.file), { recursive: true });
    const current = exists ? fs.readFileSync(t.file, 'utf8') : '';
    const cleaned = stripBlock(current).replace(/\s*$/, '');
    fs.writeFileSync(t.file, (cleaned ? cleaned + '\n\n' : '') + blockFor(t.kind));
    files.push(t.file);
  }
  return { files };
}

/**
 * Removes the git wrapper everywhere it was added.
 * @param {{ optOut?: boolean }} [opts] optOut: the user turned it off; remember that
 * @returns {{ files: string[] }}
 */
function removeShellIntegration({ optOut = false } = {}) {
  if (optOut) {
    try {
      fs.mkdirSync(path.dirname(optOutFile()), { recursive: true });
      fs.writeFileSync(optOutFile(), `Turned off on ${new Date().toISOString()}. Turn on again: gitsafty pull-scan on\n`);
    } catch (_) {}
  }
  const files = [];
  for (const t of targets()) {
    if (!fs.existsSync(t.file)) continue;
    const current = fs.readFileSync(t.file, 'utf8');
    if (!current.includes(START)) continue;
    fs.writeFileSync(t.file, stripBlock(current).replace(/\s*$/, '\n'));
    files.push(t.file);
  }
  return { files };
}

/** Re-writes installed blocks that are from another version. @returns {string[]} files updated */
function refreshShellIntegration() {
  const updated = [];
  for (const t of targets()) {
    if (!fs.existsSync(t.file)) continue;
    const text = fs.readFileSync(t.file, 'utf8');
    if (!text.includes(START) || text.includes(blockFor(t.kind).trim())) continue;
    // Same rule as the hooks: only this copy's own block, or a real global install may take it over.
    const ownBlock = text.includes(cliPath()) || text.includes(cliPath().replace(/'/g, "''"));
    if (!ownBlock && !require('./installer').isPermanentGlobalInstall(cliPath())) continue;
    fs.writeFileSync(t.file, stripBlock(text).replace(/\s*$/, '') + '\n\n' + blockFor(t.kind));
    updated.push(t.file);
  }
  return updated;
}

function shellIntegrationStatus() {
  const installed = targets().filter(t => fs.existsSync(t.file) && fs.readFileSync(t.file, 'utf8').includes(START)).map(t => t.file);
  return { installed, cliExists: fs.existsSync(cliPath()), optedOut: isOptedOut() };
}

/** True when GitSafty's global hooks are active on this PC. */
function globalHooksActive() {
  const r = spawnSync('git', ['config', '--global', '--get', 'core.hooksPath'], { encoding: 'utf8' });
  const value = (r.stdout || '').trim();
  if (!value) return false;
  const expanded = value.replace(/^~(?=$|[\\/])/, home());
  return path.resolve(expanded) === path.resolve(home(), '.git-hooks-safty');
}

/**
 * Pull scan is on by default for global installs. Turns it on unless the
 * user turned it off before, it is already on, or this is CI.
 * @param {{ onlyIfGlobalHooks?: boolean }} [opts]
 * @returns {string[]} files it was added to (empty when nothing changed)
 */
function enableByDefault({ onlyIfGlobalHooks = false } = {}) {
  if (process.env.CI || process.env.GITSAFTY_NO_PULL_SCAN === '1' || isOptedOut()) return [];
  if (shellIntegrationStatus().installed.length) return [];
  if (onlyIfGlobalHooks && !globalHooksActive()) return [];
  return installShellIntegration().files;
}

/** Command that loads the change in the current terminal. */
function reloadHint() {
  if (isWin) return '. $PROFILE   # or open a new terminal';
  const shell = path.basename(process.env.SHELL || '');
  if (shell === 'fish') return 'source ~/.config/fish/config.fish';
  return `source ~/.${shell === 'bash' ? 'bashrc' : 'zshrc'}   # or open a new terminal`;
}

/** Syntax-checks the generated POSIX function with the local sh, if any. */
function checkPosixSyntax() {
  const r = spawnSync('sh', ['-n'], { input: posixBlock(), encoding: 'utf8' });
  return r.status === 0;
}

module.exports = {
  START,
  END,
  installShellIntegration,
  removeShellIntegration,
  refreshShellIntegration,
  shellIntegrationStatus,
  enableByDefault,
  isOptedOut,
  reloadHint,
  posixBlock,
  powershellBlock,
  checkPosixSyntax
};
