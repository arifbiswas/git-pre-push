const fs = require('fs');
const path = require('path');
const { getHooksDir, isGitRepo } = require('./utils/git');

const HOOK_MARKER = '# --- GIT-SAFTY SECURITY HOOK START ---';
const HOOK_END_MARKER = '# --- GIT-SAFTY SECURITY HOOK END ---';

const HOOK_TYPES = ['pre-push', 'post-checkout', 'post-merge', 'post-rewrite'];

// Absolute path of this installation's CLI, baked into the hook so a cloned
// repository can never substitute its own ./bin/cli.js or node_modules copy.
// Forward slashes so Git for Windows' sh can test and run the path too.
const CLI_PATH = path.resolve(__dirname, '..', 'bin', 'cli.js').replace(/\\/g, '/');

function shellQuote(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`;
}

function runnerFunction() {
  return `GITSAFTY_CLI=${shellQuote(CLI_PATH)}

run_gitsafty() {
  # 1. The exact GitSafty installation that installed this hook
  if [ -f "$GITSAFTY_CLI" ] && command -v node >/dev/null 2>&1; then
    node "$GITSAFTY_CLI" "$@"
    return $?
  fi
  # 2. Globally installed command
  for c in gitsafty git-safty git-pre-push; do
    if command -v "$c" >/dev/null 2>&1; then
      "$c" "$@"
      return $?
    fi
  done
  return 127
}

# Shown when GitSafty itself can't be found, so git never fails silently.
gitsafty_missing() {
  HOOK_DIR=$(cd "$(dirname "$0")" 2>/dev/null && pwd)
  echo "" >&2
  echo "⚠  GitSafty is not reachable (\$GITSAFTY_CLI is missing and no gitsafty command on PATH)." >&2
  echo "   git still runs GitSafty's hooks, so protection is OFF until you fix this:" >&2
  echo "   Reinstall:     npm install -g @arifbiswas/git-pre-push && gitsafty init --global" >&2
  case "$HOOK_DIR" in
    *.git-hooks-safty)
      echo "   Or turn off:   git config --global --unset core.hooksPath && rm -rf ~/.git-hooks-safty" >&2 ;;
    *)
      echo "   Or turn off:   rm \\"$HOOK_DIR/pre-push\\" \\"$HOOK_DIR/post-checkout\\" \\"$HOOK_DIR/post-merge\\" \\"$HOOK_DIR/post-rewrite\\"" >&2 ;;
  esac
  echo "" >&2
}
`;
}

function prePushBody() {
  return `run_scanner() {
  run_gitsafty scan-push "$@"
  rc=$?
  if [ $rc -ne 127 ]; then return $rc; fi
  gitsafty_missing

  # 3. Published package via bunx / npx
  if command -v bunx >/dev/null 2>&1; then
    bunx --yes @arifbiswas/git-pre-push scan-push "$@" 2>/dev/null
    if [ $? -eq 0 ]; then return 0; fi
  fi
  if command -v npx >/dev/null 2>&1; then
    npx --yes @arifbiswas/git-pre-push scan-push "$@" 2>/dev/null
    if [ $? -eq 0 ]; then return 0; fi
  fi

  # 4. Shell Fallback Guard (if Node/package is not available in current subshell)
  echo "[GitSafty Fallback] Scanning push payload..."
  ZERO_OID="0000000000000000000000000000000000000000"
  SUSPICIOUS_FILES="temp_auto_push\\.bat|temp_interactive_push\\.bat|config\\.bat|autorun\\.bat|hidden_push\\.sh|.*\\.exe$|.*\\.vbs$|.*\\.ps1$|.*\\.scr$"
  SUSPICIOUS_PAYLOAD="powershell.*-enc|curl.*\\|.*bash|eval\\(base64_decode|cmd\\.exe.*\\/c|global\\[.!.\\]=.[0-9-]+.;(var|\\(function)"

  while read local_ref local_oid remote_ref remote_oid; do
    if [ "$local_oid" = "$ZERO_OID" ]; then continue; fi
    if [ "$remote_oid" = "$ZERO_OID" ]; then
      DIFF_COMMITS="$local_oid"
    else
      DIFF_COMMITS="$remote_oid..$local_oid"
    fi

    CHANGED_FILES=$(git log "$DIFF_COMMITS" --name-only --oneline | grep -v '^[a-f0-9]' | sort -u)
    MATCHED=$(echo "$CHANGED_FILES" | grep -Ei "$SUSPICIOUS_FILES")
    if [ -n "$MATCHED" ]; then
      echo "\\033[0;31m[BLOCKED] GitSafty blocked push due to malicious file pattern:\\033[0m"
      echo "$MATCHED"
      return 1
    fi

    DIFF_CONTENT=$(git diff "$DIFF_COMMITS")
    if echo "$DIFF_CONTENT" | grep -Eiq "$SUSPICIOUS_PAYLOAD"; then
      echo "\\033[0;31m[BLOCKED] GitSafty detected suspicious execution signature in commit diff!\\033[0m"
      return 1
    fi
  done

  return 0
}

run_scanner "$@"
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
  exit 1
fi`;
}

function postHookBody(hookType) {
  const command = { 'post-checkout': 'scan-checkout', 'post-merge': 'scan-merge', 'post-rewrite': 'scan-rewrite' }[hookType];
  return `# Runs after git clone / checkout / pull. Reports and removes confirmed
# malware. Never fails the git command itself.
run_gitsafty ${command} "$@"
if [ $? -eq 127 ]; then
  gitsafty_missing
  # Fallback: GitSafty not reachable, at least warn about the known loader marker.
  HITS=$(git grep -l -I -E 'global\\[.!.\\]=.[0-9-]+.;(var|\\(function)' 2>/dev/null | head -20)
  if [ -n "$HITS" ]; then
    echo "\\033[0;31m[GitSafty Fallback] MALWARE marker found. Do NOT open this folder in an IDE:\\033[0m"
    echo "$HITS"
  fi
fi
exit 0`;
}

function generateHookContent(hookType = 'pre-push') {
  const body = hookType === 'pre-push' ? prePushBody() : postHookBody(hookType);
  return `${HOOK_MARKER}
# GitSafty: Malware & Secret Guard (${hookType})
# Scans pushed commits, cloned repositories and pulled changes for malware.

${runnerFunction()}
${body}
${HOOK_END_MARKER}
`;
}

function writeHook(hooksDir, hookType) {
  const hookPath = path.join(hooksDir, hookType);
  const newHookBlock = generateHookContent(hookType);

  let finalContent = '';
  if (fs.existsSync(hookPath)) {
    // Make writable if previously locked
    try { fs.chmodSync(hookPath, 0o755); } catch (_) {}

    const existing = fs.readFileSync(hookPath, 'utf8');
    if (existing.includes(HOOK_MARKER)) {
      const regex = new RegExp(`${HOOK_MARKER}[\\s\\S]*?${HOOK_END_MARKER}`, 'm');
      finalContent = existing.replace(regex, () => newHookBlock.trim());
    } else {
      finalContent = existing.trim() + '\n\n' + newHookBlock;
    }
  } else {
    finalContent = '#!/bin/sh\n' + newHookBlock;
  }

  fs.writeFileSync(hookPath, finalContent, { mode: 0o755 });
  try { fs.chmodSync(hookPath, 0o755); } catch (_) {}
  return hookPath;
}

/**
 * Installs pre-push hook into git repository or globally
 * @param {string} [cwd] 
 * @param {boolean} [isGlobal=false]
 * @returns {{ success: boolean, message: string }}
 */
function installHook(cwd = process.cwd(), isGlobal = false) {
  let hooksDir;

  if (isGlobal) {
    const homeDir = process.env.HOME || process.env.USERPROFILE || '';
    hooksDir = path.join(homeDir, '.git-hooks-safty');
    if (!fs.existsSync(hooksDir)) {
      fs.mkdirSync(hooksDir, { recursive: true });
    }
    // Set global core.hooksPath
    const { runGit } = require('./utils/git');
    runGit(`config --global core.hooksPath "${hooksDir}"`);
  } else {
    if (!isGitRepo(cwd)) {
      return {
        success: false,
        message: 'Not a git repository. Run "git init" first or use --global.'
      };
    }
    hooksDir = getHooksDir(cwd);
  }

  if (!hooksDir) {
    return {
      success: false,
      message: 'Could not resolve git hooks directory.'
    };
  }

  try {
    if (!fs.existsSync(hooksDir)) {
      fs.mkdirSync(hooksDir, { recursive: true });
    }

    const written = HOOK_TYPES.map(type => writeHook(hooksDir, type));
    const hookPath = written[0];

    const typeMsg = isGlobal ? 'GLOBAL Git hook for ALL repositories on this PC' : 'local pre-push hook';
    return {
      success: true,
      message: `Successfully installed GitSafty ${typeMsg} (pre-push, post-checkout, post-merge, post-rewrite) at: ${path.dirname(hookPath)}`
    };
  } catch (err) {
    return {
      success: false,
      message: `Failed to install hook: ${err.message}`
    };
  }
}

function globalHooksDir() {
  const homeDir = process.env.HOME || process.env.USERPROFILE || '';
  return path.join(homeDir, '.git-hooks-safty');
}

/** Removes the GitSafty block from every hook in a directory. */
function stripHooksIn(hooksDir) {
  let removed = 0;
  for (const type of HOOK_TYPES) {
    const hookPath = path.join(hooksDir, type);
    if (!fs.existsSync(hookPath)) continue;
    try { fs.chmodSync(hookPath, 0o755); } catch (_) {}
    const existing = fs.readFileSync(hookPath, 'utf8');
    if (!existing.includes(HOOK_MARKER)) continue;

    const regex = new RegExp(`${HOOK_MARKER}[\\s\\S]*?${HOOK_END_MARKER}\\n?`, 'm');
    const cleaned = existing.replace(regex, '').trim();

    if (cleaned === '' || cleaned === '#!/bin/sh' || cleaned === '#!/usr/bin/env bash') {
      fs.unlinkSync(hookPath);
    } else {
      fs.writeFileSync(hookPath, cleaned + '\n', { mode: 0o755 });
    }
    removed++;
  }
  return removed;
}

function samePath(a, b) {
  if (!a || !b) return false;
  const norm = (p) => path.resolve(p.replace(/^~(?=$|[\\/])/, process.env.HOME || process.env.USERPROFILE || '~'));
  const x = norm(a);
  const y = norm(b);
  return process.platform === 'win32' || process.platform === 'darwin' ? x.toLowerCase() === y.toLowerCase() : x === y;
}

/**
 * Removes the GitSafty global hooks (~/.git-hooks-safty) and, when nothing
 * else is left there, the global core.hooksPath that points to it.
 */
function uninstallGlobalHook() {
  const { runGit } = require('./utils/git');
  const dir = globalHooksDir();
  const configured = runGit('config --global core.hooksPath');
  const ours = samePath(configured, dir);

  if (!fs.existsSync(dir) && !ours) {
    return { success: true, message: 'GitSafty global hooks are not installed.' };
  }

  let removed = 0;
  try {
    if (fs.existsSync(dir)) {
      removed = stripHooksIn(dir);
      if (fs.readdirSync(dir).length === 0) fs.rmdirSync(dir);
    }
  } catch (err) {
    return { success: false, message: `Failed to remove global hooks: ${err.message}` };
  }

  let unset = false;
  if (ours && !fs.existsSync(dir)) {
    runGit('config --global --unset core.hooksPath');
    unset = true;
  }

  const parts = [`Removed ${removed} GitSafty global hook(s)`];
  if (unset) parts.push('and reset git core.hooksPath');
  else if (ours) parts.push(`(kept core.hooksPath: ${dir} still holds other hooks)`);
  return { success: true, message: parts.join(' ') + '. Repositories on this PC are no longer scanned by GitSafty.' };
}

/**
 * Removes GitSafty hooks.
 * - isGlobal, or run outside a git repository: removes the global hooks.
 * - inside a repository: removes this repository's own hooks.
 * @param {string} [cwd]
 * @param {boolean} [isGlobal=false]
 * @returns {{ success: boolean, message: string }}
 */
function uninstallHook(cwd = process.cwd(), isGlobal = false) {
  if (isGlobal || !isGitRepo(cwd)) return uninstallGlobalHook();

  const { runGit } = require('./utils/git');
  // The repository's own hooks dir, NOT the global core.hooksPath.
  const localHooksPath = runGit('config --local core.hooksPath', cwd);
  const gitDir = runGit('rev-parse --git-dir', cwd);
  const hooksDir = localHooksPath ? path.resolve(cwd, localHooksPath) : path.resolve(cwd, gitDir, 'hooks');

  let removed = 0;
  try {
    if (fs.existsSync(hooksDir)) removed = stripHooksIn(hooksDir);
  } catch (err) {
    return { success: false, message: `Failed to uninstall hook: ${err.message}` };
  }

  const globalActive = samePath(runGit('config --global core.hooksPath', cwd), globalHooksDir());
  const note = globalActive ? ' Global GitSafty hooks are still active for all repos (remove with: gitsafty uninstall --global).' : '';
  if (!removed) return { success: true, message: `No GitSafty hooks in this repository.${note}` };
  return { success: true, message: `GitSafty hooks removed from this repository (${removed}).${note}` };
}

/**
 * Re-writes already installed GitSafty hooks with this version's content.
 * Used after an update so every device gets the new clone/pull protection.
 */
function refreshInstalledHooks() {
  const homeDir = process.env.HOME || process.env.USERPROFILE || '';
  const globalDir = path.join(homeDir, '.git-hooks-safty');
  const prePush = path.join(globalDir, 'pre-push');
  try {
    if (fs.existsSync(prePush) && fs.readFileSync(prePush, 'utf8').includes(HOOK_MARKER)) {
      HOOK_TYPES.forEach(type => writeHook(globalDir, type));
      return globalDir;
    }
  } catch (_) {}
  return null;
}

module.exports = {
  installHook,
  uninstallHook,
  uninstallGlobalHook,
  refreshInstalledHooks,
  generateHookContent,
  HOOK_TYPES,
  HOOK_MARKER,
  HOOK_END_MARKER
};

