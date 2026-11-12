const fs = require('fs');
const path = require('path');
const { getHooksDir, isGitRepo } = require('./utils/git');

const HOOK_MARKER = '# --- GIT-SAFTY SECURITY HOOK START ---';
const HOOK_END_MARKER = '# --- GIT-SAFTY SECURITY HOOK END ---';

const HOOK_TYPES = ['pre-push', 'post-checkout', 'post-merge'];

// Absolute path of this installation's CLI, baked into the hook so a cloned
// repository can never substitute its own ./bin/cli.js or node_modules copy.
const CLI_PATH = path.resolve(__dirname, '..', 'bin', 'cli.js');

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
`;
}

function prePushBody() {
  return `run_scanner() {
  run_gitsafty scan-push "$@"
  rc=$?
  if [ $rc -ne 127 ]; then return $rc; fi

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
  const command = hookType === 'post-checkout' ? 'scan-checkout' : 'scan-merge';
  return `# Runs after git clone / checkout / pull. Reports and removes confirmed
# malware. Never fails the git command itself.
run_gitsafty ${command} "$@"
if [ $? -eq 127 ]; then
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
      message: `Successfully installed GitSafty ${typeMsg} (pre-push, post-checkout, post-merge) at: ${path.dirname(hookPath)}`
    };
  } catch (err) {
    return {
      success: false,
      message: `Failed to install hook: ${err.message}`
    };
  }
}

/**
 * Removes GitSafty hook
 * @param {string} [cwd] 
 * @returns {{ success: boolean, message: string }}
 */
function uninstallHook(cwd = process.cwd()) {
  const hooksDir = getHooksDir(cwd);
  if (!hooksDir) {
    return { success: false, message: 'Git hooks directory not found.' };
  }

  let removed = 0;
  try {
    for (const type of HOOK_TYPES) {
      const hookPath = path.join(hooksDir, type);
      if (!fs.existsSync(hookPath)) continue;
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
  } catch (err) {
    return { success: false, message: `Failed to uninstall hook: ${err.message}` };
  }

  if (!removed) return { success: true, message: 'GitSafty hook not present.' };
  return { success: true, message: `GitSafty hooks removed successfully (${removed}).` };
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
  refreshInstalledHooks,
  generateHookContent,
  HOOK_TYPES,
  HOOK_MARKER,
  HOOK_END_MARKER
};

