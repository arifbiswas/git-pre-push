const fs = require('fs');
const path = require('path');
const { getHooksDir, isGitRepo } = require('./utils/git');

const HOOK_MARKER = '# --- GIT-SAFTY SECURITY HOOK START ---';
const HOOK_END_MARKER = '# --- GIT-SAFTY SECURITY HOOK END ---';

function generateHookContent() {
  return `${HOOK_MARKER}
# GitSafty: Automatic Pre-Push Malware & Secret Guard
# Prevents unauthorized scripts, Trojans, and secret leaks from reaching remote repositories.

run_scanner() {
  # 1. Try local node_modules
  if [ -f "./node_modules/git-safty/bin/cli.js" ]; then
    node "./node_modules/git-safty/bin/cli.js" scan-push "$@"
    return $?
  fi

  # 2. Try repository local bin
  if [ -f "./bin/cli.js" ]; then
    node "./bin/cli.js" scan-push "$@"
    return $?
  fi

  # 3. Try npx
  if command -v npx >/dev/null 2>&1; then
    npx --no-install git-safty scan-push "$@"
    return $?
  fi

  # 4. Try global command
  if command -v git-safty >/dev/null 2>&1; then
    git-safty scan-push "$@"
    return $?
  fi

  # 5. Shell Fallback Guard (if Node is not available in current subshell)
  echo "[GitSafty Fallback] Scanning push payload..."
  ZERO_OID="0000000000000000000000000000000000000000"
  SUSPICIOUS_FILES="temp_auto_push\\.bat|temp_interactive_push\\.bat|config\\.bat|autorun\\.bat|hidden_push\\.sh|.*\\.exe$|.*\\.vbs$|.*\\.ps1$|.*\\.scr$"
  SUSPICIOUS_PAYLOAD="powershell.*-enc|curl.*\\|.*bash|eval\\(base64_decode|cmd\\.exe.*\\/c"

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
fi
${HOOK_END_MARKER}
`;
}

/**
 * Installs pre-push hook into git repository
 * @param {string} [cwd] 
 * @returns {{ success: boolean, message: string }}
 */
function installHook(cwd = process.cwd()) {
  if (!isGitRepo(cwd)) {
    return {
      success: false,
      message: 'Not a git repository. Run "git init" first.'
    };
  }

  const hooksDir = getHooksDir(cwd);
  if (!hooksDir) {
    return {
      success: false,
      message: 'Could not resolve .git/hooks directory.'
    };
  }

  try {
    if (!fs.existsSync(hooksDir)) {
      fs.mkdirSync(hooksDir, { recursive: true });
    }

    const hookPath = path.join(hooksDir, 'pre-push');
    const newHookBlock = generateHookContent();

    let finalContent = '';
    if (fs.existsSync(hookPath)) {
      const existing = fs.readFileSync(hookPath, 'utf8');
      if (existing.includes(HOOK_MARKER)) {
        // Replace existing block
        const regex = new RegExp(`${HOOK_MARKER}[\\s\\S]*?${HOOK_END_MARKER}`, 'm');
        finalContent = existing.replace(regex, newHookBlock.trim());
      } else {
        // Append to existing hook
        finalContent = existing.trim() + '\n\n' + newHookBlock;
      }
    } else {
      finalContent = '#!/bin/sh\n' + newHookBlock;
    }

    fs.writeFileSync(hookPath, finalContent, { mode: 0o755 });
    // Explicitly chmod for Unix / macOS
    try {
      fs.chmodSync(hookPath, 0o755);
    } catch (_) {}

    return {
      success: true,
      message: `Successfully installed GitSafty pre-push hook at: ${hookPath}`
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

  const hookPath = path.join(hooksDir, 'pre-push');
  if (!fs.existsSync(hookPath)) {
    return { success: true, message: 'Hook was not installed.' };
  }

  try {
    const existing = fs.readFileSync(hookPath, 'utf8');
    if (!existing.includes(HOOK_MARKER)) {
      return { success: true, message: 'GitSafty hook not present in pre-push file.' };
    }

    const regex = new RegExp(`${HOOK_MARKER}[\\s\\S]*?${HOOK_END_MARKER}\\n?`, 'm');
    const cleaned = existing.replace(regex, '').trim();

    if (cleaned === '' || cleaned === '#!/bin/sh' || cleaned === '#!/usr/bin/env bash') {
      fs.unlinkSync(hookPath);
    } else {
      fs.writeFileSync(hookPath, cleaned + '\n', { mode: 0o755 });
    }

    return { success: true, message: 'GitSafty pre-push hook removed successfully.' };
  } catch (err) {
    return { success: false, message: `Failed to uninstall hook: ${err.message}` };
  }
}

module.exports = {
  installHook,
  uninstallHook,
  generateHookContent,
  HOOK_MARKER,
  HOOK_END_MARKER
};
